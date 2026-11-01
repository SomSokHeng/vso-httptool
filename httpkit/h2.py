import collections
import os
import struct
import threading
import time

from .conn import Dup
from .err import ConnError, H2Error, HpackError, HdrError, SecError
from .hdr import Hdrs, TOK
from .hpack import HpackDec, HpackEnc
from .msg import Resp

PREF = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
DATA, HEADERS, PRIORITY, RST, SETTINGS, PUSH, PING, GOAWAY, WINUP, CONT = range(10)
F_END = 1
F_ACK = 1
F_EH = 4
F_PAD = 8
F_PRI = 0x20
S_TBL, S_PUSH, S_MAXSTR, S_WIN, S_FRM, S_LST = 1, 2, 3, 4, 5, 6
E_NONE, E_PROTO, E_INT, E_FLOW, E_STTO, E_CLOSED, E_FSIZE, E_REFUSED, E_CANCEL, E_COMP, E_CONN, E_CALM = range(12)
MAXWIN = (1 << 31) - 1
CONN_H = frozenset(("connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "host"))
MF_IN = 1 << 16
SWIN_IN = 1 << 20
CWIN_IN = 1 << 24
MAX_CONT = 64


def frm(typ, flags, sid, pl=b""):
    n = len(pl)
    return struct.pack(">BHBBI", n >> 16, n & 0xFFFF, typ, flags, sid & 0x7FFFFFFF) + pl


def stg(items):
    return b"".join(struct.pack(">HI", k, v) for k, v in items)


def v_resp_hdrs(hl, trailer=False):
    out = Hdrs()
    st = None
    reg = False
    for n, v in hl:
        if n != n.lower():
            raise H2Error("uppercase header name", E_PROTO)
        if n.startswith(":"):
            if reg or trailer or n != ":status" or st is not None:
                raise H2Error("invalid pseudo-header %s" % n, E_PROTO)
            st = v
            continue
        reg = True
        if not TOK.match(n.encode("latin-1")) or n in CONN_H:
            raise H2Error("forbidden header %s" % n, E_PROTO)
        if n == "te":
            raise H2Error("te in response", E_PROTO)
        try:
            out.add(n, v)
        except HdrError as e:
            raise H2Error("bad header value: %s" % e, E_PROTO)
    if trailer:
        return None, out
    if st is None or len(st) != 3 or not st.isdigit():
        raise H2Error("missing or invalid :status", E_PROTO)
    return int(st), out


def req_hl(req):
    hl = [(":method", req.mth), (":scheme", req.url.scheme), (":authority", req.url.authority), (":path", req.url.target)]
    has_cl = False
    for k, v in req.hdrs:
        lk = k.lower()
        if lk in CONN_H:
            continue
        if lk == "te" and v.strip().lower() != "trailers":
            continue
        if lk == "content-length":
            has_cl = True
        hl.append((lk, v))
    if req.body and not has_cl:
        hl.append(("content-length", str(len(req.body))))
    elif not req.body and req.mth in ("POST", "PUT", "PATCH") and not has_cl:
        hl.append(("content-length", "0"))
    return hl


class Strm:
    def __init__(self, sid, sw, rw, head):
        self.sid = sid
        self.sw = sw
        self.rw = rw
        self.head = head
        self.ev = threading.Event()
        self.err = None
        self.status = None
        self.hdrs = None
        self.trl = Hdrs()
        self.body = bytearray()
        self.hblk = bytearray()
        self.hcnt = 0
        self.got_final = False
        self.rx = 0
        self.upd = 0
        self.rst = False
        self.sent_end = False


class H2Conn:
    proto = "h2"

    def __init__(self, conn, lim, tmo=30.0):
        self.c = conn
        self.lim = lim
        self.tmo = tmo
        self.dup = Dup(conn.sock)
        self.enc = HpackEnc(4096)
        self.dec = HpackDec(4096, lim.max_hdr_b)
        self.cv = threading.Condition()
        self.ql = threading.Lock()
        self.ocv = threading.Condition()
        self.oq = collections.deque()
        self.oqb = 0
        self.strms = {}
        self.nxt = 1
        self.rs = {S_TBL: 4096, S_PUSH: 1, S_MAXSTR: 1 << 30, S_WIN: 65535, S_FRM: 16384, S_LST: 1 << 30}
        self.cw = 65535
        self.rwc = CWIN_IN
        self.rupd = 0
        self.dead = None
        self.goaway = None
        self.got_set = False
        self.pings = {}
        self.ctl = 0
        self.ctl_t = time.monotonic()
        self.cbuf = None
        self.cur = None
        self.buf = bytearray()
        self.ok = True
        self.n = 0
        self.wt = threading.Thread(target=self.wloop, daemon=True)
        self.rt = threading.Thread(target=self.rloop, daemon=True)
        self.put(PREF + frm(SETTINGS, 0, 0, stg([(S_TBL, 4096), (S_PUSH, 0), (S_MAXSTR, 0), (S_WIN, SWIN_IN), (S_FRM, MF_IN), (S_LST, lim.max_hdr_b)])) + frm(WINUP, 0, 0, struct.pack(">I", CWIN_IN - 65535)), True)
        self.wt.start()
        self.rt.start()

    def alive(self):
        return self.dead is None and self.goaway is None and self.ok

    def put(self, data, force=False):
        with self.ocv:
            if not force:
                end = time.monotonic() + self.tmo
                while self.oqb > (1 << 20) and self.dead is None:
                    if not self.ocv.wait(max(0.01, end - time.monotonic())) and time.monotonic() >= end:
                        raise ConnError("write queue stalled")
            if self.dead is not None:
                raise self.dead
            self.oq.append(data)
            self.oqb += len(data)
            self.ocv.notify_all()

    def wloop(self):
        try:
            while True:
                with self.ocv:
                    while not self.oq and self.dead is None:
                        self.ocv.wait(0.5)
                        if self.dup.closed:
                            return
                    if not self.oq:
                        return
                    parts = []
                    n = 0
                    while self.oq and n < (1 << 18):
                        d = self.oq.popleft()
                        parts.append(d)
                        n += len(d)
                    self.oqb -= n
                    self.ocv.notify_all()
                self.dup.send_all(b"".join(parts), self.tmo)
        except ConnError as e:
            self.kill(e, False)

    def rd(self, n):
        while len(self.buf) < n:
            d = self.dup.recv(65536)
            if not d:
                raise ConnError("connection closed by peer")
            self.buf += d
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def rloop(self):
        try:
            while True:
                h = self.rd(9)
                ln = (h[0] << 16) | (h[1] << 8) | h[2]
                typ, fl = h[3], h[4]
                sid = struct.unpack(">I", h[5:9])[0] & 0x7FFFFFFF
                if ln > MF_IN:
                    raise H2Error("frame too large", E_FSIZE)
                pl = self.rd(ln) if ln else b""
                if not self.got_set and typ != SETTINGS:
                    raise H2Error("first frame must be SETTINGS", E_PROTO)
                if self.cbuf is not None and (typ != CONT or sid != self.cbuf):
                    raise H2Error("expected CONTINUATION", E_PROTO)
                self.hdl(typ, fl, sid, pl)
        except H2Error as e:
            self.kill(e, True)
        except HpackError as e:
            self.kill(H2Error("hpack: %s" % e, E_COMP), True)
        except SecError as e:
            self.kill(e, True)
        except ConnError as e:
            self.kill(e, False)
        except Exception as e:
            self.kill(ConnError("h2 reader crashed: %r" % (e,)), True)

    def calm(self):
        now = time.monotonic()
        if now - self.ctl_t > 10:
            self.ctl_t = now
            self.ctl = 0
        self.ctl += 1
        if self.ctl > self.lim.max_ctl:
            raise H2Error("control frame flood", E_CALM)

    def hdl(self, typ, fl, sid, pl):
        if typ == DATA:
            self.on_data(fl, sid, pl)
        elif typ == HEADERS:
            self.on_headers(fl, sid, pl)
        elif typ == CONT:
            if self.cbuf is None:
                raise H2Error("unexpected CONTINUATION", E_PROTO)
            self.on_cont(fl, sid, pl)
        elif typ == PRIORITY:
            self.calm()
            if len(pl) != 5 or sid == 0:
                raise H2Error("bad PRIORITY", E_FSIZE if len(pl) != 5 else E_PROTO)
        elif typ == RST:
            self.calm()
            if len(pl) != 4 or sid == 0:
                raise H2Error("bad RST_STREAM", E_FSIZE if len(pl) != 4 else E_PROTO)
            code = struct.unpack(">I", pl)[0]
            self.end_strm(sid, H2Error("stream reset by peer (code %d)" % code, code))
        elif typ == SETTINGS:
            self.calm()
            self.on_settings(fl, sid, pl)
        elif typ == PUSH:
            raise H2Error("PUSH_PROMISE received but push disabled", E_PROTO)
        elif typ == PING:
            self.calm()
            if sid != 0 or len(pl) != 8:
                raise H2Error("bad PING", E_PROTO if sid else E_FSIZE)
            if fl & F_ACK:
                ev = self.pings.pop(pl, None)
                if ev:
                    ev[1] = time.monotonic()
                    ev[0].set()
            else:
                self.put(frm(PING, F_ACK, 0, pl), True)
        elif typ == GOAWAY:
            if sid != 0 or len(pl) < 8:
                raise H2Error("bad GOAWAY", E_PROTO)
            last, code = struct.unpack(">II", pl[:8])
            self.on_goaway(last & 0x7FFFFFFF, code)
        elif typ == WINUP:
            self.calm()
            if len(pl) != 4:
                raise H2Error("bad WINDOW_UPDATE", E_FSIZE)
            inc = struct.unpack(">I", pl)[0] & 0x7FFFFFFF
            if inc == 0:
                if sid == 0:
                    raise H2Error("zero window increment", E_PROTO)
                self.rst(sid, E_PROTO)
                return
            with self.cv:
                if sid == 0:
                    if self.cw + inc > MAXWIN:
                        raise H2Error("connection window overflow", E_FLOW)
                    self.cw += inc
                else:
                    s = self.strms.get(sid)
                    if s:
                        if s.sw + inc > MAXWIN:
                            self.rst(sid, E_FLOW)
                            return
                        s.sw += inc
                self.cv.notify_all()
        else:
            self.calm()

    def pad(self, fl, pl):
        if fl & F_PAD:
            if not pl:
                raise H2Error("padded frame too short", E_FSIZE)
            p = pl[0]
            if p >= len(pl):
                raise H2Error("pad length exceeds payload", E_PROTO)
            return pl[1:len(pl) - p]
        return pl

    def on_data(self, fl, sid, pl):
        if sid == 0:
            raise H2Error("DATA on stream 0", E_PROTO)
        n = len(pl)
        with self.cv:
            if n > self.rwc:
                raise H2Error("connection flow control exceeded", E_FLOW)
            self.rwc -= n
            self.rupd += n
            if self.rupd >= CWIN_IN // 2:
                self.put(frm(WINUP, 0, 0, struct.pack(">I", self.rupd)), True)
                self.rwc += self.rupd
                self.rupd = 0
            s = self.strms.get(sid)
        if s is None:
            if sid >= self.nxt or not sid & 1:
                raise H2Error("DATA on idle stream", E_PROTO)
            self.rst(sid, E_CLOSED)
            return
        d = self.pad(fl, pl)
        if not s.got_final:
            self.rst(sid, E_PROTO)
            return
        if n > s.rw:
            self.rst(sid, E_FLOW)
            return
        s.rw -= n
        s.upd += n
        s.rx += len(d)
        if len(s.body) + len(d) > self.lim.max_body:
            self.end_strm(sid, SecError("response body exceeds limit"), E_CANCEL)
            return
        s.body += d
        if s.upd >= SWIN_IN // 2 and not fl & F_END:
            self.put(frm(WINUP, 0, sid, struct.pack(">I", s.upd)), True)
            s.rw += s.upd
            s.upd = 0
        if fl & F_END:
            self.fin(s)

    def on_headers(self, fl, sid, pl):
        if sid == 0:
            raise H2Error("HEADERS on stream 0", E_PROTO)
        if not sid & 1 and sid != 0:
            raise H2Error("server-initiated stream while push disabled", E_PROTO)
        if sid >= self.nxt:
            raise H2Error("HEADERS on idle stream", E_PROTO)
        d = self.pad(fl, pl)
        if fl & F_PRI:
            if len(d) < 5:
                raise H2Error("HEADERS priority too short", E_FSIZE)
            d = d[5:]
        self.cbuf = None
        self.cur = (sid, bool(fl & F_END), bytearray(d), 1)
        if fl & F_EH:
            self.done_block()
        else:
            self.cbuf = sid

    def on_cont(self, fl, sid, pl):
        s_, e_, blk, cnt = self.cur
        blk += pl
        cnt += 1
        if len(blk) > self.lim.max_hdr_b or cnt > MAX_CONT:
            raise H2Error("header block too large (continuation flood)", E_CALM)
        self.cur = (s_, e_, blk, cnt)
        if fl & F_EH:
            self.cbuf = None
            self.done_block()

    def done_block(self):
        sid, es, blk, _ = self.cur
        hl = self.dec.dec(bytes(blk))
        self.cur = None
        s = self.strms.get(sid)
        if s is None:
            return
        try:
            if not s.got_final:
                st, h = v_resp_hdrs(hl)
                if 100 <= st < 200:
                    if st == 101 or es:
                        raise H2Error("invalid informational response", E_PROTO)
                    return
                s.status = st
                s.hdrs = h
                s.got_final = True
                cl = h.get_all("content-length")
                if cl:
                    v = {x.strip() for x in cl}
                    if len(v) != 1 or not next(iter(v)).isdigit():
                        raise H2Error("invalid content-length", E_PROTO)
                    s.cl = int(next(iter(v)))
                else:
                    s.cl = None
                if es:
                    self.fin(s)
            else:
                if not es:
                    raise H2Error("trailers without END_STREAM", E_PROTO)
                _, s.trl = v_resp_hdrs(hl, True)
                self.fin(s)
        except H2Error as e:
            if e.code == E_PROTO and sid in self.strms:
                self.end_strm(sid, e, E_PROTO)
            else:
                raise

    def fin(self, s):
        if s.cl is not None and not s.head and s.status not in (204, 304) and s.cl != s.rx:
            self.end_strm(s.sid, H2Error("content-length mismatch (%d != %d)" % (s.cl, s.rx), E_PROTO), E_PROTO)
            return
        with self.cv:
            self.strms.pop(s.sid, None)
            self.cv.notify_all()
        s.ev.set()

    def end_strm(self, sid, err, code=None):
        with self.cv:
            s = self.strms.pop(sid, None)
            self.cv.notify_all()
        if code is not None:
            self.put(frm(RST, 0, sid, struct.pack(">I", code)), True)
        if s:
            s.err = err
            s.rst = True
            s.ev.set()

    def rst(self, sid, code):
        self.end_strm(sid, H2Error("stream error %d" % code, code), code)

    def on_settings(self, fl, sid, pl):
        if sid != 0:
            raise H2Error("SETTINGS on non-zero stream", E_PROTO)
        if fl & F_ACK:
            if pl:
                raise H2Error("SETTINGS ack with payload", E_FSIZE)
            return
        if len(pl) % 6:
            raise H2Error("bad SETTINGS length", E_FSIZE)
        self.got_set = True
        with self.cv:
            for i in range(0, len(pl), 6):
                k, v = struct.unpack(">HI", pl[i:i + 6])
                if k == S_PUSH and v > 1:
                    raise H2Error("bad ENABLE_PUSH", E_PROTO)
                if k == S_WIN:
                    if v > MAXWIN:
                        raise H2Error("bad INITIAL_WINDOW_SIZE", E_FLOW)
                    dl = v - self.rs[S_WIN]
                    for s in self.strms.values():
                        s.sw += dl
                        if s.sw > MAXWIN:
                            raise H2Error("stream window overflow", E_FLOW)
                if k == S_FRM and not 16384 <= v <= (1 << 24) - 1:
                    raise H2Error("bad MAX_FRAME_SIZE", E_PROTO)
                if k == S_TBL:
                    self.enc.set_max(v)
                if k in self.rs:
                    self.rs[k] = v
            self.cv.notify_all()
        self.put(frm(SETTINGS, F_ACK, 0), True)

    def on_goaway(self, last, code):
        with self.cv:
            self.goaway = (last, code)
            dead = [s for sid, s in self.strms.items() if sid > last]
            for s in dead:
                self.strms.pop(s.sid, None)
            self.cv.notify_all()
        for s in dead:
            s.err = H2Error("stream refused by GOAWAY", E_REFUSED)
            s.ev.set()

    def kill(self, err, send):
        with self.ocv:
            if self.dead is not None:
                return
            self.dead = err
            self.ocv.notify_all()
        if send:
            code = err.code if isinstance(err, H2Error) else E_INT
            try:
                self.dup.send_all(frm(GOAWAY, 0, 0, struct.pack(">II", 0, code)), 2.0)
            except Exception:
                pass
        self.ok = False
        with self.cv:
            ss = list(self.strms.values())
            self.strms.clear()
            self.cv.notify_all()
        for s in ss:
            s.err = err
            s.ev.set()
        for ev in list(self.pings.values()):
            ev[0].set()
        self.dup.close()

    def ping(self, tmo=5.0):
        d = os.urandom(8)
        ev = [threading.Event(), 0.0]
        self.pings[d] = ev
        t0 = time.monotonic()
        self.put(frm(PING, 0, 0, d), True)
        if not ev[0].wait(tmo) or not ev[1]:
            self.pings.pop(d, None)
            raise ConnError("ping timeout")
        return ev[1] - t0

    def send_hdrs(self, s_new, hl, es):
        blk = self.enc.enc(hl)
        mf = self.rs[S_FRM]
        parts = [blk[i:i + mf] for i in range(0, len(blk), mf)] or [b""]
        out = []
        for i, p in enumerate(parts):
            last = i == len(parts) - 1
            if i == 0:
                out.append(frm(HEADERS, (F_END if es else 0) | (F_EH if last else 0), s_new.sid, p))
            else:
                out.append(frm(CONT, F_EH if last else 0, s_new.sid, p))
        self.put(b"".join(out))

    def req(self, req, tmo=None):
        tmo = tmo or self.tmo
        hl = req_hl(req)
        body = req.body or b""
        end = time.monotonic() + tmo
        with self.cv:
            while True:
                if self.dead is not None:
                    raise self.dead
                if self.goaway is not None:
                    raise H2Error("connection going away", E_REFUSED)
                if len(self.strms) < min(self.rs[S_MAXSTR], self.lim.max_streams):
                    break
                if not self.cv.wait(max(0.01, end - time.monotonic())) and time.monotonic() >= end:
                    raise ConnError("timeout waiting for stream slot")
        with self.ql:
            with self.cv:
                if self.dead is not None:
                    raise self.dead
                sid = self.nxt
                if sid > MAXWIN:
                    raise H2Error("stream ids exhausted", E_REFUSED)
                self.nxt += 2
                s = Strm(sid, self.rs[S_WIN], SWIN_IN, req.mth == "HEAD")
                self.strms[sid] = s
                self.n += 1
            self.send_hdrs(s, hl, not body)
        try:
            self.send_body(s, body, end)
            if not s.ev.wait(max(0.01, end - time.monotonic())):
                self.rst_local(s)
                raise ConnError("request timeout")
        except BaseException:
            if not s.ev.is_set():
                self.rst_local(s)
            raise
        if s.err is not None:
            raise s.err
        r = Resp(s.status, s.hdrs, bytes(s.body), "HTTP/2", "", req.url, "h2")
        r.trailers = s.trl
        return r

    def rst_local(self, s):
        with self.cv:
            self.strms.pop(s.sid, None)
            self.cv.notify_all()
        try:
            self.put(frm(RST, 0, s.sid, struct.pack(">I", E_CANCEL)), True)
        except Exception:
            pass

    def send_body(self, s, body, end):
        off = 0
        n = len(body)
        while off < n:
            with self.cv:
                while True:
                    if self.dead is not None:
                        raise self.dead
                    if s.ev.is_set():
                        return
                    av = min(self.cw, s.sw)
                    if av > 0:
                        break
                    if not self.cv.wait(max(0.01, end - time.monotonic())) and time.monotonic() >= end:
                        raise ConnError("flow control stall")
                k = min(n - off, av, self.rs[S_FRM])
                self.cw -= k
                s.sw -= k
            last = off + k >= n
            self.put(frm(DATA, F_END if last else 0, s.sid, body[off:off + k]))
            off += k

    def close(self):
        self.ok = False
        if self.dead is None:
            try:
                self.put(frm(GOAWAY, 0, 0, struct.pack(">II", 0, E_NONE)), True)
                time.sleep(0.02)
            except Exception:
                pass
        self.kill(ConnError("closed"), False)
