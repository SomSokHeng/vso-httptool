import threading
import time

from . import qpack
from .err import ConnError, H2Error, H3Error, QpackError, QuicError, SecError
from .h2 import CONN_H, v_resp_hdrs
from .msg import Resp
from .quic import QConn, rvi, vi


def avail():
    from cryptography.x509.verification import PolicyBuilder
    return PolicyBuilder is not None


F_DATA, F_HDRS, F_CANCEL, F_SET, F_PUSH, F_GOAWAY, F_MAXPUSH = 0, 1, 3, 4, 5, 7, 0xD
E_NONE, E_GEN, E_INT, E_STRM, E_CLOSED, E_FRAME, E_EXCESS, E_ID, E_SET, E_MISSET, E_REQREJ, E_REQCAN, E_REQINC, E_MSG = 0x100, 0x101, 0x102, 0x103, 0x104, 0x105, 0x107, 0x108, 0x109, 0x10A, 0x10B, 0x10C, 0x10D, 0x10E
H2_ONLY = (0, 2, 3, 4, 5)


def frm(t, pl):
    return vi(t) + vi(len(pl)) + pl


class R:
    def __init__(self, sid, head):
        self.sid = sid
        self.head = head
        self.buf = bytearray()
        self.ev = threading.Event()
        self.err = None
        self.st = 0
        self.dleft = 0
        self.skip = 0
        self.status = None
        self.hdrs = None
        self.trl = None
        self.body = bytearray()
        self.cl = None
        self.rx = 0
        self.done = False


class H3Conn:
    proto = "h3"

    def __init__(self, q, lim):
        self.q = q
        self.lim = lim
        self.reqs = {}
        self.ub = {}
        self.goaway = None
        self.psettings = None
        self.dead = None
        self.n = 0
        self.ok = True
        q.on_stream = self.on_stream
        q.on_close = self.on_close
        with q.lk:
            c = q.open_uni()
            sp = vi(0x01) + vi(0) + vi(0x06) + vi(lim.max_hdr_b) + vi(0x07) + vi(0)
            q.send(c, vi(0) + frm(F_SET, sp))
            e = q.open_uni()
            q.send(e, vi(2))
            d = q.open_uni()
            q.send(d, vi(3))

    def alive(self):
        return self.dead is None and self.goaway is None and self.q.alive() and self.ok

    def on_close(self, err):
        self.dead = err or ConnError("quic connection closed")
        for r in list(self.reqs.values()):
            if not r.ev.is_set():
                r.err = self.dead
                r.ev.set()

    def fail(self, code, msg):
        err = H3Error(msg, code)
        self.dead = err
        self.q.close(code, msg[:100], True, True)
        for r in list(self.reqs.values()):
            if not r.ev.is_set():
                r.err = err
                r.ev.set()

    def on_stream(self, sid, data, fin):
        try:
            if data is None:
                r = self.reqs.get(sid)
                if r and not r.ev.is_set():
                    r.err = H3Error("stream reset by peer (code 0x%x)" % fin, fin)
                    r.ev.set()
                if sid & 3 == 3:
                    raise H3Error("critical stream reset", E_CLOSED)
                return
            if sid & 3 == 3:
                self.on_uni(sid, data, fin)
            elif sid & 3 == 0:
                r = self.reqs.get(sid)
                if r is None:
                    return
                self.on_req(r, data, fin)
        except H3Error as e:
            self.fail(e.code, str(e))
        except QpackError as e:
            self.fail(0x200, "qpack: %s" % e)

    def on_uni(self, sid, data, fin):
        st = self.ub.setdefault(sid, {"t": None, "b": bytearray(), "n": 0, "set": False})
        st["b"] += data
        b = st["b"]
        if st["t"] is None:
            if not b:
                return
            try:
                t, p = rvi(b, 0)
            except QuicError:
                return
            del b[:p]
            st["t"] = t
            if t == 0:
                if any(x["t"] == 0 for k, x in self.ub.items() if k != sid):
                    raise H3Error("duplicate control stream", E_STRM)
        t = st["t"]
        if fin and t in (0, 2, 3):
            raise H3Error("critical stream closed", E_CLOSED)
        if t == 1:
            raise H3Error("push stream received but push not enabled", E_ID)
        if t in (2, 3):
            st["n"] += len(b)
            b.clear()
            if st["n"] > (1 << 20):
                raise H3Error("qpack stream flood", 0x201)
            return
        if t != 0:
            b.clear()
            return
        while b:
            if st.get("skip"):
                k = min(st["skip"], len(b))
                del b[:k]
                st["skip"] -= k
                continue
            try:
                ft, p = rvi(b, 0)
                ln, p = rvi(b, p)
            except QuicError:
                return
            if ft in (F_DATA, F_HDRS, F_PUSH):
                raise H3Error("frame 0x%x on control stream" % ft, E_FRAME)
            if not st["set"] and ft != F_SET:
                raise H3Error("first control frame must be SETTINGS", E_MISSET)
            if ft == F_SET:
                if st["set"]:
                    raise H3Error("duplicate SETTINGS", E_FRAME)
                if ln > 16384:
                    raise H3Error("SETTINGS too large", E_EXCESS)
                if len(b) < p + ln:
                    return
                pl = bytes(b[p:p + ln])
                del b[:p + ln]
                seen = {}
                q = 0
                while q < len(pl):
                    k, q = rvi(pl, q)
                    v, q = rvi(pl, q)
                    if k in seen or k in H2_ONLY:
                        raise H3Error("bad SETTINGS id 0x%x" % k, E_SET)
                    seen[k] = v
                st["set"] = True
                self.psettings = seen
            elif ft in (F_GOAWAY, F_CANCEL, F_MAXPUSH):
                if len(b) < p + ln:
                    return
                pl = bytes(b[p:p + ln])
                del b[:p + ln]
                if ft == F_GOAWAY:
                    gid, _ = rvi(pl, 0)
                    if self.goaway is not None and gid > self.goaway:
                        raise H3Error("GOAWAY id increased", E_ID)
                    self.goaway = gid
                    for r in list(self.reqs.values()):
                        if r.sid >= gid and not r.ev.is_set():
                            e = H3Error("request rejected by GOAWAY", E_REQREJ)
                            e.retry = True
                            r.err = e
                            r.ev.set()
            else:
                del b[:p]
                st["skip"] = ln

    def on_req(self, r, data, fin):
        if r.ev.is_set():
            return
        r.buf += data
        b = r.buf
        lim = self.lim
        mhs = lim.max_hdr_b
        while b:
            if r.skip:
                k = min(r.skip, len(b))
                del b[:k]
                r.skip -= k
                continue
            if r.dleft:
                k = min(r.dleft, len(b))
                if len(r.body) + k > lim.max_body:
                    self.rej(r, SecError("response body exceeds limit"), E_REQCAN)
                    return
                r.body += b[:k]
                r.rx += k
                del b[:k]
                r.dleft -= k
                continue
            try:
                t, p = rvi(b, 0)
                ln, p = rvi(b, p)
            except QuicError:
                break
            if t == F_DATA:
                if r.st != 1:
                    raise H3Error("DATA frame in wrong state", E_FRAME)
                del b[:p]
                r.dleft = ln
            elif t == F_HDRS:
                if ln > mhs:
                    raise H3Error("HEADERS frame too large", E_EXCESS)
                if len(b) < p + ln:
                    break
                blk = bytes(b[p:p + ln])
                del b[:p + ln]
                hl = qpack.dec(blk, mhs)
                self.on_hdrs(r, hl)
                if r.ev.is_set():
                    return
            elif t in (F_CANCEL, F_SET, F_PUSH, F_GOAWAY, F_MAXPUSH):
                raise H3Error("frame 0x%x on request stream" % t, E_FRAME)
            else:
                del b[:p]
                r.skip = ln
        if fin:
            if r.st < 1 or b or r.dleft or r.skip:
                self.rej(r, H3Error("incomplete response", E_REQINC), E_REQINC)
                return
            if r.cl is not None and not r.head and r.status not in (204, 304) and r.cl != r.rx:
                self.rej(r, H3Error("content-length mismatch", E_MSG), E_MSG)
                return
            r.done = True
            r.ev.set()
            self.q.forget(r.sid)

    def on_hdrs(self, r, hl):
        try:
            if r.st == 0:
                st, h = v_resp_hdrs(hl)
                if 100 <= st < 200:
                    if st == 101:
                        raise H2Error("101 not allowed", 1)
                    return
                r.status = st
                r.hdrs = h
                r.st = 1
                cl = h.get_all("content-length")
                if cl:
                    v = {x.strip() for x in cl}
                    if len(v) != 1 or not next(iter(v)).isdigit():
                        raise H2Error("bad content-length", 1)
                    r.cl = int(next(iter(v)))
            elif r.st == 1:
                _, r.trl = v_resp_hdrs(hl, True)
                r.st = 2
            else:
                raise H3Error("HEADERS after trailers", E_FRAME)
        except H2Error as e:
            self.rej(r, H3Error("malformed response: %s" % e, E_MSG), E_MSG)

    def rej(self, r, err, code):
        r.err = err
        r.ev.set()
        self.q.cancel(r.sid, code)

    def req(self, req, tmo=30.0):
        hl = [(":method", req.mth), (":scheme", "https"), (":authority", req.url.authority), (":path", req.url.target)]
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
        body = req.body or b""
        if body and not has_cl:
            hl.append(("content-length", str(len(body))))
        elif not body and req.mth in ("POST", "PUT", "PATCH") and not has_cl:
            hl.append(("content-length", "0"))
        data = frm(F_HDRS, qpack.enc(hl))
        if body:
            data += frm(F_DATA, body)
        end = time.monotonic() + tmo
        while True:
            with self.q.lk:
                if self.dead is not None:
                    raise self.dead
                if self.goaway is not None:
                    e = H3Error("connection going away", E_REQREJ)
                    e.retry = True
                    raise e
                try:
                    sid = self.q.open_bidi()
                    break
                except QuicError as e:
                    if "limit" not in str(e) or time.monotonic() > end:
                        raise
            time.sleep(0.01)
        r = R(sid, req.mth == "HEAD")
        with self.q.lk:
            self.reqs[sid] = r
            self.n += 1
        try:
            self.q.send(sid, data, True)
            if not r.ev.wait(max(0.01, end - time.monotonic())):
                self.q.cancel(sid, E_REQCAN)
                raise ConnError("request timeout")
        finally:
            self.reqs.pop(sid, None)
        if r.err is not None:
            raise r.err
        res = Resp(r.status, r.hdrs, bytes(r.body), "HTTP/3", "", req.url, "h3")
        if r.trl is not None:
            res.trailers = r.trl
        return res

    def close(self):
        self.ok = False
        self.q.close(E_NONE, "", True, True)


def open_h3(u, port, guard, tmo, verify, ca, lim):
    last = None
    for fam, addr in guard.resolve(u.host, port):
        try:
            q = QConn(u.host, fam, addr, port, ("h3",), verify, ca, tmo, lim.max_body)
            q.connect()
            return H3Conn(q, lim)
        except (QuicError, OSError) as e:
            last = e
    raise ConnError("h3 connect failed: %s" % last)
