import hmac
import os
import socket
import struct
import threading
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .err import QuicError, QuicReset, TlsError
from .tls13 import CS, Tls13, exp_lbl, hk_ext

V1 = 1
SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
RT_KEY = bytes.fromhex("be0c690b9f66575a1d766b54e368c84e")
RT_NONCE = bytes.fromhex("461599d35d632bf2239825bb")
MTU = 1200
PN_LEN = 4
CONN_WIN = 1 << 24
STRM_WIN = 1 << 20
INIT_RTT = 0.25
MAX_UNI = 16
INIT_CWND = 10 * MTU
MIN_CWND = 2 * MTU
MAX_CWND = 1 << 23
MAX_TOK = 32
MAX_ACK_DELAY = 0.025
T_PADDING, T_PING, T_ACK, T_ACKE, T_RESET, T_STOP, T_CRYPTO, T_TOKEN = 0, 1, 2, 3, 4, 5, 6, 7
T_MAXDATA, T_MAXSD, T_MAXSB, T_MAXSU, T_DB, T_SDB, T_SBB, T_SBU = 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
T_NCID, T_RCID, T_PCH, T_PRS, T_CC, T_CCA, T_HDONE = 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E
E_NONE, E_INTERNAL, E_FLOW, E_STRMLIM, E_STRMST, E_FINAL, E_FRAME, E_TP, E_PROTO = 0, 1, 3, 4, 5, 6, 7, 8, 0xA
ARR = ("initial", "handshake", "app")


def avail():
    return True


def vi(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return struct.pack(">H", 0x4000 | n)
    if n < 1 << 30:
        return struct.pack(">I", 0x80000000 | n)
    return struct.pack(">Q", 0xC000000000000000 | n)


def rvi(b, pos):
    if pos >= len(b):
        raise QuicError("truncated varint", E_FRAME)
    f = b[pos] >> 6
    n = 1 << f
    if pos + n > len(b):
        raise QuicError("truncated varint", E_FRAME)
    v = b[pos] & 0x3F
    for i in range(1, n):
        v = (v << 8) | b[pos + i]
    return v, pos + n


class Pk:
    def __init__(self, secret, h, alg, kl, hp=None):
        self.secret = secret
        self.h = h
        self.alg = alg
        self.kl = kl
        key = exp_lbl(h, secret, b"quic key", b"", kl)
        self.iv = int.from_bytes(exp_lbl(h, secret, b"quic iv", b"", 12), "big")
        self.hp = hp or exp_lbl(h, secret, b"quic hp", b"", kl)
        self.aead = ChaCha20Poly1305(key) if alg == "chacha" else AESGCM(key)
        self.ecb = None if alg == "chacha" else Cipher(algorithms.AES(self.hp), modes.ECB()).encryptor()

    def mask(self, sample):
        if self.alg == "chacha":
            return Cipher(algorithms.ChaCha20(self.hp, sample), None).encryptor().update(b"\x00" * 5)
        return self.ecb.update(sample)[:5]

    def nonce(self, pn):
        return (self.iv ^ pn).to_bytes(12, "big")

    def nxt(self):
        return Pk(exp_lbl(self.h, self.secret, b"quic ku", b"", len(self.secret)), self.h, self.alg, self.kl, self.hp)


def init_keys(dcid):
    s = hk_ext("sha256", SALT, dcid)
    c = exp_lbl("sha256", s, b"client in", b"", 32)
    sv = exp_lbl("sha256", s, b"server in", b"", 32)
    return Pk(c, "sha256", "aes", 16), Pk(sv, "sha256", "aes", 16)


def dec_pn(largest, tr, nb):
    exp = largest + 1
    win = 1 << nb
    half = win >> 1
    c = (exp & ~(win - 1)) | tr
    if c <= exp - half and c < (1 << 62) - win:
        c += win
    elif c > exp + half and c >= win:
        c -= win
    return c


def tp_enc(items):
    out = b""
    for k, v in items:
        if isinstance(v, int):
            v = vi(v)
        out += vi(k) + vi(len(v)) + v
    return out


def tp_dec(b):
    out = {}
    pos = 0
    while pos < len(b):
        k, pos = rvi(b, pos)
        n, pos = rvi(b, pos)
        if pos + n > len(b):
            raise QuicError("bad transport parameter", E_TP)
        v = bytes(b[pos:pos + n])
        pos += n
        if k in out:
            raise QuicError("duplicate transport parameter", E_TP)
        out[k] = v
    return out


def tp_int(d, k, dflt):
    if k not in d:
        return dflt
    return rvi(d[k], 0)[0]


class Sp:
    def __init__(self):
        self.snd = None
        self.rcv = None
        self.pn = 0
        self.lrx = -1
        self.rr = []
        self.ackn = False
        self.sent = {}
        self.cq = []
        self.cso = 0
        self.cro = 0
        self.crb = {}
        self.lack = -1

    def note(self, pn):
        for r in self.rr:
            if r[0] <= pn <= r[1]:
                return False
        self.rr.append([pn, pn])
        self.rr.sort()
        m = [self.rr[0]]
        for lo, hi in self.rr[1:]:
            if lo <= m[-1][1] + 1:
                m[-1][1] = max(m[-1][1], hi)
            else:
                m.append([lo, hi])
        self.rr = m[-32:]
        return True

    def ack_frame(self):
        r = self.rr
        if not r:
            return b""
        lo, hi = r[-1]
        out = bytes([T_ACK]) + vi(hi) + vi(0) + vi(len(r) - 1) + vi(hi - lo)
        prev = lo
        for lo2, hi2 in reversed(r[:-1]):
            out += vi(prev - hi2 - 2) + vi(hi2 - lo2)
            prev = lo2
        return out


class Sent:
    __slots__ = ("t", "frs", "elig", "n")

    def __init__(self, t, frs, elig, n):
        self.t = t
        self.frs = frs
        self.elig = elig
        self.n = n


class QS:
    def __init__(self, sid, smax, rmax):
        self.sid = sid
        self.snd = bytearray()
        self.so = 0
        self.fin = False
        self.fsent = False
        self.retx = []
        self.smax = smax
        self.rmax = rmax
        self.roff = 0
        self.rb = {}
        self.fino = None
        self.rfin = False
        self.rhi = 0
        self.reset = False
        self.stopped = False


class QConn:
    def __init__(self, host, addr_fam, addr, port, alpn=("h3",), verify=True, ca=None, tmo=10.0, max_body=64 << 20):
        self.host = host
        self.tmo = tmo
        self.lk = threading.RLock()
        self.ready = threading.Event()
        self.closed = threading.Event()
        self.err = None
        self.on_stream = None
        self.on_close = None
        self.sock = socket.socket(addr_fam, socket.SOCK_DGRAM)
        self.sock.connect((addr, port))
        self.scid = os.urandom(8)
        self.odcid = os.urandom(8)
        self.dcid = self.odcid
        self.sp = [Sp(), Sp(), Sp()]
        self.sp[0].snd, self.sp[0].rcv = init_keys(self.dcid)
        self.token = b""
        self.retry = False
        self.rscid = None
        self.suite = None
        self.strms = {}
        self.nb = 0
        self.nu = 0
        self.ptp = {}
        self.smd = 0
        self.sdata = 0
        self.rmd = CONN_WIN
        self.rdata = 0
        self.rcons = 0
        self.ctlq = []
        self.ncid = {}
        self.confirmed = False
        self.srtt = None
        self.rttv = 0.0
        self.pto_n = 0
        self.lrxt = time.monotonic()
        self.idle = 30.0
        self.kp = 0
        self.nrk = None
        self.max_body = max_body
        self.mbs = 0
        self.mus = 0
        self.cwnd = INIT_CWND
        self.ssth = float("inf")
        self.bif = 0
        self.rec_t = 0.0
        self.probe_n = 0
        self.max_bif = 0
        self.rtok = set()
        tp = tp_enc([(1, 30000), (4, CONN_WIN), (5, STRM_WIN), (6, STRM_WIN), (7, STRM_WIN), (8, 0), (9, MAX_UNI), (0x0E, 4), (0x0C, b""), (0x0F, self.scid)])
        self.tls = Tls13(host, list(alpn), tp, verify, ca)
        self.th = threading.Thread(target=self.run, daemon=True)
        self.alpn = alpn

    def connect(self):
        with self.lk:
            self.ev(self.tls.start())
            self.flush()
        self.th.start()
        if not self.ready.wait(self.tmo):
            self.close(0, "handshake timeout", False)
            raise QuicError("quic handshake timed out")
        if self.err:
            raise self.err
        return self

    def alive(self):
        return not self.closed.is_set() and self.err is None and time.monotonic() - self.lrxt < self.idle

    def ev(self, evs):
        for e in evs:
            if e[0] == "send":
                sp = self.sp[e[1]]
                sp.cq.append((sp.cso, e[2]))
                sp.cso += len(e[2])
            elif e[0] == "keys":
                _, lvl, cs_, ss_, suite = e
                h, kl, alg = CS[suite]
                self.suite = suite
                sp = self.sp[lvl]
                sp.snd = Pk(cs_, h, alg, kl)
                sp.rcv = Pk(ss_, h, alg, kl)
            elif e[0] == "done":
                self.on_tls_done()

    def on_tls_done(self):
        d = tp_dec(self.tls.peer_tp)
        if d.get(0) != self.odcid:
            raise QuicError("original_destination_connection_id mismatch", E_TP)
        if d.get(0x0F) != self.dcid:
            raise QuicError("initial_source_connection_id mismatch", E_TP)
        if self.retry and d.get(0x10) != self.rscid:
            raise QuicError("retry_source_connection_id mismatch", E_TP)
        if not self.retry and 0x10 in d:
            raise QuicError("unexpected retry_source_connection_id", E_TP)
        self.ptp = d
        if len(d.get(2, b"")) == 16:
            self.rtok.add(bytes(d[2]))
        self.smd = tp_int(d, 4, 0)
        self.mbs = tp_int(d, 8, 0)
        self.mus = tp_int(d, 9, 0)
        idle = tp_int(d, 1, 0)
        if idle:
            self.idle = min(30.0, idle / 1000.0)
        self.ready.set()

    def run(self):
        try:
            while not self.closed.is_set():
                with self.lk:
                    tmo = self.timer()
                self.sock.settimeout(tmo)
                try:
                    d = self.sock.recv(65535)
                except socket.timeout:
                    with self.lk:
                        self.on_timer()
                    continue
                except ConnectionRefusedError:
                    self.fail(QuicError("connection refused"))
                    return
                except OSError:
                    if self.closed.is_set():
                        return
                    self.fail(QuicError("socket error"))
                    return
                with self.lk:
                    try:
                        self.dgram(d)
                        self.flush()
                    except QuicError as e:
                        self.fail(e, not isinstance(e, QuicReset))
                        return
                    except TlsError as e:
                        self.fail(QuicError("tls: %s" % e, 0x100), True, 0x128)
                        return
        except Exception as e:
            self.fail(QuicError("quic engine crashed: %r" % (e,)), True)

    def fail(self, err, send=False, code=None):
        with self.lk:
            if self.err is None and not self.closed.is_set():
                self.err = err
            if send and not self.closed.is_set():
                try:
                    self.send_cc(code if code is not None else getattr(err, "code", E_INTERNAL), str(err)[:100])
                except Exception:
                    pass
            self.closed.set()
        self.ready.set()
        try:
            self.sock.close()
        except OSError:
            pass
        if self.on_close:
            try:
                self.on_close(self.err)
            except Exception:
                pass

    def send_cc(self, code, reason, app=False):
        rb = reason.encode()
        if app:
            fr = bytes([T_CCA]) + vi(code) + vi(len(rb)) + rb
        else:
            fr = bytes([T_CC]) + vi(code) + vi(0) + vi(len(rb)) + rb
        for lvl in (2, 1, 0):
            sp = self.sp[lvl]
            if sp.snd:
                self.sock.send(self.seal(lvl, fr, False, True))
                return

    def close(self, code=0, reason="", send=True, app=False):
        with self.lk:
            if self.closed.is_set():
                return
            if send:
                try:
                    self.send_cc(code, reason, app)
                except Exception:
                    pass
            self.closed.set()
        self.ready.set()
        try:
            self.sock.close()
        except OSError:
            pass
        if self.on_close:
            try:
                self.on_close(self.err)
            except Exception:
                pass

    def dgram(self, d):
        self.lrxt = time.monotonic()
        off = 0
        while off < len(d):
            n = self.pkt(d, off)
            if n <= 0:
                break
            off += n

    def pkt(self, d, off):
        first = d[off]
        if first & 0x80:
            if off + 7 > len(d):
                return 0
            ver = struct.unpack(">I", d[off + 1:off + 5])[0]
            p = off + 5
            dl = d[p]
            p += 1
            dc = d[p:p + dl]
            p += dl
            sl = d[p]
            p += 1
            sc = d[p:p + sl]
            p += sl
            if ver == 0:
                raise QuicError("server does not support QUIC v1 (version negotiation)", E_PROTO)
            if ver != V1 or dl > 20 or sl > 20:
                return 0
            if not first & 0x40:
                return 0
            ty = (first >> 4) & 3
            if ty == 3:
                self.on_retry(d, off, p, dc, sc)
                return len(d) - off
            if ty == 1:
                return self.skip_long(d, p, ty)
            lvl = 0 if ty == 0 else 1
            if ty == 0:
                tl, p = rvi(d, p)
                p += tl
            ln, p = rvi(d, p)
            end = p + ln
            if end > len(d):
                return 0
            if dc != self.scid:
                return end - off
            sp = self.sp[lvl]
            if sp.rcv is None:
                return end - off
            r = self.unprot(sp, d, off, p, end, True)
            if r is None:
                return end - off
            pn, pl = r
            if lvl == 0 and not getattr(self, "got_srv", False):
                self.got_srv = True
                self.dcid = bytes(sc)
            elif lvl == 1 and bytes(sc) != self.dcid:
                return end - off
            self.rx(lvl, sp, pn, pl)
            return end - off
        if not first & 0x40:
            return 0
        sp = self.sp[2]
        p = off + 1 + len(self.scid)
        if d[off + 1:p] != self.scid or sp.rcv is None:
            self.chk_reset(d, off)
            return len(d) - off
        r = self.unprot(sp, d, off, p, len(d), False)
        if r is None:
            self.chk_reset(d, off)
            return len(d) - off
        self.rx(2, sp, r[0], r[1])
        return len(d) - off

    def chk_reset(self, d, off):
        if len(d) - off < 21:
            return
        t = bytes(d[-16:])
        for k in self.rtok:
            if hmac.compare_digest(k, t):
                raise QuicReset("stateless reset received: the server no longer knows this connection (restarted?)", 0x0)

    def skip_long(self, d, p, ty):
        ln, p = rvi(d, p)
        return p + ln

    def unprot(self, sp, d, off, pn_off, end, long):
        if end - pn_off < 4 + 16:
            return None
        keys = sp.rcv
        sample = bytes(d[pn_off + 4:pn_off + 20])
        m = keys.mask(sample)
        fb = d[off] ^ (m[0] & (0x0F if long else 0x1F))
        pl_ = (fb & 3) + 1
        pnb = bytes(d[pn_off + i] ^ m[1 + i] for i in range(pl_))
        tr = int.from_bytes(pnb, "big")
        pn = dec_pn(sp.lrx, tr, 8 * pl_)
        hdr = bytes([fb]) + bytes(d[off + 1:pn_off]) + pnb
        ct = bytes(d[pn_off + pl_:end])
        phase = None
        use = keys
        if not long:
            phase = (fb >> 2) & 1
            if phase != self.kp:
                if self.nrk is None:
                    self.nrk = keys.nxt()
                use = self.nrk
        try:
            pt = use.aead.decrypt(use.nonce(pn), ct, hdr)
        except Exception:
            return None
        if not long and phase != self.kp:
            sp.rcv = use
            sp.snd = sp.snd.nxt()
            self.kp = phase
            self.nrk = None
        return pn, pt

    def on_retry(self, d, off, p, dc, sc):
        if self.retry or getattr(self, "got_srv", False) or dc != self.scid:
            return
        tok = bytes(d[p:len(d) - 16])
        tag = bytes(d[len(d) - 16:])
        pseudo = bytes([len(self.odcid)]) + self.odcid + bytes(d[off:len(d) - 16])
        if AESGCM(RT_KEY).encrypt(RT_NONCE, b"", pseudo) != tag or not tok:
            return
        self.retry = True
        self.token = tok
        self.rscid = bytes(sc)
        self.dcid = bytes(sc)
        self.fly_clear(self.sp[0])
        sp = Sp()
        sp.snd, sp.rcv = init_keys(self.dcid)
        sp.cq.append((0, bytes(self.tls.msgs)))
        sp.cso = len(self.tls.msgs)
        self.sp[0] = sp

    def rx(self, lvl, sp, pn, pl):
        new = sp.note(pn)
        if pn > sp.lrx:
            sp.lrx = pn
        if not new:
            return
        elig = self.frames(lvl, sp, pl)
        if elig:
            sp.ackn = True

    def frames(self, lvl, sp, b):
        pos = 0
        n = len(b)
        elig = False
        while pos < n:
            t, pos = rvi(b, pos)
            if t == T_PADDING:
                continue
            if lvl < 2 and t not in (T_PING, T_ACK, T_ACKE, T_CRYPTO, T_CC):
                raise QuicError("frame 0x%x not allowed at %s level" % (t, ARR[lvl]), E_PROTO)
            if t not in (T_ACK, T_ACKE, T_CC, T_CCA):
                elig = True
            if t == T_PING:
                pass
            elif t in (T_ACK, T_ACKE):
                lg, pos = rvi(b, pos)
                _, pos = rvi(b, pos)
                cnt, pos = rvi(b, pos)
                fr, pos = rvi(b, pos)
                if fr > lg or cnt > 256:
                    raise QuicError("bad ACK frame", E_FRAME)
                rngs = [(lg - fr, lg)]
                sm = lg - fr
                for _ in range(cnt):
                    g, pos = rvi(b, pos)
                    r, pos = rvi(b, pos)
                    hi = sm - g - 2
                    if hi < 0 or r > hi:
                        raise QuicError("bad ACK range", E_FRAME)
                    rngs.append((hi - r, hi))
                    sm = hi - r
                if t == T_ACKE:
                    for _ in range(3):
                        _, pos = rvi(b, pos)
                self.on_ack(sp, rngs, lg)
            elif t == T_CRYPTO:
                o, pos = rvi(b, pos)
                ln, pos = rvi(b, pos)
                if pos + ln > n:
                    raise QuicError("truncated CRYPTO", E_FRAME)
                self.on_crypto(lvl, sp, o, bytes(b[pos:pos + ln]))
                pos += ln
            elif t == T_TOKEN:
                ln, pos = rvi(b, pos)
                pos += ln
            elif 8 <= t <= 0x0F:
                sid, pos = rvi(b, pos)
                o = 0
                if t & 4:
                    o, pos = rvi(b, pos)
                if t & 2:
                    ln, pos = rvi(b, pos)
                else:
                    ln = n - pos
                if pos + ln > n:
                    raise QuicError("truncated STREAM", E_FRAME)
                self.on_sdata(sid, o, bytes(b[pos:pos + ln]), bool(t & 1))
                pos += ln
            elif t == T_MAXDATA:
                v, pos = rvi(b, pos)
                self.smd = max(self.smd, v)
            elif t == T_MAXSD:
                sid, pos = rvi(b, pos)
                v, pos = rvi(b, pos)
                s = self.strms.get(sid)
                if s:
                    s.smax = max(s.smax, v)
            elif t == T_MAXSB:
                v, pos = rvi(b, pos)
                self.mbs = max(self.mbs, v)
            elif t == T_MAXSU:
                v, pos = rvi(b, pos)
                self.mus = max(self.mus, v)
            elif t in (T_DB, T_SBB, T_SBU):
                _, pos = rvi(b, pos)
            elif t == T_SDB:
                _, pos = rvi(b, pos)
                _, pos = rvi(b, pos)
            elif t == T_RESET:
                sid, pos = rvi(b, pos)
                code, pos = rvi(b, pos)
                fs, pos = rvi(b, pos)
                self.on_reset(sid, code, fs)
            elif t == T_STOP:
                sid, pos = rvi(b, pos)
                code, pos = rvi(b, pos)
                s = self.strms.get(sid)
                if s and not s.reset:
                    s.reset = True
                    self.ctlq.append(bytes([T_RESET]) + vi(sid) + vi(code) + vi(s.so))
            elif t == T_NCID:
                seq, pos = rvi(b, pos)
                rp, pos = rvi(b, pos)
                ln = b[pos]
                pos += 1
                if ln < 1 or ln > 20 or pos + ln + 16 > n:
                    raise QuicError("bad NEW_CONNECTION_ID", E_FRAME)
                self.ncid[seq] = bytes(b[pos:pos + ln])
                if len(self.rtok) < MAX_TOK:
                    self.rtok.add(bytes(b[pos + ln:pos + ln + 16]))
                pos += ln + 16
                if len(self.ncid) > 16:
                    raise QuicError("too many connection ids", 9)
            elif t == T_RCID:
                _, pos = rvi(b, pos)
            elif t == T_PCH:
                if pos + 8 > n:
                    raise QuicError("bad PATH_CHALLENGE", E_FRAME)
                self.ctlq.append(bytes([T_PRS]) + bytes(b[pos:pos + 8]))
                pos += 8
            elif t == T_PRS:
                pos += 8
            elif t in (T_CC, T_CCA):
                code, pos = rvi(b, pos)
                if t == T_CC:
                    _, pos = rvi(b, pos)
                ln, pos = rvi(b, pos)
                rs = bytes(b[pos:pos + ln]).decode("utf-8", "replace")
                pos += ln
                if self.err is None:
                    self.err = QuicError("connection closed by peer: code=0x%x %s" % (code, rs), code)
                self.closed.set()
                self.ready.set()
                try:
                    self.sock.close()
                except OSError:
                    pass
                if self.on_close:
                    self.on_close(self.err)
                return elig
            elif t == T_HDONE:
                self.confirmed = True
                self.sp[0].snd = self.sp[0].rcv = None
                self.sp[1].snd = self.sp[1].rcv = None
                self.fly_clear(self.sp[0])
                self.fly_clear(self.sp[1])
            else:
                raise QuicError("unknown frame type 0x%x" % t, E_FRAME)
        return elig

    def on_crypto(self, lvl, sp, o, data):
        if o + len(data) > sp.cro + (1 << 18):
            raise QuicError("crypto buffer overflow", 0xD)
        if o + len(data) <= sp.cro:
            return
        sp.crb[o] = data if o not in sp.crb or len(data) > len(sp.crb[o]) else sp.crb[o]
        while True:
            hit = None
            for k in sp.crb:
                if k <= sp.cro < k + len(sp.crb[k]):
                    hit = k
                    break
            if hit is None:
                break
            seg = sp.crb.pop(hit)[sp.cro - hit:]
            sp.cro += len(seg)
            self.ev(self.tls.feed(lvl, seg))
            for k in [k for k in sp.crb if k + len(sp.crb[k]) <= sp.cro]:
                del sp.crb[k]

    def sget(self, sid):
        s = self.strms.get(sid)
        if s is None:
            if sid & 3 != 3:
                return None
            if (sid >> 2) >= MAX_UNI:
                raise QuicError("peer opened more unidirectional streams than allowed", E_STRMLIM)
            s = QS(sid, 0, STRM_WIN)
            self.strms[sid] = s
        return s

    def on_sdata(self, sid, o, data, fin):
        if sid & 3 == 1:
            raise QuicError("peer-initiated bidi stream not permitted", E_STRMLIM)
        s = self.sget(sid)
        if s is None:
            if (sid & 3 == 0 and sid // 4 < self.nb) or (sid & 3 == 2 and (sid - 2) // 4 < self.nu):
                return
            raise QuicError("data on unopened stream", E_STRMST)
        end = o + len(data)
        if end > s.rmax:
            raise QuicError("stream flow control violated", E_FLOW)
        if end > s.rhi:
            self.rdata += end - s.rhi
            s.rhi = end
            if self.rdata > self.rmd:
                raise QuicError("connection flow control violated", E_FLOW)
        if fin:
            if s.fino is not None and s.fino != end:
                raise QuicError("final size changed", E_FINAL)
            s.fino = end
        elif s.fino is not None and end > s.fino:
            raise QuicError("data beyond final size", E_FINAL)
        if s.reset or s.rfin:
            return
        if end > s.roff:
            if o <= s.roff:
                data = data[s.roff - o:]
                o = s.roff
                s.rb[o] = data if o not in s.rb or len(data) > len(s.rb[o]) else s.rb[o]
            else:
                if len(s.rb) > 256:
                    raise QuicError("too many gaps", E_FLOW)
                s.rb[o] = data if o not in s.rb or len(data) > len(s.rb[o]) else s.rb[o]
        out = []
        while True:
            hit = None
            for k in s.rb:
                if k <= s.roff < k + len(s.rb[k]):
                    hit = k
                    break
            if hit is None:
                break
            seg = s.rb.pop(hit)[s.roff - hit:]
            s.roff += len(seg)
            out.append(seg)
            for k in [k for k in s.rb if k + len(s.rb[k]) <= s.roff]:
                del s.rb[k]
        done = s.fino is not None and s.roff >= s.fino
        if done:
            s.rfin = True
        if out or done:
            self.rcons += sum(len(x) for x in out)
            if s.roff > s.rmax - STRM_WIN // 2:
                s.rmax = s.roff + STRM_WIN
                self.ctlq.append(bytes([T_MAXSD]) + vi(sid) + vi(s.rmax))
            if self.rcons > CONN_WIN // 2:
                self.rmd += self.rcons
                self.rcons = 0
                self.ctlq.append(bytes([T_MAXDATA]) + vi(self.rmd))
            if self.on_stream:
                self.on_stream(sid, b"".join(out), done)

    def on_reset(self, sid, code, fs):
        s = self.strms.get(sid)
        if s is None:
            return
        s.reset = True
        s.rfin = True
        if self.on_stream:
            self.on_stream(sid, None, code)

    def on_ack(self, sp, rngs, lg):
        now = time.monotonic()
        got = False
        for lo, hi in rngs:
            for pn in [p for p in sp.sent if lo <= p <= hi]:
                sk = sp.sent.pop(pn)
                self.unfly(sk)
                if sk.elig:
                    self.cc_ack(sk)
                if pn == lg and sk.elig:
                    got = True
                    self.rtt(now - sk.t)
        if lg > sp.lack:
            sp.lack = lg
        if got:
            self.pto_n = 0
        thr = 9.0 / 8.0 * max(self.srtt or INIT_RTT, 0.001)
        lost = [p for p, sk in sp.sent.items() if p < sp.lack - 2 or (p < sp.lack and now - sk.t > thr)]
        for p in lost:
            sk = sp.sent.pop(p)
            self.unfly(sk)
            if sk.elig:
                self.cc_loss(sk, now)
            self.requeue(sp, sk)

    def unfly(self, sk):
        if sk.elig:
            self.bif = max(0, self.bif - sk.n)

    def fly_clear(self, sp):
        for sk in sp.sent.values():
            self.unfly(sk)
        sp.sent.clear()

    def cc_ack(self, sk):
        if sk.t <= self.rec_t:
            return
        if self.cwnd < self.ssth:
            self.cwnd += sk.n
        else:
            self.cwnd += MTU * sk.n // max(self.cwnd, 1)
        self.cwnd = min(self.cwnd, MAX_CWND)

    def cc_loss(self, sk, now):
        if sk.t > self.rec_t:
            self.rec_t = now
            self.ssth = max(self.cwnd // 2, MIN_CWND)
            self.cwnd = self.ssth

    def rtt(self, s):
        if self.srtt is None:
            self.srtt = s
            self.rttv = s / 2
        else:
            self.rttv = 0.75 * self.rttv + 0.25 * abs(self.srtt - s)
            self.srtt = 0.875 * self.srtt + 0.125 * s

    def requeue(self, sp, sk):
        for f in sk.frs:
            if f[0] == "c":
                sp.cq.append((f[1], f[2]))
            elif f[0] == "s":
                s = self.strms.get(f[1])
                if s and not s.reset:
                    s.retx.append((f[2], f[3], f[4]))
            elif f[0] == "x":
                self.ctlq.append(f[1])

    def pto(self):
        base = (self.srtt or INIT_RTT) + max(4 * self.rttv, 0.001) + MAX_ACK_DELAY
        return base * (1 << min(self.pto_n, 6))

    def timer(self):
        t = None
        for sp in self.sp:
            for sk in sp.sent.values():
                if sk.elig and (t is None or sk.t < t):
                    t = sk.t
        if t is None:
            return 1.0
        return max(0.001, min(1.0, t + self.pto() - time.monotonic()))

    def on_timer(self):
        now = time.monotonic()
        if now - self.lrxt > self.idle:
            self.fail(QuicError("idle timeout"))
            return
        due = False
        for lvl, sp in enumerate(self.sp):
            old = [(p, sk) for p, sk in sp.sent.items() if sk.elig]
            if old and min(sk.t for _, sk in old) + self.pto() <= now:
                due = True
                for p, sk in sorted(old)[:2]:
                    del sp.sent[p]
                    self.unfly(sk)
                    self.requeue(sp, sk)
        if due:
            self.pto_n += 1
            self.probe_n = 2
            if self.pto_n >= 3:
                self.ssth = max(self.cwnd // 2, MIN_CWND)
                self.cwnd = MIN_CWND
            if self.pto_n > 8:
                self.fail(QuicError("peer unresponsive"))
                return
            self.probe = True
            self.flush()

    def seal(self, lvl, payload, pad, force=False):
        sp = self.sp[lvl]
        pn = sp.pn
        sp.pn += 1
        k = sp.snd
        if lvl == 2:
            first = 0x40 | (self.kp << 2) | (PN_LEN - 1)
            hdr = bytes([first]) + self.dcid
            pn_off = len(hdr)
            hdr += struct.pack(">I", pn & 0xFFFFFFFF)
            body = payload
            if pad:
                body += b"\x00" * pad
            ct = k.aead.encrypt(k.nonce(pn), body, hdr)
            pk = bytearray(hdr + ct)
            long = False
        else:
            ty = 0 if lvl == 0 else 2
            first = 0xC0 | (ty << 4) | (PN_LEN - 1)
            hdr = bytearray([first]) + struct.pack(">I", V1) + bytes([len(self.dcid)]) + self.dcid + bytes([len(self.scid)]) + self.scid
            if lvl == 0:
                hdr += vi(len(self.token)) + self.token
            body = payload + (b"\x00" * pad if pad else b"")
            hdr += struct.pack(">H", 0x4000 | (PN_LEN + len(body) + 16))
            pn_off = len(hdr)
            hdr += struct.pack(">I", pn & 0xFFFFFFFF)
            ct = k.aead.encrypt(k.nonce(pn), body, bytes(hdr))
            pk = bytearray(bytes(hdr) + ct)
            long = True
        m = k.mask(bytes(pk[pn_off + 4:pn_off + 20]))
        pk[0] ^= m[0] & (0x0F if long else 0x1F)
        for i in range(PN_LEN):
            pk[pn_off + i] ^= m[1 + i]
        self.last_pn = pn
        return bytes(pk)

    def ovh(self, lvl):
        if lvl == 2:
            return 1 + len(self.dcid) + PN_LEN + 16
        return 1 + 4 + 1 + len(self.dcid) + 1 + len(self.scid) + (len(vi(len(self.token))) + len(self.token) if lvl == 0 else 0) + 2 + PN_LEN + 16

    def collect(self, lvl, room):
        sp = self.sp[lvl]
        frs = []
        out = b""
        elig = False
        if sp.ackn and sp.rr:
            a = sp.ack_frame()
            if len(a) <= room:
                out += a
                sp.ackn = False
        while sp.cq and room - len(out) > 16:
            o, d = sp.cq[0]
            take = min(len(d), room - len(out) - 12)
            if take <= 0:
                break
            fr = bytes([T_CRYPTO]) + vi(o) + vi(take) + d[:take]
            out += fr
            frs.append(("c", o, d[:take]))
            elig = True
            if take < len(d):
                sp.cq[0] = (o + take, d[take:])
            else:
                sp.cq.pop(0)
        if lvl == 2:
            can = self.bif < self.cwnd or self.probe_n > 0
            while self.ctlq and len(self.ctlq[0]) <= room - len(out):
                c = self.ctlq.pop(0)
                out += c
                frs.append(("x", c))
                elig = True
            for sid, s in (list(self.strms.items()) if can else []):
                if s.reset and not s.retx and not s.snd:
                    continue
                while room - len(out) > 24 and (s.retx or s.snd or (s.fin and not s.fsent)):
                    avail = room - len(out) - 1 - len(vi(sid)) - 8 - 4
                    if avail <= 0:
                        break
                    if s.retx:
                        o, d, f = s.retx.pop(0)
                        if len(d) > avail:
                            s.retx.insert(0, (o + avail, d[avail:], f))
                            d, f = d[:avail], False
                    else:
                        cc = max(0, self.smd - self.sdata)
                        sc = max(0, s.smax - s.so)
                        n = min(len(s.snd), avail, cc, sc)
                        if n == 0 and s.snd:
                            break
                        d = bytes(s.snd[:n])
                        o = s.so
                        f = s.fin and n == len(s.snd)
                        del s.snd[:n]
                        s.so += n
                        self.sdata += n
                        if f:
                            s.fsent = True
                    fr = bytes([0x0E | (1 if f else 0)]) + vi(sid) + vi(o) + vi(len(d)) + d
                    out += fr
                    frs.append(("s", sid, o, d, f))
                    elig = True
        if getattr(self, "probe", False) and not elig and lvl == (2 if self.sp[2].snd else (1 if self.sp[1].snd else 0)):
            out += bytes([T_PING])
            elig = True
            self.probe = False
        return out, frs, elig

    def flush(self):
        if self.closed.is_set():
            return
        guard = 0
        while guard < 64:
            guard += 1
            pkts = []
            total = 0
            has_init = False
            for lvl in (0, 1, 2):
                sp = self.sp[lvl]
                if sp.snd is None:
                    continue
                room = MTU - total - self.ovh(lvl)
                if room < 40:
                    break
                body, frs, elig = self.collect(lvl, room)
                if not body:
                    continue
                pkts.append((lvl, body, frs, elig))
                total += self.ovh(lvl) + len(body)
                if lvl == 0:
                    has_init = True
            if not pkts:
                break
            out = b""
            for i, (lvl, body, frs, elig) in enumerate(pkts):
                pad = 0
                if i == len(pkts) - 1 and has_init:
                    pad = max(0, MTU - total)
                if len(body) + pad < 4:
                    pad = 4 - len(body)
                pk = self.seal(lvl, body, pad)
                out += pk
                if frs or elig:
                    self.sp[lvl].sent[self.last_pn] = Sent(time.monotonic(), frs, elig, len(pk))
                if elig:
                    self.bif += len(pk)
                    self.max_bif = max(self.max_bif, self.bif)
                    if self.probe_n > 0:
                        self.probe_n -= 1
            try:
                self.sock.send(out)
            except OSError:
                self.fail(QuicError("send failed"))
                return
            if any(p[0] == 1 for p in pkts) and self.sp[0].snd is not None and not getattr(self, "got_hs_tx", False):
                self.got_hs_tx = True
                self.sp[0].snd = self.sp[0].rcv = None
                self.fly_clear(self.sp[0])
        self.probe = False

    def open_bidi(self):
        with self.lk:
            if self.closed.is_set():
                raise self.err or QuicError("connection closed")
            if self.nb >= self.mbs:
                raise QuicError("peer stream limit reached", E_STRMLIM)
            sid = self.nb * 4
            self.nb += 1
            self.strms[sid] = QS(sid, tp_int(self.ptp, 6, 0), STRM_WIN)
            return sid

    def open_uni(self):
        with self.lk:
            if self.closed.is_set():
                raise self.err or QuicError("connection closed")
            if self.nu >= self.mus:
                raise QuicError("peer uni stream limit reached", E_STRMLIM)
            sid = self.nu * 4 + 2
            self.nu += 1
            self.strms[sid] = QS(sid, tp_int(self.ptp, 7, 0), STRM_WIN)
            return sid

    def send(self, sid, data=b"", fin=False):
        with self.lk:
            if self.closed.is_set():
                raise self.err or QuicError("connection closed")
            s = self.strms[sid]
            s.snd += data
            if fin:
                s.fin = True
            self.flush()

    def cancel(self, sid, code=0x10C):
        with self.lk:
            s = self.strms.get(sid)
            if not s or self.closed.is_set():
                return
            s.snd.clear()
            s.retx.clear()
            s.reset = True
            self.ctlq.append(bytes([T_RESET]) + vi(sid) + vi(code) + vi(s.so))
            if not s.rfin:
                self.ctlq.append(bytes([T_STOP]) + vi(sid) + vi(code))
            self.flush()

    def forget(self, sid):
        with self.lk:
            s = self.strms.get(sid)
            if s and sid & 3 == 0 and s.rfin and (s.fsent or s.reset):
                del self.strms[sid]
