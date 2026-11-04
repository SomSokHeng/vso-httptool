import hashlib
import hmac
import ipaddress
import os
import ssl
import struct
import threading
import warnings

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519
from cryptography.x509.verification import PolicyBuilder, Store

from .err import TlsError

CS = {
    0x1301: ("sha256", 16, "aes"),
    0x1302: ("sha384", 32, "aes"),
    0x1303: ("sha256", 32, "chacha"),
}
SIGS = (0x0804, 0x0805, 0x0806, 0x0403, 0x0503, 0x0807)
HRR = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
CAFILES = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
    "/data/data/com.termux/files/usr/etc/tls/cert.pem",
)
PEMB = b"-----BEGIN CERTIFICATE-----"
CERT_SIGS = SIGS + (0x0401, 0x0501, 0x0601)
_rc = {}
_rl = threading.Lock()


def hk_ext(h, salt, ikm):
    return hmac.new(salt or b"\x00" * hashlib.new(h).digest_size, ikm, h).digest()


def hk_exp(h, prk, info, n):
    out = b""
    t = b""
    i = 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), h).digest()
        out += t
        i += 1
    return out[:n]


def exp_lbl(h, sec, lbl, ctx, n):
    full = b"tls13 " + lbl
    return hk_exp(h, sec, struct.pack(">HB", n, len(full)) + full + bytes([len(ctx)]) + ctx, n)


def der_secret(h, sec, lbl, th):
    return exp_lbl(h, sec, lbl, th, hashlib.new(h).digest_size)


def bundle_certs(ca):
    paths = [ca] if ca else []
    if not ca:
        vp = ssl.get_default_verify_paths()
        paths += [vp.cafile, vp.openssl_cafile] + list(CAFILES)
        try:
            import certifi
            paths.append(certifi.where())
        except Exception:
            pass
    for p in paths:
        if p and os.path.isfile(p):
            with open(p, "rb") as fh:
                data = fh.read()
            out = []
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                for blk in data.split(PEMB)[1:]:
                    try:
                        out.append(x509.load_pem_x509_certificate(PEMB + blk))
                    except Exception:
                        pass
            if out:
                return out
    raise TlsError("no CA bundle found; pass ca=<path> or verify=False")


def trust(ca=None):
    key = None
    if ca:
        try:
            st = os.stat(ca)
        except OSError:
            raise TlsError("cannot read CA bundle: %s" % ca) from None
        key = (ca, st.st_mtime_ns, st.st_size)
    with _rl:
        hit = _rc.get(key)
    if hit is not None:
        return hit
    certs = bundle_certs(ca)
    val = (certs, Store(certs))
    with _rl:
        if len(_rc) >= 4:
            _rc.pop(next(iter(_rc)))
        _rc[key] = val
    return val


def roots(ca=None):
    return trust(ca)[0]


def ext(t, d):
    return struct.pack(">HH", t, len(d)) + d


def u24(n):
    return struct.pack(">I", n)[1:]


def v_sig(pub, alg, sig, data):
    try:
        if alg in (0x0804, 0x0805, 0x0806):
            hh, sl = {0x0804: (hashes.SHA256(), 32), 0x0805: (hashes.SHA384(), 48), 0x0806: (hashes.SHA512(), 64)}[alg]
            if not isinstance(pub, rsa.RSAPublicKey):
                raise TlsError("key type mismatch for rsa_pss")
            pub.verify(sig, data, padding.PSS(mgf=padding.MGF1(hh), salt_length=sl), hh)
        elif alg in (0x0403, 0x0503):
            if not isinstance(pub, ec.EllipticCurvePublicKey):
                raise TlsError("key type mismatch for ecdsa")
            pub.verify(sig, data, ec.ECDSA(hashes.SHA256() if alg == 0x0403 else hashes.SHA384()))
        elif alg == 0x0807:
            if not isinstance(pub, ed25519.Ed25519PublicKey):
                raise TlsError("key type mismatch for ed25519")
            pub.verify(sig, data)
        else:
            raise TlsError("unsupported signature algorithm 0x%04x" % alg)
    except InvalidSignature as e:
        raise TlsError("CertificateVerify signature invalid") from e


class Tls13:
    def __init__(self, host, alpn, tp, verify=True, ca=None):
        self.host = host
        self.alpn = [a.encode() if isinstance(a, str) else a for a in alpn]
        self.tp = tp
        self.verify = verify
        self.ca = ca
        self.priv = x25519.X25519PrivateKey.generate()
        self.msgs = bytearray()
        self.h = None
        self.suite = None
        self.rb = {0: bytearray(), 1: bytearray(), 2: bytearray()}
        self.st = "start"
        self.peer_tp = None
        self.sel = None
        self.certs = []
        self.hs_sec = None
        self.c_hs = None
        self.s_hs = None
        self.done = False
        self.th_cv = None

    def th(self):
        return hashlib.new(self.h, bytes(self.msgs)).digest()

    def start(self):
        ke = self.priv.public_key().public_bytes_raw()
        try:
            ipaddress.ip_address(self.host)
            sni = b""
        except ValueError:
            n = self.host.encode("idna")
            sni = ext(0, struct.pack(">HBH", len(n) + 3, 0, len(n)) + n)
        al = b"".join(bytes([len(p)]) + p for p in self.alpn)
        exts = sni + ext(10, struct.pack(">HH", 2, 0x001D))
        exts += ext(13, struct.pack(">H", 2 * len(SIGS)) + b"".join(struct.pack(">H", s) for s in SIGS))
        exts += ext(0x32, struct.pack(">H", 2 * len(CERT_SIGS)) + b"".join(struct.pack(">H", s) for s in CERT_SIGS))
        exts += ext(43, b"\x02\x03\x04")
        exts += ext(51, struct.pack(">HHH", 36, 0x001D, 32) + ke)
        exts += ext(16, struct.pack(">H", len(al)) + al)
        exts += ext(45, b"\x01\x01")
        exts += ext(0x39, self.tp)
        suites = b"".join(struct.pack(">H", s) for s in CS)
        body = struct.pack(">H", 0x0303) + os.urandom(32) + b"\x00" + struct.pack(">H", len(suites)) + suites + b"\x01\x00" + struct.pack(">H", len(exts)) + exts
        m = b"\x01" + u24(len(body)) + body
        self.msgs += m
        self.st = "wait_sh"
        return [("send", 0, m)]

    def feed(self, lvl, data):
        buf = self.rb[lvl]
        buf += data
        ev = []
        while len(buf) >= 4:
            n = (buf[1] << 16) | (buf[2] << 8) | buf[3]
            if n > 1 << 18:
                raise TlsError("handshake message too large")
            if len(buf) < 4 + n:
                break
            m = bytes(buf[:4 + n])
            del buf[:4 + n]
            ev += self.proc(lvl, m[0], m[4:], m)
        return ev

    def proc(self, lvl, t, body, raw):
        if self.st == "wait_sh":
            if lvl != 0 or t != 2:
                raise TlsError("expected ServerHello")
            return self.on_sh(body, raw)
        if t == 4 and self.done:
            return []
        if lvl != 1 or self.done:
            raise TlsError("unexpected handshake message type %d at level %d" % (t, lvl))
        if self.st == "wait_ee" and t == 8:
            self.on_ee(body)
            self.msgs += raw
            self.st = "wait_cert"
            return []
        if self.st == "wait_cert" and t == 11:
            self.on_cert(body)
            self.msgs += raw
            self.st = "wait_cv"
            return []
        if self.st == "wait_cert" and t == 13:
            raise TlsError("server requested client certificate (unsupported)")
        if self.st == "wait_cv" and t == 15:
            self.on_cv(body)
            self.msgs += raw
            self.st = "wait_fin"
            return []
        if self.st == "wait_fin" and t == 20:
            return self.on_fin(body, raw)
        raise TlsError("unexpected handshake message %d in state %s" % (t, self.st))

    def exts(self, b):
        out = {}
        pos = 0
        while pos < len(b):
            if pos + 4 > len(b):
                raise TlsError("truncated extensions")
            t, n = struct.unpack(">HH", b[pos:pos + 4])
            pos += 4
            if pos + n > len(b):
                raise TlsError("truncated extension")
            if t in out:
                raise TlsError("duplicate extension")
            out[t] = b[pos:pos + n]
            pos += n
        return out

    def on_sh(self, b, raw):
        if len(b) < 38:
            raise TlsError("short ServerHello")
        rnd = b[2:34]
        if rnd == HRR:
            raise TlsError("HelloRetryRequest not supported")
        sl = b[34]
        p = 35 + sl
        cs, comp = struct.unpack(">HB", b[p:p + 3])
        p += 3
        if cs not in CS or comp != 0:
            raise TlsError("server chose unsupported cipher suite 0x%04x" % cs)
        el = struct.unpack(">H", b[p:p + 2])[0]
        ex = self.exts(b[p + 2:p + 2 + el])
        if ex.get(43) != b"\x03\x04":
            raise TlsError("server did not select TLS 1.3")
        ks = ex.get(51)
        if not ks or len(ks) != 36 or struct.unpack(">HH", ks[:4]) != (0x001D, 32):
            raise TlsError("bad server key_share")
        self.suite = cs
        self.h = CS[cs][0]
        self.msgs += raw
        try:
            ss = self.priv.exchange(x25519.X25519PublicKey.from_public_bytes(ks[4:]))
        except ValueError as e:
            raise TlsError("bad x25519 share") from e
        hl = hashlib.new(self.h).digest_size
        z = b"\x00" * hl
        early = hk_ext(self.h, z, z)
        eh = hashlib.new(self.h, b"").digest()
        derived = der_secret(self.h, early, b"derived", eh)
        self.hs_sec = hk_ext(self.h, derived, ss)
        th = self.th()
        self.c_hs = der_secret(self.h, self.hs_sec, b"c hs traffic", th)
        self.s_hs = der_secret(self.h, self.hs_sec, b"s hs traffic", th)
        self.st = "wait_ee"
        return [("keys", 1, self.c_hs, self.s_hs, cs)]

    def on_ee(self, b):
        n = struct.unpack(">H", b[:2])[0]
        ex = self.exts(b[2:2 + n])
        a = ex.get(16)
        if a is None:
            raise TlsError("server did not negotiate ALPN")
        if len(a) < 3 or struct.unpack(">H", a[:2])[0] != len(a) - 2 or a[2] != len(a) - 3:
            raise TlsError("bad ALPN extension")
        self.sel = a[3:]
        if self.sel not in self.alpn:
            raise TlsError("server selected unoffered ALPN")
        if 0x39 not in ex:
            raise TlsError("missing quic_transport_parameters")
        self.peer_tp = ex[0x39]

    def on_cert(self, b):
        if not b or b[0] != 0:
            raise TlsError("bad certificate context")
        n = (b[1] << 16) | (b[2] << 8) | b[3]
        if n + 4 != len(b):
            raise TlsError("bad certificate list length")
        pos = 4
        certs = []
        while pos < len(b):
            cl = (b[pos] << 16) | (b[pos + 1] << 8) | b[pos + 2]
            pos += 3
            certs.append(bytes(b[pos:pos + cl]))
            pos += cl
            xl = struct.unpack(">H", b[pos:pos + 2])[0]
            pos += 2 + xl
            if len(certs) > 10:
                raise TlsError("certificate chain too long")
        if not certs:
            raise TlsError("empty certificate chain")
        self.certs = certs
        self.leaf = x509.load_der_x509_certificate(certs[0])
        if self.verify:
            inter = [x509.load_der_x509_certificate(c) for c in certs[1:]]
            try:
                ipaddress.ip_address(self.host)
                sub = x509.IPAddress(ipaddress.ip_address(self.host))
            except ValueError:
                sub = x509.DNSName(self.host)
            try:
                PolicyBuilder().store(trust(self.ca)[1]).build_server_verifier(sub).verify(self.leaf, inter)
            except TlsError:
                raise
            except Exception as e:
                raise TlsError("certificate verification failed: %s" % e) from e

    def on_cv(self, b):
        alg, n = struct.unpack(">HH", b[:4])
        sig = b[4:4 + n]
        if alg not in SIGS:
            raise TlsError("unoffered signature algorithm 0x%04x" % alg)
        data = b" " * 64 + b"TLS 1.3, server CertificateVerify\x00" + self.th()
        v_sig(self.leaf.public_key(), alg, sig, data)

    def on_fin(self, b, raw):
        h = self.h
        fk = exp_lbl(h, self.s_hs, b"finished", b"", hashlib.new(h).digest_size)
        exp = hmac.new(fk, self.th(), h).digest()
        if not hmac.compare_digest(exp, b):
            raise TlsError("server Finished verify_data mismatch")
        self.msgs += raw
        th = self.th()
        hl = hashlib.new(h).digest_size
        derived = der_secret(h, self.hs_sec, b"derived", hashlib.new(h, b"").digest())
        ms = hk_ext(h, derived, b"\x00" * hl)
        c_ap = der_secret(h, ms, b"c ap traffic", th)
        s_ap = der_secret(h, ms, b"s ap traffic", th)
        cfk = exp_lbl(h, self.c_hs, b"finished", b"", hl)
        fin = hmac.new(cfk, th, h).digest()
        m = b"\x14" + u24(len(fin)) + fin
        self.msgs += m
        self.done = True
        self.st = "done"
        return [("send", 1, m), ("keys", 2, c_ap, s_ap, self.suite), ("done",)]
