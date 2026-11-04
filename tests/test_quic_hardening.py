import os
import shutil
import tempfile
import time
import unittest

try:
    import cryptography.x509
    from httpkit.quic import INIT_CWND, MIN_CWND, MTU, QConn, Sent, Sp
    from httpkit.tls13 import CERT_SIGS, SIGS, Tls13, roots, trust
    HAVE = bool(cryptography.x509)
except Exception:
    HAVE = False

try:
    import hypercorn.config
    from lab import Srv
    from udprelay import Relay
    LIVE = HAVE and bool(hypercorn.config)
except Exception:
    LIVE = False

from httpkit import Client, Hdrs, QuicError, Req
from httpkit.err import QuicReset
from httpkit.url import parse as pu


def ch_exts(m):
    p = 4 + 2 + 32
    p += 1 + m[p]
    n = int.from_bytes(m[p:p + 2], "big")
    p += 2 + n
    p += 2
    el = int.from_bytes(m[p:p + 2], "big")
    p += 2
    out = {}
    end = p + el
    while p < end:
        t = int.from_bytes(m[p:p + 2], "big")
        n = int.from_bytes(m[p + 2:p + 4], "big")
        out[t] = m[p + 4:p + 4 + n]
        p += 4 + n
    return out


def algs(b):
    n = int.from_bytes(b[:2], "big")
    return [int.from_bytes(b[2 + i:4 + i], "big") for i in range(0, n, 2)]


@unittest.skipUnless(HAVE, "needs cryptography")
class UnitT(unittest.TestCase):
    def test_sig_algs_split(self):
        m = Tls13("example.com", ["h3"], b"").start()[0][2]
        ex = ch_exts(m)
        a13, a32 = algs(ex[13]), algs(ex[0x32])
        self.assertEqual(tuple(a13), SIGS)
        self.assertNotIn(0x0401, a13)
        for x in (0x0401, 0x0501, 0x0601):
            self.assertIn(x, a32)
        self.assertEqual(tuple(a32), CERT_SIGS)

    def test_ca_bundle_cached(self):
        a = roots()
        t0 = time.perf_counter()
        b = roots()
        fast = time.perf_counter() - t0
        self.assertIs(a, b)
        self.assertLess(fast, 0.01)
        self.assertIs(trust()[1], trust()[1])

    def test_ca_cache_invalidates_on_change(self):
        src = roots()
        d = tempfile.mkdtemp()
        p = os.path.join(d, "b.pem")
        for f in ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"):
            if os.path.isfile(f):
                shutil.copy(f, p)
                break
        else:
            self.skipTest("no system bundle to copy")
        first = roots(p)
        self.assertIs(first, roots(p))
        with open(p, "a") as f:
            f.write("\n")
        self.assertIsNot(first, roots(p))
        self.assertTrue(src)

    def test_uni_stream_limit(self):
        q = QConn.__new__(QConn)
        q.strms = {}
        q.sget(3)
        q.sget(3 + 4 * 15)
        with self.assertRaises(QuicError):
            q.sget(3 + 4 * 16)
        for sid in (0, 1, 2):
            self.assertIsNone(q.sget(sid))

    def test_stateless_reset_detection(self):
        q = QConn.__new__(QConn)
        tok = os.urandom(16)
        q.rtok = {tok}
        q.scid = b"12345678"
        q.sp = [Sp(), Sp(), Sp()]
        with self.assertRaises(QuicReset):
            q.pkt(bytes([0x41]) + os.urandom(30) + tok, 0)
        d = bytes([0x41]) + os.urandom(46)
        self.assertEqual(q.pkt(d, 0), len(d))
        d = bytes([0x41]) + tok
        self.assertEqual(q.pkt(d, 0), len(d))

    def test_reno_accounting(self):
        q = QConn.__new__(QConn)
        q.cwnd = INIT_CWND
        q.ssth = float("inf")
        q.bif = 0
        q.rec_t = 0.0
        self.assertEqual(INIT_CWND, 10 * MTU)
        sk = Sent(time.monotonic(), [], True, MTU)
        q.bif += MTU
        q.unfly(sk)
        self.assertEqual(q.bif, 0)
        q.cc_ack(sk)
        self.assertEqual(q.cwnd, INIT_CWND + MTU)
        now = time.monotonic()
        q.cc_loss(Sent(now + 0.001, [], True, MTU), now + 0.002)
        self.assertEqual(q.cwnd, (INIT_CWND + MTU) // 2)
        self.assertEqual(q.ssth, q.cwnd)
        c = q.cwnd
        q.cc_loss(Sent(now + 0.0005, [], True, MTU), now + 0.003)
        self.assertEqual(q.cwnd, c)
        q.cc_ack(Sent(now + 0.01, [], True, MTU))
        self.assertGreater(q.cwnd, c)
        self.assertLess(q.cwnd, c + MTU)
        base = time.monotonic() + 10
        for i in range(1, 21):
            q.cc_loss(Sent(base + i, [], True, MTU), base + i + 0.5)
        self.assertEqual(q.cwnd, MIN_CWND)
        sp = Sp()
        sp.sent = {1: Sent(0, [], True, 500), 2: Sent(0, [], False, 700)}
        q.bif = 500
        q.fly_clear(sp)
        self.assertEqual((q.bif, len(sp.sent)), (0, 0))


@unittest.skipUnless(LIVE, "needs cryptography and hypercorn[h3]")
class LiveHardT(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = Srv().__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.s.__exit__()

    def start(self, **kw):
        rl = Relay(self.s.qp, **kw)
        url = "https://localhost:%d/echo" % rl.port
        c = Client(proto="h3", ca=self.s.ca, tmo=40)
        r = c.get(url)
        self.assertEqual((r.status, r.proto), (200, "h3"))
        pc = c.pool[(pu(url).origin, None)]
        return rl, c, pc, url

    def test_upload_burst_is_limited(self):
        rl, c, pc, url = self.start()
        q = pc.q
        rl.s2c_off = True
        base = rl.c2s
        sid = q.open_bidi()
        q.send(sid, b"x" * 3000000)
        time.sleep(0.6)
        sent = rl.c2s - base
        self.assertLess(sent, 60000, sent)
        self.assertGreater(sent, 5000)
        c.close()
        rl.close()

    def test_upload_under_loss_reduces_window(self):
        rl, c, pc, url = self.start(drop=0.08)
        r = c.req("POST", url, body=b"z" * 2000000)
        self.assertEqual(r.json()["len"], 2000000)
        self.assertNotEqual(pc.q.ssth, float("inf"))
        self.assertGreaterEqual(pc.q.cwnd, MIN_CWND)
        c.close()
        rl.close()

    def test_clean_upload_grows_window(self):
        url = "https://localhost:%d/echo" % self.s.qp
        with Client(proto="h3", ca=self.s.ca, tmo=40) as c:
            c.get(url)
            r = c.req("POST", url, body=b"z" * 3000000)
            self.assertEqual(r.json()["len"], 3000000)
            q = c.pool[(pu(url).origin, None)].q
            self.assertGreater(q.max_bif, INIT_CWND)

    def test_stateless_reset_fails_fast(self):
        rl, c, pc, url = self.start()
        self.assertTrue(pc.q.rtok)
        rl.reset_tok = next(iter(pc.q.rtok))
        t0 = time.monotonic()
        with self.assertRaises(QuicReset):
            pc.req(Req("GET", pu(url), Hdrs()), 25)
        self.assertLess(time.monotonic() - t0, 3.0)
        self.assertFalse(pc.alive())
        c.close()
        rl.close()


if __name__ == "__main__":
    unittest.main()
