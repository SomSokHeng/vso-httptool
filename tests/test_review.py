import ipaddress
import time
import unittest

from httpkit import Client, Hdrs, Req, Resp
from httpkit.follow import plan
from httpkit.sec import InfGuard, is_priv
from httpkit.url import parse as pu
from pxlab import Px, Tgt


class G(InfGuard):
    def resolve(self, host, port):
        return [(2, "93.184.216.34")]


class PoolT(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = Tgt()

    @classmethod
    def tearDownClass(cls):
        cls.t.close()

    def test_h1_idle_list_under_concurrency(self):
        t = self.t
        with Client(proto="h1", h3=False, max_idle=4) as c:
            rs = c.map([t.url("/%d" % i) for i in range(40)], workers=8)
            self.assertTrue(all(r.status == 200 for r in rs))
            first = t.conns
            self.assertLessEqual(first, 12)
            self.assertEqual(sum(len(v) for v in c.idle.values()), 4)
            b = t.conns
            for i in range(10):
                c.get(t.url("/seq"))
            self.assertEqual(t.conns, b)
            c.map([t.url("/%d" % i) for i in range(40)], workers=8)
            self.assertLessEqual(t.conns - b, 6)

    def test_idle_cap_per_key(self):
        with Client(proto="h1", h3=False, max_idle=2) as c:
            c.map([self.t.url("/%d" % i) for i in range(20)], workers=6)
            self.assertLessEqual(sum(len(v) for v in c.idle.values()), 2)

    def test_closed_idle_connection_not_reused(self):
        px = Px("http")
        with Client(proxy=px.url(), h3=False) as c:
            out = []
            for _ in range(3):
                out.append(c.get(self.t.url("/z")))
                time.sleep(0.15)
        self.assertTrue(all(not [p for p in r.trace.prob] for r in out), [r.trace.prob for r in out])
        px.close()

    def test_alt_state_locked_helpers(self):
        with Client() as c:
            u = pu("https://example.com/")
            c.set_alt(u.origin, 60, 443)
            self.assertEqual(c.alt_for(u), 443)
            c.mark_bad(u.origin, 60)
            self.assertIsNone(c.alt_for(u))
            c.clr_alt(u.origin)
            self.assertNotIn(u.origin, c.alt)


class PrivT(unittest.TestCase):
    def test_blocked(self):
        t = ipaddress.ip_address("2001:0:4136:e378:8000:63bf:3fff:fdd2").teredo
        self.assertEqual(str(t[1]), "192.0.2.45")
        for a in ("64:ff9b::a00:1", "64:ff9b::7f00:1", "64:ff9b:1::1", "2002:a00:1::", "2002:7f00:1::", "::10.0.0.1", "::7f00:1", "::5", "2001:db8::1", "192.0.2.1", "198.51.100.7", "203.0.113.9", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "100.64.0.1", "169.254.169.254", "fe80::1", "fd00::1", "::ffff:10.0.0.1", "0.0.0.0", "224.0.0.1", "240.0.0.1", "not-an-ip"):
            self.assertTrue(is_priv(a), a)

    def test_allowed(self):
        for a in ("8.8.8.8", "93.184.216.34", "2606:4700:4700::1111", "64:ff9b::808:808", "2002:808:808::", "::ffff:8.8.8.8"):
            self.assertFalse(is_priv(a), a)


class CookieRedirT(unittest.TestCase):
    def mk(self, url, loc, hdrs):
        return Req("GET", pu(url), Hdrs(hdrs), b""), Resp(302, Hdrs([("Location", loc)]))

    def test_manual_cookie_kept_same_origin(self):
        rq, rs = self.mk("https://a.com/x", "/y", [("Cookie", "m=1"), ("X-A", "1")])
        p = plan(rq, rs, G(), set(), 10, 0)
        self.assertEqual(p.req.hdrs.get("cookie"), "m=1")

    def test_manual_cookie_dropped_cross_origin(self):
        rq, rs = self.mk("https://a.com/x", "https://b.com/y", [("Cookie", "m=1"), ("Authorization", "t"), ("Proxy-Authorization", "p")])
        p = plan(rq, rs, G(), set(), 10, 0)
        self.assertEqual(len(p.req.hdrs), 0)


class CacheT(unittest.TestCase):
    def test_cache_evicts_oldest_not_all(self):
        g = InfGuard()
        for i in range(300):
            g.cache[("h%d" % i, 80)] = (time.monotonic(), [(2, "1.1.1.1")])
        g.resolve("localhost", 80)
        self.assertLessEqual(len(g.cache), 257)
        self.assertIn(("h299", 80), g.cache)


if __name__ == "__main__":
    unittest.main()
