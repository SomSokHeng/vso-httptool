import os
import subprocess
import sys
import unittest
from unittest import mock

from httpkit import Client, ClientError, HdrError, ProxyError, ProxyPool, UaPool, parse_proxy
from httpkit.proxy import bypass, from_env, load_list
from pxlab import Px, Tgt, dead_port

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ParseT(unittest.TestCase):
    def test_forms(self):
        for s, sch, port in (("http://h:3128", "http", 3128), ("h:3128", "http", 3128), ("socks5://h", "socks5", 1080), ("SOCKS5H://h:1", "socks5h", 1), ("socks4a://h:9", "socks4a", 9), ("https://h:443", "https", 443), ("socks4://h", "socks4", 1080)):
            p = parse_proxy(s)
            self.assertEqual((p.scheme, p.port), (sch, port), s)

    def test_creds_masked(self):
        p = parse_proxy("http://us%40r:p%3Aw@h:80")
        self.assertEqual((p.usr, p.pwd), ("us@r", "p:w"))
        self.assertNotIn("p:w", repr(p))
        self.assertNotIn("p%3Aw", p.safe)

    def test_bad(self):
        for s in ("ftp://h:1", "http://", "http://h:99999", "http://h:1/path", "http://h:1\r\nX: y", "", "http://h:1?q=1", "socks5://" + "u" * 300 + ":p@h"):
            with self.assertRaises(ProxyError, msg=s):
                parse_proxy(s)

    def test_bypass(self):
        self.assertTrue(bypass("a.example.com", ["example.com"]))
        self.assertTrue(bypass("example.com", [".example.com"]))
        self.assertTrue(bypass("10.1.2.3", ["10.0.0.0/8"]))
        self.assertTrue(bypass("x", ["*"]))
        self.assertFalse(bypass("notexample.com", ["example.com"]))
        self.assertFalse(bypass("8.8.8.8", ["10.0.0.0/8"]))

    def test_env(self):
        with mock.patch.dict(os.environ, {"https_proxy": "socks5h://e:1080"}, clear=True):
            self.assertEqual(from_env("https").scheme, "socks5h")
            self.assertIsNone(from_env("http"))
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://evil:1"}, clear=True):
            self.assertEqual(from_env("http").host, "evil")
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://evil:1", "REQUEST_METHOD": "GET"}, clear=True):
            self.assertIsNone(from_env("http"))

    def test_load_list(self):
        import tempfile
        d = tempfile.mkdtemp()
        p = os.path.join(d, "l.txt")
        with open(p, "w") as f:
            f.write("# one\n\nhttp://a:1\n  socks5://b:2  \n")
        self.assertEqual(load_list(p), ["http://a:1", "socks5://b:2"])


class PoolT(unittest.TestCase):
    def test_rr(self):
        p = ProxyPool(["http://a:1", "http://b:2", "http://c:3"])
        self.assertEqual([p.pick().host for _ in range(6)], ["a", "b", "c", "a", "b", "c"])

    def test_random_sticky(self):
        p = ProxyPool(["http://a:1", "http://b:2"], "random")
        self.assertEqual({p.pick().host for _ in range(60)}, {"a", "b"})
        s = ProxyPool(["http://a:1", "http://b:2"], "sticky")
        o1, o2 = ("https", "x", 443), ("https", "y", 443)
        a = [s.pick(o1).host for _ in range(5)]
        self.assertEqual(len(set(a)), 1)
        self.assertNotEqual(s.pick(o2).host, a[0])
        self.assertEqual(s.pick(o2).host, s.pick(o2).host)

    def test_errors(self):
        with self.assertRaises(ProxyError):
            ProxyPool([])
        with self.assertRaises(ProxyError):
            ProxyPool(["http://a:1"], "failover")

    def test_ua_pool(self):
        u = UaPool(["A/1", "B/2"])
        self.assertEqual([u.pick() for _ in range(4)], ["A/1", "B/2", "A/1", "B/2"])
        with self.assertRaises(HdrError):
            UaPool(["ok", "bad\r\nX: y"])
        with self.assertRaises(ValueError):
            UaPool([])
        with self.assertRaises(ValueError):
            UaPool(["a"], "worst")


class FlowT(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = Tgt()

    @classmethod
    def tearDownClass(cls):
        cls.t.close()

    def test_http_proxy_abs_form(self):
        px = Px("http")
        with Client(proxy=px.url(), h3=False) as c:
            r = c.get(self.t.url("/a?b=1"))
            self.assertEqual(r.json()["path"], "/a?b=1")
            self.assertEqual(px.seen[0], ("GET", self.t.url("/a?b=1")))
            self.assertEqual(r.proxy, px.url())
        px.close()

    def test_http_proxy_auth(self):
        px = Px("http", "u", "p")
        with Client(proxy=px.url(), h3=False) as c:
            self.assertEqual(c.get(self.t.url()).status, 200)
        bad = px.url().replace(":p@", ":wrong@")
        with Client(proxy=bad, h3=False) as c:
            r = c.get(self.t.url())
            self.assertEqual(r.status, 407)
        px.close()

    def test_connect_denied(self):
        px = Px("http", deny=True)
        with Client(proxy=px.url(), h3=False) as c:
            with self.assertRaises(ProxyError) as cm:
                c.get("https://127.0.0.1:1/")
        self.assertIn("403", str(cm.exception))
        self.assertEqual(px.seen[0], ("CONNECT", "127.0.0.1:1"))
        px.close()

    def test_connect_needs_auth(self):
        px = Px("http", "u", "p")
        with Client(proxy="http://127.0.0.1:%d" % px.port, h3=False) as c:
            with self.assertRaises(ProxyError) as cm:
                c.get("https://127.0.0.1:1/")
        self.assertIn("407", str(cm.exception))
        px.close()

    def test_socks5(self):
        px = Px("s5")
        with Client(proxy=px.url(), h3=False) as c:
            r = c.get(self.t.url("/s"))
            self.assertEqual(r.json()["path"], "/s")
        self.assertEqual(px.seen[0], ("s5", 1, "127.0.0.1", self.t.port))
        px.close()

    def test_socks5_auth(self):
        px = Px("s5", "u", "p")
        with Client(proxy=px.url(), h3=False) as c:
            self.assertEqual(c.get(self.t.url()).status, 200)
        with Client(proxy="socks5://u:no@127.0.0.1:%d" % px.port, h3=False) as c:
            with self.assertRaises(ProxyError):
                c.get(self.t.url())
        with Client(proxy="socks5://127.0.0.1:%d" % px.port, h3=False) as c:
            with self.assertRaises(ProxyError):
                c.get(self.t.url())
        px.close()

    def test_socks5_dns_modes(self):
        u = "http://localhost:%d/" % self.t.port
        px = Px("s5")
        with Client(proxy="socks5h://127.0.0.1:%d" % px.port, h3=False) as c:
            c.get(u)
        with Client(proxy="socks5://127.0.0.1:%d" % px.port, h3=False) as c:
            c.get(u)
        self.assertEqual(px.seen[0][1:3], (3, "localhost"))
        self.assertEqual(px.seen[1][1], 1)
        px.close()

    def test_socks4(self):
        px = Px("s4")
        with Client(proxy=px.url(), h3=False) as c:
            self.assertEqual(c.get(self.t.url()).status, 200)
        with Client(proxy="socks4a://127.0.0.1:%d" % px.port, h3=False) as c:
            self.assertEqual(c.get("http://localhost:%d/" % self.t.port).status, 200)
        self.assertEqual(px.seen[0][:3], ("s4", "127.0.0.1", self.t.port))
        self.assertEqual(px.seen[1][:3], ("s4a", "localhost", self.t.port))
        px.close()

    def test_dead_proxy_is_used_not_skipped(self):
        good = Px("http")
        dead = "http://127.0.0.1:%d" % dead_port()
        with Client(proxies=[dead, good.url()], h3=False) as c:
            out = []
            for _ in range(6):
                try:
                    out.append(c.get(self.t.url()).status)
                except ProxyError:
                    out.append("err")
        self.assertEqual(out, ["err", 200, "err", 200, "err", 200])
        good.close()

    def test_rotation_across_proxies(self):
        a, b = Px("http"), Px("s5")
        with Client(proxies=[a.url(), b.url()], h3=False) as c:
            ps = [c.get(self.t.url()).proxy for _ in range(4)]
        self.assertEqual(ps, [a.url(), b.url(), a.url(), b.url()])
        self.assertEqual((len(a.seen), len(b.seen)), (2, 1))
        a.close()
        b.close()

    def test_sticky_and_override(self):
        a, b = Px("http"), Px("http")
        with Client(proxies=[a.url(), b.url()], rotate="sticky", h3=False) as c:
            ps = {c.get(self.t.url()).proxy for _ in range(4)}
            self.assertEqual(len(ps), 1)
            r = c.get(self.t.url(), proxy=b.url())
            self.assertEqual(r.proxy, b.url())
            n = len(a.seen) + len(b.seen)
            self.assertIsNone(c.get(self.t.url(), proxy="direct").proxy)
            self.assertEqual(len(a.seen) + len(b.seen), n)
        a.close()
        b.close()

    def test_no_proxy_bypass(self):
        px = Px("http")
        with Client(proxy=px.url(), no_proxy="127.0.0.1", h3=False) as c:
            self.assertIsNone(c.get(self.t.url()).proxy)
        self.assertEqual(px.seen, [])
        px.close()

    def test_env_proxy(self):
        px = Px("http")
        with mock.patch.dict(os.environ, {"http_proxy": px.url()}, clear=True):
            with Client(proxy="env", h3=False) as c:
                self.assertEqual(c.get(self.t.url()).proxy, px.url())
        px.close()

    def test_h3_with_proxy_rejected(self):
        with self.assertRaises(ClientError):
            Client(proto="h3", proxy="http://127.0.0.1:1")
        with Client(h3=False):
            pass

    def test_ua_rotation(self):
        with Client(uas=["A/1", "B/2", "C/3"], h3=False) as c:
            r = [c.get(self.t.url()) for _ in range(6)]
        self.assertEqual([x.json()["ua"] for x in r], ["A/1", "B/2", "C/3"] * 2)
        self.assertEqual([x.ua for x in r][:3], ["A/1", "B/2", "C/3"])

    def test_ua_explicit_and_callable_and_random(self):
        with Client(uas=["A/1", "B/2"], h3=False) as c:
            self.assertEqual(c.get(self.t.url(), hdrs={"User-Agent": "mine/0"}).json()["ua"], "mine/0")
        n = []
        with Client(uas=lambda: n.append(1) or "call/%d" % len(n), h3=False) as c:
            self.assertEqual([c.get(self.t.url()).json()["ua"] for _ in range(2)], ["call/1", "call/2"])
        with Client(uas=["A/1", "B/2"], ua_rotate="random", h3=False) as c:
            self.assertEqual({c.get(self.t.url()).ua for _ in range(40)}, {"A/1", "B/2"})
        with Client(h3=False, ua="solo/1") as c:
            self.assertEqual(c.get(self.t.url()).json()["ua"], "solo/1")

    def test_old_ua_is_accepted_as_is(self):
        with Client(uas=["Mozilla/4.0 (compatible; MSIE 5.5)"], h3=False) as c:
            self.assertEqual(c.get(self.t.url()).json()["ua"], "Mozilla/4.0 (compatible; MSIE 5.5)")

    def test_cli(self):
        px = Px("http")
        r = subprocess.run([sys.executable, "-m", "httpkit", "-v", "-n", "2", "--proxy", px.url(), "--ua", "X/1", "--ua", "Y/2", self.t.url()], cwd=ROOT, env=dict(os.environ, PYTHONPATH=ROOT), capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("via " + px.url(), r.stderr)
        self.assertIn("ua=X/1", r.stderr)
        self.assertIn("ua=Y/2", r.stderr)
        px.close()


try:
    import cryptography.x509
    import hypercorn.config
    from lab import Srv
    LIVE = bool(cryptography.x509 and hypercorn.config)
except Exception:
    LIVE = False


@unittest.skipUnless(LIVE, "needs cryptography and hypercorn[h3]")
class LiveProxyT(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import ssl
        cls.s = Srv().__enter__()
        cls.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.ctx.load_cert_chain(os.path.join(cls.s.d, "leaf.pem"), os.path.join(cls.s.d, "leaf.key"))
        cls.t = Tgt()

    @classmethod
    def tearDownClass(cls):
        cls.s.__exit__()
        cls.t.close()

    def url(self, p="/echo"):
        return "https://localhost:%d%s" % (self.s.tp, p)

    def run_via(self, purl, proto, expect, **kw):
        with Client(proxy=purl, proto=proto, ca=self.s.ca, h3=False, **kw) as c:
            r = c.get(self.url("/echo?q=1"))
            self.assertEqual((r.status, r.proto, r.json()["qs"]), (200, expect, "q=1"))
            return r

    def test_connect_h1_h2(self):
        px = Px("http")
        self.run_via(px.url(), "h1", "http/1.1")
        self.run_via(px.url(), "h2", "h2")
        self.assertEqual(px.seen[0], ("CONNECT", "localhost:%d" % self.s.tp))
        px.close()

    def test_connect_auth(self):
        px = Px("http", "u", "p")
        self.run_via(px.url(), "auto", "h2")
        px.close()

    def test_socks_variants(self):
        px5, px4 = Px("s5"), Px("s4")
        for u in (px5.url("socks5"), px5.url("socks5h")):
            self.run_via(u, "h2", "h2")
        self.run_via(px4.url("socks4a"), "h1", "http/1.1")
        self.assertEqual([x[1] for x in px5.seen], [1, 3])
        self.assertEqual(px4.seen[0][:2], ("s4a", "localhost"))
        px5.close()
        px4.close()

    def test_https_proxy_plain_target(self):
        px = Px("http", ctx=self.ctx)
        with Client(proxy=px.url("https"), ca=self.s.ca, h3=False) as c:
            r = c.get(self.t.url("/x"))
            self.assertEqual(r.json()["path"], "/x")
        px.close()

    def test_https_proxy_nested_tls(self):
        px = Px("http", ctx=self.ctx)
        self.run_via(px.url("https"), "h1", "http/1.1")
        self.run_via(px.url("https"), "h2", "h2")
        with Client(proxy=px.url("https"), proto="h2", ca=self.s.ca, h3=False) as c:
            r = c.get(self.url("/big"))
            self.assertEqual(len(r.body), 3000000)
            r = c.req("POST", self.url("/p"), body=b"z" * 300000)
            self.assertEqual(r.json()["len"], 300000)
            rs = c.map([self.url("/echo?i=%d" % i) for i in range(20)], workers=8)
            self.assertTrue(all(x.status == 200 for x in rs))
        px.close()

    def test_target_cert_still_verified(self):
        from httpkit import ConnError
        px = Px("http")
        with Client(proxy=px.url(), h3=False) as c:
            with self.assertRaises(ConnError):
                c.get(self.url())
        px.close()

    def test_rotation_over_mixed_types(self):
        a, b, c3 = Px("http"), Px("s5"), Px("http", ctx=self.ctx)
        with Client(proxies=[a.url(), b.url(), c3.url("https")], ca=self.s.ca, proto="h2", h3=False) as c:
            rs = [c.get(self.url()) for _ in range(6)]
        self.assertTrue(all(r.status == 200 for r in rs))
        self.assertEqual([r.proxy for r in rs[:3]], [a.url(), b.url(), c3.url("https")])
        for x in (a, b, c3):
            x.close()


if __name__ == "__main__":
    unittest.main()
