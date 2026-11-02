import unittest

try:
    import cryptography.x509
    import hypercorn.config
    from lab import Srv
    OK = bool(cryptography.x509 and hypercorn.config)
except Exception:
    OK = False

from httpkit import Client


@unittest.skipUnless(OK, "needs cryptography and hypercorn[h3]")
class LiveT(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = Srv().__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.s.__exit__()

    def url(self, p, h3=False):
        return "https://localhost:%d%s" % (self.s.qp if h3 else self.s.tp, p)

    def run_proto(self, proto, h3=False):
        with Client(proto=proto, ca=self.s.ca, h3=False) as c:
            r = c.get(self.url("/echo?a=1", h3))
            self.assertEqual((r.status, r.proto, r.json()["qs"]), (200, {"h1": "http/1.1"}.get(proto, proto), "a=1"))
            self.assertEqual(r.hdrs.get_all("x-multi"), ["a", "b"])
            r = c.req("POST", self.url("/p", h3), body=b"z" * 300000)
            self.assertEqual(r.json()["len"], 300000)
            r = c.get(self.url("/big", h3))
            self.assertEqual(len(r.body), 3000000)
            r = c.get(self.url("/redir", h3))
            self.assertEqual((r.status, len(r.hist), r.json()["cookie"]), (200, 1, "sid=abc"))
            rs = c.map([self.url("/echo?i=%d" % i, h3) for i in range(20)])
            self.assertTrue(all(x.status == 200 for x in rs))

    def test_h1(self):
        self.run_proto("h1")

    def test_h2(self):
        self.run_proto("h2")

    def test_h3(self):
        self.run_proto("h3", True)

    def test_verify_fails_without_ca(self):
        from httpkit import ConnError
        with Client(proto="h2", h3=False) as c:
            with self.assertRaises(ConnError):
                c.get(self.url("/echo"))
        with Client(proto="h3") as c:
            with self.assertRaises(ConnError):
                c.get(self.url("/echo", True))

    def test_insecure_h3(self):
        with Client(proto="h3", verify=False) as c:
            self.assertEqual(c.get(self.url("/echo", True)).status, 200)

    def test_alt_svc_concurrent(self):
        with Client(proto="auto", ca=self.s.ca) as c:
            c.get(self.url("/echo"))
            rs = c.map([self.url("/echo?i=%d" % i) for i in range(24)], workers=8)
            self.assertTrue(all(r.status == 200 for r in rs))
            self.assertEqual(c.get(self.url("/echo")).proto, "h3")

    def test_alt_svc_upgrade(self):
        with Client(proto="auto", ca=self.s.ca) as c:
            a = c.get(self.url("/echo"))
            b = c.get(self.url("/echo"))
            self.assertEqual((a.proto, b.proto), ("h2", "h3"))


if __name__ == "__main__":
    unittest.main()
