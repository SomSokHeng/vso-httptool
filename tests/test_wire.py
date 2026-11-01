import gzip
import unittest

from httpkit.body import dec_enc, enc_chunked
from httpkit.cookie import Jar, parse_set_cookie
from httpkit.err import BodyError, ClientError, HdrError, SecError, UrlError
from httpkit.follow import plan
from httpkit.h1 import Rdr, rd_resp, ser_req
from httpkit.hdr import Hdrs, parse_hdrs
from httpkit.msg import Req, Resp
from httpkit.sec import InfGuard, Lim, is_priv
from httpkit.ua import parse_ua, ua_str
from httpkit.url import parse as pu


class Fk:
    def __init__(self, d):
        self.d = d

    def recv(self, n):
        o, self.d = self.d[:n], self.d[n:]
        return o


def rr(raw, mth="GET", lim=None):
    return rd_resp(Rdr(Fk(raw), lim or Lim()), mth, lim or Lim())


class HdrT(unittest.TestCase):
    def test_crlf(self):
        for v in ("a\r\nX: y", "a\nb", "a\x00b"):
            with self.assertRaises(HdrError):
                Hdrs().add("X", v)
        with self.assertRaises(HdrError):
            Hdrs().add("X Y", "v")

    def test_case(self):
        h = Hdrs([("Content-Type", "a")])
        self.assertEqual(h.get("content-type"), "a")
        h.add("Set-Cookie", "1")
        h.add("set-cookie", "2")
        self.assertEqual(h.get_all("SET-COOKIE"), ["1", "2"])

    def test_fold(self):
        with self.assertRaises(HdrError):
            parse_hdrs(b"A: b\r\n c")

    def test_space_before_colon(self):
        with self.assertRaises(HdrError):
            parse_hdrs(b"A : b")

    def test_count(self):
        with self.assertRaises(HdrError):
            parse_hdrs(b"\r\n".join(b"a%d: b" % i for i in range(300)))


class UrlT(unittest.TestCase):
    def test_bad(self):
        for u in ("file:///etc/passwd", "http://u:p@h/", "http://h\r\nx/", "ftp://h/", "http:///x", "http://h:99999/"):
            with self.assertRaises(UrlError):
                pu(u)

    def test_ok(self):
        u = pu("HTTPS://Example.COM:443/a%20b?q=1")
        self.assertEqual(str(u), "https://example.com/a%20b?q=1")
        with self.assertRaises(UrlError):
            pu("https://example.com/a b")
        self.assertEqual(pu("http://[::1]:8080/").authority, "[::1]:8080")

    def test_idna(self):
        self.assertTrue(pu("https://bücher.example/").host.startswith("xn--"))


class H1T(unittest.TestCase):
    def test_basic(self):
        r, keep = rr(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc")
        self.assertEqual((r.status, r.body, keep), (200, b"abc", True))

    def test_cl_te(self):
        with self.assertRaises(SecError):
            rr(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")

    def test_dup_cl(self):
        with self.assertRaises(SecError):
            rr(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd")

    def test_bad_cl(self):
        for v in (b"-1", b"+3", b"0x3", b"3 3"):
            with self.assertRaises(SecError):
                rr(b"HTTP/1.1 200 OK\r\nContent-Length: " + v + b"\r\n\r\nabc")

    def test_te_obf(self):
        with self.assertRaises(SecError):
            rr(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n")
        with self.assertRaises(SecError):
            rr(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n")

    def test_chunked(self):
        r, _ = rr(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=1\r\nde\r\n0\r\nX-T: 1\r\n\r\n")
        self.assertEqual(r.body, b"abcde")
        self.assertEqual(r.trailers.get("x-t"), "1")

    def test_chunk_bad(self):
        for raw in (b"zz\r\n", b"-1\r\nab\r\n", b"3\r\nabcXX"):
            with self.assertRaises((BodyError, SecError)):
                rr(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + raw)

    def test_status_line(self):
        for raw in (b"HTTP/2 200 OK\r\n\r\n", b"HTTP/1.1 20 OK\r\n\r\n", b"GARBAGE\r\n\r\n", b"HTTP/1.1 200 OK\nX: y\n\n"):
            with self.assertRaises((SecError, Exception)):
                rr(raw)

    def test_hdr_limit(self):
        with self.assertRaises(SecError):
            rr(b"HTTP/1.1 200 OK\r\n" + b"A: " + b"x" * 70000 + b"\r\n\r\n")

    def test_body_limit(self):
        with self.assertRaises(SecError):
            rr(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n" + b"a" * 1000, lim=Lim(max_body=100))

    def test_head_204(self):
        r, _ = rr(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n", "HEAD")
        self.assertEqual(r.body, b"")
        r, _ = rr(b"HTTP/1.1 204 No Content\r\n\r\n")
        self.assertEqual(r.body, b"")

    def test_100_continue(self):
        r, _ = rr(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nz")
        self.assertEqual(r.status, 200)

    def test_ser(self):
        b = ser_req(Req("POST", pu("http://h/p?q=1"), Hdrs([("X", "y")]), b"abc"))
        self.assertTrue(b.startswith(b"POST /p?q=1 HTTP/1.1\r\nX: y\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc"))

    def test_chunk_enc(self):
        self.assertEqual(enc_chunked(b"abc"), b"3\r\nabc\r\n0\r\n\r\n")


class BodyT(unittest.TestCase):
    def test_gzip(self):
        self.assertEqual(dec_enc(gzip.compress(b"hello"), "gzip", 100), b"hello")

    def test_bomb(self):
        with self.assertRaises(BodyError):
            dec_enc(gzip.compress(b"\x00" * (50 << 20)), "gzip", 1 << 20)

    def test_layers(self):
        with self.assertRaises(BodyError):
            dec_enc(b"x", "gzip, gzip, gzip, gzip", 100)

    def test_unknown(self):
        with self.assertRaises(BodyError):
            dec_enc(b"x", "zstd9", 100)


class FakeG(InfGuard):
    def __init__(self, m):
        super().__init__()
        self.m = m

    def resolve(self, host, port):
        return [(2, self.m.get(host, "93.184.216.34"))]


class FollowT(unittest.TestCase):
    def mk(self, mth, url, st, loc, body=b"", hdrs=None):
        rq = Req(mth, pu(url), Hdrs(hdrs or []), body)
        rs = Resp(st, Hdrs([("Location", loc)]))
        return rq, rs

    def test_303(self):
        rq, rs = self.mk("POST", "https://a.com/x", 303, "/y", b"d", [("Content-Type", "t")])
        p = plan(rq, rs, FakeG({}), set(), 10, 0)
        self.assertEqual((p.req.mth, p.req.body, "content-type" in p.req.hdrs), ("GET", b"", False))

    def test_307_keeps(self):
        rq, rs = self.mk("POST", "https://a.com/x", 307, "/y", b"d")
        p = plan(rq, rs, FakeG({}), set(), 10, 0)
        self.assertEqual((p.req.mth, p.req.body), ("POST", b"d"))

    def test_xo_strip(self):
        rq, rs = self.mk("GET", "https://a.com/x", 302, "https://b.com/", hdrs=[("Authorization", "t"), ("Cookie", "c=1"), ("X-A", "1")])
        p = plan(rq, rs, FakeG({}), set(), 10, 0)
        self.assertEqual([k for k, _ in p.req.hdrs], ["X-A"])

    def test_downgrade(self):
        rq, rs = self.mk("GET", "https://a.com/x", 302, "http://a.com/")
        with self.assertRaises(SecError):
            plan(rq, rs, FakeG({}), set(), 10, 0)

    def test_private(self):
        rq, rs = self.mk("GET", "https://a.com/x", 302, "http://internal/")
        with self.assertRaises(SecError):
            plan(rq, rs, FakeG({"internal": "10.0.0.5", "a.com": "93.184.216.34"}), set(), 10, 0)
        rq, rs = self.mk("GET", "https://a.com/x", 302, "https://meta/")
        with self.assertRaises(SecError):
            plan(rq, rs, FakeG({"meta": "169.254.169.254"}), set(), 10, 0)

    def test_loop_and_hops(self):
        rq, rs = self.mk("GET", "https://a.com/x", 302, "/x")
        seen = set()
        plan(rq, rs, FakeG({}), seen, 10, 0)
        with self.assertRaises(ClientError):
            plan(rq, rs, FakeG({}), seen, 10, 1)
        with self.assertRaises(ClientError):
            plan(rq, rs, FakeG({}), set(), 3, 3)

    def test_scheme(self):
        rq, rs = self.mk("GET", "https://a.com/x", 302, "file:///etc/passwd")
        with self.assertRaises(ClientError):
            plan(rq, rs, FakeG({}), set(), 10, 0)

    def test_is_priv(self):
        for a in ("127.0.0.1", "10.1.1.1", "192.168.0.1", "169.254.169.254", "::1", "fe80::1", "::ffff:127.0.0.1", "100.64.0.1"):
            self.assertTrue(is_priv(a), a)
        self.assertFalse(is_priv("93.184.216.34"))


class CookieT(unittest.TestCase):
    def test_match(self):
        j = Jar()
        u = pu("https://a.example.com/p/q")
        j.put(u, ["a=1; Path=/", "b=2; Domain=example.com; Secure", "c=3; Path=/zzz"])
        self.assertEqual(j.hdr_for(pu("https://a.example.com/p")), "b=2; a=1")
        self.assertEqual(j.hdr_for(pu("http://a.example.com/p")), "a=1")
        self.assertEqual(j.hdr_for(pu("https://other.com/")), None)

    def test_rejects(self):
        u = pu("https://a.example.com/")
        self.assertIsNone(parse_set_cookie("x=1; Domain=com", u))
        self.assertIsNone(parse_set_cookie("x=1; Domain=other.com", u))
        self.assertIsNone(parse_set_cookie("__Host-x=1; Path=/", u))
        self.assertIsNone(parse_set_cookie("x=1; Secure", pu("http://a.example.com/")))
        self.assertIsNone(parse_set_cookie("x=1\r\nSet-Cookie: y=2", u))

    def test_expire(self):
        j = Jar()
        u = pu("https://a.com/")
        j.put(u, ["a=1; Max-Age=100"], now=1000)
        self.assertIsNotNone(j.hdr_for(u, now=1050))
        self.assertIsNone(j.hdr_for(u, now=1200))
        j.put(u, ["a=1; Max-Age=0"], now=1000)

    def test_cap(self):
        j = Jar(max_n=5)
        u = pu("https://a.com/")
        for i in range(20):
            j.put(u, ["k%d=v" % i])
        self.assertLessEqual(len(j.c), 5)


class UaT(unittest.TestCase):
    def test_roundtrip(self):
        s = ua_str("vso", "2.0", ["Linux", "x"], [("Extra", "1")])
        d = parse_ua(s)
        self.assertEqual(d["products"], [("vso", "2.0"), ("Extra", "1")])
        self.assertEqual(d["comments"], ["Linux; x"])


if __name__ == "__main__":
    unittest.main()
