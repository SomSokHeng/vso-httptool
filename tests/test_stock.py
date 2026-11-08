import http.server
import os
import subprocess
import sys
import tempfile
import threading
import unittest

from httpkit import InfGuard, ProxyError
from httpkit.stock import VSO_STOCK_SRC, fetch_stock, vso_stock_max, write_stock_file

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Hdl(http.server.BaseHTTPRequestHandler):
    PAGES = {
        "/http.txt": "1.2.3.4:8080\n5.6.7.8:3128\n# comment\n\nbad line here\nnotanip\n1.2.3.4:8080\n",
        "/socks5.txt": "9.9.9.9:1080\nuser:pass@10.0.0.1:1080\n" + "\n".join("10.1.%d.%d:1080" % (i // 256, i % 256) for i in range(5000)),
        "/junk.txt": "1.1.1.1:80\nsocks5://2.2.2.2:1080\nhttp://3.3.3.3\nfoo\n4.4.4.4\nhost:notaport\n5.5.5.5:99999999\nhttp://\n<html>x</html>\n",
        "/empty.txt": "",
        "/404.txt": None,
        "/big.txt": "x" * (5 << 20),
        "/many1.txt": "\n".join("10.%d.%d.1:1080" % (i // 256, i % 256) for i in range(3000)),
        "/many2.txt": "\n".join("11.%d.%d.1:1080" % (i // 256, i % 256) for i in range(3000)),
        "/many3.txt": "\n".join("12.%d.%d.1:1080" % (i // 256, i % 256) for i in range(3000)),
    }

    def do_GET(self):
        body = self.PAGES.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


def cli(args, tmo=60):
    return subprocess.run([sys.executable, "-m", "httpkit"] + args, cwd=ROOT, env=dict(os.environ, PYTHONPATH=ROOT),
                           capture_output=True, text=True, timeout=tmo)


class StockT(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Hdl)
        cls.port = cls.srv.server_address[1]
        cls.th = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.th.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def u(self, p):
        return "http://127.0.0.1:%d%s" % (self.port, p)

    def test_real_source_list_shape(self):
        self.assertGreater(len(VSO_STOCK_SRC), 10)
        for name, url, proto in VSO_STOCK_SRC:
            self.assertTrue(url.startswith("https://raw.githubusercontent.com/"), url)
            self.assertIn(proto, ("http", "https", "socks4", "socks5"))
        self.assertEqual(len({n for n, _, _ in VSO_STOCK_SRC}), len(VSO_STOCK_SRC))
        self.assertEqual(len({u for _, u, _ in VSO_STOCK_SRC}), len(VSO_STOCK_SRC))

    def test_parse_dedup_malformed_skipped(self):
        srcs = [("a", self.u("/http.txt"), "http")]
        items, rep = fetch_stock(srcs=srcs, guard=InfGuard(blk_priv=False), tmo=5)
        self.assertEqual(len(items), 2)
        self.assertEqual({p.scheme for p in items}, {"http"})
        self.assertEqual(sorted((p.host, p.port) for p in items), [("1.2.3.4", 8080), ("5.6.7.8", 3128)])
        self.assertEqual(rep["ok"], 1)
        self.assertEqual(rep["sources"]["a"], 2)

    def test_scheme_and_auth_preserved(self):
        srcs = [("b", self.u("/socks5.txt"), "socks5")]
        items, rep = fetch_stock(srcs=srcs, guard=InfGuard(blk_priv=False), tmo=10)
        auth = [p for p in items if p.usr == "user"]
        self.assertEqual(len(auth), 1)
        self.assertEqual(auth[0].pwd, "pass")
        self.assertTrue(all(p.scheme == "socks5" for p in items))

    def test_per_source_cap(self):
        srcs = [("b", self.u("/socks5.txt"), "socks5")]
        items, rep = fetch_stock(srcs=srcs, guard=InfGuard(blk_priv=False), tmo=10)
        self.assertLessEqual(len(items), 3000)

    def test_global_cap(self):
        srcs = [("b%d" % i, self.u("/socks5.txt").replace("127.0.0.1", "127.0.0.1") + ("?x=%d" % i if i else ""), "socks5") for i in range(3)]
        items, rep = fetch_stock(srcs=srcs, guard=InfGuard(blk_priv=False), tmo=15)
        self.assertLessEqual(len(items), vso_stock_max)

    def test_bad_source_skipped_not_fatal(self):
        srcs = [("ok", self.u("/http.txt"), "http"), ("missing", self.u("/404.txt"), "http"), ("empty", self.u("/empty.txt"), "http")]
        items, rep = fetch_stock(srcs=srcs, guard=InfGuard(blk_priv=False), tmo=5)
        self.assertEqual(len(items), 2)
        self.assertEqual(rep["ok"], 2)
        self.assertEqual(rep["fail"], 1)
        self.assertIn("error", rep["sources"]["missing"])

    def test_body_cap_rejects_oversized(self):
        srcs = [("huge", self.u("/big.txt"), "http"), ("ok", self.u("/http.txt"), "http")]
        items, rep = fetch_stock(srcs=srcs, guard=InfGuard(blk_priv=False), tmo=10)
        self.assertEqual(len(items), 2)
        self.assertEqual(rep["fail"], 1)
        self.assertIn("error", rep["sources"]["huge"])
        with self.assertRaises(ProxyError):
            fetch_stock(srcs=srcs[:1], guard=InfGuard(blk_priv=False), tmo=10)

    def test_junk_lines_need_explicit_port(self):
        srcs = [("a", self.u("/junk.txt"), "http")]
        items, rep = fetch_stock(srcs=srcs, guard=InfGuard(blk_priv=False), tmo=5)
        self.assertEqual(sorted((p.scheme, p.host, p.port) for p in items), [("http", "1.1.1.1", 80), ("socks5", "2.2.2.2", 1080)])

    def test_all_sources_fail_raises(self):
        srcs = [("missing", self.u("/404.txt"), "http")]
        with self.assertRaises(ProxyError):
            fetch_stock(srcs=srcs, guard=InfGuard(blk_priv=False), tmo=5)

    def test_proto_filter(self):
        with self.assertRaises(ProxyError):
            fetch_stock(proto="ftp", srcs=[("a", self.u("/http.txt"), "http")], guard=InfGuard(blk_priv=False))
        items, _ = fetch_stock(proto=["http"], srcs=[("a", self.u("/http.txt"), "http"), ("b", self.u("/socks5.txt"), "socks5")], guard=InfGuard(blk_priv=False), tmo=10)
        self.assertTrue(all(p.scheme == "http" for p in items))

    def test_write_stock_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sub", "stock.txt")
            srcs = [("a", self.u("/http.txt"), "http")]
            got, items, rep = write_stock_file(path=path, srcs=srcs, guard=InfGuard(blk_priv=False), tmo=5)
            self.assertEqual(got, path)
            txt = open(path, encoding="utf-8").read()
            self.assertIn("http://1.2.3.4:8080", txt)
            self.assertIn("unreliable", txt)
            self.assertNotIn("http://1.2.3.4:8080\nhttp://1.2.3.4:8080", txt)

    def test_no_health_check(self):
        srcs = [("a", self.u("/socks5.txt"), "socks5")]
        items, _ = fetch_stock(srcs=srcs, guard=InfGuard(blk_priv=False), tmo=5)
        self.assertTrue(any(p.host == "9.9.9.9" for p in items))

    def test_cli_stock_warning_and_fetch(self):
        r = cli(["-sp", "--stock-proto", "http", "-v", self.u("/http.txt").replace(self.u("/http.txt"), "http://127.0.0.1:1/")])
        self.assertIn("free, public, unreliable and untrusted", r.stderr)

    def test_cli_stock_conflicts(self):
        r = cli(["-sp", "--proxy", "http://1.2.3.4:8080", "http://127.0.0.1:1/"], 10)
        self.assertEqual(r.returncode, 1)
        self.assertIn("cannot combine", r.stderr)
        r = cli(["-sp", "--h3", "http://127.0.0.1:1/"], 10)
        self.assertEqual(r.returncode, 1)
        self.assertIn("cannot be used through a proxy", r.stderr)


if __name__ == "__main__":
    unittest.main()
