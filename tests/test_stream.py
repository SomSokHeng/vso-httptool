import asyncio
import http.server
import json
import math
import os
import subprocess
import sys
import threading
import time
import unittest

try:
    import cryptography.x509
    import hypercorn.config
    from lab import Srv
    OK = bool(cryptography.x509 and hypercorn.config)
except Exception:
    OK = False

from httpkit import AsyncClient, Client, ClientError, InfGuard, InfStream, Jar, Lim
from httpkit.stream import InfRate, InfStats, parse_speed, vso_speeds
from httpkit.url import parse as parse_url

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Hdl(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = b'{"ok":1}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


def cli(args, tmo=120):
    return subprocess.run([sys.executable, "-m", "httpkit"] + args, cwd=ROOT, env=dict(os.environ, PYTHONPATH=ROOT), capture_output=True, text=True, timeout=tmo)


class SpeedT(unittest.TestCase):
    def test_names(self):
        for k, v in vso_speeds.items():
            self.assertEqual(parse_speed(k), v)
        self.assertEqual(parse_speed("MEDIUM"), vso_speeds["medium"])
        self.assertLessEqual(max(v[0] for v in vso_speeds.values()), 50)

    def test_rate(self):
        self.assertEqual(parse_speed("30"), (15, 30.0))
        self.assertEqual(parse_speed(0.5), (1, 0.5))
        self.assertEqual(parse_speed("200"), (50, 200.0))

    def test_bad(self):
        for v in ("abc", "", "0", "-5", "0.01", "201", "1e9", "nan", "inf", None, [], True and "x"):
            with self.assertRaises(ClientError, msg=repr(v)):
                parse_speed(v)

    def test_thread_caps(self):
        for n in (0, -1, 51, 1000, True, 2.5, "9"):
            with self.assertRaises(ClientError, msg=repr(n)):
                InfStream("http://127.0.0.1/", threads=n)
            with self.assertRaises(ClientError, msg=repr(n)):
                AsyncClient(workers=n)
        InfStream("http://127.0.0.1/", threads=50)
        AsyncClient(workers=50)

    def test_arg_caps(self):
        for kw in ({"n": 0}, {"n": 10 ** 9 + 1}, {"n": True}, {"dur": 0}, {"dur": -1}, {"dur": 10 ** 9}, {"dur": float("nan")}, {"dur": "x"}, {"mth": "G ET"}, {"mth": "GET\r\nX: 1"}, {"mth": ""}):
            with self.assertRaises(ClientError, msg=repr(kw)):
                InfStream("http://127.0.0.1/", **kw)

    def test_bad_url(self):
        with self.assertRaises(Exception):
            InfStream("file:///etc/passwd")
        with self.assertRaises(Exception):
            InfStream("http://exa mple.com/")


class StatsT(unittest.TestCase):
    def test_bounded(self):
        st = InfStats()

        class R:
            body = b"abc"
            proto = "h2"
            status = 200
        for i in range(60000):
            st.add_res(R, float(i % 97))
            st.add_err(ValueError("e%d" % i))
        self.assertLessEqual(len(st.lat), 2048)
        self.assertLessEqual(len(st.errs), 21)
        self.assertEqual(st.sent, 120000)
        d = st.as_dict()
        self.assertEqual(d["ok"], 60000)
        self.assertEqual(d["fail"], 60000)
        json.dumps(d)

    def test_err_text_clean(self):
        st = InfStats()
        st.add_err(ValueError("a\x1b[31mred\r\nX: y\x00"))
        k = next(iter(st.errs))
        self.assertNotRegex(k, r"[\x00-\x1f\x7f]")

    def test_pct_empty(self):
        d = InfStats().as_dict()
        self.assertIsNone(d["lat_ms"]["p50"])
        InfStats().text()


class RateT(unittest.TestCase):
    def test_pace(self):
        async def go():
            rl = InfRate(50.0)
            t0 = time.monotonic()
            await asyncio.gather(*[rl.wait() for _ in range(11)])
            return time.monotonic() - t0
        el = asyncio.run(go())
        self.assertGreaterEqual(el, 0.18)
        self.assertLess(el, 1.0)

    def test_no_burst_after_idle(self):
        async def go():
            rl = InfRate(20.0)
            await rl.wait()
            await asyncio.sleep(0.5)
            t0 = time.monotonic()
            await asyncio.gather(*[rl.wait() for _ in range(5)])
            return time.monotonic() - t0
        self.assertGreaterEqual(asyncio.run(go()), 0.15)


class ThreadSafeT(unittest.TestCase):
    def test_guard_and_jar(self):
        import socket
        g = InfGuard()
        orig = socket.getaddrinfo
        socket.getaddrinfo = lambda h, p, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.%d" % (hash(h) % 200 + 1), p))]
        errs = []
        j = Jar()

        def wg(k):
            for i in range(1500):
                try:
                    g.resolve("h%d-%d.example" % (k, i), 443)
                    u = parse_url("https://h%d.example/p" % (i % 40))
                    j.put(u, ["a%d=%d; Path=/" % (i, k)])
                    j.hdr_for(u)
                except Exception as e:
                    errs.append(repr(e))
        try:
            ts = [threading.Thread(target=wg, args=(k,)) for k in range(40)]
            [t.start() for t in ts]
            [t.join() for t in ts]
        finally:
            socket.getaddrinfo = orig
        self.assertEqual(errs, [])
        self.assertLessEqual(len(g.cache), 256)
        self.assertLessEqual(len(j.c), j.max_n)


class PlainH1T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Hdl)
        cls.port = cls.srv.server_address[1]
        cls.th = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.th.start()
        cls.url = "http://127.0.0.1:%d/" % cls.port

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_auto_h1_stream(self):
        s = InfStream(self.url, speed="200", n=150, guard=InfGuard(blk_priv=False), tmo=5)
        st = asyncio.run(s.run())
        self.assertEqual((st.sent, st.ok, st.fail), (150, 150, 0))
        self.assertEqual(dict(st.protos), {"http/1.1": 150})
        self.assertEqual(st.stop_why, "count reached")

    def test_async_gather_50(self):
        async def go():
            async with AsyncClient(workers=50, guard=InfGuard(blk_priv=False), tmo=5) as ac:
                return await ac.gather([self.url + "?i=%d" % i for i in range(200)])
        rs = asyncio.run(go())
        self.assertEqual(len(rs), 200)
        self.assertTrue(all(r.status == 200 and r.proto == "http/1.1" for r in rs))

    def test_imap_window(self):
        async def go():
            out = []
            async with AsyncClient(workers=8, guard=InfGuard(blk_priv=False), tmo=5) as ac:
                async for r in ac.imap((self.url + "?i=%d" % i for i in range(120)), win=10):
                    out.append(r)
            return out
        rs = asyncio.run(go())
        self.assertEqual(len(rs), 120)
        self.assertTrue(all(getattr(r, "status", 0) == 200 for r in rs))

    def test_gather_exc(self):
        async def go():
            async with AsyncClient(workers=4, guard=InfGuard(blk_priv=False), tmo=3) as ac:
                return await ac.gather([self.url, "http://127.0.0.1:1/"], exc=True)
        a, b = asyncio.run(go())
        self.assertEqual(a.status, 200)
        self.assertIsInstance(b, Exception)

    def test_closed_client(self):
        async def go():
            ac = AsyncClient(workers=2, guard=InfGuard(blk_priv=False))
            await ac.aclose()
            await ac.aclose()
            await ac.get(self.url)
        with self.assertRaises(ClientError):
            asyncio.run(go())

    def test_duration_stop(self):
        s = InfStream(self.url, speed="50", dur=1.5, guard=InfGuard(blk_priv=False), tmo=5)
        t0 = time.monotonic()
        st = asyncio.run(s.run())
        self.assertLess(time.monotonic() - t0, 5)
        self.assertEqual(st.stop_why, "duration reached")
        self.assertGreater(st.ok, 30)
        self.assertLess(st.ok, 120)

    def test_max_fail_stop(self):
        s = InfStream("http://127.0.0.1:1/", speed="200", max_fail=5, guard=InfGuard(blk_priv=False), tmo=2)
        st = asyncio.run(s.run())
        self.assertEqual(st.stop_why, "5 consecutive failures")
        self.assertGreaterEqual(st.fail, 5)
        self.assertLess(st.fail, 80)
        self.assertEqual(st.ok, 0)

    def test_cli_stream(self):
        r = cli(["--auto", "--stream", "fast", "-n", "120", "--priv", self.url])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("[stream] done", r.stderr)
        self.assertIn("sent=120 ok=120", r.stderr)
        self.assertEqual(r.stdout, "")

    def test_cli_stream_json(self):
        r = cli(["--stream", "100", "-n", "50", "--threads", "5", "--feedback-json", "--priv", self.url])
        self.assertEqual(r.returncode, 0, r.stderr)
        d = json.loads(r.stderr.strip().splitlines()[-1])
        self.assertEqual((d["sent"], d["ok"]), (50, 50))

    def test_cli_rejects(self):
        for a in (["--stream", "medium", "--threads", "51"], ["--stream", "999"], ["--stream", "nope"], ["--stream", "slow", "--duration", "-3"],
                  ["--stream", "slow", "--threads", "x"], ["--stream", "slow", "-I"], ["--stream", "slow", "-o", "/tmp/x"], ["--stream", "slow", "-n", "0"]):
            r = cli(a + ["--priv", self.url], 30)
            self.assertEqual(r.returncode, 1, (a, r.stderr))
            self.assertNotIn("Traceback", r.stderr)

    def test_cli_n_cap_without_stream(self):
        r = cli(["-n", "3", "--priv", self.url], 30)
        self.assertEqual(r.returncode, 0, r.stderr)


@unittest.skipUnless(OK, "needs cryptography and hypercorn[h3]")
class LiveStreamT(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = Srv().__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.s.__exit__()

    def url(self, h3=False, p="/echo"):
        return "https://localhost:%d%s" % (self.s.qp if h3 else self.s.tp, p)

    def gather(self, proto, h3=False, n=200, w=50):
        async def go():
            async with AsyncClient(workers=w, proto=proto, ca=self.s.ca, h3=False, guard=InfGuard(blk_priv=False), tmo=15) as ac:
                return await ac.gather([self.url(h3) + "?i=%d" % i for i in range(n)])
        return asyncio.run(go())

    def test_async_h1(self):
        rs = self.gather("h1")
        self.assertTrue(all(r.status == 200 and r.proto == "http/1.1" for r in rs))

    def test_async_h2(self):
        rs = self.gather("h2")
        self.assertTrue(all(r.status == 200 and r.proto == "h2" for r in rs))
        self.assertEqual(sorted(r.json()["qs"] for r in rs), sorted("i=%d" % i for i in range(200)))

    def test_async_h3(self):
        rs = self.gather("h3", True)
        self.assertTrue(all(r.status == 200 and r.proto == "h3" for r in rs))

    def test_stream_each_level(self):
        for proto, h3 in (("h1", False), ("h2", False), ("h3", True)):
            s = InfStream(self.url(h3), speed="fast", n=300, proto=proto, ca=self.s.ca, h3=False, guard=InfGuard(blk_priv=False), tmo=15)
            st = asyncio.run(s.run())
            self.assertEqual((st.sent, st.ok, st.fail), (300, 300, 0), proto)
            want = {"h1": "http/1.1"}.get(proto, proto)
            self.assertEqual(dict(st.protos), {want: 300})

    def test_stream_auto_upgrades_to_h3(self):
        s = InfStream(self.url(), speed="fast", n=300, proto="auto", ca=self.s.ca, guard=InfGuard(blk_priv=False), tmo=15)
        st = asyncio.run(s.run())
        self.assertEqual((st.sent, st.ok, st.fail), (300, 300, 0))
        self.assertEqual(st.protos["h2"], 1)
        self.assertEqual(st.protos["h3"], 299)

    def test_stream_big_body_limit(self):
        s = InfStream(self.url(p="/big"), speed="20", n=5, proto="h2", ca=self.s.ca, guard=InfGuard(blk_priv=False), lim=Lim(max_body=1 << 20), tmo=15)
        st = asyncio.run(s.run())
        self.assertEqual(st.ok, 0)
        self.assertEqual(st.fail, 5)

    def test_cli_each_level(self):
        for fl, h3, want in (("--h1", False, "http/1.1=200"), ("--h2", False, "h2=200"), ("--h3", True, "h3=200")):
            r = cli([fl, "--stream", "fast", "--threads", "50", "-n", "200", "--cacert", self.s.ca, "--priv", self.url(h3)])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn(want, r.stderr)


if __name__ == "__main__":
    unittest.main()
