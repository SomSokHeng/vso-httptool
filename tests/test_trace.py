import contextlib
import io
import json
import os
import subprocess
import sys
import unittest

from httpkit import Client, ClientError, ConnError, ProxyError, SecError, Trace, fb_err, fb_json, fb_res, fb_text, parse_proxy
from httpkit.trace import fmt_ev
from pxlab import Px, Tgt, dead_port

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def cli(*a):
    return subprocess.run([sys.executable, "-m", "httpkit"] + list(a), cwd=ROOT, env=dict(os.environ, PYTHONPATH=ROOT), capture_output=True, text=True, timeout=90)


class FormatT(unittest.TestCase):
    def test_proxy_formats(self):
        p = parse_proxy("10.0.0.1:8080:bob:s3cret")
        self.assertEqual((p.scheme, p.host, p.port, p.usr, p.pwd), ("http", "10.0.0.1", 8080, "bob", "s3cret"))
        p = parse_proxy("bob:s3cret@10.0.0.1:8080")
        self.assertEqual((p.scheme, p.usr, p.pwd, p.port), ("http", "bob", "s3cret", 8080))
        p = parse_proxy("10.0.0.1:8080:bob:p@ss:w")
        self.assertEqual((p.usr, p.pwd), ("bob", "p@ss:w"))
        p = parse_proxy("  proxy.example.com:3128  ")
        self.assertEqual((p.host, p.port, p.usr), ("proxy.example.com", 3128, None))
        p = parse_proxy("https://u:p@h.example:443")
        self.assertEqual((p.scheme, p.usr), ("https", "u"))
        self.assertNotIn("s3cret", repr(parse_proxy("10.0.0.1:8080:bob:s3cret")))

    def test_ctl_sanitized(self):
        tr = Trace()
        e = tr.add("x", "evil \x1b[31mred\x07")
        self.assertNotIn("\x1b", fmt_ev(e))


class SchemeMapT(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = Tgt()

    @classmethod
    def tearDownClass(cls):
        cls.t.close()

    def test_http_and_https_proxies_are_separate(self):
        a = Px("http")
        b = Px("http", deny=True)
        with Client(proxies={"http": a.url(), "https": b.url()}, h3=False) as c:
            r = c.get(self.t.url("/m"))
            self.assertEqual((r.status, r.proxy), (200, a.url()))
            with self.assertRaises(ProxyError):
                c.get("https://127.0.0.1:1/")
        self.assertEqual(len(a.seen), 1)
        self.assertEqual(b.seen[0], ("CONNECT", "127.0.0.1:1"))
        a.close()
        b.close()

    def test_only_http_key_leaves_https_direct(self):
        a = Px("http")
        with Client(proxies={"http": [a.url()]}, h3=False, tmo=3) as c:
            with self.assertRaises(ConnError) as cm:
                c.get("https://127.0.0.1:%d/" % dead_port())
            self.assertNotIsInstance(cm.exception, ProxyError)
        self.assertEqual(a.seen, [])
        a.close()

    def test_rotation_inside_scheme_list(self):
        a, b = Px("http"), Px("http")
        with Client(proxies={"http": [a.url(), b.url()]}, h3=False) as c:
            ps = [c.get(self.t.url()).proxy for _ in range(4)]
        self.assertEqual(ps, [a.url(), b.url(), a.url(), b.url()])
        a.close()
        b.close()

    def test_bad_key(self):
        with self.assertRaises(ProxyError):
            Client(proxies={"ftp": "http://h:1"})


class TraceT(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = Tgt()

    @classmethod
    def tearDownClass(cls):
        cls.t.close()

    def test_events_and_timing(self):
        ev = []
        with Client(verbose=ev.append, h3=False) as c:
            r = c.get(self.t.url("/x"))
        kinds = [e["kind"] for e in ev]
        for k in ("req", "dns", "tcp", "conn", "resp"):
            self.assertIn(k, kinds)
        self.assertTrue(all({"t", "kind", "msg", "bad"} <= set(e) for e in ev))
        for k in ("dns", "tcp", "ttfb", "total"):
            self.assertIn(k, r.tm)
        self.assertIs(r.trace.ev[0]["kind"] == "req", True)

    def test_silent_by_default_and_stderr_when_verbose(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            with Client(h3=False) as c:
                c.get(self.t.url())
        self.assertNotIn("req", buf.getvalue().replace("[vso-httptool]", ""))
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            with Client(h3=False, verbose=True) as c:
                c.get(self.t.url())
        self.assertIn("resp", buf.getvalue())

    def test_feedback_success(self):
        with Client(h3=False, uas=["Z/9"]) as c:
            r = c.get(self.t.url("/f"))
            fb = r.feedback()
            self.assertEqual((fb["request"]["status"], fb["request"]["ua"]), (200, "Z/9"))
            self.assertIn("ttfb", fb["timing_ms"])
            self.assertEqual(fb["response"]["bytes"], len(r.body))
            json.loads(fb_json(fb))
            txt = r.feedback(text=True)
            self.assertIn("== feedback", txt)
            self.assertIn("timing", txt)
            self.assertEqual(c.feedback(r)["request"]["status"], 200)
            self.assertIn("== feedback", c.feedback(r, text=True, events=True))
            self.assertEqual(fb_res(r)["request"]["url"], fb["request"]["url"])

    def test_problems_for_error_status(self):
        with Client(h3=False) as c:
            r = c.get(self.t.url("/x"))
            self.assertEqual(r.feedback()["problems"], [])
        px = Px("http", "u", "p")
        with Client(proxy="http://127.0.0.1:%d" % px.port, h3=False) as c:
            r = c.get(self.t.url())
            self.assertEqual(r.status, 407)
            self.assertTrue(any("407" in m for m in r.feedback()["problems"]))
        px.close()

    def test_notes_plain_http_via_proxy(self):
        px = Px("http")
        with Client(proxy=px.url(), h3=False) as c:
            fb = c.get(self.t.url()).feedback()
        self.assertTrue(any("proxy can read" in n for n in fb["notes"]))
        px.close()

    def test_failure_dead_proxy(self):
        dead = "http://127.0.0.1:%d" % dead_port()
        with Client(proxy=dead, h3=False) as c:
            with self.assertRaises(ProxyError) as cm:
                c.get(self.t.url())
        e = cm.exception
        self.assertTrue(e.vso_trace.prob)
        fb = fb_err(e)
        self.assertEqual(fb["stage"], "proxy")
        self.assertIn("does not skip dead proxies", fb["hint"])
        self.assertIn("== feedback", fb_text(fb))
        self.assertEqual(fb["error"], "ProxyError")

    def test_failure_dns(self):
        with Client(h3=False) as c:
            with self.assertRaises(SecError) as cm:
                c.get("http://no-such-host.invalid/")
        fb = fb_err(cm.exception)
        self.assertEqual(fb["stage"], "dns")
        self.assertIn("DNS", fb["hint"])

    def test_failure_refused_and_timeout_hints(self):
        with Client(h3=False, tmo=3) as c:
            with self.assertRaises(ConnError) as cm:
                c.get("http://127.0.0.1:%d/" % dead_port())
        fb = fb_err(cm.exception)
        self.assertEqual(fb["stage"], "tcp")
        self.assertIn("listening", fb["hint"])

    def test_failure_input_and_proxy_type(self):
        with Client(h3=False) as c:
            with self.assertRaises(Exception) as cm:
                c.get("file:///etc/passwd")
        self.assertEqual(fb_err(cm.exception)["stage"], "input")
        with self.assertRaises(ClientError) as cm:
            Client(proto="h3", proxy="http://h:1")
        self.assertEqual(fb_err(cm.exception)["stage"], "client")


class CliT(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = Tgt()

    @classmethod
    def tearDownClass(cls):
        cls.t.close()

    def test_verbose_live_events_body_on_stdout(self):
        r = cli("-v", self.t.url("/v"))
        self.assertEqual(r.returncode, 0, r.stderr)
        for k in ("req", "dns", "tcp", "resp"):
            self.assertIn(k, r.stderr)
        self.assertIn('"path": "/v"', r.stdout)
        self.assertNotIn("resp ", r.stdout)

    def test_fb_text_and_json(self):
        r = cli("-fb", self.t.url())
        self.assertIn("== feedback", r.stderr)
        self.assertNotIn("== feedback", r.stdout)
        r = cli("--feedback-json", self.t.url())
        data = json.loads(r.stderr[r.stderr.index("{"):])
        self.assertEqual(data["request"]["status"], 200)

    def test_failure_details_only_when_asked(self):
        dead = "http://127.0.0.1:%d" % dead_port()
        r = cli("--proxy", dead, self.t.url())
        self.assertEqual(r.returncode, 1)
        self.assertIn("re-run with -v", r.stderr)
        self.assertNotIn("hint", r.stderr)
        r = cli("-v", "--proxy", dead, self.t.url())
        self.assertIn("hint", r.stderr)
        self.assertIn("stage 'proxy'", r.stderr)
        self.assertIn("== problems", r.stderr)
        r = cli("-fb", "--proxy", dead, self.t.url())
        self.assertIn("hint", r.stderr)

    def test_repeat_continues_after_failure(self):
        good = Px("http")
        dead = "http://127.0.0.1:%d" % dead_port()
        r = cli("-v", "-n", "4", "--proxy", dead, "--proxy", good.url(), self.t.url())
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stderr.count("resp     200"), 2)
        self.assertEqual(r.stderr.count("failed"), r.stderr.count("failed"))
        self.assertIn('"path"', r.stdout)
        good.close()

    def test_scheme_proxy_flags(self):
        a = Px("http")
        r = cli("-v", "--proxy-http", a.url(), self.t.url())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("via " + a.url(), r.stderr)
        a.close()


if __name__ == "__main__":
    unittest.main()
