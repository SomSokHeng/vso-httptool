import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def cp():
    d = tempfile.mkdtemp()
    shutil.copytree(os.path.join(ROOT, "httpkit"), os.path.join(d, "httpkit"), ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(os.path.join(ROOT, "tools"), os.path.join(d, "tools"), ignore=shutil.ignore_patterns("__pycache__"))
    return d


def run(d, code):
    return subprocess.run([sys.executable, "-c", code], cwd=d, env=dict(os.environ, PYTHONPATH=d), capture_output=True, text=True, timeout=60)


def edit(p, a, b):
    with open(p) as f:
        s = f.read()
    assert a in s
    with open(p, "w") as f:
        f.write(s.replace(a, b, 1))


class SealT(unittest.TestCase):
    def test_clean(self):
        d = cp()
        r = run(d, "import httpkit;print(httpkit.__license__)")
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "MIT"))
        self.assertEqual(r.stderr, "")

    def test_tamper_any_module(self):
        for n in ("client.py", "h2.py", "quic.py", "__init__.py", "_vso.py"):
            d = cp()
            with open(os.path.join(d, "httpkit", n), "a") as f:
                f.write("\nx = 1\n")
            r = run(d, "import httpkit")
            self.assertNotEqual(r.returncode, 0, n)
            self.assertIn("integrity check failed", r.stderr, n)

    def test_tamper_notice(self):
        d = cp()
        edit(os.path.join(d, "httpkit", "_vso.py"), 'VSO_AUTHOR = "Vso (InfinityNet)"', 'VSO_AUTHOR = "Someone Else"')
        self.assertNotEqual(run(d, "import httpkit").returncode, 0)

    def test_tamper_seal_files(self):
        d = cp()
        edit(os.path.join(d, "httpkit", "_seal.py"), "'client.py': '", "'client.py': '0")
        self.assertNotEqual(run(d, "import httpkit").returncode, 0)
        d = cp()
        edit(os.path.join(d, "httpkit", "_vso.py"), 'VSO_ROOT = "', 'VSO_ROOT = "0')
        self.assertNotEqual(run(d, "import httpkit").returncode, 0)

    def test_reseal(self):
        d = cp()
        with open(os.path.join(d, "httpkit", "ua.py"), "a") as f:
            f.write("\nmine = 1\n")
        self.assertNotEqual(run(d, "import httpkit").returncode, 0)
        self.assertEqual(run(d, "import runpy;runpy.run_path('tools/seal.py', run_name='__main__')").returncode, 0)
        self.assertEqual(run(d, "import httpkit").returncode, 0)

    def test_crlf_stable(self):
        d = cp()
        for n in os.listdir(os.path.join(d, "httpkit")):
            if n.endswith(".py"):
                p = os.path.join(d, "httpkit", n)
                with open(p, "rb") as f:
                    b = f.read()
                with open(p, "wb") as f:
                    f.write(b.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
        self.assertEqual(run(d, "import httpkit").returncode, 0)

    def test_warning_on_use(self):
        r = run(ROOT, "from httpkit import Client\nClient()\nClient()")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stderr.count("illegal activity"), 1)
        self.assertIn("License: MIT", r.stderr)

    def test_cli_stdout_clean(self):
        r = subprocess.run([sys.executable, "-m", "httpkit", "ua", "a/1 (b)"], cwd=ROOT, env=dict(os.environ, PYTHONPATH=ROOT), capture_output=True, text=True, timeout=60)
        self.assertIn("illegal activity", r.stderr)
        self.assertNotIn("illegal", r.stdout)
        self.assertIn("product  a/1", r.stdout)

    def test_license_file(self):
        with open(os.path.join(ROOT, "LICENSE")) as f:
            self.assertTrue(f.read().startswith("MIT License"))


if __name__ == "__main__":
    unittest.main()
