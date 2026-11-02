import os
import subprocess
import sys
import tempfile
import unittest
import venv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.environ.get("VSO_TEST_INSTALL") == "1"


def run(py, *a):
    return subprocess.run([py, os.path.join(ROOT, "install.py")] + list(a), cwd=tempfile.gettempdir(), capture_output=True, text=True, timeout=300)


class InstallT(unittest.TestCase):
    def test_help(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "install.py"), "--help"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("--uninstall", r.stdout)

    @unittest.skipUnless(GATE, "set VSO_TEST_INSTALL=1 (needs network for pip build isolation)")
    def test_cycle(self):
        d = tempfile.mkdtemp()
        venv.create(d, with_pip=True)
        py = os.path.join(d, "bin", "python") if os.name != "nt" else os.path.join(d, "Scripts", "python.exe")
        self.assertEqual(run(py, "--check").returncode, 1)
        r = run(py)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("works from any folder", r.stdout)
        self.assertEqual(run(py, "--check").returncode, 0)
        self.assertEqual(run(py, "--uninstall").returncode, 0)
        self.assertEqual(run(py, "--check").returncode, 1)


if __name__ == "__main__":
    unittest.main()
