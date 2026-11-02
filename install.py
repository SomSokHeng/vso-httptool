import argparse
import os
import shutil
import subprocess
import sys
import tempfile

vso_root = os.path.dirname(os.path.abspath(__file__))
vso_name = "vso-httptool"
vso_need = ("pyproject.toml", "README.md", "LICENSE", "httpkit/__init__.py", "httpkit/_seal.py", "httpkit/_vso.py")
inf_eme = "externally-managed-environment"
inf_ign = shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info", "build", "dist")


def say(m):
    sys.stdout.write(m + "\n")
    sys.stdout.flush()


def die(m, code=1):
    sys.stderr.write("install: %s\n" % m)
    sys.exit(code)


def clean_env():
    return {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}


def pip(args, flags):
    cmd = [sys.executable, "-m", "pip"] + args[:1] + ["--disable-pip-version-check"] + flags + args[1:]
    return subprocess.run(cmd, capture_output=True, text=True)


def pip_try(args):
    flags = []
    p = None
    for _ in range(3):
        p = pip(args, flags)
        if p.returncode == 0:
            return True, flags, p
        out = p.stdout + p.stderr
        if inf_eme in out and "--break-system-packages" not in flags:
            flags.append("--break-system-packages")
            continue
        if args[0] == "install" and "--no-build-isolation" not in flags and "-e" not in args:
            flags.append("--no-build-isolation")
            continue
        break
    return False, flags, p


def tail(p, n=14):
    out = (p.stdout + p.stderr).strip().splitlines()
    return "\n".join(out[-n:])


def chk_root():
    miss = [f for f in vso_need if not os.path.isfile(os.path.join(vso_root, f))]
    if miss:
        die("run this from a full clone of the repo (missing: %s)" % ", ".join(miss))
    if sys.version_info < (3, 9):
        die("Python 3.9 or newer is required")
    p = subprocess.run([sys.executable, "-m", "pip", "--version"], capture_output=True, text=True)
    if p.returncode != 0:
        die("pip not found. On Termux run: pkg install python-pip")


def chk_seal():
    env = dict(os.environ, PYTHONPATH=vso_root)
    p = subprocess.run([sys.executable, "-c", "import httpkit"], cwd=tempfile.gettempdir(), env=env, capture_output=True, text=True)
    if p.returncode != 0:
        die("integrity check failed, refusing to install this copy:\n%s" % tail(p, 4))


def where():
    code = "import httpkit,sys;sys.stdout.write('%s|%s' % (httpkit.__version__, httpkit.__file__))"
    p = subprocess.run([sys.executable, "-c", code], cwd=tempfile.gettempdir(), env=clean_env(), capture_output=True, text=True)
    if p.returncode != 0:
        return None
    v, _, f = p.stdout.partition("|")
    return v, f


def h3_state():
    code = "from httpkit.client import h3_ok;import sys;sys.stdout.write('1' if h3_ok() else '0')"
    p = subprocess.run([sys.executable, "-c", code], cwd=tempfile.gettempdir(), env=clean_env(), capture_output=True, text=True)
    return p.stdout.strip() == "1"


def termux():
    return "com.termux" in sys.prefix or "com.termux" in os.environ.get("PREFIX", "")


def do_install(edit, h3):
    chk_root()
    chk_seal()
    if edit:
        ok, fl, p = pip_try(["install", "-e", vso_root])
    else:
        tmp = tempfile.mkdtemp(prefix="vso_httptool_")
        try:
            src = os.path.join(tmp, "src")
            os.makedirs(src)
            for f in ("pyproject.toml", "README.md", "LICENSE"):
                shutil.copy2(os.path.join(vso_root, f), src)
            shutil.copytree(os.path.join(vso_root, "httpkit"), os.path.join(src, "httpkit"), ignore=inf_ign)
            ok, fl, p = pip_try(["install", "--upgrade", "--force-reinstall", "--no-deps", src])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    if not ok:
        die("pip install failed:\n%s" % tail(p))
    if h3:
        req = os.path.join(vso_root, "requirements.txt")
        ok2, _, p2 = pip_try(["install", "-r", req])
        if not ok2:
            say("warning: could not install HTTP/3 requirements:\n%s" % tail(p2, 6))
    w = where()
    if not w:
        die("installed, but `import httpkit` fails outside the repo folder")
    say("installed %s %s" % (vso_name, w[0]))
    say("location  %s" % os.path.dirname(w[1]))
    say("import    from httpkit import Client   (works from any folder)")
    say("cli       httpkit https://example.com   or   python -m httpkit ...")
    h = h3_state()
    say("http/3    %s" % ("available" if h else "not available (h1 and h2 work)"))
    if not h:
        if termux():
            say("          Termux fix: pip uninstall cryptography && pkg install python-cryptography")
        else:
            say("          enable with: python install.py --h3")
    return 0


def do_update(edit, h3):
    if not os.path.isdir(os.path.join(vso_root, ".git")):
        die("not a git clone, cannot update")
    p = subprocess.run(["git", "-C", vso_root, "pull", "--ff-only"], capture_output=True, text=True)
    if p.returncode != 0:
        die("git pull failed:\n%s" % tail(p, 6))
    say(p.stdout.strip().splitlines()[-1] if p.stdout.strip() else "up to date")
    return do_install(edit, h3)


def do_uninstall():
    ok, _, p = pip_try(["uninstall", "-y", vso_name])
    if not ok:
        die("pip uninstall failed:\n%s" % tail(p))
    say("removed %s" % vso_name)
    return 0


def do_check():
    w = where()
    if not w:
        say("not installed (import httpkit fails outside the repo folder)")
        return 1
    say("installed %s at %s" % (w[0], os.path.dirname(w[1])))
    say("http/3    %s" % ("available" if h3_state() else "not available"))
    return 0


def main(av=None):
    ap = argparse.ArgumentParser(prog="install.py", description="Install vso-httptool as a library from this clone (no PyPI).")
    ap.add_argument("-e", "--editable", action="store_true", help="link to this clone so edits and git pull apply at once")
    ap.add_argument("--h3", action="store_true", help="also install HTTP/3 requirements (cryptography)")
    ap.add_argument("--update", action="store_true", help="git pull, then reinstall")
    ap.add_argument("--uninstall", action="store_true", help="remove the installed library")
    ap.add_argument("--check", action="store_true", help="show whether it imports from any folder")
    a = ap.parse_args(av)
    if a.uninstall:
        return do_uninstall()
    if a.check:
        return do_check()
    if a.update:
        return do_update(a.editable, a.h3)
    return do_install(a.editable, a.h3)


if __name__ == "__main__":
    sys.exit(main())
