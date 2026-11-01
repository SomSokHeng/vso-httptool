import importlib.util
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "httpkit")


def load():
    sp = importlib.util.spec_from_file_location("vso_seal_mod", os.path.join(PKG, "_vso.py"))
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


def main():
    v = load()
    m = v.inf_calc(PKG)
    root = v.inf_root(m)
    body = "SEAL = {\n" + "".join("    %r: %r,\n" % (k, m[k]) for k in sorted(m)) + "}\n"
    with open(os.path.join(PKG, "_seal.py"), "w") as f:
        f.write(body)
    p = os.path.join(PKG, "_vso.py")
    with open(p) as f:
        s = f.read()
    s2 = re.sub(r'^VSO_ROOT = ".*"$', 'VSO_ROOT = "%s"' % root, s, flags=re.M)
    with open(p, "w") as f:
        f.write(s2)
    chk = load()
    if chk.inf_root(chk.inf_calc(PKG)) != root:
        sys.exit("seal verification failed")
    print("sealed %d files, root %s" % (len(m), root[:16]))


if __name__ == "__main__":
    main()
