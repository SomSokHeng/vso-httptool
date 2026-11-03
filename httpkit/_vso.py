import hashlib
import importlib
import json
import os
import sys

VSO_AUTHOR = "Vso (InfinityNet)"
VSO_LICENSE = "MIT"
VSO_REPO = "https://github.com/SomSokHeng/vso-httptool"
VSO_NOTICE = "vso-httptool by %s | License: %s | %s" % (VSO_AUTHOR, VSO_LICENSE, VSO_REPO)
VSO_WARN = "WARNING: use only on systems you own or are authorized to test. Do not use for illegal activity."
VSO_ROOT = "0a2529898b7d72e25bd9cceeff083f92c21dfac90f1b33574ab288abe4c5d0f8"

inf_done = [False]


def inf_files(d):
    return sorted(n for n in os.listdir(d) if n.endswith(".py") and n != "_seal.py")


def inf_hash(p):
    with open(p, "rb") as f:
        raw = f.read().replace(b"\r\n", b"\n")
    if os.path.basename(p) == "_vso.py":
        raw = b"\n".join(x for x in raw.split(b"\n") if not x.startswith(b"VSO_ROOT = "))
    return hashlib.sha256(raw).hexdigest()


def inf_calc(d):
    return {n: inf_hash(os.path.join(d, n)) for n in inf_files(d)}


def inf_root(m):
    return hashlib.sha256(json.dumps(m, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def inf_chk():
    d = os.path.dirname(os.path.abspath(__file__))
    try:
        sl = importlib.import_module(__package__ + "._seal").SEAL
        cur = inf_calc(d)
    except Exception as e:
        raise ImportError("vso-httptool integrity data unreadable: %s" % e) from None
    if cur != sl or inf_root(cur) != VSO_ROOT or inf_root(sl) != VSO_ROOT:
        bad = sorted(k for k in set(cur) | set(sl) if cur.get(k) != sl.get(k))
        raise ImportError("vso-httptool integrity check failed (%s). %s. Reinstall the original or run tools/seal.py after your own changes." % (", ".join(bad) or "seal", VSO_NOTICE))
    return True


def inf_warn():
    if inf_done[0]:
        return
    inf_done[0] = True
    try:
        sys.stderr.write("[vso-httptool] %s\n[vso-httptool] %s\n" % (VSO_WARN, VSO_NOTICE))
        sys.stderr.flush()
    except Exception:
        pass
