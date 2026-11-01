import json
import re
import sys

from . import VSO_NOTICE, VSO_VER, _vso
from .client import Client
from .err import HttpkitError
from .tls import fmt_insp, insp
from .ua import parse_ua

CTL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x9b]")
CTLB = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

USG = """usage: httpkit [options] URL
       httpkit tls HOST[:PORT]
       httpkit ua STRING

options:
  -X METHOD       request method (default GET, POST when -d given)
  -H 'K: V'       add header (repeatable)
  -d DATA         request body; @file reads a file, @- reads stdin
  --json JSON     send JSON body
  --h1 --h2 --h3  force protocol (default: auto, with Alt-Svc upgrade to h3)
  -L              follow redirects
  -i              print response headers
  -I              HEAD request
  -k              skip certificate verification
  --cacert FILE   custom CA bundle (PEM)
  -o FILE         write body to file
  -t SEC          timeout (default 30)
  --priv          allow redirects into private address space
  -v              print summary to stderr
"""


def inf_safe(s):
    return CTL.sub(lambda m: "\\x%02x" % ord(m.group()), s)


def parse_args(av):
    o = {"mth": None, "hdrs": [], "data": None, "json": None, "proto": "auto", "follow": False, "inc": False, "head": False, "verify": True, "ca": None, "out": None, "tmo": 30.0, "priv": False, "v": False, "url": None}
    i = 0
    while i < len(av):
        a = av[i]
        def nxt():
            nonlocal i
            i += 1
            if i >= len(av):
                raise SystemExit("missing value for %s" % a)
            return av[i]
        if a == "-X":
            o["mth"] = nxt().upper()
        elif a == "-H":
            h = nxt()
            k, s, v = h.partition(":")
            if not s:
                raise SystemExit("bad header: %r" % h)
            o["hdrs"].append((k.strip(), v.strip()))
        elif a == "-d":
            o["data"] = nxt()
        elif a == "--json":
            o["json"] = nxt()
        elif a in ("--h1", "--h2", "--h3"):
            o["proto"] = a[2:]
        elif a == "-L":
            o["follow"] = True
        elif a == "-i":
            o["inc"] = True
        elif a == "-I":
            o["head"] = True
        elif a == "-k":
            o["verify"] = False
        elif a == "--cacert":
            o["ca"] = nxt()
        elif a == "-o":
            o["out"] = nxt()
        elif a == "-t":
            o["tmo"] = float(nxt())
        elif a == "--priv":
            o["priv"] = True
        elif a == "-v":
            o["v"] = True
        elif a in ("-h", "--help"):
            sys.stdout.write(USG)
            raise SystemExit(0)
        elif a == "--version":
            print("httpkit %s\n%s" % (VSO_VER, VSO_NOTICE))
            raise SystemExit(0)
        elif a.startswith("-") and len(a) > 1:
            raise SystemExit("unknown option: %s" % a)
        else:
            o["url"] = a
        i += 1
    return o


def rd_data(d):
    if d is None:
        return None
    if d == "@-":
        return sys.stdin.buffer.read()
    if d.startswith("@"):
        with open(d[1:], "rb") as f:
            return f.read()
    return d.encode("utf-8")


def do_req(o):
    if not o["url"]:
        sys.stdout.write(USG)
        return 2
    from .sec import InfGuard
    body = rd_data(o["data"])
    mth = "HEAD" if o["head"] else (o["mth"] or ("POST" if body is not None or o["json"] else "GET"))
    jb = json.loads(o["json"]) if o["json"] is not None else None
    with Client(proto=o["proto"], verify=o["verify"], ca=o["ca"], tmo=o["tmo"], follow=o["follow"], guard=InfGuard(blk_priv=not o["priv"])) as c:
        r = c.req(mth, o["url"], hdrs=o["hdrs"], body=body, json=jb)
    if o["v"]:
        for h in r.hist:
            sys.stderr.write("< %d %s -> %s\n" % (h.status, h.proto, inf_safe(h.hdrs.get("location", ""))))
        sys.stderr.write("< %s %d  %.0f ms  %d bytes\n" % (r.proto, r.status, r.elapsed * 1000, len(r.body)))
    out = sys.stdout.buffer
    if o["inc"] or o["head"]:
        ln = ["%s %d" % (r.proto.upper(), r.status)]
        ln += ["%s: %s" % (inf_safe(k), inf_safe(v)) for k, v in r.hdrs]
        out.write(("\n".join(ln) + "\n\n").encode("utf-8", "replace"))
    if o["out"]:
        with open(o["out"], "wb") as f:
            f.write(r.body)
    elif not o["head"]:
        out.write(CTLB.sub(b"?", r.body) if sys.stdout.isatty() else r.body)
    out.flush()
    return 0 if r.status < 400 else 22


def do_tls(av):
    if not av:
        sys.stdout.write(USG)
        return 2
    h, _, p = av[0].partition(":")
    print(fmt_insp(insp(h, int(p or 443), verify="-k" not in av)))
    return 0


def do_ua(av):
    if not av:
        sys.stdout.write(USG)
        return 2
    d = parse_ua(" ".join(av))
    for n, v in d["products"]:
        print("product  %s%s" % (inf_safe(n), "/" + inf_safe(v) if v else ""))
    for c in d["comments"]:
        print("comment  %s" % inf_safe(c))
    return 0


def main(av=None):
    av = list(sys.argv[1:] if av is None else av)
    _vso.inf_warn()
    try:
        if av and av[0] == "tls":
            return do_tls(av[1:])
        if av and av[0] == "ua":
            return do_ua(av[1:])
        return do_req(parse_args(av))
    except HttpkitError as e:
        sys.stderr.write("httpkit: %s: %s\n" % (type(e).__name__, inf_safe(str(e))))
        return 1
    except (OSError, ValueError) as e:
        sys.stderr.write("httpkit: %s\n" % inf_safe(str(e)))
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
