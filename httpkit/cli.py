import json
import re
import sys

from . import VSO_NOTICE, VSO_VER, _vso
from .client import Client
from .err import HttpkitError
from .feedback import fb_err, fb_json, fb_res, fb_text
from .proxy import load_list
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
  --auto          protocol auto mode: h2 or h1 by ALPN, h3 after Alt-Svc (default)
  --h1 --h2 --h3  force protocol
  -L              follow redirects
  -i              print response headers
  -I              HEAD request
  -k              skip certificate verification
  --cacert FILE   custom CA bundle (PEM)
  -o FILE         write body to file
  -t SEC          timeout (default 30)
  --priv          allow redirects into private address space
  --proxy URL     proxy: http, https, socks4, socks4a, socks5, socks5h (repeatable)
                  also host:port, host:port:user:pass, user:pass@host:port
  --proxy-http U  proxy used only for http:// targets (repeatable)
  --proxy-https U proxy used only for https:// targets (repeatable)
  --proxy-file F  read proxies from a file, one per line
  --rotate MODE   round-robin (default), random or sticky
  --proxy-env     use http_proxy / https_proxy / all_proxy / no_proxy
  --no-proxy LIST comma list of hosts that bypass the proxy
  -sp             use the library's bundled stock proxy list (free, public,
                  unreliable, untrusted — re-fetched fresh every run, not
                  health-checked; cannot combine with --proxy*)
  --stock-proto L stock proxy protocols to fetch: comma list of http, https,
                  socks4, socks5 (default: all)
  --ua STR        user-agent (repeatable)
  --ua-file F     read user-agents from a file, one per line
  --ua-rotate M   round-robin (default), random or sticky
  -n COUNT        repeat the request COUNT times (max 1000; with --stream up to 1000000000)
  --stream SPEED  long async request loop: slow, medium, fast or a rate in req/s (0.1-200)
                  runs until -n, --duration or Ctrl-C; prints live stats on stderr
  --threads N     stream concurrency, 1-50 (default by speed: slow 4, medium 16, fast 50)
  --duration SEC  stop the stream after SEC seconds
  --max-fail N    stop the stream after N consecutive failures (default 500, 0 = off)
  -v              verbose: every step and every problem, live on stderr
  -fb             feedback report on stderr after each result or failure
  --feedback-json same report as JSON
"""


def inf_safe(s):
    return CTL.sub(lambda m: "\\x%02x" % ord(m.group()), s)


def int_arg(a, v):
    try:
        return int(v)
    except ValueError:
        raise SystemExit("bad number for %s: %r" % (a, inf_safe(v))) from None


def float_arg(a, v):
    try:
        return float(v)
    except ValueError:
        raise SystemExit("bad number for %s: %r" % (a, inf_safe(v))) from None


def parse_args(av):
    o = {"mth": None, "hdrs": [], "data": None, "json": None, "proto": "auto", "follow": False, "inc": False, "head": False, "verify": True, "ca": None, "out": None, "tmo": 30.0, "priv": False, "v": False, "url": None, "px": [], "rot": "round-robin", "penv": False, "nop": None, "uas": [], "urot": "round-robin", "n": None, "fb": False, "stream": None, "thr": None, "dur": None, "mf": 500, "fbj": False, "pxh": [], "pxs": [], "sp": False, "spp": None}
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
        elif a == "--auto":
            o["proto"] = "auto"
        elif a == "--stream":
            o["stream"] = nxt()
        elif a == "--threads":
            o["thr"] = int_arg(a, nxt())
        elif a == "--duration":
            o["dur"] = float_arg(a, nxt())
        elif a == "--max-fail":
            o["mf"] = int_arg(a, nxt())
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
        elif a == "--proxy":
            o["px"].append(nxt())
        elif a == "--proxy-http":
            o["pxh"].append(nxt())
        elif a == "--proxy-https":
            o["pxs"].append(nxt())
        elif a == "-fb" or a == "--feedback":
            o["fb"] = True
        elif a == "--feedback-json":
            o["fbj"] = True
        elif a == "--proxy-file":
            o["px"] += load_list(nxt())
        elif a == "--rotate":
            o["rot"] = nxt()
        elif a == "--proxy-env":
            o["penv"] = True
        elif a == "--no-proxy":
            o["nop"] = nxt()
        elif a == "-sp" or a == "--stock-proxy":
            o["sp"] = True
        elif a == "--stock-proto":
            o["spp"] = nxt()
        elif a == "--ua":
            o["uas"].append(nxt())
        elif a == "--ua-file":
            o["uas"] += load_list(nxt())
        elif a == "--ua-rotate":
            o["urot"] = nxt()
        elif a == "-n":
            o["n"] = int_arg(a, nxt())
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


def emit_fb(fb, o):
    sys.stderr.write(inf_safe(fb_json(fb) if o["fbj"] else fb_text(fb)) + "\n")


def emit_err(e, o):
    if o["v"] or o["fb"] or o["fbj"]:
        emit_fb(fb_err(e), o)
    else:
        sys.stderr.write("httpkit: %s: %s\n  (re-run with -v for every step, -fb for feedback)\n" % (type(e).__name__, inf_safe(str(e))))


def do_stream(o, mth, body, jb, kw):
    from .sec import InfGuard
    from .stream import run_stream, stderr_line
    if o["out"] or o["inc"] or o["head"]:
        raise SystemExit("--stream does not combine with -o, -i or -I")
    ca = dict(kw)
    ca.update(proto=o["proto"], verify=o["verify"], ca=o["ca"], tmo=o["tmo"], follow=o["follow"], guard=InfGuard(blk_priv=not o["priv"]), verbose=False)
    st = run_stream(o["url"], speed=o["stream"], threads=o["thr"], n=o["n"], dur=o["dur"], mth=mth, hdrs=o["hdrs"], body=body, json=jb,
                    max_fail=max(0, o["mf"]), sink=stderr_line, **ca)
    if o["fbj"]:
        sys.stderr.write(json.dumps(st.as_dict()) + "\n")
    else:
        sys.stderr.write(inf_safe(st.text()) + "\n")
    return 0 if st.ok else 1


def do_stock(o):
    from .sec import InfGuard
    from .stock import VSO_STOCK_WARN, write_stock_file
    sys.stderr.write("httpkit: %s\n" % VSO_STOCK_WARN)
    proto = [x.strip() for x in o["spp"].split(",") if x.strip()] if o["spp"] else None
    try:
        path, items, report = write_stock_file(proto=proto, guard=InfGuard(blk_priv=True))
    except Exception as e:
        raise SystemExit("httpkit: stock proxy fetch failed: %s: %s" % (type(e).__name__, inf_safe(str(e)))) from None
    sys.stderr.write("httpkit: stock proxy: %d proxies from %d/%d sources -> %s\n" % (
        len(items), report["ok"], report["ok"] + report["fail"], path))
    if o["v"]:
        for name, v in sorted(report["sources"].items()):
            sys.stderr.write("  %s: %s\n" % (name, v))
    return items


def do_req(o):
    if not o["url"]:
        sys.stdout.write(USG)
        return 2
    from .sec import InfGuard
    body = rd_data(o["data"])
    mth = "HEAD" if o["head"] else (o["mth"] or ("POST" if body is not None or o["json"] else "GET"))
    jb = json.loads(o["json"]) if o["json"] is not None else None
    kw = {}
    if o["sp"]:
        if o["px"] or o["pxh"] or o["pxs"] or o["penv"]:
            raise SystemExit("-sp cannot combine with --proxy, --proxy-http, --proxy-https or --proxy-env")
        if o["proto"] == "h3":
            raise SystemExit("-sp cannot be used with --h3: HTTP/3 cannot be used through a proxy")
        kw["proxies"] = do_stock(o)
        kw["rotate"] = o["rot"]
    elif o["pxh"] or o["pxs"]:
        kw["proxies"] = {k: v for k, v in (("http", o["pxh"]), ("https", o["pxs"]), ("all", o["px"])) if v}
        kw["rotate"] = o["rot"]
    elif o["px"]:
        kw["proxies"] = o["px"]
        kw["rotate"] = o["rot"]
    elif o["penv"]:
        kw["proxy"] = "env"
    if o["nop"] is not None:
        kw["no_proxy"] = o["nop"]
    if o["uas"]:
        kw["uas"] = o["uas"]
        kw["ua_rotate"] = o["urot"]
    if o["stream"] is not None:
        return do_stream(o, mth, body, jb, kw)
    fails = 0
    last = None
    probs = []
    with Client(proto=o["proto"], verify=o["verify"], ca=o["ca"], tmo=o["tmo"], follow=o["follow"], guard=InfGuard(blk_priv=not o["priv"]), verbose=o["v"], **kw) as c:
        for i in range(max(1, min(1000, o["n"] or 1))):
            try:
                r = c.req(mth, o["url"], hdrs=o["hdrs"], body=body, json=jb)
            except (HttpkitError, OSError) as e:
                fails += 1
                tr = getattr(e, "vso_trace", None)
                probs += [x["msg"] for x in tr.prob if x["kind"] != "error"] if tr else [str(e)]
                emit_err(e, o)
                continue
            last = r
            probs += [x["msg"] for x in r.trace.prob]
            if o["fb"] or o["fbj"]:
                emit_fb(fb_res(r), o)
    if o["v"] and probs:
        sys.stderr.write("== problems (%d)\n" % len(probs))
        for m in probs:
            sys.stderr.write("  ! %s\n" % inf_safe(m))
    if last is None:
        return 1
    r = last
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
    if fails:
        return 1
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
