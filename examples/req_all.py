import sys
import time

from httpkit import (Client, ClientError, ConnError, H2Error, H3Error, HdrError, Hdrs, HttpkitError, InfGuard,
                     Jar, Lim, QuicError, Req, Resp, SecError, TlsError, UrlError, VSO_NOTICE, VSO_VER,
                     parse_hdrs, parse_ua, ua_str)
from httpkit.client import h3_ok
from httpkit.tls import fmt_insp, insp
from httpkit.url import parse as parse_url

vso_url = "https://infinitynetai.wispbyte.app/"
inf_lim = Lim(max_body=8 << 20, max_redirs=5, tmo=20.0)
inf_grd = InfGuard(blk_priv=True)
vso_ua = ua_str("infinitynet-probe", VSO_VER, ["Termux", "Android"])
inf_res = []


def inf_safe(s, n=200):
    s = "".join(c if c.isprintable() or c in "\n\t" else "?" for c in str(s))
    return s[:n] + ("..." if len(s) > n else "")


def sec(t):
    print("\n== %s" % t)


def show(r):
    print("  %s %d  %.0f ms  %d bytes" % (r.proto, r.status, r.elapsed * 1000, len(r.body)))
    for k in ("server", "content-type", "alt-svc", "cache-control", "strict-transport-security"):
        v = r.hdrs.get(k)
        if v:
            print("  %s: %s" % (k, inf_safe(v, 90)))


def run(name, fn):
    t0 = time.monotonic()
    try:
        fn()
        inf_res.append((name, "ok", time.monotonic() - t0))
    except HttpkitError as e:
        print("  %s: %s" % (type(e).__name__, inf_safe(e)))
        inf_res.append((name, type(e).__name__, time.monotonic() - t0))
    except Exception as e:
        print("  crash: %r" % (e,))
        inf_res.append((name, "crash", time.monotonic() - t0))


def mk(**kw):
    base = dict(verify=not OPT["insecure"], ca=OPT["ca"], lim=inf_lim, guard=inf_grd, ua=vso_ua, tmo=20.0)
    base.update(kw)
    return Client(**base)


def t_basic():
    with mk() as c:
        r = c.get(vso_url)
        show(r)
        print("  body: %s" % inf_safe(r.text().replace("\n", " "), 160))
        print("  ok=%s enc=%s" % (r.ok, r.enc))


def t_protocols():
    for p in ("h1", "h2", "h3"):
        if p == "h3" and not h3_ok():
            print("  h3: skipped (cryptography not usable here)")
            continue
        try:
            with mk(proto=p) as c:
                r = c.get(vso_url)
                print("  %-2s -> %s %d  %.0f ms" % (p, r.proto, r.status, r.elapsed * 1000))
        except (ConnError, H2Error, H3Error, QuicError, ClientError, TlsError) as e:
            print("  %-2s -> %s: %s" % (p, type(e).__name__, inf_safe(e, 90)))


def t_auto_upgrade():
    with mk(proto="auto") as c:
        a = c.get(vso_url)
        b = c.get(vso_url)
        print("  first=%s second=%s alt-svc=%s" % (a.proto, b.proto, inf_safe(a.hdrs.get("alt-svc", "none"), 60)))


def t_head_headers():
    with mk() as c:
        r = c.head(vso_url, hdrs={"X-Probe": "1", "Accept-Language": "en"})
        show(r)
        print("  headers=%d body=%d" % (len(r.hdrs), len(r.body)))
        print("  set-cookie=%s" % r.hdrs.get_all("set-cookie"))


def t_redirects():
    with mk() as c:
        a = c.get(vso_url, follow=False)
        b = c.get(vso_url, follow=True)
        print("  nofollow=%d follow=%d hops=%d final=%s" % (a.status, b.status, len(b.hist), b.url))


def t_cookies():
    jar = Jar(max_n=50)
    with mk(jar=jar) as c:
        c.get(vso_url)
        c.get(vso_url)
    print("  cookies stored=%d" % len(jar.c))
    for ck in list(jar.c.values())[:5]:
        print("   %s domain=%s secure=%s" % (ck.name, ck.dom, ck.sec))


def t_concurrent():
    with mk() as c:
        t0 = time.monotonic()
        rs = c.map([vso_url] * 12, workers=6)
        print("  %d requests, %s, %.0f ms total" % (len(rs), sorted(set(r.status for r in rs)), (time.monotonic() - t0) * 1000))
        print("  protocols=%s" % sorted(set(r.proto for r in rs)))


def t_write():
    with mk() as c:
        r = c.req("POST", vso_url, json={"probe": 1})
        print("  POST %d %s" % (r.status, r.proto))
        r = c.req("PUT", vso_url, body="probe")
        print("  PUT %d" % r.status)
        r = c.req("DELETE", vso_url)
        print("  DELETE %d" % r.status)


def t_objects():
    h = Hdrs([("Accept", "*/*")])
    h.add("X-A", "1")
    h.add("x-a", "2")
    rq = Req("get", parse_url(vso_url), h)
    rp = Resp(200, parse_hdrs(b"Server: x\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2"), b'{"k": 1}', proto="h2")
    print("  %r  all(x-a)=%s" % (rq, h.get_all("X-A")))
    print("  %r  json=%s cookies=%s" % (rp, rp.json(), rp.hdrs.get_all("set-cookie")))
    u = parse_url(vso_url)
    print("  url host=%s port=%d target=%s origin=%s" % (u.host, u.port, u.target, u.origin))


def t_tls():
    u = parse_url(vso_url)
    if u.scheme != "https":
        print("  not https")
        return
    print("  " + fmt_insp(insp(u.host, u.port, verify=not OPT["insecure"], ca=OPT["ca"])).replace("\n", "\n  "))


def t_ua():
    d = parse_ua(vso_ua)
    print("  ua=%s" % vso_ua)
    print("  products=%s comments=%s" % (d["products"], d["comments"]))


def t_guards():
    tests = [
        ("file scheme", lambda: parse_url("file:///etc/passwd"), UrlError),
        ("userinfo", lambda: parse_url("https://u:p@host/"), UrlError),
        ("header injection", lambda: Hdrs().add("X", "a\r\nInjected: 1"), HdrError),
        ("obs-fold", lambda: parse_hdrs(b"A: b\r\n c"), HdrError),
        ("private redirect", lambda: InfGuard().chk_redir(parse_url("https://example.com/"), parse_url("http://127.0.0.1/")), SecError),
        ("https->http", lambda: InfGuard().chk_redir(parse_url("https://a.example/"), parse_url("http://a.example/")), SecError),
    ]
    for n, fn, exc in tests:
        try:
            fn()
            print("  %-18s NOT BLOCKED" % n)
        except exc as e:
            print("  %-18s blocked (%s)" % (n, type(e).__name__))
        except HttpkitError as e:
            print("  %-18s blocked (%s)" % (n, type(e).__name__))


OPT = {"insecure": False, "ca": None, "write": False}


def main():
    global vso_url
    av = sys.argv[1:]
    i = 0
    while i < len(av):
        a = av[i]
        if a == "--insecure":
            OPT["insecure"] = True
        elif a == "--write":
            OPT["write"] = True
        elif a == "--ca" and i + 1 < len(av):
            i += 1
            OPT["ca"] = av[i]
        elif a.startswith("http"):
            vso_url = a
        else:
            print("usage: req_all.py [URL] [--insecure] [--ca FILE] [--write]")
            return 2
        i += 1
    parse_url(vso_url)
    print(VSO_NOTICE)
    print("target: %s   h3 available: %s" % (vso_url, h3_ok()))
    steps = [
        ("basic GET", t_basic), ("protocols h1/h2/h3", t_protocols), ("alt-svc auto upgrade", t_auto_upgrade),
        ("HEAD + headers", t_head_headers), ("redirects", t_redirects), ("cookie jar", t_cookies),
        ("concurrent map", t_concurrent), ("objects + parsing", t_objects), ("tls inspect", t_tls),
        ("user agent", t_ua), ("security guards", t_guards),
    ]
    if OPT["write"]:
        steps.append(("POST/PUT/DELETE", t_write))
    for n, fn in steps:
        sec(n)
        run(n, fn)
    sec("summary")
    for n, s, t in inf_res:
        print("  %-24s %-12s %.2fs" % (n, s, t))
    return 0 if all(s == "ok" for _, s, _ in inf_res) else 1


if __name__ == "__main__":
    sys.exit(main())
