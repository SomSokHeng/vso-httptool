import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import _vso
from .err import ProxyError
from .proxy import Proxy, parse_proxy
from .sec import InfGuard, Lim

VSO_STOCK_WARN = ("stock proxies are free, public, unreliable and untrusted \u2014 "
                   "do not send sensitive data through them")
vso_stock_max = 6000
vso_stock_src_max = 3000
vso_stock_body_cap = 3 << 20
vso_stock_tmo = 8.0
vso_line = re.compile(r"^(?:[^\s@/:]+:[^\s@/]*@)?(?:\[[0-9A-Fa-f:.]+\]|[0-9A-Za-z_.\-]{1,253}):[0-9]{1,5}$")

VSO_STOCK_SRC = (
    ("hproxy-http", "https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/http.txt", "http"),
    ("hproxy-https", "https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/https.txt", "https"),
    ("hproxy-socks4", "https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/socks4.txt", "socks4"),
    ("hproxy-socks5", "https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/socks5.txt", "socks5"),
    ("databay-http", "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/http.txt", "http"),
    ("databay-https", "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/https.txt", "https"),
    ("databay-socks4", "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/socks4.txt", "socks4"),
    ("databay-socks5", "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/socks5.txt", "socks5"),
    ("stormsia-http", "https://raw.githubusercontent.com/stormsia/proxy-list/main/http.txt", "http"),
    ("stormsia-socks4", "https://raw.githubusercontent.com/stormsia/proxy-list/main/socks4.txt", "socks4"),
    ("stormsia-socks5", "https://raw.githubusercontent.com/stormsia/proxy-list/main/socks5.txt", "socks5"),
    ("proxio-http", "https://raw.githubusercontent.com/proxio-io/proxy-list/main/http.txt", "http"),
    ("proxio-https", "https://raw.githubusercontent.com/proxio-io/proxy-list/main/https.txt", "https"),
    ("proxio-socks4", "https://raw.githubusercontent.com/proxio-io/proxy-list/main/socks4.txt", "socks4"),
    ("proxio-socks5", "https://raw.githubusercontent.com/proxio-io/proxy-list/main/socks5.txt", "socks5"),
    ("monosans-all", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt", "http"),
    ("speedx-http", "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt", "http"),
    ("speedx-socks4", "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt", "socks4"),
    ("speedx-socks5", "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt", "socks5"),
    ("clarketm-http", "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt", "http"),
    ("rooster-https", "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt", "https"),
    ("rooster-socks4", "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt", "socks4"),
    ("rooster-socks5", "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt", "socks5"),
    ("jetkai-http", "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt", "http"),
    ("jetkai-https", "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt", "https"),
    ("jetkai-socks4", "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt", "socks4"),
    ("jetkai-socks5", "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt", "socks5"),
)


def cache_dir():
    d = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    d = os.path.join(d, "vso-httptool")
    os.makedirs(d, exist_ok=True)
    return d


def stock_file():
    return os.path.join(cache_dir(), "stock_proxies.txt")


def _lines(body):
    try:
        txt = body.decode("utf-8", "ignore")
    except Exception:
        return []
    return [ln.strip() for ln in txt.splitlines()]


def _one_src(c, name, url, proto, cap):
    out = []
    got = set()
    try:
        r = c.req("GET", url)
    except Exception as e:
        return name, [], "%s: %s" % (type(e).__name__, str(e)[:120])
    if r.status != 200:
        return name, [], "http %d" % r.status
    n = 0
    for ln in _lines(r.body):
        if not ln or ln.startswith("#"):
            continue
        ln = ln.split()[0] if " " in ln or "\t" in ln else ln
        if "://" in ln:
            if not vso_line.match(ln.partition("://")[2].rstrip("/")):
                continue
            cand = ln.rstrip("/")
        elif vso_line.match(ln):
            cand = "%s://%s" % (proto, ln)
        else:
            continue
        try:
            px = parse_proxy(cand)
        except ProxyError:
            continue
        if px.key in got:
            continue
        got.add(px.key)
        out.append(px)
        n += 1
        if n >= cap:
            break
    return name, out, None


def fetch_stock(proto=None, srcs=None, tmo=vso_stock_tmo, guard=None, workers=12, sink=None):
    _vso.inf_warn()
    from .client import Client
    want = {proto} if isinstance(proto, str) else (set(proto) if proto else None)
    srcs = srcs or VSO_STOCK_SRC
    if want is not None:
        srcs = [s for s in srcs if s[2] in want]
    if not srcs:
        raise ProxyError("no stock proxy sources match proto=%r" % (proto,))
    guard = guard or InfGuard(blk_priv=True)
    seen = set()
    out = []
    report = {"ok": 0, "fail": 0, "sources": {}}
    with Client(proto="h1", tmo=tmo, guard=guard, follow=True, jar=False,
                lim=Lim(max_body=vso_stock_body_cap, max_redirs=3), verbose=False) as c:
        with ThreadPoolExecutor(max_workers=max(1, min(workers, len(srcs)))) as ex:
            futs = [ex.submit(_one_src, c, name, url, pr, vso_stock_src_max) for name, url, pr in srcs]
            for f in futs:
                name, items, err = f.result()
                if err:
                    report["fail"] += 1
                    report["sources"][name] = "error: %s" % err
                else:
                    report["ok"] += 1
                    report["sources"][name] = len(items)
                added = 0
                for px in items:
                    if len(out) >= vso_stock_max:
                        break
                    if px.key in seen:
                        continue
                    seen.add(px.key)
                    out.append(px)
                    added += 1
                if sink:
                    sink(name, added, err)
    report["total"] = len(out)
    if not out:
        raise ProxyError("fetched 0 usable stock proxies from %d sources (see report for per-source errors)" % len(srcs))
    return out, report


def write_stock_file(path=None, **kw):
    path = path or stock_file()
    items, report = fetch_stock(**kw)
    path = os.path.abspath(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp.%d" % os.getpid()
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("# %s\n# fetched %s, %d proxies from %d/%d sources\n" % (
            VSO_STOCK_WARN, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), len(items), report["ok"], report["ok"] + report["fail"]))
        for px in items:
            f.write("%s://%s:%d\n" % (px.scheme, px.host, px.port))
    os.replace(tmp, path)
    return path, items, report
