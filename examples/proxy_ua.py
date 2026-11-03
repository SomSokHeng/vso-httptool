import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from httpkit import Client, ConnError, ProxyError, load_list

vso_url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com/"
vso_px = [
    "http://user:pass@127.0.0.1:8080",
    "https://proxy.example.com:443",
    "socks4://127.0.0.1:1080",
    "socks4a://127.0.0.1:1081",
    "socks5://127.0.0.1:1082",
    "socks5h://user:pass@127.0.0.1:9050",
]
vso_ua = ["MyTool/1.0", "MyTool/2.0 (Linux)", "Mozilla/5.0 (X11; Linux x86_64)"]

print("-- rotate proxies and user agents")
with Client(proxies=vso_px, rotate="round-robin", uas=vso_ua, ua_rotate="random", tmo=8) as cl:
    for i in range(len(vso_px)):
        try:
            res = cl.get(vso_url)
            print(i, res.status, res.proto, res.proxy, res.ua)
        except (ProxyError, ConnError) as e:
            print(i, "failed:", type(e).__name__, e)

print("-- one proxy, sticky, per-request override, bypass")
with Client(proxies=vso_px[:2], rotate="sticky", no_proxy="localhost,127.0.0.1,.internal") as cl:
    for kw in ({}, {"proxy": "socks5h://127.0.0.1:9050"}, {"proxy": "direct"}):
        try:
            res = cl.get(vso_url, **kw)
            print(kw or "default", res.status, res.proxy)
        except (ProxyError, ConnError) as e:
            print(kw or "default", "failed:", type(e).__name__)

print("-- lists from files, environment proxy, callable user agent")
inf_files = [("proxies.txt", "proxies"), ("agents.txt", "uas")]
inf_kw = {}
for path, name in inf_files:
    try:
        inf_kw[name] = load_list(path)
    except OSError:
        print("no", path)
if "proxies" in inf_kw and "uas" in inf_kw:
    with Client(proxies=inf_kw["proxies"], uas=inf_kw["uas"]) as cl:
        print(cl.get(vso_url).status)
with Client(proxy="env", uas=lambda: "dyn/1.0") as cl:
    try:
        res = cl.get(vso_url)
        print(res.status, res.proxy, res.ua)
    except (ProxyError, ConnError) as e:
        print("failed:", type(e).__name__, e)
