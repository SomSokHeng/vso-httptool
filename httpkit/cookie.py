import threading
import time
from email.utils import parsedate_to_datetime

PUB = frozenset(("com", "net", "org", "edu", "gov", "io", "co", "uk", "kh", "com.kh", "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.jp", "co.in", "com.br", "github.io", "cloudfront.net", "herokuapp.com"))


class Cookie:
    __slots__ = ("name", "val", "dom", "host_only", "path", "exp", "sec", "http_only", "same_site")

    def __init__(self, name, val, dom, host_only, path, exp, sec, http_only, same_site):
        self.name = name
        self.val = val
        self.dom = dom
        self.host_only = host_only
        self.path = path
        self.exp = exp
        self.sec = sec
        self.http_only = http_only
        self.same_site = same_site

    def __repr__(self):
        return "Cookie(%s=%s; %s)" % (self.name, self.val, self.dom)


def dom_match(host, dom):
    return host == dom or (host.endswith("." + dom) and not host.replace(".", "").isdigit())


def path_match(rp, cp):
    if rp == cp:
        return True
    if rp.startswith(cp):
        return cp.endswith("/") or rp[len(cp):len(cp) + 1] == "/"
    return False


def def_path(p):
    if not p.startswith("/") or p.count("/") <= 1:
        return "/"
    return p[:p.rfind("/")]


def parse_set_cookie(line, url, now=None):
    now = now or time.time()
    if len(line) > 4096 or "\x00" in line or "\r" in line or "\n" in line:
        return None
    parts = line.split(";")
    nv = parts[0]
    if "=" not in nv:
        return None
    name, _, val = nv.partition("=")
    name = name.strip()
    val = val.strip()
    if not name or len(name) + len(val) > 4096:
        return None
    dom = url.host
    host_only = True
    path = def_path(url.path)
    exp = None
    sec = False
    ho = False
    ss = ""
    mx = None
    for a in parts[1:]:
        k, _, v = a.strip().partition("=")
        k = k.lower()
        v = v.strip()
        if k == "domain" and v:
            d = v.lstrip(".").lower()
            if d in PUB or "." not in d:
                if d != url.host:
                    return None
            if not dom_match(url.host, d):
                return None
            dom = d
            host_only = False
        elif k == "path" and v.startswith("/"):
            path = v
        elif k == "expires":
            try:
                exp = parsedate_to_datetime(v).timestamp()
            except Exception:
                pass
        elif k == "max-age":
            try:
                mx = int(v)
            except ValueError:
                pass
        elif k == "secure":
            sec = True
        elif k == "httponly":
            ho = True
        elif k == "samesite":
            ss = v.lower()
    if mx is not None:
        exp = now + mx
    ln = name.lower()
    if ln.startswith("__secure-") and not (sec and url.scheme == "https"):
        return None
    if ln.startswith("__host-") and not (sec and url.scheme == "https" and host_only and path == "/"):
        return None
    if sec and url.scheme != "https":
        return None
    return Cookie(name, val, dom, host_only, path, exp, sec, ho, ss)


class Jar:
    def __init__(self, max_n=180):
        self.c = {}
        self.max_n = max_n
        self.lk = threading.RLock()

    def put(self, url, lines, now=None):
        now = now or time.time()
        with self.lk:
            for ln in lines:
                ck = parse_set_cookie(ln, url, now)
                if ck is None:
                    continue
                k = (ck.name, ck.dom, ck.path)
                if ck.exp is not None and ck.exp <= now:
                    self.c.pop(k, None)
                    continue
                if k not in self.c and len(self.c) >= self.max_n:
                    self.purge(now)
                    if len(self.c) >= self.max_n:
                        self.c.pop(next(iter(self.c)))
                self.c[k] = ck

    def purge(self, now=None):
        now = now or time.time()
        with self.lk:
            for k in [k for k, v in self.c.items() if v.exp is not None and v.exp <= now]:
                del self.c[k]

    def match(self, url, now=None):
        now = now or time.time()
        out = []
        with self.lk:
            cks = list(self.c.values())
        for ck in cks:
            if ck.exp is not None and ck.exp <= now:
                continue
            if ck.host_only:
                if url.host != ck.dom:
                    continue
            elif not dom_match(url.host, ck.dom):
                continue
            if not path_match(url.path, ck.path):
                continue
            if ck.sec and url.scheme != "https":
                continue
            out.append(ck)
        out.sort(key=lambda c: -len(c.path))
        return out

    def hdr_for(self, url, now=None):
        ms = self.match(url, now)
        if not ms:
            return None
        return "; ".join("%s=%s" % (c.name, c.val) for c in ms)

    def clear(self):
        with self.lk:
            self.c.clear()
