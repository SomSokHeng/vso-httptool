import json as _json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import _vso
from .body import dec_enc
from .conn import Conn
from .cookie import Jar
from .err import ClientError, ConnError, H2Error, H3Error, HttpkitError, QuicError
from .follow import plan
from .h1 import H1Conn
from .h2 import H2Conn, E_REFUSED
from .hdr import Hdrs, chk
from .msg import Req
from .proxy import InfPool, bypass, env_no_proxy, from_env, parse_proxy
from .sec import InfGuard, Lim
from .ua import UaPool, VSO_UA
from .url import parse as parse_url

try:
    import brotli
    AE = "gzip, deflate, br" if brotli else "gzip, deflate"
except Exception:
    AE = "gzip, deflate"

ALT = re.compile(r'h3=":(\d+)"(?:;\s*ma=(\d+))?')
IDEM = frozenset(("GET", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE"))


def h3_ok():
    try:
        from . import h3
        return h3.avail()
    except Exception:
        return False


class Client:
    def __init__(self, proto="auto", verify=True, ca=None, tmo=30.0, follow=True, jar=True, hdrs=None, lim=None, guard=None, ua=VSO_UA, h3=True,
                 proxy=None, proxies=None, rotate="round-robin", no_proxy=None, pverify=None, pca=None,
                 uas=None, ua_rotate="round-robin", max_pool=64):
        _vso.inf_warn()
        if proto not in ("auto", "h1", "h2", "h3"):
            raise ClientError("proto must be auto, h1, h2 or h3")
        self.proto = proto
        self.verify = verify
        self.ca = ca
        self.tmo = tmo
        self.follow = follow
        self.jar = Jar() if jar is True else (jar or None)
        self.hdrs = Hdrs(hdrs or {})
        self.lim = lim or Lim()
        self.guard = guard or InfGuard()
        self.ua = ua
        self.h3 = h3
        self.pverify = pverify
        self.pca = pca
        self.max_pool = max_pool
        items = []
        self.penv = proxy == "env"
        if proxy is not None and not self.penv:
            items.append(parse_proxy(proxy))
        for x in proxies or ():
            items.append(parse_proxy(x))
        self.pp = InfPool(items, rotate) if items else None
        if no_proxy is None:
            self.nop = env_no_proxy() if self.penv else []
        else:
            self.nop = [x for x in no_proxy.split(",") if x.strip()] if isinstance(no_proxy, str) else list(no_proxy)
        if proto == "h3" and (self.pp or self.penv):
            raise ClientError("HTTP/3 cannot be used through a proxy")
        if uas is None:
            self.up = None
        elif callable(uas):
            self.up = lambda origin, fn=uas: fn()
        else:
            self.up = UaPool(uas, ua_rotate).pick
        self.pool = {}
        self.alt = {}
        self.bad = {}
        self.lk = threading.RLock()
        self.h3lk = threading.Lock()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def close(self):
        with self.lk:
            cs = list(self.pool.values())
            self.pool.clear()
        for c in cs:
            try:
                c.close()
            except Exception:
                pass

    def drop(self, c, key):
        with self.lk:
            if self.pool.get(key) is c:
                del self.pool[key]
        try:
            c.close()
        except Exception:
            pass

    def uses_px(self):
        return bool(self.pp or self.penv)

    def alt_for(self, u):
        if self.proto != "auto" or not self.h3 or u.scheme != "https" or self.uses_px():
            return None
        a = self.alt.get(u.origin)
        now = time.monotonic()
        if not a or a[0] < now or self.bad.get(u.origin, 0) > now:
            return None
        return a[1]

    def open_conn(self, u, px=None):
        tmo = self.tmo
        force = self.proto == "h2"
        if u.scheme == "https":
            if px is None and (self.proto == "h3" or self.alt_for(u)):
                port = u.port if self.proto == "h3" else self.alt_for(u)
                try:
                    from .h3 import open_h3
                    return open_h3(u, port, self.guard, tmo, self.verify, self.ca, self.lim)
                except ImportError as e:
                    if self.proto == "h3":
                        raise ClientError("HTTP/3 needs a working 'cryptography' install: %s" % e) from None
                    self.bad[u.origin] = time.monotonic() + 3600
                except Exception:
                    if self.proto == "h3":
                        raise
                    self.bad[u.origin] = time.monotonic() + 300
            alpn = ["http/1.1"] if self.proto == "h1" else ["h2", "http/1.1"]
            c = Conn.open(u, self.guard, tmo, self.verify, self.ca, alpn, px, self.pverify, self.pca, force)
            if c.alpn == "h2":
                c.sock.settimeout(None)
                return H2Conn(c, self.lim, tmo)
            if self.proto == "h2":
                c.close()
                raise ClientError("server did not negotiate h2")
            return H1Conn(c, self.lim)
        c = Conn.open(u, self.guard, tmo, self.verify, self.ca, None, px, self.pverify, self.pca, force)
        if self.proto == "h2":
            return H2Conn(c, self.lim, tmo)
        return H1Conn(c, self.lim)

    def retire(self, c):
        if isinstance(c, H1Conn):
            c.close()
            return
        t = threading.Timer(30.0, c.close)
        t.daemon = True
        t.start()

    def cap(self):
        vic = []
        with self.lk:
            while len(self.pool) > self.max_pool:
                vic.append(self.pool.pop(next(iter(self.pool))))
        for c in vic:
            self.retire(c)

    def try_h3(self, u, key):
        if not self.alt_for(u):
            return None
        with self.h3lk:
            with self.lk:
                cur = self.pool.get(key)
            if cur is not None and getattr(cur, "proto", None) == "h3" and cur.alive():
                return cur
            port = self.alt_for(u)
            if not port:
                return None
            try:
                from .h3 import open_h3
                c = open_h3(u, port, self.guard, self.tmo, self.verify, self.ca, self.lim)
            except Exception:
                self.bad[u.origin] = time.monotonic() + 300
                return None
            with self.lk:
                old = self.pool.get(key)
                self.pool[key] = c
            if old is not None:
                self.retire(old)
            return c

    def get_conn(self, u, px, key):
        with self.lk:
            c = self.pool.get(key)
            cur = getattr(c, "proto", None)
        if px is None and c is not None and cur != "h3" and self.alt_for(u):
            n = self.try_h3(u, key)
            if n is not None:
                return n, False
        with self.lk:
            c = self.pool.get(key)
            if c is not None:
                if isinstance(c, H1Conn):
                    del self.pool[key]
                    if c.alive():
                        return c, True
                    c.close()
                elif c.alive():
                    return c, True
                else:
                    del self.pool[key]
                    c.close()
        c = self.open_conn(u, px)
        if not isinstance(c, H1Conn):
            with self.lk:
                old = self.pool.get(key)
                if old is not None and not isinstance(old, H1Conn) and old.alive():
                    keep = old
                else:
                    self.pool[key] = c
                    keep = c
            if keep is not c:
                c.close()
                return keep, True
            self.cap()
        return c, False

    def give_back(self, c, key):
        if isinstance(c, H1Conn):
            if c.alive():
                with self.lk:
                    old = self.pool.get(key)
                    self.pool[key] = c
                if old is not None and old is not c:
                    old.close()
                self.cap()
            else:
                c.close()

    def prep(self, req, px=None):
        h = req.hdrs.copy()
        h.setdef("User-Agent", self.ua)
        h.setdef("Accept", "*/*")
        h.setdef("Accept-Encoding", AE)
        if self.jar is not None and "cookie" not in h:
            ck = self.jar.hdr_for(req.url)
            if ck:
                h.set("Cookie", ck)
        if px is not None and px.usr is not None and px.scheme in ("http", "https") and req.url.scheme == "http" and self.proto != "h2":
            h.set("Proxy-Authorization", px.auth)
        return Req(req.mth, req.url, h, req.body)

    def pick_px(self, u):
        if bypass(u.host, self.nop):
            return None
        if self.pp:
            return self.pp.pick(u.origin)
        if self.penv:
            return from_env(u.scheme)
        return None

    def hop_px(self, u, st):
        if bypass(u.host, self.nop):
            return None
        if self.penv:
            return from_env(u.scheme)
        return st["px"]

    def once(self, req, tmo=None, st=None):
        if st is None:
            st = {"px": None}
        u = req.url
        t0 = time.monotonic()
        stale = 0
        while True:
            px = self.hop_px(u, st)
            rq = self.prep(req, px)
            key = (u.origin, px.key if px else None)
            c, reused = self.get_conn(u, px, key)
            try:
                res = c.req(rq, tmo or self.tmo) if not isinstance(c, H1Conn) else c.req(rq)
            except H2Error as e:
                self.drop(c, key)
                if e.code == E_REFUSED and stale == 0:
                    stale += 1
                    continue
                raise
            except H3Error as e:
                self.drop(c, key)
                if getattr(e, "retry", False) and stale == 0:
                    stale += 1
                    continue
                raise
            except (ConnError, QuicError):
                self.drop(c, key)
                if stale == 0 and (reused or not isinstance(c, H1Conn)) and rq.mth in IDEM:
                    stale += 1
                    continue
                raise
            except HttpkitError:
                self.drop(c, key)
                raise
            self.give_back(c, key)
            break
        res.url = u
        res.elapsed = time.monotonic() - t0
        res.proxy = px.safe if px else None
        res.ua = rq.hdrs.get("user-agent")
        self.done(res, u)
        return res

    def done(self, res, u):
        if self.jar is not None:
            sc = res.hdrs.get_all("set-cookie")
            if sc:
                self.jar.put(u, sc)
        if self.proto == "auto" and self.h3 and u.scheme == "https" and res.proto != "h3" and not self.uses_px():
            for v in res.hdrs.get_all("alt-svc"):
                if v.strip() == "clear":
                    self.alt.pop(u.origin, None)
                    continue
                m = ALT.search(v)
                if m and h3_ok():
                    self.alt[u.origin] = (time.monotonic() + int(m.group(2) or 86400), int(m.group(1)))
        ce = res.hdrs.get("content-encoding")
        if ce and res.body:
            res.body = dec_enc(res.body, ce, self.lim.max_body)

    def req(self, mth, url, hdrs=None, body=None, json=None, follow=None, tmo=None, proxy=None):
        u = parse_url(url)
        h = self.hdrs.copy()
        for k, v in (hdrs.items() if hasattr(hdrs, "items") else (hdrs or [])):
            h.set(k, v)
        if "user-agent" not in h and self.up is not None:
            h.set("User-Agent", chk("User-Agent", self.up(u.origin))[1])
        if json is not None:
            body = _json.dumps(json).encode()
            h.setdef("Content-Type", "application/json")
        if isinstance(body, str):
            body = body.encode("utf-8")
        r = Req(mth, u, h, body or b"")
        fl = self.follow if follow is None else follow
        if proxy is None:
            px0 = self.pick_px(u)
        elif proxy == "direct":
            px0 = None
        else:
            px0 = parse_proxy(proxy)
        if px0 is not None and self.proto == "h3":
            raise ClientError("HTTP/3 cannot be used through a proxy")
        st = {"px": px0}
        hist = []
        seen = set()
        hop = 0
        while True:
            res = self.once(r, tmo, st)
            pl = plan(r, res, self.guard, seen, self.lim.max_redirs, hop) if fl else None
            if pl is None:
                break
            hist.append(res)
            r = pl.req
            hop += 1
        res.hist = hist
        return res

    def get(self, url, **kw):
        return self.req("GET", url, **kw)

    def head(self, url, **kw):
        return self.req("HEAD", url, **kw)

    def post(self, url, **kw):
        return self.req("POST", url, **kw)

    post_ = post

    def put(self, url, **kw):
        return self.req("PUT", url, **kw)

    def patch(self, url, **kw):
        return self.req("PATCH", url, **kw)

    def delete(self, url, **kw):
        return self.req("DELETE", url, **kw)

    def options(self, url, **kw):
        return self.req("OPTIONS", url, **kw)

    def map(self, urls, workers=8, **kw):
        def go(x):
            if isinstance(x, tuple):
                return self.req(x[0], x[1], **kw)
            return self.req("GET", x, **kw)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            return list(ex.map(go, urls))
