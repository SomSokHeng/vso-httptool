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
from .hdr import Hdrs
from .msg import Req
from .sec import InfGuard, Lim
from .ua import VSO_UA
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
    def __init__(self, proto="auto", verify=True, ca=None, tmo=30.0, follow=True, jar=True, hdrs=None, lim=None, guard=None, ua=VSO_UA, h3=True):
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

    def drop(self, c, origin):
        with self.lk:
            if self.pool.get(origin) is c:
                del self.pool[origin]
        try:
            c.close()
        except Exception:
            pass

    def alt_for(self, u):
        if self.proto != "auto" or not self.h3 or u.scheme != "https":
            return None
        a = self.alt.get(u.origin)
        now = time.monotonic()
        if not a or a[0] < now or self.bad.get(u.origin, 0) > now:
            return None
        return a[1]

    def open_conn(self, u):
        tmo = self.tmo
        if u.scheme == "https":
            if self.proto == "h3" or self.alt_for(u):
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
            c = Conn.open(u, self.guard, tmo, self.verify, self.ca, alpn)
            if c.alpn == "h2":
                c.sock.settimeout(None)
                return H2Conn(c, self.lim, tmo)
            if self.proto == "h2":
                c.close()
                raise ClientError("server did not negotiate h2")
            return H1Conn(c, self.lim)
        c = Conn.open(u, self.guard, tmo)
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

    def try_h3(self, u):
        if not self.alt_for(u):
            return None
        with self.h3lk:
            with self.lk:
                cur = self.pool.get(u.origin)
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
                old = self.pool.get(u.origin)
                self.pool[u.origin] = c
            if old is not None:
                self.retire(old)
            return c

    def get_conn(self, u):
        with self.lk:
            c = self.pool.get(u.origin)
            cur = getattr(c, "proto", None)
        if c is not None and cur != "h3" and self.alt_for(u):
            n = self.try_h3(u)
            if n is not None:
                return n, False
        with self.lk:
            c = self.pool.get(u.origin)
            if c is not None:
                if isinstance(c, H1Conn):
                    del self.pool[u.origin]
                    if c.alive():
                        return c, True
                    c.close()
                elif c.alive():
                    return c, True
                else:
                    del self.pool[u.origin]
                    c.close()
        c = self.open_conn(u)
        if not isinstance(c, H1Conn):
            with self.lk:
                old = self.pool.get(u.origin)
                if old is not None and not isinstance(old, H1Conn) and old.alive():
                    keep = old
                else:
                    self.pool[u.origin] = c
                    keep = c
            if keep is not c:
                c.close()
                return keep, True
        return c, False

    def give_back(self, c, u):
        if isinstance(c, H1Conn):
            if c.alive():
                with self.lk:
                    old = self.pool.get(u.origin)
                    self.pool[u.origin] = c
                if old is not None and old is not c:
                    old.close()
            else:
                c.close()

    def prep(self, req):
        h = req.hdrs.copy()
        h.setdef("User-Agent", self.ua)
        h.setdef("Accept", "*/*")
        h.setdef("Accept-Encoding", AE)
        if self.jar is not None and "cookie" not in h:
            ck = self.jar.hdr_for(req.url)
            if ck:
                h.set("Cookie", ck)
        return Req(req.mth, req.url, h, req.body)

    def once(self, req, tmo=None):
        u = req.url
        rq = self.prep(req)
        t0 = time.monotonic()
        last = None
        for att in range(2):
            c, reused = self.get_conn(u)
            try:
                res = c.req(rq, tmo or self.tmo) if not isinstance(c, H1Conn) else c.req(rq)
            except H2Error as e:
                self.drop(c, u.origin)
                last = e
                if e.code == E_REFUSED and att == 0:
                    continue
                raise
            except H3Error as e:
                self.drop(c, u.origin)
                last = e
                if getattr(e, "retry", False) and att == 0:
                    continue
                raise
            except (ConnError, QuicError) as e:
                self.drop(c, u.origin)
                last = e
                if att == 0 and (reused or not isinstance(c, H1Conn)) and rq.mth in IDEM:
                    continue
                raise
            except HttpkitError:
                self.drop(c, u.origin)
                raise
            self.give_back(c, u)
            break
        else:
            raise last
        res.url = u
        res.elapsed = time.monotonic() - t0
        self.post(res, u)
        return res

    def post(self, res, u):
        if self.jar is not None:
            sc = res.hdrs.get_all("set-cookie")
            if sc:
                self.jar.put(u, sc)
        if self.proto == "auto" and self.h3 and u.scheme == "https" and res.proto != "h3":
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

    def req(self, mth, url, hdrs=None, body=None, json=None, follow=None, tmo=None):
        u = parse_url(url)
        h = self.hdrs.copy()
        for k, v in (hdrs.items() if hasattr(hdrs, "items") else (hdrs or [])):
            h.set(k, v)
        if json is not None:
            body = _json.dumps(json).encode()
            h.setdef("Content-Type", "application/json")
        if isinstance(body, str):
            body = body.encode("utf-8")
        r = Req(mth, u, h, body or b"")
        fl = self.follow if follow is None else follow
        hist = []
        seen = set()
        hop = 0
        while True:
            res = self.once(r, tmo)
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

    def post_(self, url, **kw):
        return self.req("POST", url, **kw)

    def put(self, url, **kw):
        return self.req("PUT", url, **kw)

    def delete(self, url, **kw):
        return self.req("DELETE", url, **kw)

    def map(self, urls, workers=8, **kw):
        def go(x):
            if isinstance(x, tuple):
                return self.req(x[0], x[1], **kw)
            return self.req("GET", x, **kw)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            return list(ex.map(go, urls))
