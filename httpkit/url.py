import re
from urllib.parse import urlsplit, urljoin, quote

from .err import UrlError

BAD = re.compile(r"[\x00-\x20\x7f\\]")
DEF = {"http": 80, "https": 443}


class Url:
    __slots__ = ("scheme", "host", "port", "path", "query")

    def __init__(self, scheme, host, port, path, query):
        self.scheme = scheme
        self.host = host
        self.port = port
        self.path = path or "/"
        self.query = query

    @property
    def target(self):
        return self.path + ("?" + self.query if self.query else "")

    @property
    def authority(self):
        h = "[%s]" % self.host if ":" in self.host else self.host
        return h if self.port == DEF[self.scheme] else "%s:%d" % (h, self.port)

    @property
    def origin(self):
        return (self.scheme, self.host, self.port)

    def __str__(self):
        return "%s://%s%s" % (self.scheme, self.authority, self.target)

    def __repr__(self):
        return "Url(%s)" % self


def enc_host(h):
    if not h:
        raise UrlError("empty host")
    try:
        h.encode("ascii")
        return h.lower()
    except UnicodeEncodeError:
        try:
            return h.encode("idna").decode("ascii").lower()
        except UnicodeError as e:
            raise UrlError("bad idna host") from e


def parse(s, base=None):
    if isinstance(s, Url):
        return s
    if base is not None:
        s = urljoin(str(base), s)
    if BAD.search(s):
        raise UrlError("illegal char in url")
    p = urlsplit(s)
    if p.scheme not in DEF:
        raise UrlError("unsupported scheme: %r" % p.scheme)
    if p.username is not None or p.password is not None:
        raise UrlError("userinfo in url not allowed")
    if not p.hostname:
        raise UrlError("missing host")
    try:
        port = p.port or DEF[p.scheme]
    except ValueError as e:
        raise UrlError("bad port") from e
    if not 0 < port < 65536:
        raise UrlError("bad port")
    host = enc_host(p.hostname)
    path = quote(p.path, safe="/%:@!$&'()*+,;=-._~") or "/"
    qry = quote(p.query, safe="/%:@!$&'()*+,;=-._~?")
    return Url(p.scheme, host, port, path, qry)


def join(base, ref):
    return parse(ref, base)
