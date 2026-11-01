import json as _json

from .err import ClientError
from .hdr import Hdrs


class Req:
    def __init__(self, mth, url, hdrs=None, body=b""):
        self.mth = mth.upper()
        self.url = url
        self.hdrs = hdrs if hdrs is not None else Hdrs()
        self.body = body or b""

    def __repr__(self):
        return "Req(%s %s)" % (self.mth, self.url)


class Resp:
    def __init__(self, status, hdrs, body=b"", ver="", reason="", url=None, proto=""):
        self.status = status
        self.hdrs = hdrs
        self.body = body
        self.ver = ver
        self.reason = reason
        self.url = url
        self.proto = proto or ver
        self.hist = []
        self.trailers = Hdrs()
        self.elapsed = 0.0

    @property
    def ok(self):
        return 200 <= self.status < 400

    @property
    def enc(self):
        ct = self.hdrs.get("content-type", "") or ""
        for p in ct.split(";")[1:]:
            k, _, v = p.strip().partition("=")
            if k.lower() == "charset":
                return v.strip("\"'") or "utf-8"
        return "utf-8"

    def text(self):
        try:
            return self.body.decode(self.enc, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    def json(self):
        return _json.loads(self.body.decode("utf-8"))

    def raise_for_status(self):
        if self.status >= 400:
            raise ClientError("HTTP %d for %s" % (self.status, self.url))
        return self

    def __repr__(self):
        return "Resp(%d %s)" % (self.status, self.proto)
