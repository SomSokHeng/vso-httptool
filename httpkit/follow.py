from .err import ClientError
from .hdr import Hdrs
from .msg import Req
from .url import parse as parse_url

RED = (301, 302, 303, 307, 308)
SENS = ("authorization", "cookie", "proxy-authorization")


class Plan:
    def __init__(self, req, strip, why):
        self.req = req
        self.strip = strip
        self.why = why


def next_mth(mth, status):
    if status == 303:
        return "GET" if mth != "HEAD" else "HEAD"
    if status in (301, 302) and mth == "POST":
        return "GET"
    return mth


def plan(req, resp, guard, seen, max_redirs, hop):
    if resp.status not in RED:
        return None
    loc = resp.hdrs.get("location")
    if not loc:
        return None
    if hop >= max_redirs:
        raise ClientError("too many redirects (%d)" % max_redirs)
    try:
        dst = parse_url(loc, req.url)
    except Exception as e:
        raise ClientError("bad redirect location: %s" % e) from e
    guard.chk_redir(req.url, dst)
    mth = next_mth(req.mth, resp.status)
    body = req.body if mth == req.mth else b""
    if mth == req.mth and resp.status in (307, 308) and req.body is None:
        raise ClientError("cannot replay body")
    h = Hdrs()
    drop = {"host", "content-length", "transfer-encoding", "cookie"}
    if mth != req.mth:
        drop |= {"content-type", "content-encoding", "content-language", "content-location"}
    xo = dst.origin != req.url.origin
    if xo:
        drop |= set(SENS)
    for k, v in req.hdrs:
        if k.lower() not in drop:
            h.add(k, v)
    key = (mth, str(dst), body)
    if key in seen:
        raise ClientError("redirect loop detected")
    seen.add(key)
    return Plan(Req(mth, dst, h, body), xo, resp.status)
