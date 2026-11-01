import re

from .err import ConnError, SecError, BodyError
from .hdr import Hdrs, parse_hdrs, TOK
from .msg import Resp

STAT = re.compile(rb"^HTTP/1\.([01]) (\d{3})(?: ([\t\x20-\x7e\x80-\xff]*))?$")
CLEN = re.compile(rb"^\d{1,18}$")
HEXS = re.compile(rb"^[0-9a-fA-F]{1,16}$")


class Rdr:
    def __init__(self, sock, lim):
        self.s = sock
        self.b = bytearray()
        self.lim = lim
        self.eof = False

    def fill(self):
        try:
            d = self.s.recv(65536)
        except OSError as e:
            raise ConnError("recv failed: %s" % e) from e
        if not d:
            self.eof = True
            return False
        self.b += d
        return True

    def until(self, sep, mx):
        st = 0
        while True:
            i = self.b.find(sep, st)
            if i >= 0:
                if i > mx:
                    raise SecError("line or header block exceeds limit")
                out = bytes(self.b[:i])
                del self.b[:i + len(sep)]
                return out
            if len(self.b) > mx:
                raise SecError("line or header block exceeds limit")
            st = max(0, len(self.b) - len(sep) + 1)
            if not self.fill():
                raise ConnError("connection closed mid-message")

    def take(self, n):
        while len(self.b) < n:
            if not self.fill():
                raise ConnError("connection closed mid-body")
        out = bytes(self.b[:n])
        del self.b[:n]
        return out

    def rest(self, mx):
        while True:
            if len(self.b) > mx:
                raise SecError("body exceeds limit")
            if not self.fill():
                break
        out = bytes(self.b)
        self.b.clear()
        return out


def ser_req(req, keep=True):
    m = req.mth
    if not TOK.match(m.encode("latin-1")):
        raise SecError("bad method")
    t = req.url.target
    h = req.hdrs.copy()
    h.setdef("Host", req.url.authority)
    if not keep:
        h.set("Connection", "close")
    if req.body or m in ("POST", "PUT", "PATCH"):
        h.pop("Transfer-Encoding")
        h.set("Content-Length", str(len(req.body)))
    out = bytearray(("%s %s HTTP/1.1\r\n" % (m, t)).encode("ascii"))
    for k, v in h:
        out += k.encode("latin-1") + b": " + v.encode("latin-1") + b"\r\n"
    out += b"\r\n"
    return bytes(out) + req.body


def chk_framing(h):
    te = h.get_all("transfer-encoding")
    cl = h.get_all("content-length")
    if te and cl:
        raise SecError("both Transfer-Encoding and Content-Length present")
    chunked = False
    if te:
        toks = [x.strip().lower() for v in te for x in v.split(",") if x.strip()]
        if not toks or toks[-1] != "chunked" or toks.count("chunked") != 1:
            raise SecError("unsupported or ambiguous Transfer-Encoding")
        if len(toks) > 1:
            raise SecError("stacked transfer-codings unsupported")
        chunked = True
    n = None
    if cl:
        vals = {x.strip() for v in cl for x in v.split(",")}
        if len(vals) != 1:
            raise SecError("conflicting Content-Length values")
        v = vals.pop().encode("ascii", "replace")
        if not CLEN.match(v):
            raise SecError("invalid Content-Length")
        n = int(v)
    return chunked, n


def rd_chunked(rd, mx, lim):
    parts = []
    tot = 0
    while True:
        ln = rd.until(b"\r\n", 4096)
        sz = ln.split(b";", 1)[0].strip()
        if not HEXS.match(sz):
            raise BodyError("bad chunk size")
        n = int(sz, 16)
        if n == 0:
            break
        tot += n
        if tot > mx:
            raise SecError("body exceeds limit")
        parts.append(rd.take(n))
        if rd.take(2) != b"\r\n":
            raise BodyError("missing chunk terminator")
    tr = Hdrs()
    blk = []
    while True:
        ln = rd.until(b"\r\n", lim.max_hdr_b)
        if not ln:
            break
        blk.append(ln)
        if sum(len(x) for x in blk) > lim.max_hdr_b:
            raise SecError("trailers too large")
    if blk:
        tr = parse_hdrs(b"\r\n".join(blk), lim.max_hdrs, lim.max_hdr_b)
    return b"".join(parts), tr


def rd_resp(rd, mth, lim):
    while True:
        head = rd.until(b"\r\n\r\n", lim.max_hdr_b)
        sl, _, hb = head.partition(b"\r\n")
        m = STAT.match(sl)
        if not m:
            raise SecError("malformed status line")
        ver = "HTTP/1." + m.group(1).decode()
        st = int(m.group(2))
        rs = (m.group(3) or b"").decode("latin-1")
        if 100 <= st < 200 and st != 101:
            continue
        break
    h = parse_hdrs(hb, lim.max_hdrs, lim.max_hdr_b)
    r = Resp(st, h, b"", ver, rs, proto="http/1.1")
    keep = ver == "HTTP/1.1"
    cn = [x.strip().lower() for v in h.get_all("connection") for x in v.split(",")]
    if "close" in cn:
        keep = False
    elif ver == "HTTP/1.0":
        keep = "keep-alive" in cn
    if mth == "HEAD" or st in (204, 304) or 100 <= st < 200:
        return r, keep
    chunked, n = chk_framing(h)
    if chunked:
        r.body, r.trailers = rd_chunked(rd, lim.max_body, lim)
    elif n is not None:
        if n > lim.max_body:
            raise SecError("Content-Length exceeds limit")
        r.body = rd.take(n)
    else:
        r.body = rd.rest(lim.max_body)
        keep = False
    return r, keep


class H1Conn:
    proto = "http/1.1"

    def __init__(self, conn, lim):
        self.c = conn
        self.lim = lim
        self.rd = Rdr(conn.sock, lim)
        self.ok = True
        self.n = 0

    def alive(self):
        if not self.ok:
            return False
        return not self.rd.b

    def req(self, req):
        self.c.send(ser_req(req))
        self.n += 1
        try:
            r, keep = rd_resp(self.rd, req.mth, self.lim)
        except Exception:
            self.ok = False
            raise
        if not keep:
            self.ok = False
        r.url = req.url
        return r

    def close(self):
        self.ok = False
        self.c.close()
