from ._huf import HUF
from .err import HpackError

ST = (
    (":authority", ""), (":method", "GET"), (":method", "POST"), (":path", "/"),
    (":path", "/index.html"), (":scheme", "http"), (":scheme", "https"), (":status", "200"),
    (":status", "204"), (":status", "206"), (":status", "304"), (":status", "400"),
    (":status", "404"), (":status", "500"), ("accept-charset", ""), ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""), ("accept-ranges", ""), ("accept", ""), ("access-control-allow-origin", ""),
    ("age", ""), ("allow", ""), ("authorization", ""), ("cache-control", ""),
    ("content-disposition", ""), ("content-encoding", ""), ("content-language", ""), ("content-length", ""),
    ("content-location", ""), ("content-range", ""), ("content-type", ""), ("cookie", ""),
    ("date", ""), ("etag", ""), ("expect", ""), ("expires", ""), ("from", ""), ("host", ""),
    ("if-match", ""), ("if-modified-since", ""), ("if-none-match", ""), ("if-range", ""),
    ("if-unmodified-since", ""), ("last-modified", ""), ("link", ""), ("location", ""),
    ("max-forwards", ""), ("proxy-authenticate", ""), ("proxy-authorization", ""), ("range", ""),
    ("referer", ""), ("refresh", ""), ("retry-after", ""), ("server", ""), ("set-cookie", ""),
    ("strict-transport-security", ""), ("transfer-encoding", ""), ("user-agent", ""), ("vary", ""),
    ("via", ""), ("www-authenticate", ""),
)

ST_FULL = {}
ST_NAME = {}
for _i, (_n, _v) in enumerate(ST, 1):
    ST_FULL.setdefault((_n, _v), _i)
    ST_NAME.setdefault(_n, _i)

SENS = frozenset(("authorization", "cookie", "set-cookie", "proxy-authorization"))

HTRIE = {}
for _s, (_c, _l) in enumerate(HUF):
    HTRIE[(_c, _l)] = _s


def huf_enc(b):
    acc = 0
    nb = 0
    out = bytearray()
    for ch in b:
        c, l = HUF[ch]
        acc = (acc << l) | c
        nb += l
        while nb >= 8:
            nb -= 8
            out.append((acc >> nb) & 0xFF)
    if nb:
        out.append(((acc << (8 - nb)) | ((1 << (8 - nb)) - 1)) & 0xFF)
    return bytes(out)


def huf_len(b):
    return (sum(HUF[ch][1] for ch in b) + 7) // 8


def huf_dec(b, max_out=1 << 20):
    out = bytearray()
    code = 0
    ln = 0
    for byte in b:
        for i in range(7, -1, -1):
            code = (code << 1) | ((byte >> i) & 1)
            ln += 1
            s = HTRIE.get((code, ln))
            if s is not None:
                if s == 256:
                    raise HpackError("EOS in huffman string")
                out.append(s)
                if len(out) > max_out:
                    raise HpackError("huffman output too large")
                code = 0
                ln = 0
            elif ln > 30:
                raise HpackError("bad huffman code")
    if ln > 7 or code != (1 << ln) - 1:
        raise HpackError("bad huffman padding")
    return bytes(out)


def int_enc(v, pb, first=0):
    mx = (1 << pb) - 1
    if v < mx:
        return bytes([first | v])
    out = bytearray([first | mx])
    v -= mx
    while v >= 128:
        out.append((v & 127) | 128)
        v >>= 7
    out.append(v)
    return bytes(out)


def int_dec(b, pos, pb):
    if pos >= len(b):
        raise HpackError("truncated integer")
    mx = (1 << pb) - 1
    v = b[pos] & mx
    pos += 1
    if v < mx:
        return v, pos
    m = 0
    while True:
        if pos >= len(b):
            raise HpackError("truncated integer")
        x = b[pos]
        pos += 1
        v += (x & 127) << m
        m += 7
        if m > 56 or v > (1 << 40):
            raise HpackError("integer overflow")
        if not x & 128:
            return v, pos


def str_enc(s, huf=True):
    b = s if isinstance(s, bytes) else s.encode("latin-1")
    if huf and huf_len(b) < len(b):
        h = huf_enc(b)
        return int_enc(len(h), 7, 0x80) + h
    return int_enc(len(b), 7, 0) + b


def str_dec(b, pos, max_len):
    if pos >= len(b):
        raise HpackError("truncated string")
    h = b[pos] & 0x80
    n, pos = int_dec(b, pos, 7)
    if n > max_len or pos + n > len(b):
        raise HpackError("string length invalid")
    raw = bytes(b[pos:pos + n])
    pos += n
    if h:
        raw = huf_dec(raw, max_len * 2)
    return raw, pos


class Tbl:
    def __init__(self, mx=4096):
        self.mx = mx
        self.cap = mx
        self.ents = []
        self.sz = 0

    def ev(self, need=0):
        while self.ents and self.sz + need > self.cap:
            n, v = self.ents.pop()
            self.sz -= len(n) + len(v) + 32

    def add(self, n, v):
        es = len(n) + len(v) + 32
        if es > self.cap:
            self.ents.clear()
            self.sz = 0
            return
        self.ev(es)
        self.ents.insert(0, (n, v))
        self.sz += es

    def resize(self, cap):
        self.cap = cap
        self.ev()

    def get(self, i):
        if i < 1:
            raise HpackError("index 0")
        if i <= len(ST):
            return ST[i - 1]
        j = i - len(ST) - 1
        if j >= len(self.ents):
            raise HpackError("index out of range: %d" % i)
        return self.ents[j]

    def find(self, n, v):
        fi = ST_FULL.get((n, v))
        if fi:
            return fi, True
        for j, (en, ev) in enumerate(self.ents):
            if en == n and ev == v:
                return len(ST) + 1 + j, True
        ni = ST_NAME.get(n)
        if ni:
            return ni, False
        for j, (en, _) in enumerate(self.ents):
            if en == n:
                return len(ST) + 1 + j, False
        return 0, False


class HpackEnc:
    def __init__(self, mx=4096):
        self.t = Tbl(mx)
        self.lim = mx
        self.pend = None

    def set_max(self, n):
        n = min(n, self.lim)
        if n != self.t.cap:
            self.pend = n if self.pend is None else min(self.pend, n)
            self.t.resize(n)

    def enc(self, hdrs):
        out = bytearray()
        if self.pend is not None:
            out += int_enc(self.pend, 5, 0x20)
            self.pend = None
        for n, v in hdrs:
            n = n.lower()
            if n in SENS:
                ni, _ = self.t.find(n, "\x00")
                if ni:
                    out += int_enc(ni, 4, 0x10)
                else:
                    out += b"\x10" + str_enc(n)
                out += str_enc(v)
                continue
            i, full = self.t.find(n, v)
            if full:
                out += int_enc(i, 7, 0x80)
                continue
            if i:
                out += int_enc(i, 6, 0x40)
            else:
                out += b"\x40" + str_enc(n)
            out += str_enc(v)
            self.t.add(n, v)
        return bytes(out)


class HpackDec:
    def __init__(self, mx=4096, max_list=65536):
        self.t = Tbl(mx)
        self.lim = mx
        self.max_list = max_list

    def dec(self, b):
        out = []
        pos = 0
        tot = 0
        n = len(b)
        seen_hdr = False
        while pos < n:
            c = b[pos]
            if c & 0x80:
                i, pos = int_dec(b, pos, 7)
                name, val = self.t.get(i)
                add = False
            elif c & 0x40:
                i, pos = int_dec(b, pos, 6)
                if i:
                    name = self.t.get(i)[0]
                else:
                    raw, pos = str_dec(b, pos, self.max_list)
                    name = raw.decode("latin-1")
                raw, pos = str_dec(b, pos, self.max_list)
                val = raw.decode("latin-1")
                add = True
            elif c & 0x20:
                if seen_hdr:
                    raise HpackError("table size update after header")
                sz, pos = int_dec(b, pos, 5)
                if sz > self.lim:
                    raise HpackError("table size update exceeds limit")
                self.t.resize(sz)
                continue
            else:
                i, pos = int_dec(b, pos, 4)
                if i:
                    name = self.t.get(i)[0]
                else:
                    raw, pos = str_dec(b, pos, self.max_list)
                    name = raw.decode("latin-1")
                raw, pos = str_dec(b, pos, self.max_list)
                val = raw.decode("latin-1")
                add = False
            seen_hdr = True
            tot += len(name) + len(val) + 32
            if tot > self.max_list:
                raise HpackError("header list too large")
            out.append((name, val))
            if add:
                self.t.add(name, val)
        return out
