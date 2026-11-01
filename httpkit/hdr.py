import re

from .err import HdrError

TOK = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
VAL = re.compile(rb"^[\t\x20-\x7e\x80-\xff]*$")
MAX_N = 256
MAX_B = 65536


def chk(name, val):
    nb = name.encode("latin-1") if isinstance(name, str) else name
    vb = val.encode("latin-1") if isinstance(val, str) else val
    if not TOK.match(nb):
        raise HdrError("bad header name: %r" % nb[:40])
    if not VAL.match(vb):
        raise HdrError("bad header value for %s" % nb[:40].decode("latin-1"))
    return nb.decode("latin-1"), vb.decode("latin-1").strip(" \t")


class Hdrs:
    def __init__(self, items=None):
        self.lst = []
        if items:
            it = items.items() if hasattr(items, "items") else items
            for k, v in it:
                self.add(k, v)

    def add(self, k, v):
        k, v = chk(k, v)
        self.lst.append((k, v))

    def set(self, k, v):
        k, v = chk(k, v)
        lk = k.lower()
        self.lst = [(a, b) for a, b in self.lst if a.lower() != lk]
        self.lst.append((k, v))

    def setdef(self, k, v):
        if k not in self:
            self.add(k, v)

    def get(self, k, d=None):
        lk = k.lower()
        for a, b in self.lst:
            if a.lower() == lk:
                return b
        return d

    def get_all(self, k):
        lk = k.lower()
        return [b for a, b in self.lst if a.lower() == lk]

    def pop(self, k, d=None):
        v = self.get(k, d)
        lk = k.lower()
        self.lst = [(a, b) for a, b in self.lst if a.lower() != lk]
        return v

    def items(self):
        return list(self.lst)

    def copy(self):
        n = Hdrs()
        n.lst = list(self.lst)
        return n

    def __contains__(self, k):
        lk = k.lower()
        return any(a.lower() == lk for a, _ in self.lst)

    def __len__(self):
        return len(self.lst)

    def __iter__(self):
        return iter(self.lst)

    def __repr__(self):
        return "Hdrs(%r)" % (self.lst,)


def parse_hdrs(raw, max_n=MAX_N, max_b=MAX_B):
    if len(raw) > max_b:
        raise HdrError("header block too large")
    out = Hdrs()
    n = 0
    for ln in raw.split(b"\r\n"):
        if not ln:
            continue
        if ln[:1] in (b" ", b"\t"):
            raise HdrError("obsolete line folding rejected")
        if b"\n" in ln or b"\r" in ln or b"\x00" in ln:
            raise HdrError("bare control char in header")
        i = ln.find(b":")
        if i <= 0:
            raise HdrError("malformed header line")
        k, v = ln[:i], ln[i + 1:]
        if not TOK.match(k):
            raise HdrError("bad header name: %r" % k[:40])
        if not VAL.match(v):
            raise HdrError("bad header value")
        n += 1
        if n > max_n:
            raise HdrError("too many headers")
        out.lst.append((k.decode("latin-1"), v.decode("latin-1").strip(" \t")))
    return out
