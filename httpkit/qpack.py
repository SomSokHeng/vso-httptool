from .err import QpackError
from .hpack import SENS, huf_dec, huf_enc, huf_len, int_dec, int_enc

QST = (
    (":authority", ""), (":path", "/"), ("age", "0"), ("content-disposition", ""), ("content-length", "0"),
    ("cookie", ""), ("date", ""), ("etag", ""), ("if-modified-since", ""), ("if-none-match", ""),
    ("last-modified", ""), ("link", ""), ("location", ""), ("referer", ""), ("set-cookie", ""),
    (":method", "CONNECT"), (":method", "DELETE"), (":method", "GET"), (":method", "HEAD"),
    (":method", "OPTIONS"), (":method", "POST"), (":method", "PUT"), (":scheme", "http"),
    (":scheme", "https"), (":status", "103"), (":status", "200"), (":status", "304"),
    (":status", "404"), (":status", "503"), ("accept", "*/*"), ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"), ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"), ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"), ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"), ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"), ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"), ("content-encoding", "br"),
    ("content-encoding", "gzip"), ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"), ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"), ("content-type", "image/gif"),
    ("content-type", "image/jpeg"), ("content-type", "image/png"), ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"), ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"), ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    ("strict-transport-security", "max-age=31536000; includesubdomains"),
    ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
    ("vary", "accept-encoding"), ("vary", "origin"), ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"), (":status", "100"), (":status", "204"), (":status", "206"),
    (":status", "302"), (":status", "400"), (":status", "403"), (":status", "421"), (":status", "425"),
    (":status", "500"), ("accept-language", ""), ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"), ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"), ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"), ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"), ("access-control-request-method", "get"),
    ("access-control-request-method", "post"), ("alt-svc", "clear"), ("authorization", ""),
    ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
    ("early-data", "1"), ("expect-ct", ""), ("forwarded", ""), ("if-range", ""), ("origin", ""),
    ("purpose", "prefetch"), ("server", ""), ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"), ("user-agent", ""), ("x-forwarded-for", ""),
    ("x-frame-options", "deny"), ("x-frame-options", "sameorigin"),
)

QFULL = {}
QNAME = {}
for _i, (_n, _v) in enumerate(QST):
    QFULL.setdefault((_n, _v), _i)
    QNAME.setdefault(_n, _i)


def vstr(v):
    b = v.encode("latin-1") if isinstance(v, str) else v
    if huf_len(b) < len(b):
        h = huf_enc(b)
        return int_enc(len(h), 7, 0x80) + h
    return int_enc(len(b), 7, 0) + b


def enc(hl):
    out = bytearray(b"\x00\x00")
    for n, v in hl:
        n = n.lower()
        sens = n in SENS
        if not sens and (n, v) in QFULL:
            out += int_enc(QFULL[(n, v)], 6, 0xC0)
        elif n in QNAME:
            out += int_enc(QNAME[n], 4, 0x50 | (0x20 if sens else 0))
            out += vstr(v)
        else:
            nb = n.encode("latin-1")
            if huf_len(nb) < len(nb):
                h = huf_enc(nb)
                out += int_enc(len(h), 3, 0x28 | (0x10 if sens else 0)) + h
            else:
                out += int_enc(len(nb), 3, 0x20 | (0x10 if sens else 0)) + nb
            out += vstr(v)
    return bytes(out)


def rstr(b, pos, pb, hbit, mx):
    if pos >= len(b):
        raise QpackError("truncated string")
    h = b[pos] & hbit
    n, pos = int_dec(b, pos, pb)
    if n > mx or pos + n > len(b):
        raise QpackError("string length invalid")
    raw = bytes(b[pos:pos + n])
    pos += n
    if h:
        try:
            raw = huf_dec(raw, mx * 2)
        except Exception as e:
            raise QpackError("bad huffman string: %s" % e) from e
    return raw, pos


def dec(b, mx=65536):
    try:
        ric, pos = int_dec(b, 0, 8)
        if ric:
            raise QpackError("dynamic table reference but capacity is 0")
        _, pos = int_dec(b, pos, 7)
        out = []
        tot = 0
        n = len(b)
        while pos < n:
            c = b[pos]
            if c & 0x80:
                if not c & 0x40:
                    raise QpackError("dynamic table reference")
                i, pos = int_dec(b, pos, 6)
                if i >= len(QST):
                    raise QpackError("static index out of range")
                nm, v = QST[i]
            elif c & 0x40:
                if not c & 0x10:
                    raise QpackError("dynamic name reference")
                i, pos = int_dec(b, pos, 4)
                if i >= len(QST):
                    raise QpackError("static index out of range")
                nm = QST[i][0]
                raw, pos = rstr(b, pos, 7, 0x80, mx)
                v = raw.decode("latin-1")
            elif c & 0x20:
                ln_h = c & 0x08
                ln, p2 = int_dec(b, pos, 3)
                if ln > mx or p2 + ln > n:
                    raise QpackError("name length invalid")
                raw = bytes(b[p2:p2 + ln])
                pos = p2 + ln
                if ln_h:
                    raw = huf_dec(raw, mx * 2)
                nm = raw.decode("latin-1")
                raw, pos = rstr(b, pos, 7, 0x80, mx)
                v = raw.decode("latin-1")
            else:
                raise QpackError("post-base reference with empty dynamic table")
            tot += len(nm) + len(v) + 32
            if tot > mx:
                raise QpackError("field section too large")
            out.append((nm, v))
        return out
    except QpackError:
        raise
    except Exception as e:
        raise QpackError("malformed field section: %s" % e) from e
