import zlib

from .err import BodyError

try:
    import brotli as _br
except Exception:
    _br = None


def enc_chunked(data, sz=16384):
    out = []
    for i in range(0, len(data), sz):
        c = data[i:i + sz]
        out.append(b"%x\r\n" % len(c) + c + b"\r\n")
    out.append(b"0\r\n\r\n")
    return b"".join(out)


def dec_one(data, enc, lim):
    if enc in ("identity", ""):
        if len(data) > lim:
            raise BodyError("body exceeds limit")
        return data
    if enc in ("gzip", "x-gzip", "deflate"):
        wb = 31 if enc != "deflate" else 15
        d = zlib.decompressobj(wb)
        try:
            out = d.decompress(data, lim + 1)
            if len(out) > lim or d.unconsumed_tail:
                raise BodyError("decompressed body exceeds limit")
            return out
        except zlib.error as e:
            if enc == "deflate":
                d = zlib.decompressobj(-15)
                try:
                    out = d.decompress(data, lim + 1)
                    if len(out) > lim:
                        raise BodyError("decompressed body exceeds limit")
                    return out
                except zlib.error:
                    pass
            raise BodyError("bad %s data" % enc) from e
    if enc == "br":
        if _br is None:
            raise BodyError("brotli not installed")
        try:
            out = _br.decompress(data)
        except Exception as e:
            raise BodyError("bad br data") from e
        if len(out) > lim:
            raise BodyError("decompressed body exceeds limit")
        return out
    raise BodyError("unsupported content-encoding: %s" % enc)


def dec_enc(data, ce, lim, max_ratio=1000, max_layers=3):
    if not ce:
        return data
    encs = [e.strip().lower() for e in ce.split(",") if e.strip()]
    if len(encs) > max_layers:
        raise BodyError("too many content-encoding layers")
    n0 = max(len(data), 1)
    for e in reversed(encs):
        data = dec_one(data, e, lim)
        if len(data) / n0 > max_ratio and len(data) > 1 << 20:
            raise BodyError("decompression ratio too high")
    return data
