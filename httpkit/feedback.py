import json
import re

STG = (("ProxyError", "proxy"), ("TlsError", "tls"), ("SecError", "security"), ("UrlError", "input"), ("HdrError", "input"),
       ("BodyError", "decode"), ("HpackError", "http2"), ("H2Error", "http2"), ("QpackError", "http3"), ("H3Error", "http3"),
       ("QuicError", "quic"), ("ClientError", "client"), ("ConnError", "network"))

HINTS = (
    (r"\b407\b", "the proxy wants credentials: use user:pass@host:port"),
    (r"refused connect", "the proxy refused to tunnel to this host or port (its own rules); try another proxy"),
    (r"cannot connect to proxy|proxy closed|proxy .* failed", "the proxy is down, unreachable, or not the type you set (http, https, socks4, socks5); the tool does not skip dead proxies, so check or replace it"),
    (r"not a socks5|bad socks|socks.*(reply|reject|error)", "wrong proxy type? try http://, socks4:// or socks5:// for this proxy"),
    (r"cannot resolve|dns failure|name or service not known|nodename nor servname|getaddrinfo", "DNS lookup failed: check the hostname; socks5h and http(s) proxies resolve names at the proxy"),
    (r"certificate verify|self.signed|local issuer|hostname mismatch|doesn't match|certificate verification", "the certificate is not trusted: pass ca=<bundle> for a private CA, fix the hostname, or use verify=False only on a network you trust"),
    (r"tls|ssl|handshake", "TLS handshake failed: the server or proxy may not speak TLS on this port; try http:// or another proxy scheme"),
    (r"timed out|timeout", "timed out: raise tmo=, or the host or proxy is slow or filtered"),
    (r"connection refused", "nothing is listening on that host:port, or a firewall rejected it"),
    (r"private address|disallowed scheme|https to http", "the redirect guard blocked this: use InfGuard(blk_priv=False) / --priv or allow_downgrade=True only if you intend it"),
    (r"exceeds limit", "the response is bigger than the limit: raise Lim(max_body=...)"),
    (r"ratio too high|decompress", "possible compression bomb: the tool refuses extreme compression ratios"),
    (r"too many redirects|redirect loop", "the redirect chain is too long or loops: check the server or raise Lim(max_redirs=...)"),
    (r"http/3|cryptography", "HTTP/3 needs a working cryptography install; h1 and h2 work without it"),
    (r"closed by peer|connection closed|reset|broken pipe", "the peer closed the connection: a server or proxy limit, or a stale connection"),
)

SEC_HDRS = (("strict-transport-security", "no HSTS header"), ("x-content-type-options", "no X-Content-Type-Options header"))


def stage(e, tr=None):
    if tr is not None:
        for p in reversed(tr.prob):
            if p["kind"] in ("dns", "tcp", "tls", "proxy"):
                return p["kind"]
    s = "unknown"
    for cls in type(e).__mro__:
        for n, v in STG:
            if cls.__name__ == n:
                s = v
                break
        if s != "unknown":
            break
    return s


def hint(e):
    m = ("%s %s" % (type(e).__name__, e)).lower()
    for pat, h in HINTS:
        if re.search(pat, m):
            return h
    return ""


def chain(e):
    out = []
    seen = set()
    while e is not None and id(e) not in seen and len(out) < 6:
        seen.add(id(e))
        out.append("%s: %s" % (type(e).__name__, str(e)[:200]))
        e = e.__cause__ or (None if e.__suppress_context__ else e.__context__)
    return out


def lint(tr, res, verify, px, rq, retried):
    if not verify:
        tr.add("problem", "certificate verification is disabled", True)
    st = res.status
    if st >= 500:
        tr.add("problem", "server error %d" % st, True)
    elif st == 429:
        tr.add("problem", "rate limited (Retry-After: %s)" % res.hdrs.get("retry-after", "-"), True)
    elif st == 407:
        tr.add("problem", "proxy authentication required (407)", True)
    elif st in (401, 403):
        tr.add("problem", "access denied (%d)" % st, True)
    elif st >= 400:
        tr.add("problem", "client error %d" % st, True)
    if retried:
        tr.add("problem", "a stale or refused connection was retried", True)
    if res.t_hdr and res.t_send and (res.t_hdr - res.t_send) > 2.0:
        tr.add("problem", "slow first byte: %.0f ms" % ((res.t_hdr - res.t_send) * 1000), True)
    t = res.tls or {}
    if t.get("cert_days") is not None and t["cert_days"] < 14:
        tr.add("problem", "certificate expires in %d days" % t["cert_days"], True)
    if t.get("version") in ("TLSv1.2", "TLSv1.1", "TLSv1"):
        tr.add("note", "negotiated %s (TLS 1.3 not used)" % t["version"])
    if px is not None and rq.url.scheme == "http" and px.scheme in ("http", "https", "socks4", "socks4a", "socks5", "socks5h"):
        tr.add("note", "plain http through a proxy: the proxy can read and change this traffic")
    if rq.url.scheme == "https":
        for h, m in SEC_HDRS:
            if h not in res.hdrs:
                tr.add("note", m)
    sv = res.hdrs.get("server", "")
    if re.search(r"\d+\.\d+", sv):
        tr.add("note", "server banner exposes a version: %s" % sv[:60])
    for c in res.hdrs.get_all("set-cookie"):
        low = c.lower()
        miss = [n for n, k in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite")) if k not in low]
        if miss and rq.url.scheme == "https":
            tr.add("note", "cookie %s lacks %s" % (c.split("=", 1)[0][:30], ", ".join(miss)))
    if res.body and not res.hdrs.get("content-type"):
        tr.add("note", "response has a body but no Content-Type")


def fb_res(res):
    tr = res.trace
    tm = {k: round(v) for k, v in (res.tm or {}).items()}
    probs = [e["msg"] for e in (tr.prob if tr else [])]
    notes = [e["msg"] for e in (tr.ev if tr else []) if e["kind"] == "note"]
    return {
        "request": {"url": str(res.url), "status": res.status, "proto": res.proto, "proxy": res.proxy, "ua": res.ua, "reused_connection": bool(res.reused)},
        "timing_ms": tm,
        "tls": dict(res.tls) if res.tls else None,
        "response": {"headers": len(res.hdrs), "bytes": len(res.body), "wire_bytes": res.wire, "content_encoding": res.enc_in, "content_type": res.hdrs.get("content-type"), "trailers": len(res.trailers)},
        "redirects": [{"status": h.status, "location": h.hdrs.get("location")} for h in res.hist],
        "cookies_set": len(res.hdrs.get_all("set-cookie")),
        "problems": probs,
        "notes": notes,
        "events": [{"t": e["t"], "kind": e["kind"], "msg": e["msg"], "bad": e["bad"]} for e in (tr.ev if tr else [])],
    }


def fb_err(e):
    tr = getattr(e, "vso_trace", None)
    return {
        "error": type(e).__name__,
        "message": str(e)[:400],
        "stage": stage(e, tr),
        "causes": chain(e),
        "hint": hint(e),
        "problems": [p["msg"] for p in (tr.prob if tr else []) if p["kind"] != "error"],
        "events": [{"t": x["t"], "kind": x["kind"], "msg": x["msg"], "bad": x["bad"]} for x in (tr.ev if tr else [])],
    }


def fb_text(fb, events=False):
    ln = ["== feedback " + "=" * 40]
    if "error" in fb:
        ln.append("failed    %s at stage '%s'" % (fb["error"], fb["stage"]))
        ln.append("message   %s" % fb["message"])
        for c in fb["causes"][1:]:
            ln.append("cause     %s" % c)
        if fb["hint"]:
            ln.append("hint      %s" % fb["hint"])
    else:
        r = fb["request"]
        ln.append("request   %s -> %d (%s)" % (r["url"], r["status"], r["proto"]))
        if r["proxy"]:
            ln.append("via       %s" % r["proxy"])
        ln.append("agent     %s" % (r["ua"] or "-"))
        t = fb["timing_ms"]
        order = [k for k in ("dns", "tcp", "proxy", "tls", "ttfb", "total") if k in t]
        ln.append("timing    %s%s" % (" | ".join("%s %d ms" % (k, t[k]) for k in order), "   (pooled connection reused)" if r["reused_connection"] else ""))
        if fb["tls"]:
            x = fb["tls"]
            ln.append("tls       %s %s alpn=%s%s" % (x.get("version"), x.get("cipher"), x.get("alpn"), "  cert expires in %d days" % x["cert_days"] if x.get("cert_days") is not None else ""))
        p = fb["response"]
        dec = "" if not p["content_encoding"] else " (decoded from %d bytes %s)" % (p["wire_bytes"] or 0, p["content_encoding"])
        ln.append("body      %d bytes%s  type=%s  headers=%d" % (p["bytes"], dec, p["content_type"], p["headers"]))
        if fb["redirects"]:
            ln.append("redirects %s" % " ; ".join("%d -> %s" % (x["status"], x["location"]) for x in fb["redirects"]))
        ln.append("cookies   %d set" % fb["cookies_set"])
    ln.append("problems  %d" % len(fb["problems"]))
    for x in fb["problems"]:
        ln.append("  ! %s" % x)
    if "notes" in fb:
        ln.append("notes     %d" % len(fb["notes"]))
        for x in fb["notes"]:
            ln.append("  - %s" % x)
    if events:
        ln.append("events")
        for e in fb["events"]:
            ln.append("  [%8.1f ms] %s %-8s %s" % (e["t"], "!" if e["bad"] else " ", e["kind"], e["msg"]))
    return "\n".join(ln)


def fb_json(fb):
    return json.dumps(fb, indent=2, default=str)
