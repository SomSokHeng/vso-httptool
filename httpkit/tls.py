import hashlib
import socket
import ssl

from . import _vso
from .conn import mk_ctx
from .err import TlsError

SUITES = {
    0x1301: ("TLS_AES_128_GCM_SHA256", "sha256", 16),
    0x1302: ("TLS_AES_256_GCM_SHA384", "sha384", 32),
    0x1303: ("TLS_CHACHA20_POLY1305_SHA256", "sha256", 32),
}

WEAK = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "anon")


def cipher_info(name):
    for v, (n, h, kl) in SUITES.items():
        if n == name:
            return {"id": v, "name": n, "hash": h, "key_bits": kl * 8, "tls": "1.3"}
    weak = any(w in name for w in WEAK)
    return {"id": None, "name": name, "hash": None, "key_bits": None, "tls": "1.2", "weak": weak}


def insp(host, port=443, tmo=10.0, verify=True, ca=None, alpn=("h2", "http/1.1")):
    _vso.inf_warn()
    ctx = mk_ctx(verify, ca, alpn)
    try:
        raw = socket.create_connection((host, port), tmo)
        s = ctx.wrap_socket(raw, server_hostname=host)
    except (ssl.SSLError, OSError) as e:
        raise TlsError("tls inspect failed: %s" % e) from e
    try:
        der = s.getpeercert(binary_form=True)
        ci = s.cipher()
        out = {
            "host": host,
            "port": port,
            "version": s.version(),
            "cipher": cipher_info(ci[0]) if ci else None,
            "alpn": s.selected_alpn_protocol(),
            "verified": verify,
            "cert_sha256": hashlib.sha256(der).hexdigest() if der else None,
        }
        if verify:
            pc = s.getpeercert()
            out["subject"] = dict(x[0] for x in pc.get("subject", ()))
            out["issuer"] = dict(x[0] for x in pc.get("issuer", ()))
            out["not_after"] = pc.get("notAfter")
            out["san"] = [v for _, v in pc.get("subjectAltName", ())]
        return out
    finally:
        s.close()


def fmt_insp(d):
    ln = ["%s:%s" % (d["host"], d["port"]), "  tls     %s" % d["version"]]
    c = d["cipher"]
    if c:
        ln.append("  cipher  %s%s" % (c["name"], "  (weak)" if c.get("weak") else ""))
    ln.append("  alpn    %s" % d["alpn"])
    if "subject" in d:
        ln.append("  subject %s" % d["subject"].get("commonName", d["subject"]))
        ln.append("  issuer  %s" % d["issuer"].get("organizationName", d["issuer"]))
        ln.append("  expires %s" % d["not_after"])
        ln.append("  san     %s" % ", ".join(d["san"][:6]))
    ln.append("  sha256  %s" % d["cert_sha256"])
    return "\n".join(ln)
