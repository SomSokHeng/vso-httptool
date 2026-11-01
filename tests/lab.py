import datetime
import ipaddress
import os
import socket
import subprocess
import sys
import tempfile
import time

APP = '''
import json, os
QP = os.environ.get("LAB_QPORT", "4433")
async def app(scope, receive, send):
    if scope["type"] == "lifespan":
        while True:
            m = await receive()
            if m["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            else:
                await send({"type": "lifespan.shutdown.complete"})
                return
    if scope["type"] != "http":
        return
    body = b""
    while True:
        m = await receive()
        body += m.get("body", b"")
        if not m.get("more_body"):
            break
    p = scope["path"]
    hd = dict((k.decode(), v.decode()) for k, v in scope["headers"])
    if p == "/big":
        data = b"x" * 3000000
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", str(len(data)).encode())]})
        await send({"type": "http.response.body", "body": data})
        return
    if p == "/redir":
        await send({"type": "http.response.start", "status": 302, "headers": [(b"location", b"/echo?x=1"), (b"set-cookie", b"sid=abc; Path=/; Secure")]})
        await send({"type": "http.response.body", "body": b""})
        return
    out = json.dumps({"method": scope["method"], "path": p, "qs": scope["query_string"].decode(), "len": len(body), "http": scope["http_version"], "cookie": hd.get("cookie")}).encode()
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(out)).encode()), (b"alt-svc", ('h3=":%s"; ma=60' % QP).encode()), (b"x-multi", b"a"), (b"x-multi", b"b")]})
    await send({"type": "http.response.body", "body": out})
'''


def mk_certs(d):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    now = datetime.datetime.now(datetime.timezone.utc)
    ck = ec.generate_private_key(ec.SECP256R1())
    lk = ec.generate_private_key(ec.SECP256R1())
    cn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lab ca")])
    ca = (x509.CertificateBuilder().subject_name(cn).issuer_name(cn).public_key(ck.public_key()).serial_number(1)
          .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ck.public_key()), False)
          .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), True)
          .sign(ck, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(cn).public_key(lk.public_key()).serial_number(2)
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=10))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ck.public_key()), False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(lk.public_key()), False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(ck, hashes.SHA256()))
    pe = serialization.Encoding.PEM
    for n, b in (("ca.pem", ca.public_bytes(pe)), ("leaf.pem", leaf.public_bytes(pe)), ("leaf.key", lk.private_bytes(pe, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))):
        with open(os.path.join(d, n), "wb") as fh:
            fh.write(b)


def free(kind):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Srv:
    def __enter__(self):
        self.d = tempfile.mkdtemp()
        mk_certs(self.d)
        with open(os.path.join(self.d, "labapp.py"), "w") as fh:
            fh.write(APP)
        self.tp = free(socket.SOCK_STREAM)
        self.qp = free(socket.SOCK_DGRAM)
        self.ca = os.path.join(self.d, "ca.pem")
        env = dict(os.environ, LAB_QPORT=str(self.qp))
        self.p = subprocess.Popen([sys.executable, "-m", "hypercorn", "labapp:app", "--certfile", os.path.join(self.d, "leaf.pem"), "--keyfile", os.path.join(self.d, "leaf.key"), "--bind", "127.0.0.1:%d" % self.tp, "--quic-bind", "127.0.0.1:%d" % self.qp], cwd=self.d, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.time() + 15
        while time.time() < end:
            try:
                socket.create_connection(("127.0.0.1", self.tp), 0.3).close()
                break
            except OSError:
                time.sleep(0.2)
        time.sleep(0.3)
        return self

    def __exit__(self, *a):
        self.p.terminate()
        try:
            self.p.wait(5)
        except Exception:
            self.p.kill()
