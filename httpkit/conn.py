import select
import socket
import ssl
import threading
import time

from .err import ConnError, SecError, TlsError
from .proxy import Nest, open_tunnel
from .trace import note, span


def mk_ctx(verify=True, ca=None, alpn=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if verify:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        if ca:
            ctx.load_verify_locations(cafile=ca)
        else:
            ctx.load_default_certs()
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        ctx.set_alpn_protocols(list(alpn))
    return ctx


class Conn:
    def __init__(self, sock, host, port, tls=False):
        self.sock = sock
        self.host = host
        self.port = port
        self.tls = tls
        self.alpn = None
        self.tls_ver = None
        self.cipher = None
        self.abs_form = False
        self.proxy = None
        self.cert_days = None

    @classmethod
    def open_px(cls, url, guard, tmo, verify, ca, alpn, px, pverify, pca, force):
        with span("proxy"):
            raw, absf = open_tunnel(px, url, guard, tmo, pverify, pca, force)
        note("proxy", "%s via %s" % ("request will use absolute-form (no tunnel)" if absf else "tunnel to %s:%d ready" % (url.host, url.port), px.safe))
        c = cls(raw, url.host, url.port, url.scheme == "https")
        c.abs_form = absf
        c.proxy = px
        if not c.tls:
            raw.settimeout(tmo)
            return c
        with span("tls"):
            try:
                ctx = mk_ctx(verify, ca, alpn)
                s = Nest.wrap(raw, ctx, url.host, tmo) if isinstance(raw, ssl.SSLSocket) else ctx.wrap_socket(raw, server_hostname=url.host)
            except ssl.SSLError as e:
                raw.close()
                note("tls", "handshake failed: %s" % e, True)
                raise TlsError("tls handshake failed: %s" % e) from e
            except OSError as e:
                raw.close()
                note("tls", "handshake failed: %s" % e, True)
                raise ConnError("tls handshake failed: %s" % e) from e
        c.tls_up(s, verify)
        return c

    def tls_up(self, s, verify):
        self.sock = s
        self.alpn = s.selected_alpn_protocol()
        self.tls_ver = s.version()
        ci = s.cipher()
        self.cipher = ci[0] if ci else None
        if verify:
            try:
                na = s.getpeercert().get("notAfter")
                if na:
                    self.cert_days = int((ssl.cert_time_to_seconds(na) - time.time()) // 86400)
            except Exception:
                pass
        note("tls", "%s %s alpn=%s verified=%s%s" % (self.tls_ver, self.cipher, self.alpn, bool(verify), "" if self.cert_days is None else " cert_days=%d" % self.cert_days))

    @classmethod
    def open(cls, url, guard, tmo=30.0, verify=True, ca=None, alpn=None, proxy=None, pverify=None, pca=None, force=False):
        if proxy is not None:
            return cls.open_px(url, guard, tmo, verify, ca, alpn, proxy, verify if pverify is None else pverify, ca if pca is None else pca, force)
        with span("dns"):
            try:
                addrs = guard.resolve(url.host, url.port)
            except SecError as e:
                note("dns", "lookup failed for %s: %s" % (url.host, e), True)
                raise
        note("dns", "%s -> %s" % (url.host, ", ".join(a for _, a in addrs)))
        last = None
        raw = None
        with span("tcp"):
            for fam, addr in addrs:
                try:
                    raw = socket.socket(fam, socket.SOCK_STREAM)
                    raw.settimeout(tmo)
                    raw.connect((addr, url.port))
                    note("tcp", "connected to %s:%d" % (addr, url.port))
                    break
                except OSError as e:
                    last = e
                    note("tcp", "connect to %s:%d failed: %s" % (addr, url.port, e), True)
                    if raw:
                        raw.close()
                    raw = None
        if raw is None:
            raise ConnError("connect failed to %s:%d: %s" % (url.host, url.port, last))
        try:
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        c = cls(raw, url.host, url.port, url.scheme == "https")
        if c.tls:
            with span("tls"):
                try:
                    ctx = mk_ctx(verify, ca, alpn)
                    s = ctx.wrap_socket(raw, server_hostname=url.host)
                except ssl.SSLError as e:
                    raw.close()
                    note("tls", "handshake failed: %s" % e, True)
                    raise TlsError("tls handshake failed: %s" % e) from e
                except OSError as e:
                    raw.close()
                    note("tls", "handshake failed: %s" % e, True)
                    raise ConnError("tls handshake failed: %s" % e) from e
            c.tls_up(s, verify)
        return c

    def send(self, b):
        try:
            self.sock.sendall(b)
        except OSError as e:
            raise ConnError("send failed: %s" % e) from e

    def recv(self, n=65536):
        try:
            return self.sock.recv(n)
        except socket.timeout as e:
            raise ConnError("read timeout") from e
        except OSError as e:
            raise ConnError("recv failed: %s" % e) from e

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class Dup:
    def __init__(self, sock):
        self.s = sock
        self.lk = threading.Lock()
        self.closed = False
        sock.setblocking(False)

    def send_all(self, data, tmo=30.0):
        mv = memoryview(data)
        off = 0
        end = time.monotonic() + tmo
        while off < len(mv):
            if self.closed:
                raise ConnError("connection closed")
            try:
                with self.lk:
                    n = self.s.send(mv[off:off + 65536])
                off += n
                end = time.monotonic() + tmo
            except (ssl.SSLWantWriteError, BlockingIOError):
                rem = end - time.monotonic()
                if rem <= 0:
                    raise ConnError("send timeout")
                select.select([], [self.s], [], min(rem, 0.5))
            except ssl.SSLWantReadError:
                select.select([self.s], [], [], 0.05)
            except (OSError, ValueError) as e:
                raise ConnError("send failed: %s" % e) from e

    def recv(self, n=65536):
        while True:
            if self.closed:
                return b""
            try:
                with self.lk:
                    d = self.s.recv(n)
                return d
            except (ssl.SSLWantReadError, BlockingIOError):
                pass
            except ssl.SSLWantWriteError:
                select.select([], [self.s], [], 0.05)
                continue
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                return b""
            except (OSError, ValueError) as e:
                if self.closed:
                    return b""
                raise ConnError("recv failed: %s" % e) from e
            try:
                select.select([self.s], [], [], 0.5)
            except (OSError, ValueError):
                return b""

    def close(self):
        self.closed = True
        try:
            self.s.close()
        except OSError:
            pass
