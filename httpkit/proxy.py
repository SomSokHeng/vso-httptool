import base64
import ipaddress
import os
import random
import select
import socket
import ssl
import struct
import threading
import time
from urllib.parse import unquote, urlsplit

from .err import ProxyError, SecError, TlsError

VSO_PXS = ("http", "https", "socks4", "socks4a", "socks5", "socks5h")
DEFP = {"http": 8080, "https": 8080, "socks4": 1080, "socks4a": 1080, "socks5": 1080, "socks5h": 1080}
MODES = ("round-robin", "random", "sticky")
BADCH = frozenset(chr(i) for i in list(range(0, 33)) + [127])
S5ERR = {1: "general failure", 2: "not allowed by ruleset", 3: "network unreachable", 4: "host unreachable", 5: "connection refused", 6: "ttl expired", 7: "command not supported", 8: "address type not supported"}
S4ERR = {0x5B: "request rejected or failed", 0x5C: "proxy cannot reach identd", 0x5D: "identd user mismatch"}


class Proxy:
    __slots__ = ("scheme", "host", "port", "usr", "pwd")

    def __init__(self, scheme, host, port, usr=None, pwd=None):
        self.scheme = scheme
        self.host = host
        self.port = port
        self.usr = usr
        self.pwd = pwd

    @property
    def key(self):
        return "%s://%s:%d#%s" % (self.scheme, self.host, self.port, self.usr or "")

    @property
    def safe(self):
        h = "[%s]" % self.host if ":" in self.host else self.host
        a = "" if self.usr is None else "%s:***@" % self.usr
        return "%s://%s%s:%d" % (self.scheme, a, h, self.port)

    @property
    def auth(self):
        return "Basic " + base64.b64encode(("%s:%s" % (self.usr or "", self.pwd or "")).encode("utf-8")).decode("ascii")

    def __repr__(self):
        return "Proxy(%s)" % self.safe


def parse_proxy(s):
    if isinstance(s, Proxy):
        return s
    if not isinstance(s, str) or not s or len(s) > 2048 or any(c in BADCH for c in s):
        raise ProxyError("invalid proxy string")
    if "://" not in s:
        s = "http://" + s
    p = urlsplit(s)
    sch = p.scheme.lower()
    if sch not in VSO_PXS:
        raise ProxyError("unsupported proxy scheme: %s" % sch)
    try:
        host = p.hostname
        port = p.port or DEFP[sch]
    except ValueError:
        raise ProxyError("invalid proxy port") from None
    if not host or not 0 < port < 65536 or p.path not in ("", "/") or p.query or p.fragment:
        raise ProxyError("invalid proxy address")
    usr = unquote(p.username) if p.username is not None else None
    pwd = unquote(p.password) if p.password is not None else None
    for x in (usr, pwd):
        if x and any(ord(c) < 32 or ord(c) == 127 for c in x):
            raise ProxyError("control character in proxy credentials")
    if sch.startswith("socks5") and ((usr and len(usr.encode()) > 255) or (pwd and len(pwd.encode()) > 255)):
        raise ProxyError("socks5 credentials too long")
    return Proxy(sch, host.lower(), port, usr, pwd)


def load_list(path, cap=10000):
    out = []
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            if len(ln) > 2048:
                raise ValueError("line too long in %s" % path)
            out.append(ln)
            if len(out) > cap:
                raise ValueError("too many entries in %s" % path)
    return out


def bypass(host, pats):
    for p in pats or ():
        p = p.strip().lower()
        if not p:
            continue
        if p == "*":
            return True
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError:
            net = None
        if net is not None:
            try:
                if ipaddress.ip_address(host) in net:
                    return True
            except ValueError:
                pass
            continue
        p = p.lstrip("*").lstrip(".")
        if host == p or host.endswith("." + p):
            return True
    return False


def from_env(scheme):
    names = ("https_proxy", "all_proxy") if scheme == "https" else ("http_proxy", "all_proxy")
    cgi = "REQUEST_METHOD" in os.environ
    for n in names:
        v = os.environ.get(n) or (None if cgi else os.environ.get(n.upper()))
        if v:
            return parse_proxy(v)
    return None


def env_no_proxy():
    v = os.environ.get("no_proxy") or os.environ.get("NO_PROXY") or ""
    return [x for x in v.split(",") if x.strip()]


class InfPool:
    def __init__(self, items, mode="round-robin"):
        if mode not in MODES:
            raise ProxyError("rotate must be one of: %s" % ", ".join(MODES))
        self.items = [parse_proxy(x) for x in items]
        if not self.items:
            raise ProxyError("empty proxy list")
        self.mode = mode
        self.n = 0
        self.stick = {}
        self.lk = threading.Lock()

    def pick(self, origin=None):
        with self.lk:
            if self.mode == "random":
                return random.choice(self.items)
            if self.mode == "sticky" and origin in self.stick:
                return self.items[self.stick[origin]]
            i = self.n % len(self.items)
            self.n += 1
            if self.mode == "sticky":
                self.stick[origin] = i
            return self.items[i]

    def __len__(self):
        return len(self.items)


def rd_exact(s, n):
    b = b""
    while len(b) < n:
        d = s.recv(n - len(b))
        if not d:
            raise ProxyError("proxy closed the connection during handshake")
        b += d
    return b


def tcp_to(px, guard, tmo):
    try:
        addrs = guard.resolve(px.host, px.port)
    except SecError as e:
        raise ProxyError("cannot resolve proxy host: %s" % e) from None
    last = None
    for fam, addr in addrs:
        s = socket.socket(fam, socket.SOCK_STREAM)
        try:
            s.settimeout(tmo)
            s.connect((addr, px.port))
            try:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            return s
        except OSError as e:
            last = e
            s.close()
    raise ProxyError("cannot connect to proxy %s: %s" % (px.safe, last))


def http_connect(s, px, host, port):
    h = "[%s]" % host if ":" in host else host
    t = "%s:%d" % (h, port)
    msg = "CONNECT %s HTTP/1.1\r\nHost: %s\r\n" % (t, t)
    if px.usr is not None:
        msg += "Proxy-Authorization: %s\r\n" % px.auth
    s.sendall((msg + "\r\n").encode("ascii"))
    b = b""
    while not b.endswith(b"\r\n\r\n"):
        d = s.recv(1)
        if not d:
            raise ProxyError("proxy closed the connection after CONNECT")
        b += d
        if len(b) > 16384:
            raise ProxyError("proxy CONNECT response too large")
    sl = b.split(b"\r\n", 1)[0].decode("latin-1")
    parts = sl.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/1.") or not parts[1].isdigit():
        raise ProxyError("malformed proxy CONNECT response")
    st = int(parts[1])
    if 200 <= st < 300:
        return
    if st == 407:
        raise ProxyError("proxy %s requires authentication (407)" % px.safe)
    raise ProxyError("proxy %s refused CONNECT: %d %s" % (px.safe, st, parts[2] if len(parts) > 2 else ""))


def ip_or_none(host):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def s4(s, px, host, port, guard):
    remote = px.scheme == "socks4a"
    ip = ip_or_none(host)
    tail = b""
    if ip is not None:
        if ip.version != 4:
            raise ProxyError("socks4 supports IPv4 targets only")
        ab = ip.packed
    elif remote:
        ab = b"\x00\x00\x00\x01"
        tail = host.encode("idna") + b"\x00"
        if len(tail) > 256:
            raise ProxyError("hostname too long")
    else:
        try:
            v4 = [a for f, a in guard.resolve(host, port) if f == socket.AF_INET]
        except SecError as e:
            raise ProxyError("cannot resolve %s: %s" % (host, e)) from None
        if not v4:
            raise ProxyError("no IPv4 address for %s (socks4 needs one)" % host)
        ab = socket.inet_aton(v4[0])
    uid = (px.usr or "").encode("utf-8") + b"\x00"
    s.sendall(b"\x04\x01" + struct.pack(">H", port) + ab + uid + tail)
    r = rd_exact(s, 8)
    if r[0] != 0 or r[1] != 0x5A:
        raise ProxyError("socks4 proxy %s: %s" % (px.safe, S4ERR.get(r[1], "error 0x%02x" % r[1])))


def addr5(host, remote, guard, port):
    ip = ip_or_none(host)
    if ip is None and remote:
        hb = host.encode("idna")
        if len(hb) > 255:
            raise ProxyError("hostname too long for socks5")
        return b"\x03" + bytes([len(hb)]) + hb
    if ip is None:
        try:
            ip = ipaddress.ip_address(guard.resolve(host, port)[0][1])
        except SecError as e:
            raise ProxyError("cannot resolve %s: %s" % (host, e)) from None
    return (b"\x01" if ip.version == 4 else b"\x04") + ip.packed


def s5(s, px, host, port, guard):
    ms = b"\x00\x02" if px.usr is not None else b"\x00"
    s.sendall(b"\x05" + bytes([len(ms)]) + ms)
    r = rd_exact(s, 2)
    if r[0] != 5:
        raise ProxyError("not a socks5 proxy: %s" % px.safe)
    if r[1] == 0xFF:
        raise ProxyError("socks5 proxy %s accepts none of our auth methods" % px.safe)
    if r[1] == 2:
        if px.usr is None:
            raise ProxyError("socks5 proxy %s requires credentials" % px.safe)
        u = px.usr.encode("utf-8")
        p = (px.pwd or "").encode("utf-8")
        s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        a = rd_exact(s, 2)
        if a[1] != 0:
            raise ProxyError("socks5 proxy %s rejected the credentials" % px.safe)
    elif r[1] != 0:
        raise ProxyError("socks5 proxy %s chose unsupported method %d" % (px.safe, r[1]))
    s.sendall(b"\x05\x01\x00" + addr5(host, px.scheme == "socks5h", guard, port) + struct.pack(">H", port))
    h = rd_exact(s, 4)
    if h[0] != 5:
        raise ProxyError("bad socks5 reply")
    if h[1] != 0:
        raise ProxyError("socks5 proxy %s: %s" % (px.safe, S5ERR.get(h[1], "error %d" % h[1])))
    at = h[3]
    if at == 1:
        rd_exact(s, 6)
    elif at == 4:
        rd_exact(s, 18)
    elif at == 3:
        rd_exact(s, rd_exact(s, 1)[0] + 2)
    else:
        raise ProxyError("bad socks5 address type in reply")


def open_tunnel(px, url, guard, tmo, verify=True, ca=None, force=False):
    s = tcp_to(px, guard, tmo)
    try:
        if px.scheme == "https":
            from .conn import mk_ctx
            s = mk_ctx(verify, ca).wrap_socket(s, server_hostname=px.host)
        if px.scheme in ("http", "https"):
            if url.scheme == "http" and not force:
                return s, True
            http_connect(s, px, url.host, url.port)
            return s, False
        if px.scheme in ("socks4", "socks4a"):
            s4(s, px, url.host, url.port, guard)
        else:
            s5(s, px, url.host, url.port, guard)
        return s, False
    except ProxyError:
        s.close()
        raise
    except (OSError, ssl.SSLError) as e:
        s.close()
        raise ProxyError("proxy %s failed: %s" % (px.safe, e)) from None


class Nest:
    def __init__(self, o, obj, inc, out):
        self.o = o
        self.obj = obj
        self.inc = inc
        self.out = out
        self.pend = bytearray()

    @classmethod
    def wrap(cls, o, ctx, host, tmo):
        inc = ssl.MemoryBIO()
        out = ssl.MemoryBIO()
        obj = ctx.wrap_bio(inc, out, server_hostname=host)
        n = cls(o, obj, inc, out)
        o.settimeout(tmo)
        while True:
            try:
                obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                n.flush()
                d = o.recv(65536)
                if not d:
                    raise TlsError("connection closed during tls handshake")
                inc.write(d)
            except ssl.SSLWantWriteError:
                n.flush()
        n.flush()
        return n

    def fileno(self):
        return self.o.fileno()

    def settimeout(self, t):
        self.o.settimeout(t)

    def setblocking(self, f):
        self.o.setblocking(f)

    def flush(self):
        d = self.out.read()
        if d:
            self.pend += d
        end = time.monotonic() + 30.0
        while self.pend:
            try:
                n = self.o.send(bytes(self.pend))
                del self.pend[:n]
            except (ssl.SSLWantWriteError, BlockingIOError):
                if time.monotonic() > end:
                    raise socket.timeout("send timeout")
                select.select([], [self.o], [], 0.5)
            except ssl.SSLWantReadError:
                select.select([self.o], [], [], 0.05)

    def recv(self, n=65536):
        while True:
            try:
                return self.obj.read(n)
            except ssl.SSLWantReadError:
                pass
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                return b""
            self.flush()
            try:
                d = self.o.recv(65536)
            except (ssl.SSLWantReadError, BlockingIOError):
                raise ssl.SSLWantReadError("would block") from None
            except ssl.SSLWantWriteError:
                select.select([], [self.o], [], 0.05)
                continue
            if d:
                self.inc.write(d)
            else:
                self.inc.write_eof()

    def send(self, data):
        n = self.obj.write(bytes(data))
        self.flush()
        return n

    def sendall(self, data):
        mv = memoryview(data)
        off = 0
        while off < len(mv):
            off += self.send(mv[off:off + 16384])

    def selected_alpn_protocol(self):
        return self.obj.selected_alpn_protocol()

    def version(self):
        return self.obj.version()

    def cipher(self):
        return self.obj.cipher()

    def getpeercert(self, binary_form=False):
        return self.obj.getpeercert(binary_form)

    def close(self):
        try:
            self.o.close()
        except OSError:
            pass
