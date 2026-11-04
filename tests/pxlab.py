import base64
import json
import select
import socket
import ssl
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class Tgt:
    def __init__(self):
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                out = json.dumps({"path": self.path, "ua": self.headers.get("User-Agent"), "host": self.headers.get("Host"), "len": len(body), "pauth": self.headers.get("Proxy-Authorization")}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)
                outer.hits += 1

            do_POST = do_GET

            def log_message(self, *a):
                pass

        self.hits = 0
        self.conns = 0

        class S(ThreadingHTTPServer):
            daemon_threads = True

            def get_request(self):
                r = super().get_request()
                outer.conns += 1
                return r

        self.srv = S(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def url(self, p="/"):
        return "http://127.0.0.1:%d%s" % (self.port, p)

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def pipe(a, b):
    socks = [a, b]
    try:
        while True:
            rd = [s for s in socks if isinstance(s, ssl.SSLSocket) and s.pending()]
            if not rd:
                rd, _, _ = select.select(socks, [], [], 8)
            if not rd:
                return
            for s in rd:
                d = s.recv(65536)
                if not d:
                    return
                (b if s is a else a).sendall(d)
    except OSError:
        pass
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass


def rd(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d:
            raise OSError("eof")
        b += d
    return b


def until0(c):
    b = b""
    while True:
        x = rd(c, 1)
        if x == b"\x00":
            return b
        b += x


class Px:
    def __init__(self, kind, usr=None, pwd=None, ctx=None, deny=False):
        self.kind = kind
        self.usr = usr
        self.pwd = pwd
        self.ctx = ctx
        self.deny = deny
        self.seen = []
        self.ls = socket.socket()
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind(("127.0.0.1", 0))
        self.ls.listen(32)
        self.port = self.ls.getsockname()[1]
        threading.Thread(target=self.loop, daemon=True).start()

    def url(self, scheme=None):
        a = "" if self.usr is None else "%s:%s@" % (self.usr, self.pwd)
        return "%s://%s127.0.0.1:%d" % (scheme or {"http": "http", "s5": "socks5", "s4": "socks4"}[self.kind], a, self.port)

    def loop(self):
        while True:
            try:
                c, _ = self.ls.accept()
            except OSError:
                return
            threading.Thread(target=self.hdl, args=(c,), daemon=True).start()

    def close(self):
        try:
            self.ls.close()
        except OSError:
            pass

    def hdl(self, c):
        try:
            c.settimeout(10)
            if self.ctx:
                c = self.ctx.wrap_socket(c, server_side=True)
            getattr(self, "h_" + self.kind)(c)
        except Exception:
            try:
                c.close()
            except OSError:
                pass

    def h_http(self, c):
        b = b""
        while b"\r\n\r\n" not in b:
            d = c.recv(4096)
            if not d:
                return
            b += d
        head, _, rest = b.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        mth, tgt, _ = lines[0].split(" ", 2)
        hd = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            hd[k.strip().lower()] = v.strip()
        self.seen.append((mth, tgt))
        if self.usr is not None:
            exp = "Basic " + base64.b64encode(("%s:%s" % (self.usr, self.pwd)).encode()).decode()
            if hd.get("proxy-authorization") != exp:
                c.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=x\r\nContent-Length: 0\r\n\r\n")
                c.close()
                return
        if mth == "CONNECT":
            if self.deny:
                c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                c.close()
                return
            h, _, p = tgt.rpartition(":")
            t = socket.create_connection((h.strip("[]"), int(p)), 5)
            c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            pipe(c, t)
            return
        u = urlsplit(tgt)
        t = socket.create_connection((u.hostname, u.port or 80), 5)
        path = (u.path or "/") + ("?" + u.query if u.query else "")
        out = "%s %s HTTP/1.1\r\n" % (mth, path)
        for k, v in hd.items():
            if k not in ("proxy-authorization", "proxy-connection", "connection"):
                out += "%s: %s\r\n" % (k, v)
        t.sendall((out + "Connection: close\r\n\r\n").encode("latin-1") + rest)
        pipe(c, t)

    def h_s5(self, c):
        n = rd(c, 2)[1]
        ms = rd(c, n)
        if self.usr is not None:
            if 2 not in ms:
                c.sendall(b"\x05\xff")
                return
            c.sendall(b"\x05\x02")
            rd(c, 1)
            u = rd(c, rd(c, 1)[0])
            p = rd(c, rd(c, 1)[0])
            ok = (u, p) == (self.usr.encode(), self.pwd.encode())
            c.sendall(b"\x01" + (b"\x00" if ok else b"\x01"))
            if not ok:
                c.close()
                return
        else:
            c.sendall(b"\x05\x00")
        h = rd(c, 4)
        at = h[3]
        if at == 1:
            host = socket.inet_ntoa(rd(c, 4))
        elif at == 3:
            host = rd(c, rd(c, 1)[0]).decode()
        else:
            host = socket.inet_ntop(socket.AF_INET6, rd(c, 16))
        port = struct.unpack(">H", rd(c, 2))[0]
        self.seen.append(("s5", at, host, port))
        t = socket.create_connection((host, port), 5)
        c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        pipe(c, t)

    def h_s4(self, c):
        h = rd(c, 8)
        port = struct.unpack(">H", h[2:4])[0]
        ip = h[4:8]
        uid = until0(c)
        if ip[:3] == b"\x00\x00\x00" and ip[3] != 0:
            host = until0(c).decode()
            kind = "s4a"
        else:
            host = socket.inet_ntoa(ip)
            kind = "s4"
        self.seen.append((kind, host, port, uid.decode()))
        t = socket.create_connection((host, port), 5)
        c.sendall(b"\x00\x5a" + b"\x00" * 6)
        pipe(c, t)


def dead_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p
