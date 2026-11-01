import socket
import struct
import threading
import unittest

from httpkit import Client, H2Error, HttpkitError
from httpkit.h2 import CONT, DATA, HEADERS, PING, PUSH, SETTINGS, frm
from httpkit.hpack import HpackEnc

PREF = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def rd(s, n):
    b = b""
    while len(b) < n:
        d = s.recv(n - len(b))
        if not d:
            raise OSError("eof")
        b += d
    return b


def rframe(s):
    h = rd(s, 9)
    ln = (h[0] << 16) | (h[1] << 8) | h[2]
    return h[3], h[4], struct.unpack(">I", h[5:9])[0] & 0x7FFFFFFF, rd(s, ln) if ln else b""


class Evil:
    def __init__(self, fn):
        self.fn = fn
        self.ls = socket.socket()
        self.ls.bind(("127.0.0.1", 0))
        self.ls.listen(1)
        self.port = self.ls.getsockname()[1]
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        try:
            c, _ = self.ls.accept()
            c.settimeout(5)
            rd(c, 24)
            c.sendall(frm(SETTINGS, 0, 0))
            while True:
                t, f, sid, pl = rframe(c)
                if t == HEADERS:
                    break
            self.fn(c, sid)
            c.settimeout(1)
            try:
                while c.recv(65536):
                    pass
            except OSError:
                pass
            c.close()
        except OSError:
            pass
        finally:
            self.ls.close()


def hit(fn):
    e = Evil(fn)
    with Client(proto="h2", tmo=5, h3=False) as c:
        return c.get("http://127.0.0.1:%d/" % e.port)


ENC = HpackEnc()


def hb(hl):
    return HpackEnc().enc(hl)


class H2AttackT(unittest.TestCase):
    def test_ok(self):
        r = hit(lambda c, sid: c.sendall(frm(HEADERS, 5, sid, hb([(":status", "200"), ("x-a", "b")]))))
        self.assertEqual((r.status, r.hdrs.get("x-a")), (200, "b"))

    def test_continuation_flood(self):
        def f(c, sid):
            c.sendall(frm(HEADERS, 0, sid, b"\x00" * 16000))
            for _ in range(10):
                c.sendall(frm(CONT, 0, sid, b"\x00" * 16384))
        with self.assertRaises(HttpkitError):
            hit(f)

    def test_ping_flood(self):
        def f(c, sid):
            c.sendall(frm(PING, 0, 0, b"12345678") * 3000)
        with self.assertRaises(H2Error) as cm:
            hit(f)
        self.assertEqual(cm.exception.code, 11)

    def test_push_promise(self):
        with self.assertRaises(H2Error):
            hit(lambda c, sid: c.sendall(frm(PUSH, 4, sid, b"\x00\x00\x00\x02" + b"\x88")))

    def test_cl_mismatch(self):
        def f(c, sid):
            c.sendall(frm(HEADERS, 4, sid, hb([(":status", "200"), ("content-length", "5")])) + frm(DATA, 1, sid, b"abc"))
        with self.assertRaises(H2Error):
            hit(f)

    def test_uppercase_name(self):
        with self.assertRaises(H2Error):
            hit(lambda c, sid: c.sendall(frm(HEADERS, 5, sid, b"\x88\x00\x04X-Up\x01b")))

    def test_conn_header(self):
        with self.assertRaises(H2Error):
            hit(lambda c, sid: c.sendall(frm(HEADERS, 5, sid, hb([(":status", "200"), ("connection", "close")]))))

    def test_missing_status(self):
        with self.assertRaises(H2Error):
            hit(lambda c, sid: c.sendall(frm(HEADERS, 5, sid, hb([("x-a", "b")]))))

    def test_bad_hpack(self):
        with self.assertRaises(H2Error):
            hit(lambda c, sid: c.sendall(frm(HEADERS, 5, sid, b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")))

    def test_data_before_headers_closed_stream(self):
        with self.assertRaises(HttpkitError):
            hit(lambda c, sid: c.sendall(frm(DATA, 1, sid, b"x")))

    def test_oversize_frame(self):
        def f(c, sid):
            c.sendall(struct.pack(">BHBBI", 0x20, 0, DATA, 0, sid))
        with self.assertRaises(H2Error):
            hit(f)

    def test_body_limit(self):
        from httpkit import Lim
        def f(c, sid):
            c.sendall(frm(HEADERS, 4, sid, hb([(":status", "200")])))
            for _ in range(20):
                c.sendall(frm(DATA, 0, sid, b"a" * 16000))
        e = Evil(f)
        with Client(proto="h2", tmo=5, h3=False, lim=Lim(max_body=100000)) as cl:
            with self.assertRaises(HttpkitError):
                cl.get("http://127.0.0.1:%d/" % e.port)


if __name__ == "__main__":
    unittest.main()
