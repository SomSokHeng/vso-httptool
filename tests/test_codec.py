import unittest

from httpkit import qpack
from httpkit.err import HpackError, QpackError
from httpkit.hpack import HpackDec, HpackEnc, huf_dec, huf_enc


class HpackT(unittest.TestCase):
    def test_huffman_vec(self):
        self.assertEqual(huf_enc(b"www.example.com").hex(), "f1e3c2e5f23a6ba0ab90f4ff")
        self.assertEqual(huf_dec(bytes.fromhex("f1e3c2e5f23a6ba0ab90f4ff")), b"www.example.com")

    def test_rfc_c4(self):
        d = HpackDec()
        r1 = d.dec(bytes.fromhex("828684418cf1e3c2e5f23a6ba0ab90f4ff"))
        self.assertEqual(r1[-1], (":authority", "www.example.com"))
        r2 = d.dec(bytes.fromhex("828684be5886a8eb10649cbf"))
        self.assertEqual(r2[-1], ("cache-control", "no-cache"))
        r3 = d.dec(bytes.fromhex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"))
        self.assertEqual(r3[-1], ("custom-key", "custom-value"))

    def test_roundtrip(self):
        e = HpackEnc()
        d = HpackDec()
        hs = [(":method", "GET"), (":path", "/a"), ("cookie", "a=b"), ("x-k", "v" * 50), ("authorization", "Bearer t")]
        for _ in range(3):
            self.assertEqual(d.dec(e.enc(hs)), hs)

    def test_bad_padding(self):
        with self.assertRaises(HpackError):
            huf_dec(b"\x00")

    def test_list_bomb(self):
        e = HpackEnc()
        blk = e.enc([("x-%d" % i, "v" * 200) for i in range(400)])
        with self.assertRaises(HpackError):
            HpackDec(4096, 20000).dec(blk)

    def test_table_update_over_limit(self):
        with self.assertRaises(HpackError):
            HpackDec(4096).dec(b"\x3f\xe2\x1f")

    def test_index_zero(self):
        with self.assertRaises(HpackError):
            HpackDec().dec(b"\x80")

    def test_truncated(self):
        with self.assertRaises(HpackError):
            HpackDec().dec(b"\x40\x05ab")


class QpackT(unittest.TestCase):
    def test_table_size(self):
        self.assertEqual(len(qpack.QST), 99)

    def test_roundtrip(self):
        hs = [(":method", "GET"), (":scheme", "https"), (":authority", "e.com"), (":path", "/x"), ("x-a", "b"), ("cookie", "c=d")]
        self.assertEqual(qpack.dec(qpack.enc(hs)), hs)

    def test_dynamic_rejected(self):
        with self.assertRaises(QpackError):
            qpack.dec(b"\x01\x00\x80")
        with self.assertRaises(QpackError):
            qpack.dec(b"\x00\x00\x80")

    def test_static_oob(self):
        with self.assertRaises(QpackError):
            qpack.dec(b"\x00\x00\xff\x7f")

    def test_oversize(self):
        with self.assertRaises(QpackError):
            qpack.dec(qpack.enc([("x-%d" % i, "v" * 100) for i in range(100)]), 2000)


if __name__ == "__main__":
    unittest.main()
