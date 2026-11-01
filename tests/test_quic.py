import unittest

from httpkit.quic import QConn, Sp, dec_pn, init_keys, rvi, vi

try:
    from aioquic.quic.crypto import CryptoPair
    HAVE = True
except Exception:
    HAVE = False


class QuicT(unittest.TestCase):
    def test_initial_keys(self):
        c, s = init_keys(bytes.fromhex("8394c8f03e515708"))
        self.assertEqual(c.secret.hex(), "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        self.assertEqual(c.hp.hex(), "9f50449e04a0e810283a1e9933adedd2")
        self.assertEqual(c.iv.to_bytes(12, "big").hex(), "fa044b2f42a3fd3b46fb255c")
        self.assertEqual(s.secret.hex(), "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
        self.assertEqual(s.hp.hex(), "c206b8d9b9f0f37644430b490eeaa314")

    def test_varint(self):
        for n, h in ((37, "25"), (15293, "7bbd"), (494878333, "9d7f3e7d"), (151288809941952652, "c2197c5eff14e88c")):
            self.assertEqual(vi(n).hex(), h)
            self.assertEqual(rvi(bytes.fromhex(h), 0), (n, len(h) // 2))

    def test_pn(self):
        self.assertEqual(dec_pn(0xA82F30EA, 0x9B32, 16), 0xA82F9B32)

    def test_ranges(self):
        sp = Sp()
        for p in (1, 2, 3, 7, 8, 10, 4):
            sp.note(p)
        self.assertEqual(sp.rr, [[1, 4], [7, 8], [10, 10]])
        self.assertFalse(sp.note(2))
        f = sp.ack_frame()
        lg, p = rvi(f, 1)
        _, p = rvi(f, p)
        cnt, p = rvi(f, p)
        fr, p = rvi(f, p)
        self.assertEqual((lg, cnt, fr), (10, 2, 0))

    @unittest.skipUnless(HAVE, "needs aioquic")
    def test_interop_protection(self):
        dcid = bytes.fromhex("8394c8f03e515708")
        pair = CryptoPair()
        pair.setup_initial(dcid, is_client=True, version=1)
        payload = bytes(range(64)) * 2
        scid = b"\x01\x02\x03\x04"
        pn = 7
        ln = 4 + len(payload) + 16
        hdr = bytes([0xC3]) + (1).to_bytes(4, "big") + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + b"\x00" + vi(ln)[:2].rjust(2, b"\x00") + pn.to_bytes(4, "big")
        hdr = hdr[:-6] + (0x4000 | ln).to_bytes(2, "big") + pn.to_bytes(4, "big")
        pk = pair.encrypt_packet(hdr, payload, pn)
        q = QConn.__new__(QConn)
        q.kp = 0
        q.nrk = None
        sp = Sp()
        sp.rcv = init_keys(dcid)[0]
        pn_off = len(hdr) - 4
        r = q.unprot(sp, pk, 0, pn_off, len(pk), True)
        self.assertEqual(r, (pn, payload))


if __name__ == "__main__":
    unittest.main()
