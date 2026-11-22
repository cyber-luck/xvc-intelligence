"""FASE 3 - AES-XTS por pagina (AesXtsTransform do xvdtool)."""
import struct
import unittest

from lab_test_helpers import requires_crypto

from lab_common import Rng
import lab_xts as X


class TestGF(unittest.TestCase):
    def test_multiply_byte_port_equals_int_version(self):
        rng = Rng(1)
        for i in range(2000):
            t = rng.bytes(f"t{i}", 16)
            a = X.multiply_tweak_xvdtool(t)
            b = X.multiply_tweak_int(int.from_bytes(t, "little")).to_bytes(16, "little")
            self.assertEqual(a, b)

    def test_reduction_0x87_when_top_bit_set(self):
        t = bytes(15) + b"\x80"                       # bit 127 ligado
        self.assertEqual(X.multiply_tweak_xvdtool(t), b"\x87" + bytes(15))
        self.assertEqual(X.multiply_tweak_xvdtool(b"\x01" + bytes(15)), b"\x02" + bytes(15))

    def test_carry_between_bytes_little_endian(self):
        self.assertEqual(X.multiply_tweak_xvdtool(b"\x80" + bytes(15)), b"\x00\x01" + bytes(14))


class TestSeed(unittest.TestCase):
    def test_seed_layout(self):
        vd = bytes(range(16))
        s = X.build_tweak_seed(0x11223344, 0x3E9, vd)
        self.assertEqual(s[0:4], struct.pack("<I", 0x11223344))
        self.assertEqual(s[4:8], struct.pack("<I", 0x3E9))
        self.assertEqual(s[8:16], vd[:8])

    def test_split_order(self):
        cik = bytes(range(32))
        tk, dk = X.split_cik(cik)
        self.assertEqual(tk, cik[:16])
        self.assertEqual(dk, cik[16:])


@requires_crypto
class TestVectors(unittest.TestCase):
    def test_all_known_vectors(self):
        import lab_vectors
        r = lab_vectors.run_known_vectors()
        for row in r["results"]:
            for k, v in row.items():
                if k != "vector":
                    self.assertIsNot(v, False, f"{row['vector']}: {k}")
        self.assertTrue(r["all_pass"])

    def test_xvdtool_vector(self):
        import lab_vectors
        x = lab_vectors.load()["xvdtool"]
        cik = bytes.fromhex(x["cik"])
        plain = x["plaintext_unit"].encode() * 256
        ct = b"".join(X.xts_page(cik, plain[i * 0x1000:(i + 1) * 0x1000], i, 1, bytes.fromhex(x["vduid8"]), True)
                      for i in range(3))
        from lab_common import sha256_hex
        self.assertEqual(sha256_hex(ct), x["ciphertext_sha256"])


@requires_crypto
class TestTransform(unittest.TestCase):
    def setUp(self):
        self.rng = Rng(2)

    def test_fast_equals_literal_and_openssl(self):
        for i in range(12):
            cik = self.rng.bytes(f"c{i}", 32)
            page = self.rng.bytes(f"p{i}", 0x1000)
            du, sec, vd = self.rng.u32(f"d{i}"), self.rng.u32(f"s{i}"), self.rng.bytes(f"v{i}", 16)
            fast = X.xts_page(cik, page, du, sec, vd, True)
            lit = X.AesXtsTransformLiteral(X.build_tweak_seed(du, sec, vd), cik[16:], cik[:16], True).transform_data_unit(page, du)
            self.assertEqual(fast, lit)
            self.assertEqual(fast, X.xts_page_openssl(cik, page, du, sec, vd, True))
            self.assertEqual(X.xts_page(cik, fast, du, sec, vd, False), page)

    def test_every_tweak_input_changes_ciphertext(self):
        cik, page, vd = self.rng.bytes("c", 32), self.rng.bytes("p", 0x1000), self.rng.bytes("v", 16)
        base = X.xts_page(cik, page, 5, 1, vd, True)
        self.assertNotEqual(base, X.xts_page(cik, page, 6, 1, vd, True))           # data unit
        self.assertNotEqual(base, X.xts_page(cik, page, 5, 2, vd, True))           # section id
        vd2 = bytes([vd[0] ^ 1]) + vd[1:]
        self.assertNotEqual(base, X.xts_page(cik, page, 5, 1, vd2, True))          # VDUID[0:8]
        vd3 = vd[:8] + bytes(8)
        self.assertEqual(base, X.xts_page(cik, page, 5, 1, vd3, True))             # VDUID[8:16] nao entra

    def test_partial_block_rejected(self):
        with self.assertRaises(ValueError):
            X.xts_page(bytes(range(32)), bytes(20), 0, 1, bytes(16), True)

    def test_crypt_section_one_data_unit_per_page(self):
        cik, vd = self.rng.bytes("c", 32), self.rng.bytes("v", 16)
        data = self.rng.bytes("sec", 3 * 0x1000)
        dus = [0x7A3C1000, 0x400, 9]                 # nao sequencial
        ct = X.crypt_section(cik, data, dus, 0x3E9, vd, True)
        for i, du in enumerate(dus):
            self.assertEqual(ct[i * 0x1000:(i + 1) * 0x1000], X.xts_page(cik, data[i * 0x1000:(i + 1) * 0x1000], du, 0x3E9, vd, True))
        self.assertEqual(X.crypt_section(cik, ct, dus, 0x3E9, vd, False), data)

    def test_xts_is_permutation_for_any_key(self):
        """Round-trip exato com chave ERRADA: reversivel nao significa correto."""
        right, wrong, vd = self.rng.bytes("r", 32), self.rng.bytes("w", 32), self.rng.bytes("v", 16)
        ct = X.xts_page(right, self.rng.bytes("p", 0x1000), 1, 1, vd, True)
        bad_pt = X.xts_page(wrong, ct, 1, 1, vd, False)
        self.assertEqual(X.xts_page(wrong, bad_pt, 1, 1, vd, True), ct)


if __name__ == "__main__":
    unittest.main()
