"""FASE 2 - perfis de chave: A (ODK/CIK) e B (CIK regional por GUID)."""
import unittest
import uuid

from lab_test_helpers import generated, requires_crypto

from lab_common import Rng, read_json


@requires_crypto
class TestProfileA(unittest.TestCase):
    def test_wrap_unwrap_identity(self):
        from lab_xvd_profile import gen_cik, gen_odk, unwrap_cik, wrap_cik
        for i in range(10):
            rng = Rng(100 + i)
            odk, cik = gen_odk(rng), gen_cik(rng)
            km = wrap_cik(odk, cik)
            self.assertEqual(len(km), 32)                 # ECB sem padding: 32 -> 32
            self.assertNotEqual(km, cik)
            self.assertEqual(unwrap_cik(odk, km), cik)

    def test_ecb_two_independent_blocks(self):
        from lab_xvd_profile import wrap_cik
        odk = bytes(range(32))
        cik = bytes(16) + bytes(16)                      # dois blocos iguais -> ECB da dois blocos iguais
        km = wrap_cik(odk, cik)
        self.assertEqual(km[:16], km[16:])

    def test_wrong_odk_gives_wrong_cik_silently(self):
        from lab_xvd_profile import unwrap_cik, wrap_cik
        odk, cik = Rng(5).bytes("o", 32), Rng(5).bytes("c", 32)
        km = wrap_cik(odk, cik)
        bad = unwrap_cik(Rng(6).bytes("o", 32), km)     # sem excecao: nao ha autenticacao
        self.assertEqual(len(bad), 32)
        self.assertNotEqual(bad, cik)

    def test_header_carries_sealed_cik_and_slot(self):
        g = generated()
        truth = g["truth"]
        from pathlib import Path
        data = (Path(g["public"]) / "lab_xvd_encrypted.bin").read_bytes()
        self.assertEqual(data[0x34C:0x36C].hex(), truth["xvd"]["key_material"])
        self.assertEqual(int.from_bytes(data[0x49C:0x4A0], "little"), truth["xvd"]["odk_slot"])
        from lab_xvd_profile import unwrap_cik
        self.assertEqual(unwrap_cik(bytes.fromhex(truth["odk"]), data[0x34C:0x36C]).hex(), truth["xvd"]["cik"])
        self.assertEqual(truth["xvd"]["cik_tweak_key"], truth["xvd"]["cik"][:32])
        self.assertEqual(truth["xvd"]["cik_data_key"], truth["xvd"]["cik"][32:])


@requires_crypto
class TestProfileB(unittest.TestCase):
    def setUp(self):
        from lab_xvc_profile import gen_xvc_keys
        self.keys = gen_xvc_keys(Rng(9), 2)
        self.table = [g for g, _ in self.keys]
        self.store = {str(g): k for g, k in self.keys}

    def test_keyid_indexes_guid_table(self):
        from lab_xvc_profile import get_xvc_key
        self.assertEqual(get_xvc_key(self.table, 2, 0, self.store), self.keys[0][1])
        self.assertEqual(get_xvc_key(self.table, 2, 1, self.store), self.keys[1][1])

    def test_key_none_and_out_of_range(self):
        from lab_xvc_profile import XVC_KEY_NONE, get_xvc_key
        self.assertIsNone(get_xvc_key(self.table, 2, XVC_KEY_NONE, self.store))
        self.assertIsNone(get_xvc_key(self.table, 1, 1, self.store))      # KeyId + 1 > KeyCount
        self.assertIsNone(get_xvc_key([uuid.UUID(int=0)], 1, 0, self.store))   # GUID nulo

    def test_missing_key_raises(self):
        from lab_xvc_profile import KeyNotAvailable, get_xvc_key
        with self.assertRaises(KeyNotAvailable):
            get_xvc_key(self.table, 2, 0, {})

    def test_xvc_needs_no_odk(self):
        g = generated()
        from pathlib import Path
        ks = read_json(Path(g["sealed"]) / "lab_keystore.json")
        ks_no_odk = {**ks, "odk": {}}
        import lab_decryptor
        c = lab_decryptor.open_container(Path(g["public"]) / "lab_xvc_encrypted.bin")
        r = lab_decryptor.decrypt_xvc(c, ks_no_odk)
        pe = (Path(g["sealed"]) / "lab_plaintext.exe").read_bytes()
        self.assertEqual(r["files"]["lab_plaintext.exe"], pe)
        data = (Path(g["public"]) / "lab_xvc_encrypted.bin").read_bytes()
        self.assertEqual(data[0x34C:0x36C], bytes(32))   # KeyMaterial vazio no XVC

    def test_regions_bound_to_distinct_keys(self):
        t = generated()["truth"]["xvc"]
        enc = {r["id"]: r["key_id"] for r in t["regions"] if r["encrypted"]}
        self.assertEqual(enc, {"0x3E9": 0, "0x3EA": 1})
        self.assertNotEqual(t["key_table"][0]["cik"], t["key_table"][1]["cik"])


if __name__ == "__main__":
    unittest.main()
