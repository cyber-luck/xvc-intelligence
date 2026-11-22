"""FASE 6 - analise as cegas: separacao auditada e nenhuma alegacao falsa."""
import shutil
import unittest
from pathlib import Path

from lab_test_helpers import blind_report, generated, requires_crypto, tmp_root

import lab_common


@requires_crypto
class TestBlind(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = blind_report()

    def test_access_audit(self):
        au = self.r["access_audit"]
        self.assertTrue(au["separation_respected"], au["violations"])
        self.assertGreater(au["events_recorded"], 50)
        self.assertFalse([p for p in au["data_files_opened"] if "sealed" in Path(p).parts])

    def test_no_false_recovery_claim(self):
        self.assertEqual(set(self.r["recovery_claim"]["target_plaintext_bytes_recovered"].values()), {0})
        for t, v in self.r["shadow_pe_reconstructor"].items():
            self.assertEqual(v["classification"], "METADATA_ONLY", t)
            self.assertEqual(v["bytes_original_with_proof"], 0, t)
            self.assertFalse(v["partial_pe_written"], t)

    def test_carving_rejects_random_mz(self):
        for tag, c in self.r["pe_carving"].items():
            self.assertEqual(c["pe_candidates"], 0, tag)
            self.assertTrue(c["entire_file_scanned"], tag)
        self.assertGreater(sum(c["raw_mz_hits"] for c in self.r["pe_carving"].values()), 0)

    def test_decoy_and_ciphertext_not_pe(self):
        for name, v in self.r["pe_check"].items():
            self.assertFalse(v["is_pe"], name)

    def test_metadata_observable(self):
        files = {f["name"]: f for f in self.r["xvc_files"]}
        self.assertTrue(files["lab_plaintext.exe"]["encrypted_by_keyid"])
        self.assertFalse(files["lab_public_notes.txt"]["encrypted_by_keyid"])
        truth = generated()["truth"]
        pe_a = truth["pe"]["A"]
        self.assertEqual(files["lab_plaintext.exe"]["size"], pe_a["size"])      # tamanho exato vaza
        self.assertFalse(files["lab_plaintext.exe"]["stored_starts_with_MZ"])

    def test_build_distinction_indeterminate(self):
        bd = self.r["build_distinction"]
        self.assertEqual(bd["verdict"], "INDETERMINADO sem chave")
        self.assertEqual(bd["identical_ciphertext_pages_same_position"], 0)

    def test_refuses_sealed_or_contaminated_input(self):
        import blind_forensic_analysis as BFA
        g = generated()
        with self.assertRaises(lab_common.LabSafetyError):
            BFA.analyze(Path(g["sealed"]), tmp_root() / "bw1")
        dirty = tmp_root() / "dirty_public"
        shutil.copytree(g["public"], dirty)
        shutil.copy(Path(g["sealed"]) / "lab_ground_truth.json", dirty)
        with self.assertRaises(lab_common.LabSafetyError):
            BFA.analyze(dirty, tmp_root() / "bw2")


if __name__ == "__main__":
    unittest.main()
