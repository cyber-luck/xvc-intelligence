"""FASE 7 - revelacao das chaves, round-trip e controles negativos."""
import unittest

from lab_test_helpers import requires_crypto, reveal_report


@requires_crypto
class TestKeyReveal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = reveal_report()

    def test_cik_unwrapped(self):
        self.assertTrue(self.r["xvd"]["unwrapped_cik_equals_ground_truth"])
        self.assertTrue(self.r["xvd"]["cik_split"]["tweak_key_equals_truth"])
        self.assertTrue(self.r["xvd"]["cik_split"]["data_key_equals_truth"])

    def test_exact_recovery_all_targets(self):
        for k, v in self.r["recovered"].items():
            self.assertTrue(v["vs_original"]["sha256_equal"], k)
            if k.endswith(".exe"):
                self.assertEqual(v["vs_original"]["pct_equal"], 100.0)
                self.assertTrue(v["pe"]["project_alpha_validate_pe"]["valid"])
                self.assertEqual(len(v["ground_truth_strings_found"]), v["ground_truth_strings_total"])

    def test_roundtrip(self):
        self.assertTrue(self.r["xvd"]["roundtrip_reencrypt_equals_stored"])
        self.assertTrue(self.r["xvc"]["roundtrip_reencrypt_equals_stored"])
        self.assertFalse(self.r["xvc"]["odk_used"])

    def test_hash_tree_before_decrypt(self):
        for tag in ("xvd", "xvc"):
            self.assertTrue(self.r["hash_tree"][tag]["top_and_links"]["ok"])
            self.assertTrue(self.r["hash_tree"][tag]["leaves"]["ok"])

    def test_negative_controls_match_expected_matrix(self):
        import compare_results as CR
        ev = CR.evaluate_controls(self.r["negative_controls"])
        bad = [row["control"] for row in ev["rows"] if not row["matches_expectation"]]
        self.assertEqual(bad, [])
        self.assertEqual({row["control"] for row in ev["rows"]}, set(CR.EXPECTED_CONTROLS))

    def test_roundtrip_exact_even_when_plaintext_wrong(self):
        for c in self.r["negative_controls"]:
            for tag, res in c["results"].items():
                if res.get("applicable") and c["control"] != "missing_key":
                    self.assertTrue(res["roundtrip_reencrypt_equals_stored"], (c["control"], tag))

    def test_wrong_odk_yields_wrong_cik(self):
        row = next(c for c in self.r["negative_controls"] if c["control"] == "wrong_odk")
        self.assertIs(row["results"]["xvd"]["unwrapped_cik_equals_true_cik"], False)

    def test_originals_untouched(self):
        self.assertTrue(self.r["originals_untouched"]["unchanged"])


if __name__ == "__main__":
    unittest.main()
