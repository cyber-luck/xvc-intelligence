"""FASE 5 - conteineres: parseaveis pelo xvcintel, arvore integra, marcador, reprodutiveis."""
import unittest
from pathlib import Path

from lab_test_helpers import generated, requires_crypto, tmp_root

import lab_hash_tree as HT
from lab_common import LAB_MARKER, PAGE, sha256_file


@requires_crypto
class TestContainers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.g = generated()
        cls.pub = Path(cls.g["public"])
        cls.truth = cls.g["truth"]

    def _pkg(self, name):
        from xvcintel.core.reader import FileSource
        from xvcintel.engines.package import load_package
        src = FileSource(str(self.pub / name))
        self.addCleanup(src.close)
        return load_package(src).value

    def test_separation_on_disk(self):
        self.assertEqual(sorted(p.name for p in self.pub.iterdir()),
                         ["lab_manifest.json", "lab_xvc_encrypted.bin", "lab_xvd_encrypted.bin"])
        sealed = sorted(p.name for p in Path(self.g["sealed"]).iterdir())
        self.assertIn("lab_ground_truth.json", sealed)
        self.assertIn("lab_plaintext.exe", sealed)

    def test_lab_marker(self):
        for n in ("lab_xvd_encrypted.bin", "lab_xvc_encrypted.bin"):
            d = (self.pub / n).read_bytes()
            self.assertTrue(d.startswith(LAB_MARKER))
            self.assertTrue(d[0x39C:0x3AC].startswith(LAB_MARKER))

    def test_xvc_parsed_and_consistent(self):
        from xvcintel.evidence.model import FAIL
        pkg = self._pkg("lab_xvc_encrypted.bin")
        self.assertEqual(pkg.errors, [])
        self.assertFalse([c.id for c in pkg.checks if c.status == FAIL])
        self.assertTrue(all(ok for _, ok, _ in pkg.file_checks))
        self.assertEqual([r.name for r in pkg.rows], [f["name"] for f in self.truth["xvc"]["files"]])

    def test_xvcintel_integrity_and_pages(self):
        from xvcintel.engines.integrity import IntegrityOptions, run_integrity
        from xvcintel.engines.pages import run_pages
        from xvcintel.evidence.model import FAIL
        for n in ("lab_xvc_encrypted.bin", "lab_xvd_encrypted.bin"):
            pkg = self._pkg(n)
            res = run_integrity(pkg, IntegrityOptions(full_leaf_level=True)) + (run_pages(pkg) if pkg.xvcinfo else [])
            self.assertFalse([c.id for c in res if c.status == FAIL], n)

    def test_leaf_data_units_match_truth(self):
        pkg = self._pkg("lab_xvc_encrypted.bin")
        data = (self.pub / "lab_xvc_encrypted.bin").read_bytes()
        tr = pkg.layout.get("hash tree")
        tree = data[tr.offset:tr.end]
        for f in self.truth["xvc"]["files"]:
            if f["data_units"]:
                got = [HT.data_unit_of_page(tree, pkg.layout.geometry, f["hashed_index_first_page"] + i)
                       for i in range(f["pages"])]
                self.assertEqual(got, f["data_units"], f["name"])
        a = next(f for f in self.truth["xvc"]["files"] if f["name"] == "lab_plaintext.exe")
        self.assertNotEqual(a["data_units"], list(range(a["pages"])))          # A: nao sequencial

    def test_xvd_section_starts_at_user_data(self):
        pkg = self._pkg("lab_xvd_encrypted.bin")
        self.assertEqual(pkg.layout.get("user data").offset, self.truth["xvd"]["layout"]["user_data"][0])
        self.assertIsNone(pkg.xvcinfo)
        self.assertIsNone(pkg.userdata)                 # user data cifrado

    def test_keyless_tools(self):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
        import validate_xts
        for n in ("lab_xvd_encrypted.bin", "lab_xvc_encrypted.bin"):
            v = validate_xts.validate(self.pub / n)
            self.assertTrue(v["hash_tree"]["top_ok"])
            self.assertEqual(v["hash_tree"]["links_bad"], 0)
            self.assertTrue(v["hash_tree"]["leaves"]["ok"])
            self.assertTrue(all(s["aligned_0x1000"] for s in v["xts_sections"]))

    def test_reproducible_with_seed(self):
        import lab_encryptor
        from lab_test_helpers import SEED
        g2 = lab_encryptor.generate(tmp_root() / "gen_again", SEED)
        for n in ("lab_xvd_encrypted.bin", "lab_xvc_encrypted.bin"):
            self.assertEqual(sha256_file(self.pub / n), sha256_file(Path(g2["public"]) / n))

    def test_random_mode_differs(self):
        import lab_encryptor
        r1 = lab_encryptor.generate(tmp_root() / "rnd1", None)
        r2 = lab_encryptor.generate(tmp_root() / "rnd2", None)
        self.assertEqual(r1["truth"]["mode"], "secure-random-keys")
        self.assertNotEqual(r1["truth"]["odk"], r2["truth"]["odk"])
        self.assertNotEqual(sha256_file(Path(r1["public"]) / "lab_xvc_encrypted.bin"),
                            sha256_file(Path(r2["public"]) / "lab_xvc_encrypted.bin"))

    def test_pages_are_xts_units(self):
        size = (self.pub / "lab_xvd_encrypted.bin").stat().st_size
        self.assertEqual(size % PAGE, 0)


if __name__ == "__main__":
    unittest.main()
