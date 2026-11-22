"""FASE 4 - executavel PE32+ sintetico."""
import struct
import tempfile
import unittest
from pathlib import Path

from lab_test_helpers import generated  # noqa: F401

from lab_common import PAGE, Rng
from lab_pe_generator import B_CHANGED_DATA_PAGES, IMPORTS, _checksum, build_pe
from xvcintel.core.result import Ok
from xvcintel.formats.pe import parse_pe


class TestPe(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = build_pe(Rng(3), "00112233aabbccdd", "A")
        cls.b = build_pe(Rng(3), "00112233aabbccdd", "B")

    def test_headers(self):
        d = self.a.data
        self.assertEqual(d[:2], b"MZ")
        lf = struct.unpack_from("<I", d, 0x3C)[0]
        self.assertEqual(d[lf:lf + 4], b"PE\0\0")
        self.assertEqual(struct.unpack_from("<H", d, lf + 4)[0], 0x8664)
        self.assertEqual(struct.unpack_from("<H", d, lf + 24)[0], 0x20B)

    def test_parse_sections_imports_resources(self):
        r = parse_pe(self.a.data)
        self.assertIsInstance(r, Ok)
        pe = r.value
        self.assertEqual(pe.problems, [])
        self.assertEqual([s.name for s in pe.sections], [".text", ".rdata", ".data", ".rsrc"])
        self.assertEqual({i.dll: i.functions for i in pe.imports}, IMPORTS)
        self.assertEqual(pe.resources["leaf_count"], 2)
        self.assertEqual(pe.optional["AddressOfEntryPoint"], 0x1000)

    def test_checksum_valid(self):
        d = self.a.data
        lf = struct.unpack_from("<I", d, 0x3C)[0]
        off = lf + 4 + 20 + 64
        self.assertEqual(struct.unpack_from("<I", d, off)[0], _checksum(d, off))

    def test_strings_and_lab_id(self):
        for s in self.a.info["strings"]:
            self.assertIn(s.encode(), self.a.data)
        self.assertIn(b"LAB_SYNTHETIC", self.a.data)
        self.assertIn(b"LABID-00112233aabbccdd", self.a.data)

    def test_deterministic(self):
        self.assertEqual(build_pe(Rng(3), "00112233aabbccdd", "A").data, self.a.data)
        self.assertNotEqual(build_pe(Rng(4), "00112233aabbccdd", "A").data, self.a.data)

    def test_build_b_same_size_localized_changes(self):
        a, b = self.a.data, self.b.data
        self.assertEqual(len(a), len(b))
        self.assertNotEqual(a, b)
        diff = [i for i in range(len(a) // PAGE + 1) if a[i * PAGE:(i + 1) * PAGE] != b[i * PAGE:(i + 1) * PAGE]]
        self.assertLess(len(diff), 12)
        data_raw = next(s for s in self.a.info["sections"] if s["name"] == ".data")["raw_pointer"]
        for p in B_CHANGED_DATA_PAGES:
            self.assertIn((data_raw + p * PAGE) // PAGE, diff)

    def test_project_alpha_validator(self):
        import _bootstrap  # noqa: F401
        from validation.pe_validator import validate_pe
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.exe"
            p.write_bytes(self.a.data)
            v = validate_pe(p, expect_machine=0x8664, expect_magic=0x20B)
        self.assertTrue(v["valid"], [c for c in v["checks"] if not c["ok"]])


if __name__ == "__main__":
    unittest.main()
