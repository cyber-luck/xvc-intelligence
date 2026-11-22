"""Arvore de hashes: entradas de 24 bytes, data units, niveis, indice do xvdtool."""
import struct
import unittest

from lab_test_helpers import generated  # noqa: F401  (ajusta sys.path)

import lab_hash_tree as HT
from lab_common import PAGE, Rng, sha256

# InlineData de LibXboxOne.Tests/XvdHashBlockTests.cs (TestCalculateHashBlockNumForBlockNum):
# (hashTreeLevels, xvdDataBlockCount, blockNum, index) -> (entryNum, result)
XVDTOOL_INDEX_VECTORS = [
    (0x2, 0x4000, 0xE02, 0x0, 0x10, 0x16),
    (0x3, 0xC001, 0x150A, 0x0, 0x74, 0x22),
    (0x3, 0x20001, 0x3772, 0x0, 0x54, 0x59),
    (0x3, 0x5F653, 0x5F604, 0x0, 0x0, 0x909),
    (0x3, 0x5F653, 0x5F604, 0x1, 0x58, 0xE),
    (0x3, 0x5F653, 0x5BB94, 0x1, 0x0, 0xE),
    (0x3, 0x5F653, 0x5BB94, 0x2, 0xD, 0x0),
    (0x3, 0x5F653, 0xAB2, 0x0, 0x12, 0x1F),
    (0x3, 0x5F653, 0xF20B, 0x0, 0x53, 0x17B),
    (0x3, 0x5F653, 0xF60A, 0x0, 0x56, 0x181),
]


class TestLeaf(unittest.TestCase):
    def test_encrypted_leaf_layout(self):
        page = Rng(1).bytes("p", PAGE)
        e = HT.leaf_entry_encrypted(page, 0xDEADBEEF)
        self.assertEqual(len(e), 0x18)
        self.assertEqual(e[:0x14], sha256(page)[:0x14])
        self.assertEqual(struct.unpack("<I", e[0x14:])[0], 0xDEADBEEF)

    def test_plain_leaf(self):
        page = Rng(2).bytes("p", PAGE)
        self.assertEqual(HT.leaf_entry_plain(page), sha256(page)[:0x18])


class TestTree(unittest.TestCase):
    def _tree(self, n, dus):
        rng = Rng(n)
        pages = [rng.bytes(f"p{i}", PAGE) for i in range(n)]
        leaves = [HT.leaf_entry_encrypted(p, d) for p, d in zip(pages, dus)]
        tree, geo, top = HT.build(leaves)
        return pages, tree, geo, top

    def test_sequential_data_units(self):
        n = 400                                       # 3 paginas L0 -> 2 niveis
        pages, tree, geo, top = self._tree(n, list(range(n)))
        self.assertEqual(geo.levels, 2)
        self.assertEqual([HT.data_unit_of_page(tree, geo, i) for i in range(n)], list(range(n)))
        self.assertTrue(HT.verify_tree(tree, geo, top)["ok"])
        self.assertTrue(HT.verify_leaves(tree, geo, lambda i: pages[i], lambda i: True)["ok"])

    def test_non_sequential_data_units(self):
        n = 200
        dus = [0x7A3C1000 + i for i in range(50)] + [0x400 + i for i in range(150)]
        dus[77] = 0xFFFFFFFF
        pages, tree, geo, top = self._tree(n, dus)
        self.assertEqual([HT.data_unit_of_page(tree, geo, i) for i in range(n)], dus)

    def test_three_levels(self):
        n = 0xAA * 0xAA + 5                           # forca 3 niveis
        leaves = [struct.pack("<I", i) * 6 for i in range(n)]
        tree, geo, top = HT.build(leaves)
        self.assertEqual(geo.levels, 3)
        self.assertTrue(HT.verify_tree(tree, geo, top)["ok"])

    def test_tamper_detected(self):
        pages, tree, geo, top = self._tree(400, list(range(400)))
        t = bytearray(tree)
        t[geo.level_start(0) * PAGE + 5] ^= 1          # folha alterada -> ligacao L0->L1 quebra
        self.assertFalse(HT.verify_tree(bytes(t), geo, top)["ok"])
        bad_page = bytearray(pages[10])
        bad_page[0] ^= 1
        r = HT.verify_leaves(tree, geo, lambda i: bytes(bad_page) if i == 10 else pages[i], lambda i: True)
        self.assertEqual(r["bad"], [10])

    def test_xvdtool_index_vectors(self):
        for levels, n, block, level, exp_entry, exp_result in XVDTOOL_INDEX_VECTORS:
            self.assertEqual(HT.xvdtool_block_num(levels, n, block, level), (exp_result, exp_entry),
                             f"levels={levels} n={n:#x} block={block:#x} level={level}")

    def test_xvdtool_port_matches_geometry(self):
        for n in (171, 400, 30000):
            geo = HT.compute_geometry(n)
            for b in range(0, n, max(1, n // 97)):
                self.assertEqual(HT.xvdtool_block_num(geo.levels, n, b, 0), geo.leaf_location(b))


if __name__ == "__main__":
    unittest.main()
