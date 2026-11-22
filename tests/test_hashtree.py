import hashlib
import random
import struct

import pytest

from xvcintel.formats.hashtree import (ENTRIES_PER_PAGE, HASH_ENTRY_SIZE, PAGE, build_tree, compute_geometry,
                                       leaf_matches)

REAL_N = 54_605_734


def test_constants():
    assert ENTRIES_PER_PAGE == 170 and HASH_ENTRY_SIZE == 0x18


def test_real_geometry():
    g = compute_geometry(REAL_N)
    assert g.level_pages == (321211, 1890, 12, 1)
    assert [g.level_start(i) for i in range(4)] == [1903, 13, 1, 0]
    assert g.total_pages * PAGE == 0x4EE2A000
    assert g.leaf_location(0) == (1903, 0)
    assert g.leaf_location(REAL_N - 1) == (1903 + (REAL_N - 1) // 170, (REAL_N - 1) % 170)


def test_geometry_edges():
    assert compute_geometry(0).levels == 0
    assert compute_geometry(1).level_pages == (1,)
    assert compute_geometry(170).level_pages == (1,)
    assert compute_geometry(171).level_pages == (2, 1)
    assert compute_geometry(170 * 170 + 1).level_pages == (171, 2, 1)
    assert compute_geometry(171, resilient=True).total_pages == 6
    g = compute_geometry(171)
    with pytest.raises(IndexError):
        g.leaf_location(171)
    with pytest.raises(IndexError):
        g.parent_location(1, 0)
    with pytest.raises(IndexError):
        g.level_start(5)


@pytest.mark.parametrize("n", [171, 5000, 170 * 170 + 3, REAL_N])
def test_matches_xvdtool_reference(n):
    """Reimplementacao direta de XvdMath.CalculateHashBlockNumForBlockLevel == geometria propria."""
    g = compute_geometry(n)
    rnd = random.Random(n)
    for block in [0, 1, 169, 170, n - 1] + [rnd.randrange(n) for _ in range(200)]:
        assert g.xvdtool_location(block, 0) == g.leaf_location(block)
        for level in range(1, min(g.levels, 4)):
            page_in_lower = block // 170 ** level
            exp = g.parent_location(level - 1, page_in_lower) if level < g.levels else None
            got = g.xvdtool_location(block, level)
            if level == g.levels - 1 == 3:
                assert got == (0, exp[1])
            else:
                assert got == exp


def test_build_tree_links_and_top():
    rnd = random.Random(3)
    leaves = [rnd.randbytes(0x18) for _ in range(400)]
    tree, g = build_tree(leaves)
    assert g.level_pages == (3, 1) and len(tree) == 4
    # topo primeiro; cada pagina do nivel 0 esta ligada ao topo
    for i in range(3):
        tp, e = g.parent_location(0, i)
        assert tree[tp][e * 0x18:(e + 1) * 0x18] == hashlib.sha256(tree[g.level_start(0) + i]).digest()[:0x18]
    tp, e = g.leaf_location(399)
    assert tree[tp][e * 0x18:(e + 1) * 0x18] == leaves[399]


def test_leaf_rule():
    page = bytes(range(256)) * 16
    d = hashlib.sha256(page).digest()
    keyed = d[:0x14] + struct.pack("<I", 0xDEADBEEF)
    assert leaf_matches(keyed, page, keyed=True)
    assert not leaf_matches(keyed, page, keyed=False)
    assert leaf_matches(d[:0x18], page, keyed=False)
    assert not leaf_matches(d[:0x18], page[:-1] + b"\1", keyed=False)
