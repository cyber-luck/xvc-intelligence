"""Arvore de hashes XVD do laboratorio.

Entrada de nivel 0 de pagina cifrada (xvdtool, XVDFile.cs 27-28/128/337-339/883-917):

    [ SHA256(ciphertext_page)[:20] ][ LE32(data_unit) ]      (0x18 bytes)

Entrada de pagina sem KeyId (observacao do xvcintel no pacote real): SHA256(page)[:24].
Niveis superiores: SHA256(pagina do nivel inferior)[:24]; 170 (0xAA) entradas por
pagina; nivel mais alto gravado primeiro; TopHashBlockHash = SHA256(1a pagina).

A construcao reaproveita xvcintel.formats.hashtree.build_tree; a localizacao da
entrada usa duas implementacoes independentes (geometria do xvcintel e porte de
XvdMath.CalculateHashBlockNumForBlockNum) que os testes comparam.
"""
from __future__ import annotations

import struct

import lab_common  # noqa: F401  (ajusta sys.path)
from lab_common import PAGE, sha256
from xvcintel.formats.hashtree import ENTRIES_PER_PAGE, HASH_ENTRY_SIZE, HashTreeGeometry, build_tree, compute_geometry

ENCRYPTED_HASH_PREFIX = 0x14
DATA_UNIT_OFFSET = 0x14


def leaf_entry_encrypted(ciphertext_page: bytes, data_unit: int) -> bytes:
    if len(ciphertext_page) != PAGE:
        raise ValueError("pagina deve ter 0x1000 bytes")
    return sha256(ciphertext_page)[:ENCRYPTED_HASH_PREFIX] + struct.pack("<I", data_unit & 0xFFFFFFFF)


def leaf_entry_plain(page: bytes) -> bytes:
    if len(page) != PAGE:
        raise ValueError("pagina deve ter 0x1000 bytes")
    return sha256(page)[:HASH_ENTRY_SIZE]


def build(leaves: list[bytes]) -> tuple[bytes, HashTreeGeometry, bytes]:
    """-> (bytes da arvore na ordem gravada, geometria, TopHashBlockHash)."""
    pages, geo = build_tree(leaves)
    tree = b"".join(pages)
    return tree, geo, sha256(tree[:PAGE])


def xvdtool_block_num(levels: int, hashed_pages: int, block: int, level: int) -> tuple[int, int]:
    """Porte direto de XvdMath.CalculateHashBlockNumForBlockNum (tipo Fixed, nao resiliente).
    -> (pagina da arvore, indice da entrada)."""
    def exp(n: int) -> int:
        return 0xAA ** n

    def ceil(a: int, b: int) -> int:
        return (a + b - 1) // b

    if level > 3:
        raise ValueError("xvdtool define niveis 0..3")
    entry = block % 0xAA if level == 0 else block // exp(level) % 0xAA
    if level == 3:
        return 0, entry
    result = block // exp(level + 1)
    lv = levels - (level + 1)
    if level == 0 and lv > 0:
        result += ceil(hashed_pages, exp(2))
        lv -= 1
    if level in (0, 1) and lv > 0:
        result += ceil(hashed_pages, exp(3))
        lv -= 1
    if lv > 0:
        result += ceil(hashed_pages, exp(4))
    return result, entry


def leaf_offset(geo: HashTreeGeometry, hashed_index: int) -> int:
    """Offset da entrada de nivel 0 dentro da arvore."""
    tp, e = geo.leaf_location(hashed_index)
    return geo.entry_offset(tp, e)


def leaf_entry(tree: bytes, geo: HashTreeGeometry, hashed_index: int) -> bytes:
    o = leaf_offset(geo, hashed_index)
    return tree[o:o + HASH_ENTRY_SIZE]


def data_unit_of_page(tree: bytes, geo: HashTreeGeometry, hashed_index: int) -> int:
    """xvdtool: 'last 4 bytes of hash entry = dataUnit' (XVDFile.cs 336-339)."""
    return struct.unpack_from("<I", leaf_entry(tree, geo, hashed_index), DATA_UNIT_OFFSET)[0]


def verify_tree(tree: bytes, geo: HashTreeGeometry, top_hash: bytes) -> dict:
    """Topo + todas as ligacoes entre niveis. So usa os bytes gravados (sem chave)."""
    res = {"top_ok": sha256(tree[:PAGE]) == top_hash, "links_checked": 0, "links_bad": []}
    for lvl in range(geo.levels - 1):
        for p in range(geo.level_pages[lvl]):
            child = geo.level_start(lvl) + p
            ptp, pe = geo.parent_location(lvl, p)
            o = geo.entry_offset(ptp, pe)
            ok = tree[o:o + HASH_ENTRY_SIZE] == sha256(tree[child * PAGE:(child + 1) * PAGE])[:HASH_ENTRY_SIZE]
            res["links_checked"] += 1
            if not ok:
                res["links_bad"].append((lvl, p))
    res["ok"] = res["top_ok"] and not res["links_bad"]
    return res


def verify_leaves(tree: bytes, geo: HashTreeGeometry, read_page, keyed) -> dict:
    """read_page(hashed_index) -> bytes gravados; keyed(hashed_index) -> bool."""
    out = {"keyed_ok": 0, "keyed_bad": 0, "plain_ok": 0, "plain_bad": 0, "bad": []}
    for i in range(geo.hashed_pages):
        page = read_page(i)
        ent = leaf_entry(tree, geo, i)
        d = sha256(page)
        if keyed(i):
            ok = ent[:ENCRYPTED_HASH_PREFIX] == d[:ENCRYPTED_HASH_PREFIX]
            out["keyed_ok" if ok else "keyed_bad"] += 1
        else:
            ok = ent == d[:HASH_ENTRY_SIZE]
            out["plain_ok" if ok else "plain_bad"] += 1
        if not ok:
            out["bad"].append(i)
    out["ok"] = not out["bad"]
    return out


__all__ = ["ENTRIES_PER_PAGE", "HASH_ENTRY_SIZE", "build", "compute_geometry", "data_unit_of_page", "leaf_entry",
           "leaf_entry_encrypted", "leaf_entry_plain", "leaf_offset", "verify_leaves", "verify_tree",
           "xvdtool_block_num"]
