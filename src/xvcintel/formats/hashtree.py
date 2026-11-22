"""Geometria da arvore de hashes XVD.

Conferida contra xvdtool (XvdMath.CalculateNumberHashPages e
CalculateHashBlockNumForBlockLevel): SHA-256, entradas de 0x18 bytes,
0xAA (170) entradas por pagina, nivel mais alto gravado primeiro.

Nivel 0 (folhas) tem uma entrada por pagina hasheada; o nivel k+1 tem uma
entrada por pagina do nivel k. A pagina hasheada 0 e a primeira pagina do user
data (paginas hasheadas = drive + user data + XvcInfo + dynamic header).
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

PAGE = 0x1000
HASH_ENTRY_SIZE = 0x18
ENTRIES_PER_PAGE = PAGE // HASH_ENTRY_SIZE     # 0xAA = 170
LEAF_HASH_PREFIX_KEYED = 0x14                   # bytes de SHA-256 em entradas de regiao com KeyId
DATA_UNIT_OFFSET = 0x14                         # u32 em entry[0x14:0x18] (xvdtool: unidade de dados XTS)


def ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b


@dataclass(frozen=True)
class HashTreeGeometry:
    hashed_pages: int
    level_pages: tuple[int, ...]      # [L0, L1, ..., Ltop]
    resilient: bool = False

    @property
    def levels(self) -> int:
        return len(self.level_pages)

    @property
    def total_pages(self) -> int:
        t = sum(self.level_pages)
        return t * 2 if self.resilient else t

    def level_start(self, level: int) -> int:
        """Indice da primeira pagina do nivel dentro da arvore (topo primeiro)."""
        if not 0 <= level < self.levels:
            raise IndexError(f"nivel {level} fora de 0..{self.levels - 1}")
        return sum(self.level_pages[level + 1:])

    def leaf_location(self, hashed_index: int) -> tuple[int, int]:
        """(pagina da arvore, indice da entrada) da folha da pagina hasheada."""
        if not 0 <= hashed_index < self.hashed_pages:
            raise IndexError(f"pagina hasheada {hashed_index} fora de 0..{self.hashed_pages - 1}")
        return self.level_start(0) + hashed_index // ENTRIES_PER_PAGE, hashed_index % ENTRIES_PER_PAGE

    def parent_location(self, level: int, page_in_level: int) -> tuple[int, int]:
        """Entrada (no nivel level+1) que guarda o hash da pagina page_in_level do nivel `level`."""
        if not 0 <= level < self.levels - 1:
            raise IndexError(f"nivel {level} nao tem pai")
        if not 0 <= page_in_level < self.level_pages[level]:
            raise IndexError(f"pagina {page_in_level} fora do nivel {level}")
        return self.level_start(level + 1) + page_in_level // ENTRIES_PER_PAGE, page_in_level % ENTRIES_PER_PAGE

    def entry_offset(self, tree_page: int, entry: int) -> int:
        """Offset relativo ao inicio da arvore."""
        return tree_page * PAGE + entry * HASH_ENTRY_SIZE

    def xvdtool_location(self, block: int, level: int) -> tuple[int, int]:
        """Reimplementacao direta de XvdMath.CalculateHashBlockNumForBlockLevel (xvdtool),
        usada nos testes como implementacao de referencia independente."""
        def exp(n: int) -> int:
            return ENTRIES_PER_PAGE ** n
        tree_levels = self.levels
        n = self.hashed_pages
        if level > 3:
            raise ValueError("xvdtool so define niveis 0..3")
        entry = block % ENTRIES_PER_PAGE if level == 0 else block // exp(level) % ENTRIES_PER_PAGE
        if level == 3:
            return 0, entry
        result = block // exp(level + 1)
        tree_levels -= level + 1
        if level == 0 and tree_levels > 0:
            result += ceil_div(n, exp(2))
            tree_levels -= 1
        if level in (0, 1) and tree_levels > 0:
            result += ceil_div(n, exp(3))
            tree_levels -= 1
        if tree_levels > 0:
            result += ceil_div(n, exp(4))
        return result, entry


def compute_geometry(hashed_pages: int, resilient: bool = False) -> HashTreeGeometry:
    if hashed_pages <= 0:
        return HashTreeGeometry(0, (), resilient)
    levels = [ceil_div(hashed_pages, ENTRIES_PER_PAGE)]
    while levels[-1] > 1:
        levels.append(ceil_div(levels[-1], ENTRIES_PER_PAGE))
    return HashTreeGeometry(hashed_pages, tuple(levels), resilient)


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


@dataclass(frozen=True)
class LeafEntry:
    raw: bytes

    @property
    def hash_prefix_keyed(self) -> bytes:
        return self.raw[:LEAF_HASH_PREFIX_KEYED]

    @property
    def data_unit(self) -> int:
        return struct.unpack_from("<I", self.raw, DATA_UNIT_OFFSET)[0]


def leaf_matches(entry: bytes, page: bytes, keyed: bool) -> bool:
    """Regra observada: regiao com KeyId compara 0x14 bytes; sem KeyId compara 0x18."""
    d = sha256(page)
    return entry[:0x14] == d[:0x14] if keyed else entry[:0x18] == d[:0x18]


def build_tree(page_hashes_entries: list[bytes]) -> tuple[list[bytes], HashTreeGeometry]:
    """Constroi a arvore a partir das entradas de folha (0x18 bytes cada).

    Devolve (paginas da arvore na ordem gravada, geometria). Usado por fixtures
    sinteticas e por testes; reproduz a regra de ligacao entre niveis.
    """
    geo = compute_geometry(len(page_hashes_entries))
    level_entries = list(page_hashes_entries)
    levels_pages: list[list[bytes]] = []
    for lvl in range(geo.levels):
        pages_ = []
        for i in range(0, len(level_entries), ENTRIES_PER_PAGE):
            chunk = b"".join(level_entries[i:i + ENTRIES_PER_PAGE])
            pages_.append(chunk.ljust(PAGE, b"\0"))
        levels_pages.append(pages_)
        level_entries = [sha256(p)[:HASH_ENTRY_SIZE] for p in pages_]
    ordered = [p for lvl in reversed(levels_pages) for p in lvl]
    return ordered, geo
