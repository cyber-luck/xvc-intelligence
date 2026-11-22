"""Acesso a arvore de hashes no pacote (com cache de paginas e leitura em streaming)."""
from __future__ import annotations

import struct
from collections import OrderedDict
from typing import Iterator

from ..core.reader import DEFAULT_CHUNK
from ..core.util import PAGE
from ..formats.hashtree import ENTRIES_PER_PAGE, HASH_ENTRY_SIZE
from ..formats.layout import HASH_TREE, Layout


class TreeReader:
    def __init__(self, src, layout: Layout, cache_pages: int = 4096):
        self.src = src
        self.layout = layout
        self.geo = layout.geometry
        self.base = layout.get(HASH_TREE).offset
        self._cache: OrderedDict[int, bytes] = OrderedDict()
        self._cache_max = cache_pages

    def tree_page(self, idx: int) -> bytes:
        b = self._cache.get(idx)
        if b is not None:
            self._cache.move_to_end(idx)
            return b
        b = self.src.read_at(self.base + idx * PAGE, PAGE)
        self._cache[idx] = b
        if len(self._cache) > self._cache_max:
            self._cache.popitem(last=False)
        return b

    def prefetch(self, first: int, count: int) -> None:
        """Le paginas consecutivas da arvore de uma vez (menos seeks em disco lento)."""
        count = min(count, self._cache_max)
        blob = self.src.read_at(self.base + first * PAGE, count * PAGE)
        for i in range(len(blob) // PAGE):
            self._cache[first + i] = blob[i * PAGE:(i + 1) * PAGE]
            self._cache.move_to_end(first + i)
        while len(self._cache) > self._cache_max:
            self._cache.popitem(last=False)

    def entry(self, tree_page: int, entry: int) -> bytes:
        p = self.tree_page(tree_page)
        return p[entry * HASH_ENTRY_SIZE:(entry + 1) * HASH_ENTRY_SIZE]

    def leaf(self, hashed_index: int) -> bytes:
        tp, e = self.geo.leaf_location(hashed_index)
        return self.entry(tp, e)

    def leaf_for_page(self, abs_page: int) -> bytes:
        return self.leaf(self.layout.hashed_index_of_page(abs_page))

    def data_unit(self, abs_page: int) -> int:
        return struct.unpack_from("<I", self.leaf_for_page(abs_page), 0x14)[0]

    def leaf_offset(self, abs_page: int) -> int:
        tp, e = self.geo.leaf_location(self.layout.hashed_index_of_page(abs_page))
        return self.base + tp * PAGE + e * HASH_ENTRY_SIZE

    def iter_level_pages(self, level: int, first: int = 0, count: int | None = None,
                         chunk: int = DEFAULT_CHUNK) -> Iterator[tuple[int, bytes]]:
        """(indice da pagina dentro do nivel, bytes) em ordem, lendo em blocos."""
        n = self.geo.level_pages[level]
        count = n - first if count is None else min(count, n - first)
        start = self.base + (self.geo.level_start(level) + first) * PAGE
        idx = first
        for blob in self.src.iter_chunks(start, count * PAGE, chunk):
            for i in range(len(blob) // PAGE):
                yield idx, blob[i * PAGE:(i + 1) * PAGE]
                idx += 1

    def iter_data_units(self, first_hashed: int, count: int, chunk: int = DEFAULT_CHUNK) -> Iterator[tuple[int, bytes]]:
        """(indice hasheado, entrada de folha) para um intervalo, lendo o nivel 0 em streaming."""
        if count <= 0:
            return
        first_page = first_hashed // ENTRIES_PER_PAGE
        last_page = (first_hashed + count - 1) // ENTRIES_PER_PAGE
        end = first_hashed + count
        for pidx, page in self.iter_level_pages(0, first_page, last_page - first_page + 1, chunk):
            base = pidx * ENTRIES_PER_PAGE
            lo = max(first_hashed, base)
            hi = min(end, base + ENTRIES_PER_PAGE)
            for h in range(lo, hi):
                e = h - base
                yield h, page[e * HASH_ENTRY_SIZE:(e + 1) * HASH_ENTRY_SIZE]
