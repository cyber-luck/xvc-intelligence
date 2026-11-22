"""Layout de um XVD/XVC calculado a partir do cabecalho (nada fixo por pacote).

Ordem (xvdtool): cabecalho 0x3000 | XVD embutido | MDU | hash tree | user data |
XvcInfo | dynamic header | drive data. O MDU vem de MutableDataPageCount (0x470).
Os nomes das regioes sao os do xvc_probe.py original (compatibilidade).
"""
from __future__ import annotations

from dataclasses import dataclass

from ..core.util import PAGE, pages
from .hashtree import HashTreeGeometry, compute_geometry
from .xvd_header import HEADER_INCL_SIGNATURE_SIZE, XvdHeader

HEADER = "cabecalho"
EMBEDDED = "XVD embutido"
MDU = "mutable data (MDU)"
HASH_TREE = "hash tree"
USER_DATA = "user data"
XVC_INFO = "XvcInfo"
DYN_HEADER = "dynamic header"
DRIVE = "drive data"
ORDER = (HEADER, EMBEDDED, MDU, HASH_TREE, USER_DATA, XVC_INFO, DYN_HEADER, DRIVE)


@dataclass(frozen=True)
class LayoutRegion:
    name: str
    offset: int
    size: int

    @property
    def end(self) -> int:
        return self.offset + self.size


@dataclass(frozen=True)
class Layout:
    regions: tuple[LayoutRegion, ...]
    integrity: bool
    resilient: bool
    mdu_pages: int
    mdu_source: str
    geometry: HashTreeGeometry
    hashed_pages: int

    def get(self, name: str) -> LayoutRegion:
        return next(r for r in self.regions if r.name == name)

    @property
    def end(self) -> int:
        return self.regions[-1].end

    def region_of(self, off: int) -> str:
        for r in self.regions:
            if r.offset <= off < r.end:
                return r.name if r.name != DRIVE else f"drive data +0x{off - r.offset:x}"
        return "fora do arquivo"

    @property
    def user_data_page(self) -> int:
        """Pagina absoluta do arquivo onde comeca o espaco hasheado (pagina hasheada 0)."""
        return self.get(USER_DATA).offset // PAGE

    def hashed_index_of_page(self, abs_page: int) -> int:
        return abs_page - self.user_data_page

    def as_tuples(self) -> list[tuple[str, int, int]]:
        return [(r.name, r.offset, r.size) for r in self.regions]


def hashed_page_count(h: XvdHeader) -> int:
    return h.drive_size // PAGE + pages(h.user_data_length) + pages(h.xvc_data_length) + pages(h.dynamic_header_length)


def compute_layout(h: XvdHeader, mdu_pages: int | None = None, extra_hash_tree_pages: int = 0) -> Layout:
    """mdu_pages=None usa MutableDataPageCount do cabecalho (0x470)."""
    source = "cabecalho 0x470 (MutableDataPageCount)"
    if mdu_pages is None:
        mdu_pages = h.mutable_data_page_count
    else:
        source = "informado pelo chamador"
    n_hashed = hashed_page_count(h)
    geo = compute_geometry(n_hashed, h.resilient) if h.integrity else compute_geometry(0)
    ht_pages = (geo.total_pages if h.integrity else 0) + extra_hash_tree_pages
    regs = []
    off = 0
    for name, size in (
        (HEADER, HEADER_INCL_SIGNATURE_SIZE),
        (EMBEDDED, pages(h.embedded_xvd_length) * PAGE),
        (MDU, mdu_pages * PAGE),
        (HASH_TREE, ht_pages * PAGE),
        (USER_DATA, pages(h.user_data_length) * PAGE),
        (XVC_INFO, pages(h.xvc_data_length) * PAGE),
        (DYN_HEADER, pages(h.dynamic_header_length) * PAGE),
        (DRIVE, h.drive_size),
    ):
        regs.append(LayoutRegion(name, off, size))
        off += size
    return Layout(tuple(regs), h.integrity, h.resilient, mdu_pages, source, geo, n_hashed)
