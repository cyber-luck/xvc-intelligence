"""Carrega o pacote: cabecalho -> layout -> XvcInfo -> user data -> SegmentMetadata -> mapa.

Tudo e calculado a partir do cabecalho; o unico "fallback" e a busca da ancora
do XvcInfo (ContentID == VDUID) em volta do offset calculado, que fica
registrada como falha de checagem se for necessaria.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..core.result import Err, Ok, Result
from ..core.util import PAGE, pages
from ..evidence.model import FAIL, INFO, PASS, CheckResult, Evidence
from ..formats import layout as L
from ..formats.filemap import Check, FileRow, map_files
from ..formats.layout import Layout, compute_layout
from ..formats.userdata import SEGMETA_NAME, SegmentMetadata, UserData, parse_segment_metadata, parse_userdata
from ..formats.xvcinfo import XvcInfo, parse_xvcinfo, structural_checks
from ..formats.xvd_header import HEADER_INCL_SIGNATURE_SIZE, HEADER_STRUCT_SIZE, XvdHeader, parse_xvd_header

DESC_TO_LAYOUT = {
    "XVC-HD": (L.HEADER,),
    "XVC-EXVD": (L.EMBEDDED,),
    "XVC-MDU": (L.MDU,),
    "XVC-MD": (L.HASH_TREE, L.USER_DATA, L.XVC_INFO, L.DYN_HEADER),
}


@dataclass
class Package:
    src: object
    size: int
    header: XvdHeader
    layout: Layout
    xvcinfo: XvcInfo | None = None
    xvcinfo_offset: int | None = None
    userdata: UserData | None = None
    segmeta: SegmentMetadata | None = None
    rows: list[FileRow] = field(default_factory=list)
    file_checks: list[Check] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    embedded_header: XvdHeader | None = None
    embedded_layout: Layout | None = None

    def check(self, cid: str) -> CheckResult | None:
        return next((c for c in self.checks if c.id == cid), None)

    def row(self, name: str) -> FileRow | None:
        return next((r for r in self.rows if r.name.casefold() == name.casefold()), None)

    @property
    def path(self) -> str:
        return getattr(self.src, "name", "<?>")


def _find_anchor(src, est: int, needle: bytes, radius: int) -> int | None:
    for delta in sorted(range(-radius, radius + 1), key=abs):
        off = est + delta * PAGE
        if off < 0 or off + len(needle) > src.size:
            continue
        if src.read_at(off, len(needle)) == needle:
            return off
    return None


def load_header(src, base: int = 0) -> Result[XvdHeader]:
    return parse_xvd_header(src.read_at(base, HEADER_STRUCT_SIZE), base)


def load_package(src, anchor_radius: int = 64, mdu_pages: int | None = None) -> Result[Package]:
    r = load_header(src)
    if isinstance(r, Err):
        return r
    h = r.value
    lay = compute_layout(h, mdu_pages)
    pkg = Package(src, src.size, h, lay)
    ev_mdu = Evidence("xvc:cabecalho", "MutableDataPageCount", 0x470, str(h.mutable_data_page_count))

    # ---- XvcInfo
    if h.is_xvc:
        est = lay.get(L.XVC_INFO).offset
        needle = h.vduid.bytes_le
        at_est = est + 16 <= src.size and src.read_at(est, 16) == needle
        off = est if at_est else _find_anchor(src, est, needle, anchor_radius)
        pkg.checks.append(CheckResult(
            "layout.xvcinfo_anchor", "XvcInfo.ContentID == VDUID no offset calculado pelo layout",
            PASS if at_est else FAIL,
            f"calculado 0x{est:X}; ancora " + (f"0x{off:X}" if off is not None else "nao encontrada"),
            evidence=[ev_mdu, Evidence("xvc:XvcInfo", "ContentID", est, None, "layout.xvcinfo_anchor")]))
        if off is not None:
            raw = src.read_at(off, h.xvc_data_length)
            rx = parse_xvcinfo(raw, off)
            if isinstance(rx, Ok):
                pkg.xvcinfo, pkg.xvcinfo_offset = rx.value, off
            else:
                pkg.errors.append(str(rx.error))
    xi = pkg.xvcinfo

    # ---- checagens de layout contra as regioes
    if xi:
        mdu = xi.region_by_desc("XVC-MDU")
        if mdu:
            ok = mdu.length == lay.mdu_pages * PAGE
            pkg.checks.append(CheckResult(
                "layout.mdu_vs_region", "MutableDataPageCount (0x470) x comprimento da regiao XVC-MDU",
                PASS if ok else FAIL, f"0x470={h.mutable_data_page_count} pagina(s); XVC-MDU 0x{mdu.length:X}",
                evidence=[ev_mdu, Evidence("xvc:XvcInfo", "region XVC-MDU Length", xi.base_offset + mdu.rel + 0x58,
                                           f"0x{mdu.length:X}")]))
        md = xi.region_by_desc("XVC-MD")
        if md:
            ht_obs = md.length - sum(lay.get(n).size for n in (L.USER_DATA, L.XVC_INFO, L.DYN_HEADER))
            ht_calc = lay.get(L.HASH_TREE).size
            pkg.checks.append(CheckResult(
                "layout.hash_tree_size", "tamanho da hash tree: formula xvdtool x regiao XVC-MD",
                PASS if ht_obs == ht_calc else FAIL, f"formula 0x{ht_calc:X}, observado 0x{ht_obs:X}",
                counts={"levels": list(lay.geometry.level_pages), "hashed_pages": lay.hashed_pages}))
        bad = []
        for desc, names in DESC_TO_LAYOUT.items():
            rr = xi.region_by_desc(desc)
            if rr is None:
                continue
            start = lay.get(names[0]).offset
            end = lay.get(names[-1]).end
            if (rr.offset, rr.end) != (start, end):
                bad.append(f"{desc}: regiao 0x{rr.offset:X}-0x{rr.end:X}, layout 0x{start:X}-0x{end:X}")
        pkg.checks.append(CheckResult("layout.regions_match", "regioes XVC-HD/EXVD/MDU/MD == layout calculado",
                                      FAIL if bad else PASS, "; ".join(bad) or "4/4 coincidem"))
        for i, (name, ok, detail) in enumerate(structural_checks(xi, src.size)):
            pkg.checks.append(CheckResult(f"xvcinfo.struct.{i:02d}", name, PASS if ok else FAIL, detail))
        for w in xi.warnings:
            pkg.errors.append(w)
    pkg.checks.append(CheckResult("layout.end_equals_size", "fim do layout calculado == tamanho do arquivo",
                                  PASS if lay.end == src.size else (INFO if h.type == 1 else FAIL),
                                  f"0x{lay.end:X} vs 0x{src.size:X}"))

    # ---- user data
    if h.user_data_length:
        ud_off = lay.get(L.USER_DATA).offset
        ru = parse_userdata(src.read_at(ud_off, h.user_data_length))
        if isinstance(ru, Ok):
            pkg.userdata = ru.value
            sm_file = pkg.userdata.file(SEGMETA_NAME)
            if sm_file:
                rs = parse_segment_metadata(sm_file.data)
                if isinstance(rs, Ok):
                    pkg.segmeta = rs.value
                else:
                    pkg.errors.append(str(rs.error))
        else:
            pkg.errors.append(f"user data: {ru.error}")
    if pkg.segmeta and xi:
        pkg.rows, pkg.file_checks = map_files(pkg.segmeta, xi, lay, src.size)

    # ---- XVD embutido (segunda amostra do parser de cabecalho)
    emb = lay.get(L.EMBEDDED)
    if emb.size >= HEADER_INCL_SIGNATURE_SIZE:
        re_ = load_header(src, emb.offset)
        if isinstance(re_, Ok):
            pkg.embedded_header = re_.value
            pkg.embedded_layout = compute_layout(re_.value)
        else:
            pkg.errors.append(f"XVD embutido: {re_.error}")
    return Ok(pkg)


# ------------------------------------------------------------------ texto
def header_lines(h: XvdHeader) -> list[str]:
    return [f"   {k:<28} {v}" for k, v in h.summary().items()]


def layout_lines(lay: Layout, size: int) -> list[str]:
    out = [f"== layout (MDU: {lay.mdu_pages} paginas, fonte: {lay.mdu_source})"]
    for r in lay.regions:
        out.append(f"   {r.name:<20} 0x{r.offset:012x}  +0x{r.size:x}  ({r.size / 2**20:.1f} MB)")
    out.append(f"   fim calculado 0x{lay.end:x}  tamanho real 0x{size:x}  "
               f"{'OK' if lay.end == size else f'DIFERE em {size - lay.end:+#x}'}")
    g = lay.geometry
    if g.levels:
        out.append(f"   hash tree: {lay.hashed_pages} paginas hasheadas; niveis L0..L{g.levels - 1} = "
                   f"{list(g.level_pages)}; inicio de cada nivel (pagina) = "
                   f"{[g.level_start(i) for i in range(g.levels)]}")
    return out
