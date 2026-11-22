"""Mapa arquivo -> segmento -> regiao (SegmentMetadata x XvcInfo x layout).

Mesmas checagens e nomes do map_files() do xvc_probe.py original, para manter
o relatorio JSON compativel.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..core.util import PAGE, pages
from .layout import DRIVE, Layout
from .userdata import SegmentMetadata, SegMetaEntry
from .xvcinfo import XvcInfo, XvcRegion


@dataclass(frozen=True)
class FileRow:
    index: int
    entry: SegMetaEntry
    start: int
    end: int
    region: XvcRegion | None
    segment_page: int
    segment_end: int
    slack: int
    relative_page: int

    @property
    def name(self) -> str:
        return self.entry.name

    @property
    def size(self) -> int:
        return self.entry.size


Check = tuple[str, bool, str]


def map_files(sm: SegmentMetadata, xi: XvcInfo, lay: Layout, file_size: int) -> tuple[list[FileRow], list[Check]]:
    drive = lay.get(DRIVE)
    checks: list[Check] = []

    def check(name: str, ok, detail: str = "") -> None:
        checks.append((name, bool(ok), detail))

    fsmd = xi.region_by_desc("FS-MD")
    check("drive data do cabecalho == inicio da regiao FS-MD", fsmd and fsmd.offset == drive.offset,
          f"cabecalho 0x{drive.offset:x}, FS-MD " + (f"0x{fsmd.offset:x}" if fsmd else "ausente"))
    check("drive data termina no fim do arquivo", drive.end == file_size, f"0x{drive.end:x} vs 0x{file_size:x}")
    check("quantidade de arquivos == quantidade de segmentos", len(sm.entries) == len(xi.segments),
          f"{len(sm.entries)} arquivos, {len(xi.segments)} segmentos")
    if len(sm.entries) != len(xi.segments) or len(sm.pages) != len(sm.entries):
        return [], checks

    rows: list[FileRow] = []
    for i, (e, sm_page, seg) in enumerate(zip(sm.entries, sm.pages, xi.segments)):
        start = drive.offset + sm_page * PAGE
        region = xi.region_at(start)
        seg_end = xi.segments[i + 1].offset if i + 1 < len(xi.segments) else file_size
        if region:
            seg_end = min(seg_end, region.end)
        rows.append(FileRow(i, e, start, start + e.size, region, seg.page, seg_end,
                            seg_end - start - pages(e.size) * PAGE, sm_page))

    bad_page = [r.index for r in rows if r.start != r.segment_page * PAGE]
    check("inicio do arquivo == PageNum do segmento", not bad_page,
          f"{len(rows) - len(bad_page)}/{len(rows)}" + (f"; divergem {bad_page[:10]}" if bad_page else ""))
    no_region = [r.index for r in rows if r.region is None]
    check("todo arquivo comeca dentro de uma regiao", not no_region, f"sem regiao: {no_region[:10]}")
    outside = [r.index for r in rows if r.region and r.end > r.region.end]
    check("todo arquivo termina dentro da sua regiao", not outside, f"ultrapassam: {outside[:10]}")
    spill = [r.index for r in rows if r.end > r.segment_end]
    check("todo arquivo cabe no seu segmento (nao invade o seguinte)", not spill, f"invadem: {spill[:10]}")
    beyond = [r.index for r in rows if r.end > file_size]
    check("todo arquivo termina antes do fim do .xvc", not beyond, f"ultrapassam: {beyond[:10]}")
    ordered = sorted(rows, key=lambda r: r.start)
    overlaps = [(a.index, b.index) for a, b in zip(ordered, ordered[1:]) if b.start < a.end]
    check("nenhuma sobreposicao entre arquivos", not overlaps, f"pares: {overlaps[:10]}")
    check("arquivos na mesma ordem dos segmentos", [r.index for r in ordered] == list(range(len(rows))))
    slack = [(r.index, r.slack) for r in rows if r.slack]
    check("arquivos ocupam exatamente as paginas do segmento", True,
          f"{len(rows) - len(slack)}/{len(rows)} exatos" + "".join(f"; seg {i} sobra 0x{s:x}" for i, s in slack))
    return rows, checks
