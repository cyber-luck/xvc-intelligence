"""XvcInfo: campos, cabecalhos de regiao, update segments, array por segmento e
tabela de paginas (PageNum, Value).

Ate 0xDA8 segue o struct XvcInfo do xvdtool. O xvdtool chama 0xD54..0xDA8 de
"ReservedD54" e nao le nada depois dos segmentos (exceto RegionSpecifiers quando
RegionSpecifierCount > 0). O array por segmento e a tabela de paginas sao
observacoes deste projeto (ver achados/testes), nao do xvdtool.
"""
from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field

from ..core.result import INCONSISTENT, OUT_OF_BOUNDS, TRUNCATED, Ok, Result, err, need
from ..core.util import PAGE, utf16z

CONTENT_ID_OFF = 0x0
KEYS_OFF = 0x10
MAX_KEYS = 0xC0
DESCRIPTION_OFF = 0xC10
DESCRIPTION_SIZE = 0x100
REGIONS_OFF = 0xDA8
REGION_SIZE = 0x80
SEGMENT_SIZE = 0x0C
SEGMENT_VALUE_SIZE = 4
PAGE_ENTRY_SIZE = 8
NO_KEY = 0xFFFF

# (offset, nome, formato, observacao)
FIELDS = [
    (0xD10, "Version", "<I", ""),
    (0xD14, "RegionCount", "<I", "confirmado: numero de cabecalhos validos"),
    (0xD18, "Flags", "<I", ""),
    (0xD1C, "PaddingD1C", "<H", ""),
    (0xD1E, "KeyCount", "<H", ""),
    (0xD20, "UnknownD20", "<I", ""),
    (0xD24, "InitialPlayRegionId", "<I", "confirmado se existir regiao com esse Id"),
    (0xD28, "InitialPlayOffset", "<Q", "nome do xvdtool; semantica nao verificada"),
    (0xD30, "FileTimeCreated", "<Q", ""),
    (0xD38, "PreviewRegionId", "<I", ""),
    (0xD3C, "UpdateSegmentCount", "<I", "confirmado: ultimo segmento fecha com a ultima regiao"),
    (0xD40, "PreviewOffset", "<Q", ""),
    (0xD48, "UnusedSpace", "<Q", ""),
    (0xD50, "RegionSpecifierCount", "<I", "nome do xvdtool (UnknownD50 no probe antigo)"),
    (0xD54, "PageTableCount", "<I", "xvdtool: ReservedD54; contagem da tabela de paginas (confirmado pelo fechamento)"),
]
FIELD_OFFSET = {n: o for o, n, _, _ in FIELDS}

# xvdtool XvcRegionFlags (nomes publicos; o significado neste pacote NAO foi verificado)
REGION_FLAGS = {0x1: "Resident", 0x2: "InitialPlay", 0x4: "Preview", 0x8: "FileSystemMetadata",
                0x10: "Present", 0x20: "OnDemand", 0x40: "Available"}


def region_flag_names(v: int) -> list[str]:
    return [n for b, n in REGION_FLAGS.items() if v & b] + ([f"0x{v & ~0x7F:X}?"] if v & ~0x7F else [])


@dataclass(frozen=True)
class XvcRegion:
    index: int
    rel: int
    id: int
    key_id: int
    padding6: int
    flags: int
    first_segment_index: int
    description: str
    description_trailing: bool
    offset: int
    length: int
    hash: bytes
    reserved: bytes

    @property
    def end(self) -> int:
        return self.offset + self.length

    @property
    def keyed(self) -> bool:
        return self.key_id != NO_KEY

    def contains(self, off: int) -> bool:
        return self.offset <= off < self.end

    def label(self) -> str:
        return self.description or f"0x{self.id:X}"

    def legacy_dict(self) -> dict:
        return {"index": self.index, "rel": self.rel, "Id": self.id, "KeyId": self.key_id,
                "Padding6": self.padding6, "Flags": self.flags, "FirstSegmentIndex": self.first_segment_index,
                "Description": self.description, "DescriptionTrailing": self.description_trailing,
                "Offset": self.offset, "Length": self.length, "Hash": self.hash, "Reserved": self.reserved}


@dataclass(frozen=True)
class XvcSegment:
    index: int
    page: int          # pagina absoluta do arquivo
    hash: bytes        # 8 bytes

    @property
    def offset(self) -> int:
        return self.page * PAGE


@dataclass
class XvcInfo:
    base_offset: int
    length: int
    content_id: uuid.UUID
    fields: dict[str, int]
    keys: list[uuid.UUID]
    description: str
    regions: list[XvcRegion]
    segments: list[XvcSegment]
    segment_values: list[int]
    page_table: list[tuple[int, int]]
    seg_off: int
    segval_off: int
    table_off: int
    tail_off: int
    tail_nonzero: int
    next_after_regions: int | None
    warnings: list[str] = field(default_factory=list)

    def region_by_desc(self, desc: str) -> XvcRegion | None:
        return next((r for r in self.regions if r.description == desc), None)

    def region_by_id(self, rid: int) -> XvcRegion | None:
        return next((r for r in self.regions if r.id == rid), None)

    def region_at(self, off: int) -> XvcRegion | None:
        return next((r for r in self.regions if r.contains(off)), None)

    def region_segments(self, r: XvcRegion) -> list[int]:
        return [s.index for s in self.segments if r.contains(s.offset)]

    def segment_end(self, i: int, file_size: int) -> int:
        """Fim do segmento: proximo segmento ou fim da regiao, o que vier antes."""
        s = self.segments[i]
        end = self.segments[i + 1].offset if i + 1 < len(self.segments) else file_size
        r = self.region_at(s.offset)
        return min(end, r.end) if r else end

    def field_abs(self, name: str) -> int:
        return self.base_offset + FIELD_OFFSET[name]


def _decode_region(b: bytes, rel: int, index: int) -> XvcRegion:
    raw_desc = b[rel + 0x10:rel + 0x50]
    desc, _, after = raw_desc.decode("utf-16-le", errors="replace").partition("\0")
    return XvcRegion(
        index=index, rel=rel,
        id=struct.unpack_from("<I", b, rel)[0],
        key_id=struct.unpack_from("<H", b, rel + 0x4)[0],
        padding6=struct.unpack_from("<H", b, rel + 0x6)[0],
        flags=struct.unpack_from("<I", b, rel + 0x8)[0],
        first_segment_index=struct.unpack_from("<I", b, rel + 0xC)[0],
        description=desc,
        description_trailing=any(c != "\0" for c in after),
        offset=struct.unpack_from("<Q", b, rel + 0x50)[0],
        length=struct.unpack_from("<Q", b, rel + 0x58)[0],
        hash=bytes(b[rel + 0x60:rel + 0x68]),
        reserved=bytes(b[rel + 0x68:rel + REGION_SIZE]),
    )


def parse_xvcinfo(b: bytes, base_offset: int = 0, page_table_limit: int | None = None) -> Result[XvcInfo]:
    st = "XvcInfo"
    e = need(b, 0, REGIONS_OFF, st)
    if e:
        return e
    fields = {name: struct.unpack_from(fmt, b, o)[0] for o, name, fmt, _ in FIELDS}
    warnings: list[str] = []
    key_count = fields["KeyCount"]
    if key_count > MAX_KEYS:
        return err(INCONSISTENT, f"KeyCount {key_count} > {MAX_KEYS}", base_offset + 0xD1E, st)
    keys = [uuid.UUID(bytes_le=bytes(b[KEYS_OFF + i * 16:KEYS_OFF + (i + 1) * 16])) for i in range(key_count)]

    n_reg = fields["RegionCount"]
    n_seg = fields["UpdateSegmentCount"]
    seg_off = REGIONS_OFF + n_reg * REGION_SIZE
    segval_off = seg_off + n_seg * SEGMENT_SIZE
    if segval_off > len(b):
        return err(OUT_OF_BOUNDS, f"RegionCount={n_reg} e UpdateSegmentCount={n_seg} excedem o XvcInfo "
                   f"(0x{segval_off:x} > 0x{len(b):x})", base_offset + 0xD14, st)
    regions = [_decode_region(b, REGIONS_OFF + i * REGION_SIZE, i) for i in range(n_reg)]
    segments = [XvcSegment(i, struct.unpack_from("<I", b, seg_off + i * SEGMENT_SIZE)[0],
                           bytes(b[seg_off + i * SEGMENT_SIZE + 4:seg_off + (i + 1) * SEGMENT_SIZE]))
                for i in range(n_seg)]
    next_hdr = struct.unpack_from("<I", b, seg_off)[0] if seg_off + 4 <= len(b) else None

    seg_values: list[int] = []
    table: list[tuple[int, int]] = []
    table_off = segval_off + SEGMENT_VALUE_SIZE * n_seg
    tail_off = segval_off
    if fields["RegionSpecifierCount"]:
        # o xvdtool le especificadores logo apos os segmentos; o tamanho deles nao foi verificado aqui
        warnings.append(f"RegionSpecifierCount={fields['RegionSpecifierCount']}: array por segmento e tabela "
                        "de paginas NAO decodificados (posicao depende dos especificadores)")
    else:
        n_tab = fields["PageTableCount"]
        if page_table_limit is not None and n_tab > page_table_limit:
            return err(INCONSISTENT, f"PageTableCount={n_tab} acima do limite {page_table_limit}",
                       base_offset + 0xD54, st)
        table_end = table_off + n_tab * PAGE_ENTRY_SIZE
        if table_end > len(b):
            kind = TRUNCATED if table_off <= len(b) else OUT_OF_BOUNDS
            return err(kind, f"PageTableCount={n_tab} excede o XvcInfo (0x{table_end:x} > 0x{len(b):x})",
                       base_offset + 0xD54, st)
        seg_values = list(struct.unpack_from(f"<{n_seg}I", b, segval_off))
        flat = struct.unpack_from(f"<{2 * n_tab}I", b, table_off)
        table = list(zip(flat[0::2], flat[1::2]))
        tail_off = table_end
    tail_nonzero = sum(1 for x in b[tail_off:] if x)
    return Ok(XvcInfo(
        base_offset=base_offset, length=len(b),
        content_id=uuid.UUID(bytes_le=bytes(b[0:16])),
        fields=fields, keys=keys,
        description=utf16z(b[DESCRIPTION_OFF:DESCRIPTION_OFF + DESCRIPTION_SIZE]),
        regions=regions, segments=segments, segment_values=seg_values, page_table=table,
        seg_off=seg_off, segval_off=segval_off, table_off=table_off, tail_off=tail_off,
        tail_nonzero=tail_nonzero, next_after_regions=next_hdr, warnings=warnings,
    ))


def structural_checks(xi: XvcInfo, file_size: int) -> list[tuple[str, bool, str]]:
    """Checagens internas (sem ler o pacote). (nome, passou, detalhe)."""
    out: list[tuple[str, bool, str]] = []
    ids = [r.id for r in xi.regions]
    out.append(("Ids de regiao unicos", len(set(ids)) == len(ids), f"{len(ids)} regioes"))
    bad_pad = [r.index for r in xi.regions if r.padding6 or any(r.reserved)]
    out.append(("padding/reservado das regioes zerados", not bad_pad, f"regioes com bytes nao-zero: {bad_pad}"))
    bad_key = [r.index for r in xi.regions if r.keyed and r.key_id >= len(xi.keys)]
    out.append(("KeyId < KeyCount (ou 0xFFFF)", not bad_key, f"regioes invalidas: {bad_key}"))
    cursor, gaps = 0, []
    for r in sorted(xi.regions, key=lambda r: r.offset):
        if r.offset != cursor:
            gaps.append(f"0x{cursor:x}->0x{r.offset:x}")
        cursor = max(cursor, r.end)
    out.append(("regioes ladrilham o arquivo sem lacuna/sobreposicao", not gaps and cursor == file_size,
                f"fim 0x{cursor:x}, arquivo 0x{file_size:x}; lacunas/sobreposicoes {gaps[:5]}"))
    pages_ = [s.page for s in xi.segments]
    out.append(("PageNum dos segmentos crescente", pages_ == sorted(pages_), ""))
    orphan = [s.index for s in xi.segments if xi.region_at(s.offset) is None]
    out.append(("todo segmento dentro de uma regiao", not orphan, f"orfaos: {orphan[:10]}"))
    bad_first = []
    for r in xi.regions:
        segs = xi.region_segments(r)
        if segs and (segs[0] != r.first_segment_index or segs != list(range(segs[0], segs[0] + len(segs)))
                     or xi.segments[segs[0]].offset != r.offset):
            bad_first.append(r.index)
    out.append(("FirstSegmentIndex/contiguidade/inicio da regiao", not bad_first, f"regioes: {bad_first}"))
    if xi.page_table:
        tp = [p for p, _ in xi.page_table]
        out.append(("tabela de paginas estritamente crescente", all(a < b for a, b in zip(tp, tp[1:])), ""))
        idx = set(tp)
        miss = [s.index for s in xi.segments if s.page not in idx]
        out.append(("toda pagina de segmento abre uma entrada da tabela", not miss, f"ausentes: {miss[:10]}"))
        outside = sum(1 for p in tp if xi.region_at(p * PAGE) is None)
        out.append(("entradas da tabela dentro de regioes", outside == 0, f"{outside} fora"))
    out.append(("bytes apos a tabela sao zero", xi.tail_nonzero == 0,
                f"+0x{xi.tail_off:x}, {xi.length - xi.tail_off} bytes, {xi.tail_nonzero} nao-zero"))
    return out
