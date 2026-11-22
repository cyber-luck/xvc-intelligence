"""Sonda de layout de um pacote XVD/XVC (somente leitura).

Fases:
  1. le o cabecalho XVD e estima o offset de cada regiao (layout do xvdtool)
  2. localiza o XvcInfo pela ancora ContentID == VDUID
  3. decodifica o XvcInfo: campos, cabecalhos de regiao e update segments,
     e refaz o layout com os tamanhos observados nas regioes
  4. busca strings de regiao em ASCII e UTF-16LE         (pule com --skip-scan)
  5. mapa de entropia amostrado                          (pule com --skip-scan)
"""
import argparse
import collections
import datetime
import json
import math
import os
import re
import struct
import sys
import uuid

PAGE = 0x1000
HEADER_SIZE = 0x3000           # assinatura 0x200 + cabecalho (xvdtool: XVD_HEADER_INCL_SIGNATURE_SIZE)
HASH_ENTRIES_PER_PAGE = 0xAA   # 0x1000 // 0x18
XVD_MAGIC = b"msft-xvd"

FLAG_DATA_INTEGRITY_DISABLED = 0x4
FLAG_RESILIENCY_ENABLED = 0x10

# XvcInfo (offsets relativos ao inicio do XvcInfo)
XVCINFO_REGIONS_OFF = 0xDA8    # observado: RegionCount cabecalhos seguidos a partir daqui
REGION_SIZE = 0x80
SEGMENT_SIZE = 0x0C            # u32 PageNum + 8 bytes de hash
NO_KEY = 0xFFFF
MAX_KEYS = 0xC0                # espaco de 0x10..0xC10 para KeyIds de 16 bytes

# (offset, nome, formato, observacao). "confirmado" = conferido contra outra estrutura deste pacote.
XVCINFO_FIELDS = [
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
    (0xD50, "UnknownD50", "<I", ""),
    (0xD54, "PageTableCount", "<I", "inferido: entradas da tabela de paginas apos os segmentos"),
]
PAGE_ENTRY_SIZE = 8            # u32 PageNum + u32 Value

# descricao da regiao -> regiao do layout que ela deve cobrir exatamente
DESC_TO_LAYOUT = {
    "XVC-HD": ("cabecalho",),
    "XVC-EXVD": ("XVD embutido",),
    "XVC-MDU": ("mutable data (MDU)",),
    "XVC-MD": ("hash tree", "user data", "XvcInfo", "dynamic header"),
}


def pages(n):
    return (n + PAGE - 1) // PAGE


def entropy(b):
    if not b:
        return 0.0
    n = len(b)
    return 0.0 - sum(c / n * math.log2(c / n) for c in collections.Counter(b).values())


def filetime(v):
    if not v:
        return "0"
    try:
        dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=v // 10)
        return dt.isoformat()
    except OverflowError:
        return "fora do intervalo"


def hexdump(f, off, size):
    f.seek(off)
    d = f.read(size)
    for i in range(0, len(d), 16):
        ch = d[i:i + 16]
        print(f"  {off + i:012x}  " + " ".join(f"{x:02x}" for x in ch).ljust(47)
              + "  " + "".join(chr(x) if 32 <= x < 127 else "." for x in ch))
    return d


# ---------------------------------------------------------------- fase 1: cabecalho e layout
def read_header(f):
    f.seek(0)
    h = f.read(HEADER_SIZE)
    if len(h) < HEADER_SIZE or h[0x200:0x208] != XVD_MAGIC:
        sys.exit(f"magic XVD ausente em 0x200: {h[0x200:0x208]!r}")
    return {
        "VolumeFlags": struct.unpack_from("<I", h, 0x208)[0],
        "FormatVersion": struct.unpack_from("<I", h, 0x20C)[0],
        "DriveSize": struct.unpack_from("<Q", h, 0x218)[0],
        "VDUID": uuid.UUID(bytes_le=h[0x220:0x230]),
        "UDUID": uuid.UUID(bytes_le=h[0x230:0x240]),
        "Type": struct.unpack_from("<I", h, 0x280)[0],
        "ContentType": struct.unpack_from("<I", h, 0x284)[0],
        "EmbeddedXVDLength": struct.unpack_from("<I", h, 0x288)[0],
        "UserDataLength": struct.unpack_from("<I", h, 0x28C)[0],
        "XvcDataLength": struct.unpack_from("<I", h, 0x290)[0],
        "DynamicHeaderLength": struct.unpack_from("<I", h, 0x294)[0],
        "BlockSize": struct.unpack_from("<I", h, 0x298)[0],
        # neste pacote 0x5E0 vale 0, mas a regiao XVC-MDU mostra 1 pagina: nao e confiavel
        "Byte@0x5E0": h[0x5E0],
    }


def hash_tree_pages(n_hashed, resilient):
    # cada pagina de hash cobre 0xAA paginas do nivel abaixo; soma os niveis ate a raiz
    level = (n_hashed + HASH_ENTRIES_PER_PAGE - 1) // HASH_ENTRIES_PER_PAGE
    total = level
    while level > 1:
        level = (level + HASH_ENTRIES_PER_PAGE - 1) // HASH_ENTRIES_PER_PAGE
        total += level
    return total * 2 if resilient else total


def layout(hdr, mdu_pages, extra_ht_pages=0):
    flags = hdr["VolumeFlags"]
    integrity = not flags & FLAG_DATA_INTEGRITY_DISABLED
    resilient = bool(flags & FLAG_RESILIENCY_ENABLED)

    user_p = pages(hdr["UserDataLength"])
    xvc_p = pages(hdr["XvcDataLength"])
    dyn_p = pages(hdr["DynamicHeaderLength"])
    n_hashed = hdr["DriveSize"] // PAGE + user_p + xvc_p + dyn_p
    ht_p = (hash_tree_pages(n_hashed, resilient) if integrity else 0) + extra_ht_pages

    regions = []
    off = 0
    for name, size in [
        ("cabecalho", HEADER_SIZE),
        ("XVD embutido", pages(hdr["EmbeddedXVDLength"]) * PAGE),
        ("mutable data (MDU)", mdu_pages * PAGE),
        ("hash tree", ht_p * PAGE),
        ("user data", user_p * PAGE),
        ("XvcInfo", xvc_p * PAGE),
        ("dynamic header", dyn_p * PAGE),
        ("drive data", hdr["DriveSize"]),
    ]:
        regions.append((name, off, size))
        off += size
    return regions, integrity, resilient


def region_start(regions, name):
    return next((s, sz) for n, s, sz in regions if n == name)


def region_of(regions, off):
    for name, start, size in regions:
        if start <= off < start + size:
            return name if name != "drive data" else f"drive data +0x{off - start:x}"
    return "fora do arquivo"


def find_page_anchor(f, est_off, needle, radius_pages):
    """Procura `needle` no inicio de paginas em est_off +/- radius_pages."""
    for delta in sorted(range(-radius_pages, radius_pages + 1), key=abs):
        off = est_off + delta * PAGE
        if off < 0:
            continue
        f.seek(off)
        if f.read(len(needle)) == needle:
            return off
    return None


# ---------------------------------------------------------------- fase 3: XvcInfo
def decode_region(b, rel, index):
    raw_desc = b[rel + 0x10:rel + 0x50]
    desc, _, after = raw_desc.decode("utf-16-le", errors="replace").partition("\0")
    return {
        "index": index,
        "rel": rel,
        "Id": struct.unpack_from("<I", b, rel)[0],
        "KeyId": struct.unpack_from("<H", b, rel + 0x4)[0],
        "Padding6": struct.unpack_from("<H", b, rel + 0x6)[0],
        "Flags": struct.unpack_from("<I", b, rel + 0x8)[0],
        "FirstSegmentIndex": struct.unpack_from("<I", b, rel + 0xC)[0],
        "Description": desc,
        "DescriptionTrailing": any(c != "\0" for c in after),
        "Offset": struct.unpack_from("<Q", b, rel + 0x50)[0],
        "Length": struct.unpack_from("<Q", b, rel + 0x58)[0],
        "Hash": b[rel + 0x60:rel + 0x68],
        "Reserved": b[rel + 0x68:rel + REGION_SIZE],
    }


def decode_xvcinfo(f, off, length):
    f.seek(off)
    b = f.read(length)
    if len(b) < XVCINFO_REGIONS_OFF:
        return None, f"XvcInfo truncado: {len(b):#x} bytes"

    fields = {name: struct.unpack_from(fmt, b, o)[0] for o, name, fmt, _ in XVCINFO_FIELDS}
    key_count = fields["KeyCount"]
    keys = [uuid.UUID(bytes_le=b[0x10 + i * 16:0x20 + i * 16]) for i in range(min(key_count, MAX_KEYS))]

    n_reg = fields["RegionCount"]
    seg_off = XVCINFO_REGIONS_OFF + n_reg * REGION_SIZE
    n_seg = fields["UpdateSegmentCount"]
    tail_off = seg_off + n_seg * SEGMENT_SIZE
    if tail_off > len(b):
        return None, (f"RegionCount={n_reg} e UpdateSegmentCount={n_seg} excedem o XvcInfo "
                      f"({tail_off:#x} > {len(b):#x})")

    regions = [decode_region(b, XVCINFO_REGIONS_OFF + i * REGION_SIZE, i) for i in range(n_reg)]
    segments = [(struct.unpack_from("<I", b, seg_off + i * SEGMENT_SIZE)[0],
                 b[seg_off + i * SEGMENT_SIZE + 4:seg_off + (i + 1) * SEGMENT_SIZE]) for i in range(n_seg)]
    # o que vem logo depois dos cabecalhos deve ser o primeiro segmento, nao outro cabecalho
    next_hdr_id = struct.unpack_from("<I", b, seg_off)[0] if seg_off + 4 <= len(b) else None

    # depois dos segmentos: um u32 por segmento, e entao a tabela de paginas (PageNum, Value)
    segval_off = tail_off
    table_off = segval_off + 4 * n_seg
    n_tab = fields["PageTableCount"]
    table_end = table_off + n_tab * PAGE_ENTRY_SIZE
    if table_end > len(b):
        return None, f"PageTableCount={n_tab} excede o XvcInfo ({table_end:#x} > {len(b):#x})"
    seg_values = list(struct.unpack_from(f"<{n_seg}I", b, segval_off))
    table = [struct.unpack_from("<II", b, table_off + i * PAGE_ENTRY_SIZE) for i in range(n_tab)]
    return {
        "fields": fields,
        "keys": keys,
        "regions": regions,
        "segments": segments,
        "seg_off": seg_off,
        "segval_off": segval_off,
        "seg_values": seg_values,
        "table_off": table_off,
        "table": table,
        "tail_off": table_end,
        "tail": b[table_end:],
        "next_after_regions": next_hdr_id,
    }, None


def by_desc(xi, desc):
    return next((r for r in xi["regions"] if r["Description"] == desc), None)


def region_segments(r, segments):
    """Indices dos segmentos cuja pagina cai dentro da regiao."""
    lo, hi = r["Offset"], r["Offset"] + r["Length"]
    return [i for i, (p, _) in enumerate(segments) if lo <= p * PAGE < hi]


def segment_check(r, segments):
    segs = region_segments(r, segments)
    if not segs:
        return "sem seg" if r["FirstSegmentIndex"] == 0 else "! sem seg"
    if segs[0] != r["FirstSegmentIndex"]:
        return f"! 1o={segs[0]}"
    if segs != list(range(segs[0], segs[0] + len(segs))):
        return "! nao contig"
    if segments[segs[0]][0] * PAGE != r["Offset"]:
        return "! pag"
    if len(segs) == 1:
        return "ok h=seg" if segments[segs[0]][1] == r["Hash"] else "! h!=seg"
    return "ok"


def print_xvcinfo(xi, xvc_off, lay, size):
    f_ = xi["fields"]
    regions, segments = xi["regions"], xi["segments"]
    print(f"== XvcInfo @ 0x{xvc_off:x}")
    for o, name, fmt, note in XVCINFO_FIELDS:
        v = f_[name]
        extra = f"  {filetime(v)}" if name == "FileTimeCreated" else ""
        if name == "InitialPlayRegionId":
            hit = next((r for r in regions if r["Id"] == v), None)
            extra = f"  -> regiao #{hit['index']}" if hit else "  -> nenhuma regiao com esse Id"
        print(f"   +0x{o:03x} {name:<20} {v:#x}{extra}" + (f"   ({note})" if note else ""))
    for i, k in enumerate(xi["keys"]):
        print(f"   +0x{0x10 + i * 16:03x} KeyId[{i}]{'':<12} {k}")

    print(f"== cabecalhos de regiao: {len(regions)} x 0x{REGION_SIZE:x} em +0x{XVCINFO_REGIONS_OFF:x}")
    print(f"   {'#':>2} {'Id':>10} {'Key':>4} {'Flags':>5} {'Seg':>4} {'nSeg':>4} {'Offset':>14} {'Length':>14}"
          f"  {'Hash':<16}  {'Seg?':<9} {'Desc':<9} Local")
    for r in regions:
        key = "-" if r["KeyId"] == NO_KEY else str(r["KeyId"])
        print(f"   {r['index']:>2} {r['Id']:>#10x} {key:>4} {r['Flags']:>#5x} {r['FirstSegmentIndex']:>4}"
              f" {len(region_segments(r, segments)):>4} {r['Offset']:>#14x} {r['Length']:>#14x}"
              f"  {r['Hash'].hex()}  {segment_check(r, segments):<9}"
              f" {r['Description'] or '-':<9} {region_of(lay, r['Offset'])}")

    print("== verificacoes")
    problems = []
    ids = [r["Id"] for r in regions]
    if len(set(ids)) != len(ids):
        problems.append("Ids repetidos")
    for r in regions:
        if r["Padding6"] or any(r["Reserved"]):
            problems.append(f"regiao #{r['index']}: bytes nao-zero em padding/reservado "
                            f"(+0x6={r['Padding6']:#x}, +0x68={r['Reserved'].hex()})")
        if r["DescriptionTrailing"]:
            problems.append(f"regiao #{r['index']}: dados depois do NUL da descricao")
        if r["KeyId"] != NO_KEY and r["KeyId"] >= len(xi["keys"]):
            problems.append(f"regiao #{r['index']}: KeyId {r['KeyId']} >= KeyCount {len(xi['keys'])}")
    if xi["next_after_regions"] is not None and (xi["next_after_regions"] >> 24) == 0x40:
        problems.append("o dado apos o ultimo cabecalho parece outro cabecalho (Id 0x40xxxxxx)")

    # cobertura: regioes devem ladrilhar o arquivo
    cursor = 0
    for r in sorted(regions, key=lambda r: r["Offset"]):
        if r["Offset"] > cursor:
            problems.append(f"lacuna 0x{cursor:x}-0x{r['Offset']:x} antes da regiao #{r['index']}")
        elif r["Offset"] < cursor:
            problems.append(f"regiao #{r['index']} sobrepoe 0x{r['Offset']:x}-0x{cursor:x}")
        cursor = max(cursor, r["Offset"] + r["Length"])
    print(f"   cobertura: regioes vao ate 0x{cursor:x}; arquivo 0x{size:x} "
          f"{'OK' if cursor == size else 'DIFERE'}")

    # descricoes conhecidas devem coincidir com o layout
    for desc, names in DESC_TO_LAYOUT.items():
        r = by_desc(xi, desc)
        if not r:
            continue
        start = region_start(lay, names[0])[0]
        end = sum(region_start(lay, names[-1]))
        same = (r["Offset"], r["Offset"] + r["Length"]) == (start, end)
        print(f"   {desc:<9} = {' + '.join(names):<45} {'OK' if same else f'DIFERE (layout 0x{start:x}-0x{end:x})'}")

    # segmentos
    pages_ = [p for p, _ in segments]
    if pages_ != sorted(pages_):
        problems.append("PageNum dos segmentos fora de ordem")
    orphan = [p for p in pages_ if not any(r["Offset"] <= p * PAGE < r["Offset"] + r["Length"] for r in regions)]
    if orphan:
        problems.append(f"{len(orphan)} segmentos fora de qualquer regiao (1o: pagina 0x{orphan[0]:x})")
    checks = [(r, segment_check(r, segments)) for r in regions]
    for r, c in checks:
        if c.startswith("!"):
            problems.append(f"regiao #{r['index']}: segmentos {c[2:]}")
    single = [r for r in regions if len(region_segments(r, segments)) == 1]
    multi = [r for r in regions if len(region_segments(r, segments)) > 1]
    seg_hashes = {h for _, h in segments}
    multi_match = sum(r["Hash"] in seg_hashes for r in multi)
    print(f"   update segments: {len(segments)} em +0x{xi['seg_off']:x}; "
          f"{sum(len(region_segments(r, segments)) for r in regions)} dentro de regioes")
    print(f"   hash da regiao == hash do segmento: {sum(c == 'ok h=seg' for _, c in checks)}/{len(single)} "
          f"regioes de 1 segmento; {multi_match}/{len(multi)} regioes de varios segmentos "
          f"tem hash igual a algum segmento")
    problems += print_page_table(xi, lay)

    tail = xi["tail"]
    nz = sum(1 for x in tail if x)
    print(f"   apos a tabela: +0x{xi['tail_off']:x}, 0x{len(tail):x} bytes "
          + ("todos zero" if not nz else f"NAO decodificados ({nz} nao-zero, H={entropy(tail):.2f})"))
    for p in problems:
        print(f"   ! {p}")
    if not problems:
        print("   nenhuma inconsistencia")


def print_page_table(xi, lay):
    regions, segments, table = xi["regions"], xi["segments"], xi["table"]
    seg_values = xi["seg_values"]
    problems = []
    print(f"== valores por segmento: {len(seg_values)} x u32 em +0x{xi['segval_off']:x}")
    print(f"== tabela de paginas: {len(table)} x (u32 PageNum, u32 Value) em +0x{xi['table_off']:x}")
    if not table:
        return problems

    pages_ = [p for p, _ in table]
    if any(a >= b for a, b in zip(pages_, pages_[1:])):
        problems.append("tabela de paginas: PageNum nao estritamente crescente")
    page_idx = {p: i for i, p in enumerate(pages_)}

    # cada segmento e cada inicio de regiao de conteudo deve abrir uma entrada da tabela
    seg_missing = [p for p, _ in segments if p not in page_idx]
    content = [r for r in regions if region_segments(r, segments)]
    reg_missing = [r for r in content if r["Offset"] // PAGE not in page_idx]
    print(f"   paginas de segmento presentes: {len(segments) - len(seg_missing)}/{len(segments)}; "
          f"inicios de regiao com segmentos presentes: {len(content) - len(reg_missing)}/{len(content)}")
    if seg_missing:
        problems.append(f"{len(seg_missing)} paginas de segmento ausentes da tabela")
    if reg_missing:
        problems.append(f"{len(reg_missing)} inicios de regiao ausentes da tabela")

    # valor por segmento x Value da primeira entrada do segmento
    same = [i for i, (p, _) in enumerate(segments) if p in page_idx and table[page_idx[p]][1] == seg_values[i]]
    print(f"   valor do segmento == Value da 1a entrada do segmento: {len(same)}/{len(segments)}")
    for i, (p, _) in enumerate(segments):
        if i not in same and p in page_idx:
            v = table[page_idx[p]][1]
            print(f"     seg {i:>3} pag 0x{p:x}: valor 0x{seg_values[i]:08x}, Value 0x{v:08x} "
                  f"(dif {(seg_values[i] - v + 2**31) % 2**32 - 2**31:+d})")

    # distribuicao por regiao e regioes do layout
    per_region = collections.Counter()
    outside = 0
    for p in pages_:
        r = next((r for r in regions if r["Offset"] <= p * PAGE < r["Offset"] + r["Length"]), None)
        if r is None:
            outside += 1
        else:
            per_region[r["index"]] += 1
    if outside:
        problems.append(f"{outside} entradas da tabela fora de qualquer regiao")
    print(f"   primeira entrada: pag 0x{pages_[0]:x} [{region_of(lay, pages_[0] * PAGE)}] "
          f"Value 0x{table[0][1]:x}; ultima: pag 0x{pages_[-1]:x} Value 0x{table[-1][1]:x}")
    print("   entradas por regiao: " + ", ".join(
        f"#{i}={n}" for i, n in sorted(per_region.items())))

    # Value avanca junto com PageNum dentro de uma sequencia? (observacao, sem semantica atribuida)
    da = [b[0] - a[0] for a, b in zip(table, table[1:])]
    db = [((b[1] - a[1] + 2**31) % 2**32) - 2**31 for a, b in zip(table, table[1:])]
    near = sum(abs(y - x) <= 16 for x, y in zip(da, db))
    print(f"   |dValue - dPageNum| <= 16 em {near}/{len(da)} pares consecutivos; "
          f"Value repetido em {sum(y == 0 for y in db)}; "
          f"{len({v >> 16 for _, v in table})} valores distintos nos 16 bits altos")
    return problems


# ---------------------------------------------------------------- user data
UD_HEADER_SIZE = 0x10          # Length, Version, Type, Unknown
UD_TYPE_PACKAGE_FILES = 0
PKG_NAME_BYTES = 0x208         # UTF-16, 0x104 caracteres
PKG_ENTRY_SIZE = 0x210         # caminho UTF-16 (0x208) + u32 Size + u32 Offset
SEGMETA_NAME = "SegmentMetadata.bin"
SEGMETA_MAGIC = b" PFX"
SEGMETA_ENTRY_SIZE = 0x10      # u16 ?, u16 NameLength (chars), u32 NameOffset, u64 Size


def utf16z(raw):
    return raw.decode("utf-16-le", errors="replace").split("\0", 1)[0]


def decode_userdata(f, off, length):
    f.seek(off)
    b = f.read(length)
    if len(b) < UD_HEADER_SIZE + 4 + PKG_NAME_BYTES + 4:
        return None, f"user data truncado: {len(b):#x} bytes"
    hlen, ver, typ, unk = struct.unpack_from("<4I", b, 0)
    if hlen != UD_HEADER_SIZE or typ != UD_TYPE_PACKAGE_FILES:
        return None, f"cabecalho de user data inesperado: Length={hlen:#x} Type={typ}"
    pkg_ver = struct.unpack_from("<I", b, 0x10)[0]
    pkg_name = utf16z(b[0x14:0x14 + PKG_NAME_BYTES])
    count_off = 0x14 + PKG_NAME_BYTES
    count = struct.unpack_from("<I", b, count_off)[0]
    first = count_off + 4
    if first + count * PKG_ENTRY_SIZE > len(b):
        return None, f"FileCount={count} excede o user data"
    files = []
    for i in range(count):
        e = first + i * PKG_ENTRY_SIZE
        size, rel = struct.unpack_from("<II", b, e + PKG_NAME_BYTES)
        start = hlen + rel                 # offsets relativos ao fim do cabecalho de 0x10
        files.append({"path": utf16z(b[e:e + PKG_NAME_BYTES]), "size": size, "start": start,
                      "data": b[start:start + size]})
    return {"Version": ver, "Unknown": unk, "PackageVersion": pkg_ver, "PackageFullName": pkg_name,
            "files": files, "entries_end": first + count * PKG_ENTRY_SIZE, "length": len(b)}, None


def decode_segment_metadata(d):
    if len(d) < 0x2C or d[:4] != SEGMETA_MAGIC:
        return None, f"magic {d[:4]!r} != {SEGMETA_MAGIC!r}"
    ver, unk08, hdr_size, count, str_size = struct.unpack_from("<5I", d, 4)
    str_off = hdr_size + count * SEGMETA_ENTRY_SIZE
    pages_off = str_off + str_size
    if pages_off + 4 * count != len(d):
        return None, (f"tamanho nao fecha: cabecalho 0x{hdr_size:x} + {count} entradas + strings 0x{str_size:x}"
                      f" + {count} paginas = 0x{pages_off + 4 * count:x}, arquivo 0x{len(d):x}")
    entries = []
    for i in range(count):
        flags, nlen, noff, size = struct.unpack_from("<HHIQ", d, hdr_size + i * SEGMETA_ENTRY_SIZE)
        if noff + 2 * nlen > str_size:
            return None, f"entrada {i}: nome fora da tabela de strings"
        name = d[str_off + noff:str_off + noff + 2 * nlen].decode("utf-16-le", errors="replace")
        entries.append({"flags": flags, "name": name, "size": size, "name_off": noff})
    pages_ = list(struct.unpack_from(f"<{count}I", d, pages_off))
    return {"Version": ver, "Unknown08": unk08, "HeaderSize": hdr_size, "GUID": uuid.UUID(bytes_le=d[0x18:0x28]),
            "Unknown28": struct.unpack_from("<I", d, 0x28)[0], "entries": entries, "pages": pages_,
            "str_off": str_off, "pages_off": pages_off}, None


def print_userdata_files(ud, ud_off):
    problems = []
    print(f"== user data @ 0x{ud_off:x} (0x{ud['length']:x} bytes)")
    print(f"   Version {ud['Version']}  PackageVersion {ud['PackageVersion']}  "
          f"PackageFullName {ud['PackageFullName']!r}  FileCount {len(ud['files'])}")
    cursor = ud["entries_end"]
    for i, fl in enumerate(ud["files"]):
        kind = fl["data"][:4]
        print(f"   {i} +0x{fl['start']:04x} 0x{fl['size']:<6x} {fl['path']:<26} {kind!r}")
        if fl["start"] < cursor:
            problems.append(f"user data: {fl['path']} sobrepoe o anterior")
        cursor = fl["start"] + fl["size"]
    print(f"   fim do ultimo arquivo +0x{cursor:x}; UserDataLength 0x{ud['length']:x} "
          f"{'OK' if cursor == ud['length'] else 'DIFERE'}")
    return problems


def map_files(sm, xi, lay, file_size):
    """Associa cada arquivo do SegmentMetadata a segmento e regiao e valida os intervalos.

    O inicio do drive data vem do layout calculado a partir do cabecalho XVD; nada e fixo.
    Retorna (linhas, checks), com checks = [(nome, passou, detalhe)].
    """
    segments, regions = xi["segments"], xi["regions"]
    ents, sm_pages = sm["entries"], sm["pages"]
    drive_off, drive_len = region_start(lay, "drive data")
    checks = []

    def check(name, ok, detail=""):
        checks.append((name, bool(ok), detail))

    fsmd = by_desc(xi, "FS-MD")
    check("drive data do cabecalho == inicio da regiao FS-MD", fsmd and fsmd["Offset"] == drive_off,
          f"cabecalho 0x{drive_off:x}, FS-MD " + (f"0x{fsmd['Offset']:x}" if fsmd else "ausente"))
    check("drive data termina no fim do arquivo", drive_off + drive_len == file_size,
          f"0x{drive_off + drive_len:x} vs 0x{file_size:x}")
    check("quantidade de arquivos == quantidade de segmentos", len(ents) == len(segments),
          f"{len(ents)} arquivos, {len(segments)} segmentos")
    if len(ents) != len(segments):
        return [], checks

    rows = []
    for i, (e, sm_page, (seg_page, _)) in enumerate(zip(ents, sm_pages, segments)):
        start = drive_off + sm_page * PAGE
        end = start + e["size"]
        region = next((r for r in regions if r["Offset"] <= start < r["Offset"] + r["Length"]), None)
        seg_end = segments[i + 1][0] * PAGE if i + 1 < len(segments) else file_size
        if region:
            seg_end = min(seg_end, region["Offset"] + region["Length"])
        rows.append({"index": i, "entry": e, "start": start, "end": end, "region": region,
                     "segment_page": seg_page, "segment_end": seg_end,
                     "slack": seg_end - start - pages(e["size"]) * PAGE})

    bad_page = [r["index"] for r in rows if r["start"] != r["segment_page"] * PAGE]
    check("inicio do arquivo == PageNum do segmento", not bad_page,
          f"{len(rows) - len(bad_page)}/{len(rows)}" + (f"; divergem {bad_page[:10]}" if bad_page else ""))
    no_region = [r["index"] for r in rows if r["region"] is None]
    check("todo arquivo comeca dentro de uma regiao", not no_region, f"sem regiao: {no_region[:10]}")
    outside = [r["index"] for r in rows if r["region"] and r["end"] > r["region"]["Offset"] + r["region"]["Length"]]
    check("todo arquivo termina dentro da sua regiao", not outside, f"ultrapassam: {outside[:10]}")
    spill = [r["index"] for r in rows if r["end"] > r["segment_end"]]
    check("todo arquivo cabe no seu segmento (nao invade o seguinte)", not spill, f"invadem: {spill[:10]}")
    beyond = [r["index"] for r in rows if r["end"] > file_size]
    check("todo arquivo termina antes do fim do .xvc", not beyond, f"ultrapassam: {beyond[:10]}")

    ordered = sorted(rows, key=lambda r: r["start"])
    overlaps = [(a["index"], b["index"]) for a, b in zip(ordered, ordered[1:]) if b["start"] < a["end"]]
    check("nenhuma sobreposicao entre arquivos", not overlaps, f"pares: {overlaps[:10]}")
    check("arquivos na mesma ordem dos segmentos", [r["index"] for r in ordered] == list(range(len(rows))))

    slack = [(r["index"], r["slack"]) for r in rows if r["slack"]]
    check("arquivos ocupam exatamente as paginas do segmento", True,
          f"{len(rows) - len(slack)}/{len(rows)} exatos" +
          "".join(f"; seg {i} sobra 0x{s:x}" for i, s in slack))
    return rows, checks


def print_file_map(sm, rows, checks, regions, list_files):
    print(f"== {SEGMETA_NAME}: Version {sm['Version']}  Unknown08 {sm['Unknown08']}  "
          f"{len(sm['entries'])} arquivos  GUID {sm['GUID']}  Unknown28 {sm['Unknown28']}")
    print("== validacao dos intervalos de arquivo")
    for name, ok, detail in checks:
        print(f"   [{'OK' if ok else 'FALHA'}] {name}" + (f"  ({detail})" if detail else ""))
    if any(e["flags"] for e in sm["entries"]):
        print(f"   ! {SEGMETA_NAME}: campo u16 inicial nao-zero em alguma entrada")

    by_region = collections.defaultdict(list)
    for r in rows:
        if r["region"]:
            by_region[r["region"]["index"]].append(r["entry"]["name"])
    print("   arquivos por regiao:")
    for idx, names in sorted(by_region.items()):
        reg = regions[idx]
        shown = ", ".join(names[:3]) + (f" ... (+{len(names) - 3})" if len(names) > 3 else "")
        print(f"     #{idx:<2} 0x{reg['Id']:<8x} {len(names):>3}  {shown}")
    if list_files:
        print("   seg  regiao      offset          tamanho       arquivo")
        for r in rows:
            rid = f"0x{r['region']['Id']:x}" if r["region"] else "-"
            print(f"   {r['index']:>3}  {rid:<10}  0x{r['start']:<12x}  0x{r['entry']['size']:<11x} {r['entry']['name']}")


# ---------------------------------------------------------------- relatorio JSON
SAMPLE_SIZE = 0x10000          # 64 KB do inicio de cada arquivo
MIN_ENTROPY_SAMPLE = 0x1000    # abaixo disso a entropia de bytes nao discrimina bem
OPAQUE_ENTROPY = 7.9           # dados cifrados/comprimidos ficam perto de 8 bits/byte
STRUCTURED_ENTROPY = 7.0
SIGNATURES = [                 # (prefixo, formato); "MZ" so vira "PE" com PE\0\0 em e_lfanew
    (b"MZ", "MZ"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"regf", "registry hive"),
    (b"\xef\xbb\xbf<?xml", "XML"),
    (b"<?xml", "XML"),
    (b"mrm_pri", "PRI"),
]


PE_SUBSYSTEMS = {1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 10: "EFI_APPLICATION",
                 14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION", 17: "XBOX_CODE_CATALOG"}


def pe_header(d):
    """Valida MZ -> e_lfanew -> PE\\0\\0 -> COFF -> optional header. None se nao houver MZ."""
    if len(d) < 0x40 or d[:2] != b"MZ":
        return None
    lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    info = {"e_lfanew": f"0x{lfanew:X}", "pe_signature": False}
    if lfanew + 24 > len(d):
        info["problem"] = "e_lfanew fora da amostra"
        return info
    if d[lfanew:lfanew + 4] != b"PE\0\0":
        info["problem"] = "sem PE\\0\\0 em e_lfanew"
        return info
    machine, nsec, _, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", d, lfanew + 4)
    info.update(pe_signature=True, machine=f"0x{machine:04X}", number_of_sections=nsec,
                characteristics=f"0x{chars:04X}", size_of_optional_header=opt_size)
    opt = lfanew + 24
    if opt + 72 <= len(d) and opt_size >= 72:
        magic = struct.unpack_from("<H", d, opt)[0]
        if magic in (0x10B, 0x20B):
            sub = struct.unpack_from("<H", d, opt + 68)[0]
            info.update(optional_magic=f"0x{magic:X}",
                        size_of_code=struct.unpack_from("<I", d, opt + 4)[0],
                        entry_point_rva=f"0x{struct.unpack_from('<I', d, opt + 16)[0]:X}",
                        subsystem=sub, subsystem_name=PE_SUBSYSTEMS.get(sub))
        else:
            info["problem"] = f"magic do optional header desconhecido 0x{magic:X}"
    return info


def classify(sample, size):
    sig = next((name for magic, name in SIGNATURES if sample.startswith(magic)), None)
    if sig == "MZ":
        pe = pe_header(sample)
        if pe and pe["pe_signature"]:
            sig = "PE"
    h = entropy(sample) if sample else None
    if size == 0:
        state = "EMPTY"
    elif sig:
        state = "PLAINTEXT_SIGNATURE"
    elif len(sample) < MIN_ENTROPY_SAMPLE:
        state = "TOO_SMALL"
    elif h >= OPAQUE_ENTROPY:
        state = "OPAQUE"
    elif h < STRUCTURED_ENTROPY:
        state = "STRUCTURED"
    else:
        state = "MIXED"
    return sig, h, state


def encryption_status(key_id, state):
    if key_id == NO_KEY:
        return "NO_KEY_PER_REGION"
    if state == "OPAQUE":
        return "LIKELY_ENCRYPTED_UNVERIFIED"
    if state == "PLAINTEXT_SIGNATURE":
        return "INCONSISTENT_PLAINTEXT_WITH_KEY"
    return "UNKNOWN"


def build_report(f, path, file_size, hdr, lay, rows, checks):
    files = []
    for r in rows:
        e, reg = r["entry"], r["region"]
        n = min(SAMPLE_SIZE, e["size"])
        f.seek(r["start"])
        sample = f.read(n)
        sig, h, state = classify(sample, e["size"])
        key_id = reg["KeyId"] if reg else None
        files.append({
            "filename": e["name"],
            "segment_index": r["index"],
            "region_id": f"0x{reg['Id']:X}" if reg else None,
            "key_id": key_id,
            "relative_page": f"0x{(r['start'] - region_start(lay, 'drive data')[0]) // PAGE:X}",
            "absolute_offset": f"0x{r['start']:X}",
            "end_offset_exclusive": f"0x{r['end']:X}",
            "size": e["size"],
            "sample_size": len(sample),
            "signature": sig,
            "pe_signature_found": sig == "PE",
            "pe": pe_header(sample),
            "entropy_64kb": round(h, 3) if h is not None else None,
            "content_state": state,
            "encryption_status": encryption_status(key_id, state) if key_id is not None else "UNKNOWN",
        })
    drive_off, _ = region_start(lay, "drive data")
    return {
        "schema_version": 1,
        "source": {
            "path": str(path),
            "size": file_size,
            "vduid": str(hdr["VDUID"]),
            "drive_data_offset": f"0x{drive_off:X}",
            "drive_data_offset_source": "layout calculado do cabecalho XVD (MDU pela regiao XVC-MDU)",
        },
        "classification_rules": {
            "sample": f"primeiros {SAMPLE_SIZE} bytes de cada arquivo",
            "signatures": sorted({name for _, name in SIGNATURES} | {"PE"}),
            "PE": "MZ com e_lfanew valido e PE\\0\\0; so 'MZ' quando falta o PE\\0\\0",
            "OPAQUE": f"sem assinatura, amostra >= {MIN_ENTROPY_SAMPLE} bytes, entropia >= {OPAQUE_ENTROPY}",
            "STRUCTURED": f"sem assinatura, entropia < {STRUCTURED_ENTROPY}",
            "MIXED": "entre STRUCTURED e OPAQUE",
            "TOO_SMALL": f"amostra < {MIN_ENTROPY_SAMPLE} bytes, sem assinatura",
            "LIKELY_ENCRYPTED_UNVERIFIED": "regiao com KeyId e conteudo OPAQUE; algoritmo nao verificado",
            "NO_KEY_PER_REGION": "regiao com KeyId 0xFFFF",
        },
        "validation": {
            "passed": all(ok for _, ok, _ in checks),
            "checks": [{"name": n, "passed": ok, "detail": d} for n, ok, d in checks],
        },
        "files": files,
    }


# ---------------------------------------------------------------- fase 4: strings


def extract_userdata(ud, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    for fl in ud["files"]:
        name = os.path.basename(fl["path"].replace("\\", "/"))
        if name in ("", ".", ".."):
            print(f"   ! nome invalido ignorado: {fl['path']!r}")
            continue
        with open(os.path.join(out_dir, name), "wb") as out:
            out.write(fl["data"])
    print(f"   {len(ud['files'])} arquivos extraidos em {os.path.abspath(out_dir)}")


# ---------------------------------------------------------------- fase 4: strings
def utf16(pattern_ascii):
    return b"".join(re.escape(bytes([c])) + b"\x00" for c in pattern_ascii)


LITERALS = [b"MSFT-XVC", b"msft-xvc", b"msft-xvd", b"FS-MD", b"XVC-EXVD"]
PATTERNS = re.compile(
    rb"(?P<a>XVC-[A-Z]{2,4}|" + b"|".join(re.escape(x) for x in LITERALS) + b")"
    + rb"|(?P<u>X\x00V\x00C\x00-\x00(?:[A-Z]\x00){2,4}|" + b"|".join(utf16(x) for x in LITERALS) + b")"
)
OVERLAP = 64   # >= maior match possivel (16 bytes em UTF-16)


def scan_strings(f, end, chunk=1 << 24):
    hits = []
    pos = 0
    while pos < end:
        f.seek(pos)
        limit = min(chunk, end - pos)
        b = f.read(limit + OVERLAP)
        if not b:
            break
        for m in PATTERNS.finditer(b):
            if m.start() >= limit:      # fica para o proximo bloco: evita duplicata
                break
            enc = "ascii" if m.group("a") else "utf16"
            hits.append((pos + m.start(), m.group().decode("ascii" if enc == "ascii" else "utf-16-le"), enc))
        pos += chunk
    return hits


# ---------------------------------------------------------------- fase 5: entropia
def entropy_runs(f, end, window, stride, threshold, max_gap):
    runs = []   # [inicio, fim, janelas_baixas, h_min]
    pos = 0
    while pos < end:
        f.seek(pos)
        b = f.read(window)
        if not b:
            break
        h = entropy(b)
        if h < threshold:
            if runs and pos - runs[-1][1] <= max_gap:
                r = runs[-1]
                r[1] = pos + len(b)
                r[2] += 1
                r[3] = min(r[3], h)
            else:
                runs.append([pos, pos + len(b), 1, h])
        pos += stride
    return runs


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    num = lambda s: int(s, 0)
    ap.add_argument("path", nargs="?",
                    default=r"G:\MyGame_v1\28872443D20A7_1.0.2.1_neutral__k2ss7vbb13xte_xs.xvc")
    ap.add_argument("--mdu-pages", type=int, default=None,
                    help="forca o tamanho do MDU em paginas (padrao: regiao XVC-MDU)")
    ap.add_argument("--anchor-radius", type=int, default=64,
                    help="paginas a procurar em volta do XvcInfo estimado")
    ap.add_argument("--skip-scan", action="store_true", help="pula as fases 4 e 5 (leitura longa)")
    ap.add_argument("--scan-end", type=num, default=None,
                    help="fim da varredura (padrao: inicio do drive data + 64 MB)")
    ap.add_argument("--window", type=num, default=16 * 1024)
    ap.add_argument("--stride", type=num, default=256 * 1024)
    ap.add_argument("--threshold", type=float, default=6.0)
    ap.add_argument("--max-gap", type=num, default=4 * 1024 * 1024)
    ap.add_argument("--dump", type=num, default=0, help="bytes de hexdump no inicio do XvcInfo")
    ap.add_argument("--list-files", action="store_true", help="lista os 108 arquivos com segmento e regiao")
    ap.add_argument("--extract-userdata", metavar="DIR", help="grava os arquivos do user data em DIR")
    ap.add_argument("--json-report", metavar="ARQUIVO",
                    help="grava relatorio JSON dos arquivos (segmento, regiao, offset, entropia, classificacao)")
    args = ap.parse_args()

    size = os.path.getsize(args.path)
    with open(args.path, "rb") as f:
        hdr = read_header(f)
        print("== cabecalho XVD")
        for k, v in hdr.items():
            print(f"   {k:<22} {v:#x}" if isinstance(v, int) else f"   {k:<22} {v}")

        # estimativa inicial: MDU desconhecido (0 paginas) salvo se o usuario informar
        mdu_pages = args.mdu_pages if args.mdu_pages is not None else 0
        mdu_source = "--mdu-pages" if args.mdu_pages is not None else "estimativa (0)"
        lay, integrity, resilient = layout(hdr, mdu_pages)
        print(f"   integridade={'sim' if integrity else 'nao'}  resiliencia={'sim' if resilient else 'nao'}")

        # O XvcInfo comeca com o ContentID, igual ao VDUID neste formato: ancora observada.
        est_xvc, _ = region_start(lay, "XvcInfo")
        xvc_off = find_page_anchor(f, est_xvc, hdr["VDUID"].bytes_le, args.anchor_radius)
        if xvc_off is None:
            print(f"== ancora XvcInfo (VDUID) nao encontrada em 0x{est_xvc:x} +/- {args.anchor_radius} paginas")
            xi = None
        else:
            print(f"== ancora XvcInfo em 0x{xvc_off:x} (estimado 0x{est_xvc:x}, "
                  f"{(xvc_off - est_xvc) // PAGE:+d} paginas)")
            xi, err = decode_xvcinfo(f, xvc_off, hdr["XvcDataLength"])
            if err:
                print(f"   ! {err}")

        if xi:
            mdu = by_desc(xi, "XVC-MDU")
            if mdu and args.mdu_pages is None:
                mdu_pages, mdu_source = pages(mdu["Length"]), "regiao XVC-MDU"
                lay, _, _ = layout(hdr, mdu_pages)
            md = by_desc(xi, "XVC-MD")
            if md:
                ht_obs = md["Length"] - sum(region_start(lay, n)[1]
                                            for n in ("user data", "XvcInfo", "dynamic header"))
                ht_calc = region_start(lay, "hash tree")[1]
                print(f"== hash tree: formula 0x{ht_calc:x}, observada via XVC-MD 0x{ht_obs:x} "
                      f"{'OK' if ht_obs == ht_calc else 'DIFERE'}")
                if ht_obs != ht_calc and ht_obs % PAGE == 0:
                    lay, _, _ = layout(hdr, mdu_pages, (ht_obs - ht_calc) // PAGE)
        elif xvc_off is not None and xvc_off != est_xvc:
            # sem XvcInfo legivel: a diferenca fica antes do user data, origem indeterminada
            lay, _, _ = layout(hdr, mdu_pages, (xvc_off - est_xvc) // PAGE)
            mdu_source += "; diferenca antes do user data sem origem determinada"

        print(f"== layout (MDU: {mdu_pages} paginas, fonte: {mdu_source})")
        for name, start, rsize in lay:
            print(f"   {name:<20} 0x{start:012x}  +0x{rsize:x}  ({rsize / 2**20:.1f} MB)")
        total = lay[-1][1] + lay[-1][2]
        print(f"   fim calculado 0x{total:x}  tamanho real 0x{size:x}  "
              f"{'OK' if total == size else f'DIFERE em {size - total:+#x}'}")
        if xi and region_start(lay, "XvcInfo")[0] != xvc_off:
            print(f"   ! layout poe o XvcInfo em 0x{region_start(lay, 'XvcInfo')[0]:x}, ancora em 0x{xvc_off:x}")

        if xi:
            print_xvcinfo(xi, xvc_off, lay, size)

        ud_off, _ = region_start(lay, "user data")
        ud, err = decode_userdata(f, ud_off, hdr["UserDataLength"])
        sm = rows = checks = None
        if err:
            print(f"== user data @ 0x{ud_off:x}: ! {err}")
        else:
            for p in print_userdata_files(ud, ud_off):
                print(f"   ! {p}")
            if args.extract_userdata:
                extract_userdata(ud, args.extract_userdata)
            sm_file = next((fl for fl in ud["files"] if fl["path"] == SEGMETA_NAME), None)
            if sm_file:
                sm, err = decode_segment_metadata(sm_file["data"])
                if err:
                    print(f"== {SEGMETA_NAME}: ! {err}")
            if sm and xi:
                rows, checks = map_files(sm, xi, lay, size)
                print_file_map(sm, rows, checks, xi["regions"], args.list_files)

        if args.json_report:
            if not rows:
                print("== relatorio JSON nao gerado: mapa de arquivos indisponivel")
            else:
                report = build_report(f, args.path, size, hdr, lay, rows, checks)
                with open(args.json_report, "w", encoding="utf-8") as out:
                    json.dump(report, out, indent=2, ensure_ascii=False)
                states = collections.Counter((x["content_state"], x["encryption_status"]) for x in report["files"])
                print(f"== relatorio JSON: {os.path.abspath(args.json_report)} ({len(report['files'])} arquivos)")
                for (st, enc), n in sorted(states.items()):
                    print(f"   {n:>3}  {st:<20} {enc}")

        if args.dump and xvc_off is not None:
            print(f"== dump XvcInfo @ 0x{xvc_off:x}")
            hexdump(f, xvc_off, args.dump)

        if args.skip_scan:
            return

        drive_off, _ = region_start(lay, "drive data")
        scan_end = min(args.scan_end if args.scan_end is not None else drive_off + (64 << 20), size)

        print(f"== strings de regiao ate 0x{scan_end:x}")
        by_text = collections.defaultdict(list)
        for off, text, enc in scan_strings(f, scan_end):
            by_text[(text, enc)].append(off)
        if not by_text:
            print("   nenhuma")
        for (text, enc), offs in sorted(by_text.items(), key=lambda kv: kv[1][0]):
            shown = ", ".join(f"0x{o:x} [{region_of(lay, o)}]" for o in offs[:8])
            more = f" ... (+{len(offs) - 8})" if len(offs) > 8 else ""
            print(f"   {text!r:<14} {enc:<5} x{len(offs):<5} {shown}{more}")

        print(f"== janelas H<{args.threshold} ({args.window // 1024} KB a cada {args.stride // 1024} KB, "
              f"lacunas <= {args.max_gap / 2**20:.0f} MB unidas)")
        runs = entropy_runs(f, scan_end, args.window, args.stride, args.threshold, args.max_gap)
        if not runs:
            print("   nenhuma")
        for a, b, n, hmin in runs:
            print(f"   0x{a:x} - 0x{b:x}  ({(b - a) / 2**20:.1f} MB, {n} janelas, H_min={hmin:.2f})"
                  f"  [{region_of(lay, a)}]")


if __name__ == "__main__":
    main()
