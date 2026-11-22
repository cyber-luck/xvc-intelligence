"""Gerador de um pacote XVC sintetico completo e pequeno (~1 MB) para testes.

Reproduz as regras observadas no pacote real (sem nenhum byte dele, exceto os
arquivos de configuracao em tests/fixtures/userdata_files, que sao extratos
pequenos): cabecalho, XVD embutido, MDU, hash tree de 2 niveis, user data com
SegmentMetadata, XvcInfo com regioes/segmentos/array por segmento/tabela de
paginas RLE, hashes de regiao e de segmento. Conteudo "cifrado" = bytes
pseudoaleatorios (nada e cifrado de verdade).
"""
from __future__ import annotations

import hashlib
import random
import struct
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from xvcintel.formats.hashtree import build_tree, compute_geometry

PAGE = 0x1000
FIX = Path(__file__).parent / "fixtures"
NO_KEY = 0xFFFF
MD_HASH = bytes.fromhex("5c2b65ad36990544")
STORE_ID = "9NL3WWNZLZZN"


def sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def pages_of(n: int) -> int:
    return (n + PAGE - 1) // PAGE


def pad(b: bytes, n: int | None = None) -> bytes:
    n = pages_of(len(b)) * PAGE if n is None else n
    return b.ljust(n, b"\0")


def utf16_fixed(s: str, size: int) -> bytes:
    return s.encode("utf-16-le").ljust(size, b"\0")[:size]


@dataclass
class SynthFile:
    name: str
    data: bytes
    du_runs: list[tuple[int, int]] = field(default_factory=list)   # (pagina relativa ao arquivo, valor)


@dataclass
class SynthRegion:
    id: int
    key_id: int
    flags: int
    files: list[SynthFile]
    extra_pages: int = 0


@dataclass
class Synth:
    data: bytes
    info: dict


def fixture(name: str) -> bytes:
    return (FIX / "userdata_files" / name).read_bytes()


def build_segment_metadata(names_sizes: list[tuple[str, int]], rel_pages: list[int], guid: uuid.UUID) -> bytes:
    hdr_size = 0x64
    strings = b""
    entries = b""
    for name, size in names_sizes:
        enc = name.encode("utf-16-le")
        entries += struct.pack("<HHIQ", 0, len(name), len(strings), size)
        strings += enc
    head = bytearray(hdr_size)
    head[0:4] = b" PFX"
    struct.pack_into("<5I", head, 4, 4, 2, hdr_size, len(names_sizes), len(strings))
    head[0x18:0x28] = guid.bytes_le
    struct.pack_into("<I", head, 0x28, 1)
    return bytes(head) + entries + strings + struct.pack(f"<{len(rel_pages)}I", *rel_pages)


def build_userdata(files: list[tuple[str, bytes]], pkg_name: str) -> bytes:
    count = len(files)
    first = 0x14 + 0x208 + 4
    data_off = first + count * 0x210
    entries = b""
    blobs = b""
    for name, d in files:
        rel = data_off + len(blobs) - 0x10
        entries += utf16_fixed(name, 0x208) + struct.pack("<II", len(d), rel)
        blobs += d
    return struct.pack("<4I", 0x10, 1, 0, 0) + struct.pack("<I", 1) + utf16_fixed(pkg_name, 0x208) + \
        struct.pack("<I", count) + entries + blobs


def make_header(fields: dict) -> bytearray:
    h = bytearray(0x3000)
    h[0x200:0x208] = b"msft-xvd"
    struct.pack_into("<I", h, 0x208, fields.get("flags", 0x41))
    struct.pack_into("<I", h, 0x20C, 3)
    struct.pack_into("<Q", h, 0x210, 0x01DD74577AD5D7ED)
    struct.pack_into("<Q", h, 0x218, fields["drive_size"])
    h[0x220:0x230] = fields["vduid"].bytes_le
    h[0x230:0x240] = fields.get("uduid", fields["vduid"]).bytes_le
    struct.pack_into("<II", h, 0x280, fields.get("type", 0), fields.get("content_type", 1))
    struct.pack_into("<IIIII", h, 0x288, fields.get("emb_len", 0), fields.get("ud_len", 0),
                     fields.get("xvc_len", 0), fields.get("dyn_len", 0), 0xAA000)
    h[0x32C:0x33C] = fields.get("emb_pduid", bytes(16))
    h[0x39C:0x3AC] = fields.get("product_id", bytes(16))
    h[0x3AC:0x3BC] = fields.get("pduid", bytes(16))
    struct.pack_into("<4H", h, 0x3BC, *fields.get("pkg_version", (0, 0, 0, 0)))
    struct.pack_into("<I", h, 0x46C, fields.get("pls", 0))
    h[0x470] = fields.get("mdu", 0)
    h[0x471] = fields.get("u471", 0)
    struct.pack_into("<4H", h, 0x494, *fields.get("min_sys", (0, 0, 0, 0)))
    return h


def build_embedded(pduid: bytes) -> bytes:
    """XVD fixo minimo: cabecalho + arvore de 1 pagina + 2 paginas de drive."""
    rnd = random.Random(7)
    drive = bytes(rnd.getrandbits(8) for _ in range(2 * PAGE))
    leaves = [sha(drive[i * PAGE:(i + 1) * PAGE])[:0x14] + b"\0\0\0\0" for i in range(2)]
    tree, _ = build_tree(leaves)
    h = make_header({"flags": 0x01, "drive_size": 2 * PAGE, "vduid": uuid.UUID(int=0xE8A8), "uduid": uuid.UUID(int=0),
                     "type": 0, "content_type": 3, "pduid": pduid})
    h[0x240:0x260] = sha(tree[0])
    return bytes(h) + b"".join(tree) + drive


def default_regions(rnd: random.Random) -> list[SynthRegion]:
    def blob(n):
        return bytes(rnd.getrandbits(8) for _ in range(n))
    exe = SynthFile("game_scarlett_master.exe", blob(5 * PAGE - 0xC00), [(0, 0xE5046EA2)])
    return [
        SynthRegion(0x40000003, NO_KEY, 0, [
            SynthFile("microsoft_gameconfig.bin", fixture("microsoft_gameconfig.bin")),
            SynthFile("MicrosoftGame.Config", fixture("MicrosoftGame.config")),
            SynthFile("appxmanifest.xml", fixture("appxmanifest.xml")),
            SynthFile("Catalog000.bin", (FIX / "Catalog000.bin").read_bytes()),
        ]),
        SynthRegion(0x3E8, 0, 0, [SynthFile("appdata0.rpf", blob(3 * PAGE - 100), [(0, 0x1000), (2, 0x0FF0)])]),
        SynthRegion(0x3E9, 0, 0, [exe]),
        SynthRegion(0x3EA, 0, 0, [SynthFile("vcruntime140.dll", blob(2 * PAGE + 5), [(0, 0x5000)]),
                                  SynthFile("XCurl.dll", blob(4 * PAGE), [(0, 0x5004), (1, 0x6000), (3, 0x5000)])]),
        SynthRegion(0xBC1, 0, 0x4, [SynthFile("Update.alignmentchunk", b"\0", [(0, 0xF420B93D)])], extra_pages=1),
    ]


def build(seed: int = 1, segment_value_exceptions: dict[int, int] | None = None) -> Synth:
    """segment_value_exceptions: {indice do segmento: delta somado ao valor do array}."""
    rnd = random.Random(seed)
    regions = default_regions(rnd)
    if segment_value_exceptions is None:
        segment_value_exceptions = {4: -1}       # appdata0.rpf (como o anim.rpf real)
    vduid = uuid.UUID("3202719e-b4b4-421c-9f8f-70d1c4a7d60b")
    emb_pduid = bytes.fromhex("b78ddf1f2d874e4abf8b9b507a3f322e")
    key_guid = uuid.UUID("d4b2880b-884d-cf1b-eea5-bef5a2a7d4f6")
    seg_guid = uuid.UUID("b364c736-a183-4185-b6ca-2145e57dcc38")

    # ---- drive data (paginas relativas)
    fsmd = bytes(rnd.getrandbits(8) for _ in range(2 * PAGE))
    drive_pages: list[bytes] = [fsmd[:PAGE], fsmd[PAGE:]]
    keyed_page: list[bool] = [False, False]
    du_of: dict[int, int] = {}
    seg_rel_pages: list[int] = []
    files_meta: list[tuple[str, int]] = []
    region_spans: list[tuple[SynthRegion, int, int]] = []
    table_rel: list[tuple[int, int | None]] = [(0, 0)]
    for reg in regions:
        start = len(drive_pages)
        for f in reg.files:
            fp = pages_of(len(f.data))
            seg_rel_pages.append(len(drive_pages))
            files_meta.append((f.name, len(f.data)))
            base = len(drive_pages)
            for i in range(fp):
                drive_pages.append(pad(f.data[i * PAGE:(i + 1) * PAGE], PAGE))
                keyed_page.append(reg.key_id != NO_KEY)
            if reg.key_id != NO_KEY:
                runs = sorted(f.du_runs)
                for j, (rp, val) in enumerate(runs):
                    end = runs[j + 1][0] if j + 1 < len(runs) else fp
                    for k in range(rp, end):
                        du_of[base + k] = (val + k - rp) & 0xFFFFFFFF
                    table_rel.append((base + rp, val))
            else:
                table_rel.append((base, None))     # valor = sha[0x14:0x18] da pagina (como no pacote real)
        for _ in range(reg.extra_pages):
            last = max(du_of) if du_of else 0
            drive_pages.append(bytes(PAGE))
            keyed_page.append(reg.key_id != NO_KEY)
            if reg.key_id != NO_KEY:
                du_of[len(drive_pages) - 1] = (du_of.get(len(drive_pages) - 2, 0) + 1) & 0xFFFFFFFF
        region_spans.append((reg, start, len(drive_pages) - start))
    n_drive = len(drive_pages)
    drive = b"".join(drive_pages)

    # ---- tamanhos e layout
    seg_meta = build_segment_metadata(files_meta, seg_rel_pages, seg_guid)
    ud_files = [("appxmanifest.xml", fixture("appxmanifest.xml")),
                ("microsoft_gameconfig.bin", fixture("microsoft_gameconfig.bin")),
                ("MicrosoftGame.config", fixture("MicrosoftGame.config")),
                ("Summary.json", fixture("Summary.json")), ("Metadata.json", fixture("Metadata.json")),
                ("SegmentMetadata.bin", seg_meta)]
    userdata = build_userdata(ud_files, "RockstarGamesInc.28872443D20A7_1.0.2.1_neutral__k2ss7vbb13xte")
    xvc_len = 2 * PAGE
    embedded = build_embedded(emb_pduid)
    ud_p, xvc_p = pages_of(len(userdata)), xvc_len // PAGE
    n_hashed = n_drive + ud_p + xvc_p
    geo = compute_geometry(n_hashed)
    off_emb = 0x3000
    off_mdu = off_emb + len(embedded)
    off_ht = off_mdu + PAGE
    off_ud = off_ht + geo.total_pages * PAGE
    off_xvc = off_ud + ud_p * PAGE
    off_drive = off_xvc + xvc_len
    drive_page0 = off_drive // PAGE
    file_end = off_drive + len(drive)

    # ---- tabela de paginas e valores
    table = []
    for rp, val in table_rel:
        if val is None:
            val = struct.unpack_from("<I", sha(drive_pages[rp]), 0x14)[0]
        table.append((drive_page0 + rp, val))
    seg_values = []
    for i, rp in enumerate(seg_rel_pages):
        v = du_of.get(rp, struct.unpack_from("<I", sha(drive_pages[rp]), 0x14)[0])
        seg_values.append((v + segment_value_exceptions.get(i, 0)) & 0xFFFFFFFF)

    # ---- regioes
    def region_bytes(rel_start, n):
        return drive[rel_start * PAGE:(rel_start + n) * PAGE]

    hdr_regions = [
        (0x40000005, NO_KEY, 1, 0, "XVC-HD", 0, 0x3000, MD_HASH),
        (0x40000004, NO_KEY, 1, 0, "XVC-EXVD", off_emb, len(embedded), emb_pduid[:8]),
        (0x40000006, NO_KEY, 1, 0, "XVC-MDU", off_mdu, PAGE, bytes(8)),
        (0x40000001, NO_KEY, 1, 0, "XVC-MD", off_ht, off_drive - off_ht, MD_HASH),
        (0x40000002, NO_KEY, 1, 0, "FS-MD", off_drive, 2 * PAGE, sha(region_bytes(0, 2))[:8]),
    ]
    seg_idx = 0
    for reg, rs, rn in region_spans:
        hdr_regions.append((reg.id, reg.key_id, reg.flags, seg_idx, "", off_drive + rs * PAGE, rn * PAGE,
                            sha(region_bytes(rs, rn))[:8]))
        seg_idx += len(reg.files)
    # hashes de segmento
    seg_abs = [drive_page0 + rp for rp in seg_rel_pages]
    seg_hashes = []
    for i, p in enumerate(seg_abs):
        reg_end = next(o + ln for (_, _, _, _, _, o, ln, _) in hdr_regions if o <= p * PAGE < o + ln) // PAGE
        end = min(seg_abs[i + 1] if i + 1 < len(seg_abs) else reg_end, reg_end)
        seg_hashes.append(sha(drive[(p - drive_page0) * PAGE:(end - drive_page0) * PAGE])[:8])

    # ---- XvcInfo
    xi = bytearray(xvc_len)
    xi[0:16] = vduid.bytes_le
    xi[0x10:0x20] = key_guid.bytes_le
    struct.pack_into("<IIIHHI", xi, 0xD10, 2, len(hdr_regions), 7, 0, 1, 0)
    struct.pack_into("<IQQ", xi, 0xD24, 0xBC1, file_end, 0x01DD74577AD5CC0E)
    struct.pack_into("<IIQQII", xi, 0xD38, 0, len(seg_abs), 0, 0, 0, len(table))
    o = 0xDA8
    for rid, key, flags, first, desc, roff, rlen, rhash in hdr_regions:
        rb = bytearray(0x80)
        struct.pack_into("<IHHII", rb, 0, rid, key, 0, flags, first)
        rb[0x10:0x50] = utf16_fixed(desc, 0x40)
        struct.pack_into("<QQ", rb, 0x50, roff, rlen)
        rb[0x60:0x68] = rhash
        xi[o:o + 0x80] = rb
        o += 0x80
    for p, hsh in zip(seg_abs, seg_hashes):
        struct.pack_into("<I", xi, o, p)
        xi[o + 4:o + 12] = hsh
        o += 12
    for v in seg_values:
        struct.pack_into("<I", xi, o, v)
        o += 4
    for p, v in table:
        struct.pack_into("<II", xi, o, p, v)
        o += 8
    xi = bytes(xi)

    # ---- folhas e arvore
    leaves = []
    ud_padded = pad(userdata)
    for i in range(ud_p):
        leaves.append(sha(ud_padded[i * PAGE:(i + 1) * PAGE])[:0x18])
    for i in range(xvc_p):
        leaves.append(sha(xi[i * PAGE:(i + 1) * PAGE])[:0x18])
    for i, pg in enumerate(drive_pages):
        d = sha(pg)
        leaves.append(d[:0x14] + struct.pack("<I", du_of[i]) if keyed_page[i] else d[:0x18])
    tree, geo2 = build_tree(leaves)
    assert geo2 == geo

    product_id = STORE_ID[:7].encode() + bytes.fromhex("30c0") + STORE_ID[7:].encode() + bytes.fromhex("aa00")
    h = make_header({"flags": 0x41, "drive_size": len(drive), "vduid": vduid, "emb_len": len(embedded),
                     "ud_len": len(userdata), "xvc_len": xvc_len, "emb_pduid": emb_pduid, "product_id": product_id,
                     "pduid": bytes.fromhex("8cf6cadc5ef5b246899f30e6894d409a"), "pkg_version": (1, 2, 0, 1),
                     "pls": 0x800, "mdu": 1, "u471": 4, "min_sys": (0x25AF, 0x65F4, 0, 0x800A)})
    h[0x240:0x260] = sha(tree[0])
    data = bytes(h) + embedded + bytes(PAGE) + b"".join(tree) + ud_padded + xi + drive
    assert len(data) == file_end
    info = {"file_end": file_end, "off_drive": off_drive, "off_ht": off_ht, "off_ud": off_ud, "off_xvc": off_xvc,
            "geometry": geo, "n_files": len(files_meta), "files": files_meta, "seg_abs": seg_abs,
            "seg_values": seg_values, "du_of": {drive_page0 + k: v for k, v in du_of.items()}, "table": table,
            "regions": hdr_regions, "exe_offset": off_drive + seg_rel_pages[5] * PAGE, "keyed_page": keyed_page,
            "drive_page0": drive_page0, "segment_value_exceptions": segment_value_exceptions}
    return Synth(data, info)


def write(path: Path, seed: int = 1) -> Synth:
    s = build(seed)
    path.write_bytes(s.data)
    return s
