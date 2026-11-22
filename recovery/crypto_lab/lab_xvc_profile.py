"""PERFIL B - XVC com criptografia por regiao.

Reproduz (xvdtool XVDFile.cs CryptXvcRegion 302-320, CryptSectionXts 322-383,
GetXvcKey/GetXvcKeyByGuid 1008-1060):

  * cada CIK tem um GUID; XvcInfo.EncryptionKeyIds[] (0x10) guarda os GUIDs e
    KeyCount (0xD1E) quantos sao validos;
  * RegionHeader.KeyId e o INDICE nessa tabela; 0xFFFF = regiao sem cifra;
  * a CIK vem de um armazenamento de chaves por GUID - a ODK NAO participa
    (CryptHeaderCik retorna cedo para XVC);
  * headerId do tweak = RegionHeader.Id; data unit = entry[0x14:0x18] da folha.

Leiaute: cabecalho | MDU (1 pag) | hash tree | user data | XvcInfo (2 pag) | drive.
Drive: FS-MD (2 pag, texto publico) | regioes de dados.
"""
from __future__ import annotations

import json
import struct
import uuid
from dataclasses import dataclass, field

import lab_common  # noqa: F401
from lab_common import LAB_BANNER, LAB_MARKER_STR, PAGE, Rng, pad_page, sha256, sha256_hex
import lab_hash_tree as HT
from lab_container import (CONTENT_TYPE_APPLICATION, FLAG_READ_ONLY, FLAG_REGION_ID_IN_XTS, build_segment_metadata,
                           build_userdata, guid_from, make_header, utf16_fixed)
from lab_xts import crypt_section

XVC_KEY_NONE = 0xFFFF
FLAGS_XVC = FLAG_READ_ONLY | FLAG_REGION_ID_IN_XTS
XVCINFO_PAGES = 2
REGIONS_OFF = 0xDA8
REGION_SIZE = 0x80
ID_HEADER, ID_MDU, ID_MD, ID_FSMD, ID_UNKNOWN = 0x40000005, 0x40000006, 0x40000001, 0x40000002, 0x40000003


@dataclass
class LabFile:
    name: str
    data: bytes
    du_runs: list[tuple[int, int]] = field(default_factory=list)   # (pagina relativa ao arquivo, data unit inicial)


@dataclass
class LabRegion:
    id: int
    key_id: int
    files: list[LabFile]
    description: str = ""


def gen_xvc_keys(rng: Rng, n: int = 2) -> list[tuple[uuid.UUID, bytes]]:
    return [(guid_from(rng.bytes(f"id:cik_guid:{i}", 16)), rng.bytes(f"key:cik:xvc:{i}", 32)) for i in range(n)]


class KeyNotAvailable(LookupError):
    pass


def get_xvc_key(key_table: list[uuid.UUID], key_count: int, key_id: int, keystore: dict[str, bytes]) -> bytes | None:
    """Porte de GetXvcKey + GetXvcKeyByGuid. Retorna None para regiao sem cifra;
    KeyNotAvailable se o GUID nao esta no armazenamento (sem chave -> sem decifrar)."""
    if key_id == XVC_KEY_NONE or key_id + 1 > key_count:
        return None
    if not key_table or key_count == 0:
        return None
    guid = key_table[key_id]
    if guid.int == 0:                       # IsKeyNulled
        return None
    if guid not in key_table[:key_count]:
        raise KeyNotAvailable(f"Key {guid} is not used by this XVC")
    k = keystore.get(str(guid))
    if k is None:
        raise KeyNotAvailable(f"Did not find CIK {guid} loaded in Keystorage")
    return k


def data_units_for(f: LabFile) -> list[int]:
    n = (len(f.data) + PAGE - 1) // PAGE
    runs = sorted(f.du_runs)
    out = []
    for j, (start_page, val) in enumerate(runs):
        end = runs[j + 1][0] if j + 1 < len(runs) else n
        out += [(val + k - start_page) & 0xFFFFFFFF for k in range(start_page, end)]
    if len(out) != n:
        raise ValueError(f"{f.name}: data units nao cobrem todas as {n} paginas")
    return out


@dataclass
class XvcContainer:
    data: bytes
    truth: dict


def build_xvc_container(regions: list[LabRegion], *, keys: list[tuple[uuid.UUID, bytes]], rng: Rng) -> XvcContainer:
    vduid = guid_from(rng.bytes("id:vduid:xvc", 16))
    seg_guid = guid_from(rng.bytes("id:segmeta_guid", 16))
    key_table = [g for g, _ in keys]
    cik_of = {i: k for i, (_, k) in enumerate(keys)}

    # ---------------- drive (plaintext, paginas relativas)
    fsmd_text = (f"{LAB_BANNER}\nFS-MD sintetico do laboratorio (texto publico, sem chave).\n").encode()
    drive_plain: list[bytes] = [p for p in _pages(pad_page(fsmd_text.ljust(2 * PAGE, b"\0")))]
    page_key: list[int] = [XVC_KEY_NONE, XVC_KEY_NONE]
    page_du: dict[int, int] = {}
    files_meta, seg_rel_pages, file_rows = [], [], []
    spans = []
    for reg in regions:
        start = len(drive_plain)
        for f in reg.files:
            rel = len(drive_plain)
            seg_rel_pages.append(rel)
            files_meta.append((f.name, len(f.data)))
            pp = list(_pages(pad_page(f.data)))
            dus = data_units_for(f) if reg.key_id != XVC_KEY_NONE else [None] * len(pp)
            for i, pg in enumerate(pp):
                drive_plain.append(pg)
                page_key.append(reg.key_id)
                if dus[i] is not None:
                    page_du[rel + i] = dus[i]
            file_rows.append({"name": f.name, "region_id": reg.id, "key_id": reg.key_id, "drive_rel_page": rel,
                              "pages": len(pp), "size": len(f.data), "sha256": sha256_hex(f.data),
                              "data_units": dus if reg.key_id != XVC_KEY_NONE else None,
                              "du_runs": f.du_runs if reg.key_id != XVC_KEY_NONE else None})
        spans.append((reg, start, len(drive_plain) - start))

    # ---------------- cifra por regiao
    drive_stored = list(drive_plain)
    for reg, start, n in spans:
        if reg.key_id == XVC_KEY_NONE:
            continue
        cik = cik_of[reg.key_id]
        sec = b"".join(drive_plain[start:start + n])
        dus = [page_du[start + i] for i in range(n)]
        ct = crypt_section(cik, sec, dus, reg.id, vduid.bytes_le, encrypt=True)
        for i in range(n):
            drive_stored[start + i] = ct[i * PAGE:(i + 1) * PAGE]
    drive = b"".join(drive_stored)

    # ---------------- user data
    seg_meta = build_segment_metadata(files_meta, seg_rel_pages, seg_guid)
    lab_manifest = json.dumps({"marker": LAB_MARKER_STR, "banner": LAB_BANNER, "profile": "B-XVC-REGION"},
                              sort_keys=True).encode()
    userdata = build_userdata([("LabManifest.json", lab_manifest), ("SegmentMetadata.bin", seg_meta)],
                              f"{LAB_MARKER_STR}.CryptoLab_1.0.0.0_neutral__lab")
    ud_padded = pad_page(userdata)
    ud_p = len(ud_padded) // PAGE
    xvc_len = XVCINFO_PAGES * PAGE
    n_hashed = ud_p + XVCINFO_PAGES + len(drive_plain)
    geo = HT.compute_geometry(n_hashed)
    off_mdu = 0x3000
    off_ht = off_mdu + PAGE
    off_ud = off_ht + geo.total_pages * PAGE
    off_xvc = off_ud + ud_p * PAGE
    off_drive = off_xvc + xvc_len
    drive_page0 = off_drive // PAGE
    hashed0 = off_ud // PAGE
    file_end = off_drive + len(drive)

    def drive_hashed(rel: int) -> int:
        return drive_page0 + rel - hashed0

    # ---------------- regioes (cabecalhos)
    hdr_regions = [
        (ID_HEADER, XVC_KEY_NONE, 1, 0, "XVC-HD", 0, 0x3000, bytes(8)),
        (ID_MDU, XVC_KEY_NONE, 1, 0, "XVC-MDU", off_mdu, PAGE, bytes(8)),
        (ID_MD, XVC_KEY_NONE, 1, 0, "XVC-MD", off_ht, off_drive - off_ht, bytes(8)),
        (ID_FSMD, XVC_KEY_NONE, 1, 0, "FS-MD", off_drive, 2 * PAGE, sha256(drive[:2 * PAGE])[:8]),
    ]
    seg_idx = 0
    for reg, start, n in spans:
        b = drive[start * PAGE:(start + n) * PAGE]
        hdr_regions.append((reg.id, reg.key_id, 0, seg_idx, reg.description, off_drive + start * PAGE, n * PAGE,
                            sha256(b)[:8]))
        seg_idx += len(reg.files)

    seg_abs = [drive_page0 + r for r in seg_rel_pages]
    seg_hashes, seg_values = [], []
    for i, p in enumerate(seg_abs):
        reg_end = next(o + ln for (_, _, _, _, _, o, ln, _) in hdr_regions if o <= p * PAGE < o + ln) // PAGE
        end = min(seg_abs[i + 1] if i + 1 < len(seg_abs) else reg_end, reg_end)
        seg_hashes.append(sha256(drive[(p - drive_page0) * PAGE:(end - drive_page0) * PAGE])[:8])
        rel = p - drive_page0
        seg_values.append(page_du.get(rel, struct.unpack_from("<I", sha256(drive_stored[rel]), 0x14)[0]))

    # tabela de paginas RLE: uma entrada por run de data unit; arquivos sem chave -> sha[0x14:0x18]
    table: list[tuple[int, int]] = [(drive_page0, struct.unpack_from("<I", sha256(drive_stored[0]), 0x14)[0])]
    for row in file_rows:
        rel = row["drive_rel_page"]
        if row["key_id"] == XVC_KEY_NONE:
            table.append((drive_page0 + rel, struct.unpack_from("<I", sha256(drive_stored[rel]), 0x14)[0]))
        else:
            for rp, val in sorted(row["du_runs"]):
                table.append((drive_page0 + rel + rp, val))

    # ---------------- XvcInfo
    xi = bytearray(xvc_len)
    xi[0:16] = vduid.bytes_le                                   # ContentID == VDUID (ancora)
    for i, g in enumerate(key_table):
        xi[0x10 + 16 * i:0x20 + 16 * i] = g.bytes_le
    xi[0xC10:0xD10] = utf16_fixed(f"{LAB_MARKER_STR} crypto_lab XVC (synthetic, not an Xbox package)", 0x100)
    region_a = next((r for r in regions if r.key_id != XVC_KEY_NONE), None)
    ip_off = next((o for (rid, *_rest, o, _ln, _h) in hdr_regions if region_a and rid == region_a.id), 0)
    struct.pack_into("<IIIHHI", xi, 0xD10, 2, len(hdr_regions), 0, 0, len(key_table), 0)
    struct.pack_into("<IQQ", xi, 0xD24, region_a.id if region_a else 0, ip_off, 0x01DD5A1B00000000)
    struct.pack_into("<IIQQII", xi, 0xD38, 0, len(seg_abs), 0, 0, 0, len(table))
    o = REGIONS_OFF
    for rid, key, flags, first, desc, roff, rlen, rhash in hdr_regions:
        rb = bytearray(REGION_SIZE)
        struct.pack_into("<IHHII", rb, 0, rid, key, 0, flags, first)
        rb[0x10:0x50] = utf16_fixed(desc, 0x40)
        struct.pack_into("<QQ", rb, 0x50, roff, rlen)
        rb[0x60:0x68] = rhash
        xi[o:o + REGION_SIZE] = rb
        o += REGION_SIZE
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
    if o > xvc_len:
        raise ValueError("XvcInfo excede 2 paginas")
    xi = bytes(xi)

    # ---------------- folhas e arvore
    leaves = [HT.leaf_entry_plain(ud_padded[i * PAGE:(i + 1) * PAGE]) for i in range(ud_p)]
    leaves += [HT.leaf_entry_plain(xi[i * PAGE:(i + 1) * PAGE]) for i in range(XVCINFO_PAGES)]
    for rel, pg in enumerate(drive_stored):
        leaves.append(HT.leaf_entry_encrypted(pg, page_du[rel]) if page_key[rel] != XVC_KEY_NONE
                      else HT.leaf_entry_plain(pg))
    tree, geo2, top = HT.build(leaves)
    assert geo2 == geo

    hdr = make_header(flags=FLAGS_XVC, drive_size=len(drive), vduid=vduid, content_type=CONTENT_TYPE_APPLICATION,
                      user_data_len=len(userdata), xvc_len=xvc_len, mdu_pages=1, top_hash=top,
                      pduid=rng.bytes("id:pduid:xvc", 16), package_version=(0, 0, 0, 1))
    data = bytes(hdr) + bytes(PAGE) + tree + ud_padded + xi + drive
    assert len(data) == file_end

    for row in file_rows:
        rel = row["drive_rel_page"]
        row["container_offset"] = off_drive + rel * PAGE
        row["hashed_index_first_page"] = drive_hashed(rel)
        row["stored_sha256"] = sha256_hex(drive[rel * PAGE:rel * PAGE + row["size"]])
    truth = {
        "profile": "B-XVC-REGION",
        "vduid": str(vduid), "vduid_bytes_le": vduid.bytes_le.hex(),
        "odk_used": False,
        "key_table": [{"key_id": i, "guid": str(g), "cik": k.hex(), "tweak_key": k[:16].hex(), "data_key": k[16:].hex()}
                      for i, (g, k) in enumerate(keys)],
        "regions": [{"id": f"0x{rid:X}", "key_id": key, "description": desc, "offset": roff, "length": rlen,
                     "hash": rhash.hex(), "encrypted": key != XVC_KEY_NONE}
                    for rid, key, _f, _s, desc, roff, rlen, rhash in hdr_regions],
        "files": file_rows,
        "layout": {"header": [0, 0x3000], "mdu": [off_mdu, PAGE], "hash_tree": [off_ht, off_ud - off_ht],
                   "user_data": [off_ud, len(ud_padded)], "xvcinfo": [off_xvc, xvc_len], "drive": [off_drive, len(drive)],
                   "file_size": file_end},
        "hash_tree_levels": list(geo.level_pages), "hashed_pages": geo.hashed_pages,
        "page_table": [(p, v) for p, v in table],
    }
    return XvcContainer(data, truth)


def _pages(b: bytes):
    for i in range(0, len(b), PAGE):
        yield b[i:i + PAGE]
