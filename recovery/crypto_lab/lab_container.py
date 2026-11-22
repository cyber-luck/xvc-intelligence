"""Estruturas de conteiner compartilhadas pelos dois perfis (cabecalho XVD, user data,
SegmentMetadata). Offsets absolutos iguais aos lidos pelo xvcintel
(src/xvcintel/formats/xvd_header.py) e aos do xvdtool (+0x200).

Area de assinatura (0x000-0x200): o laboratorio NAO assina nada; grava ali o
marcador LAB_SYNTHETIC. ProductId (0x39C) tambem recebe o marcador.
"""
from __future__ import annotations

import struct
import uuid

import lab_common  # noqa: F401
from lab_common import LAB_BANNER, LAB_MARKER, PAGE

HEADER_SIZE = 0x3000
LAB_FILETIME = 0x01DD5A1B00000000         # constante do laboratorio (nao e a hora real)
LAB_PRODUCT_ID = LAB_MARKER.ljust(16, b"\0")
LAB_ODK_SLOT = 0x1AB5                     # slot sintetico; nao corresponde a nenhum OdkIndex real

FLAG_READ_ONLY = 0x01
FLAG_ENCRYPTION_DISABLED = 0x02
FLAG_DATA_INTEGRITY_DISABLED = 0x04
FLAG_REGION_ID_IN_XTS = 0x40

CONTENT_TYPE_DATA = 0          # nao-XVC para o xvdtool
CONTENT_TYPE_APPLICATION = 6   # tipo XVC para o xvdtool (XvdFile.XvcContentTypes)


def utf16_fixed(s: str, size: int) -> bytes:
    return s.encode("utf-16-le").ljust(size, b"\0")[:size]


def make_header(*, flags: int, drive_size: int, vduid: uuid.UUID, content_type: int, user_data_len: int,
                xvc_len: int, mdu_pages: int, key_material: bytes = bytes(32), odk_slot: int = 0,
                top_hash: bytes = bytes(32), pduid: bytes = bytes(16), package_version=(0, 0, 0, 1)) -> bytearray:
    h = bytearray(HEADER_SIZE)
    banner = LAB_MARKER + b"\0" + LAB_BANNER.encode()
    h[0:len(banner)] = banner[:0x200]
    h[0x200:0x208] = b"msft-xvd"
    struct.pack_into("<I", h, 0x208, flags)
    struct.pack_into("<I", h, 0x20C, 3)
    struct.pack_into("<Q", h, 0x210, LAB_FILETIME)
    struct.pack_into("<Q", h, 0x218, drive_size)
    h[0x220:0x230] = vduid.bytes_le
    h[0x230:0x240] = vduid.bytes_le
    h[0x240:0x260] = top_hash
    struct.pack_into("<II", h, 0x280, 0, content_type)           # Type Fixed
    struct.pack_into("<IIIII", h, 0x288, 0, user_data_len, xvc_len, 0, 0xAA000)
    if len(key_material) != 32:
        raise ValueError("KeyMaterial tem 32 bytes")
    h[0x34C:0x36C] = key_material
    h[0x39C:0x3AC] = LAB_PRODUCT_ID
    h[0x3AC:0x3BC] = pduid
    struct.pack_into("<4H", h, 0x3BC, *package_version)
    h[0x470] = mdu_pages
    struct.pack_into("<I", h, 0x49C, odk_slot)
    return h


def build_segment_metadata(names_sizes: list[tuple[str, int]], rel_pages: list[int], guid: uuid.UUID) -> bytes:
    hdr_size = 0x64
    strings = b""
    entries = b""
    for name, size in names_sizes:
        entries += struct.pack("<HHIQ", 0, len(name), len(strings), size)
        strings += name.encode("utf-16-le")
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
    return (struct.pack("<4I", 0x10, 1, 0, 0) + struct.pack("<I", 1) + utf16_fixed(pkg_name, 0x208) +
            struct.pack("<I", count) + entries + blobs)


def guid_from(raw16: bytes) -> uuid.UUID:
    """GUID versao 4 a partir de 16 bytes (sinteticos)."""
    return uuid.UUID(bytes=bytes(raw16), version=4)


def page_count(n: int) -> int:
    return (n + PAGE - 1) // PAGE
