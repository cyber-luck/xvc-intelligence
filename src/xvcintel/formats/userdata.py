"""User data do tipo 0 (arquivos do pacote) e SegmentMetadata.bin (" PFX").

Estruturas observadas neste projeto (o xvdtool nao decodifica o conteudo):
  user data: cabecalho 0x10 (Length, Version, Type, Unknown), PackageVersion u32,
  PackageFullName UTF-16 [0x208], FileCount u32, entradas {caminho UTF-16 [0x208],
  u32 Size, u32 Offset relativo ao fim do cabecalho de 0x10}.
  SegmentMetadata: " PFX", Version, Unknown08, HeaderSize, Count, StringTableSize,
  GUID em 0x18, Unknown28 em 0x28; entradas de 16 bytes {u16, u16 NameLen, u32 NameOff,
  u64 Size}; strings UTF-16; Count x u32 paginas relativas ao drive data.
"""
from __future__ import annotations

import os
import struct
import uuid
from dataclasses import dataclass, field

from ..core.result import BAD_MAGIC, INCONSISTENT, INVALID_VALUE, OUT_OF_BOUNDS, Ok, Result, err, need
from ..core.util import utf16z

UD_HEADER_SIZE = 0x10
UD_TYPE_PACKAGE_FILES = 0
PKG_NAME_BYTES = 0x208
PKG_ENTRY_SIZE = 0x210
SEGMETA_NAME = "SegmentMetadata.bin"
SEGMETA_MAGIC = b" PFX"
SEGMETA_ENTRY_SIZE = 0x10
SEGMETA_MIN_HEADER = 0x2C


@dataclass(frozen=True)
class UserDataFile:
    index: int
    path: str
    size: int
    start: int          # relativo ao inicio do user data
    entry_offset: int   # onde a entrada esta (relativo ao user data)
    data: bytes = field(repr=False)


@dataclass
class UserData:
    header_length: int
    version: int
    type: int
    unknown: int
    package_version: int
    package_full_name: str
    files: list[UserDataFile]
    entries_end: int
    length: int
    problems: list[str]

    def file(self, name: str) -> UserDataFile | None:
        return next((f for f in self.files if f.path.casefold() == name.casefold()), None)


def parse_userdata(b: bytes) -> Result[UserData]:
    st = "UserData"
    e = need(b, 0, UD_HEADER_SIZE + 4 + PKG_NAME_BYTES + 4, st)
    if e:
        return e
    hlen, ver, typ, unk = struct.unpack_from("<4I", b, 0)
    if hlen != UD_HEADER_SIZE:
        return err(INVALID_VALUE, f"Length do cabecalho 0x{hlen:x} != 0x{UD_HEADER_SIZE:x}", 0, st)
    if typ != UD_TYPE_PACKAGE_FILES:
        return err(INVALID_VALUE, f"Type {typ} != {UD_TYPE_PACKAGE_FILES} (so o tipo 0 e suportado)", 8, st)
    pkg_ver = struct.unpack_from("<I", b, 0x10)[0]
    pkg_name = utf16z(b[0x14:0x14 + PKG_NAME_BYTES])
    count_off = 0x14 + PKG_NAME_BYTES
    count = struct.unpack_from("<I", b, count_off)[0]
    first = count_off + 4
    if first + count * PKG_ENTRY_SIZE > len(b):
        return err(OUT_OF_BOUNDS, f"FileCount={count} excede o user data", count_off, st)
    files: list[UserDataFile] = []
    problems: list[str] = []
    for i in range(count):
        eo = first + i * PKG_ENTRY_SIZE
        size, rel = struct.unpack_from("<II", b, eo + PKG_NAME_BYTES)
        start = hlen + rel
        if start + size > len(b):
            return err(OUT_OF_BOUNDS, f"arquivo {i}: 0x{start:x}+0x{size:x} excede o user data (0x{len(b):x})", eo, st)
        files.append(UserDataFile(i, utf16z(b[eo:eo + PKG_NAME_BYTES]), size, start, eo, bytes(b[start:start + size])))
    cursor = first + count * PKG_ENTRY_SIZE
    for f in files:
        if f.start < cursor:
            problems.append(f"{f.path} sobrepoe o anterior")
        cursor = max(cursor, f.start + f.size)
    return Ok(UserData(hlen, ver, typ, unk, pkg_ver, pkg_name, files, first + count * PKG_ENTRY_SIZE, len(b), problems))


@dataclass(frozen=True)
class SegMetaEntry:
    index: int
    flags: int
    name: str
    size: int
    name_off: int


@dataclass
class SegmentMetadata:
    version: int
    unknown08: int
    header_size: int
    count: int
    string_table_size: int
    guid: uuid.UUID
    unknown28: int
    entries: list[SegMetaEntry]
    pages: list[int]
    str_off: int
    pages_off: int

    def find(self, name: str) -> SegMetaEntry | None:
        return next((e for e in self.entries if e.name.casefold() == name.casefold()), None)


def parse_segment_metadata(d: bytes) -> Result[SegmentMetadata]:
    st = "SegmentMetadata"
    e = need(d, 0, SEGMETA_MIN_HEADER, st)
    if e:
        return e
    if d[:4] != SEGMETA_MAGIC:
        return err(BAD_MAGIC, f"magic {d[:4]!r} != {SEGMETA_MAGIC!r}", 0, st)
    ver, unk08, hdr_size, count, str_size = struct.unpack_from("<5I", d, 4)
    if hdr_size < SEGMETA_MIN_HEADER:
        return err(INVALID_VALUE, f"HeaderSize 0x{hdr_size:x} < 0x{SEGMETA_MIN_HEADER:x}", 0xC, st)
    str_off = hdr_size + count * SEGMETA_ENTRY_SIZE
    pages_off = str_off + str_size
    if pages_off + 4 * count != len(d):
        return err(INCONSISTENT, (f"tamanho nao fecha: cabecalho 0x{hdr_size:x} + {count} entradas + strings "
                                  f"0x{str_size:x} + {count} paginas = 0x{pages_off + 4 * count:x}, arquivo 0x{len(d):x}"),
                   0x10, st)
    entries = []
    for i in range(count):
        flags, nlen, noff, size = struct.unpack_from("<HHIQ", d, hdr_size + i * SEGMETA_ENTRY_SIZE)
        if noff + 2 * nlen > str_size:
            return err(OUT_OF_BOUNDS, f"entrada {i}: nome fora da tabela de strings", hdr_size + i * SEGMETA_ENTRY_SIZE, st)
        name = d[str_off + noff:str_off + noff + 2 * nlen].decode("utf-16-le", errors="replace")
        entries.append(SegMetaEntry(i, flags, name, size, noff))
    pages_ = list(struct.unpack_from(f"<{count}I", d, pages_off))
    return Ok(SegmentMetadata(ver, unk08, hdr_size, count, str_size, uuid.UUID(bytes_le=bytes(d[0x18:0x28])),
                              struct.unpack_from("<I", d, 0x28)[0], entries, pages_, str_off, pages_off))


def safe_basename(path: str) -> str | None:
    name = os.path.basename(path.replace("\\", "/"))
    return None if name in ("", ".", "..") else name
