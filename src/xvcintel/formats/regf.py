"""Leitor minimo de hive de registro (regf), somente leitura, com limites.

Toda celula e conferida contra o tamanho do buffer; erros viram Err.
"""
from __future__ import annotations

import datetime
import struct
from dataclasses import dataclass, field

from ..core.result import BAD_MAGIC, INVALID_VALUE, OUT_OF_BOUNDS, TRUNCATED, Err, Ok, ParseError, Result, err

TYPES = {0: "NONE", 1: "SZ", 2: "EXPAND_SZ", 3: "BINARY", 4: "DWORD", 5: "DWORD_BE", 7: "MULTI_SZ", 11: "QWORD"}
HBIN_BASE = 0x1000
MAX_DEPTH = 64


def filetime(v: int) -> str:
    try:
        return (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=v // 10)).isoformat() if v else "0"
    except OverflowError:
        return "fora do intervalo"


@dataclass
class RegValue:
    name: str
    type: int
    data: bytes

    @property
    def type_name(self) -> str:
        return TYPES.get(self.type, f"type{self.type}")

    def decoded(self):
        vt, d = self.type, self.data
        if vt in (1, 2):
            return d.decode("utf-16-le", "replace").rstrip("\0")
        if vt == 7:
            return [s for s in d.decode("utf-16-le", "replace").split("\0") if s]
        if vt == 4 and len(d) == 4:
            return struct.unpack("<I", d)[0]
        if vt == 11 and len(d) == 8:
            return struct.unpack("<Q", d)[0]
        return d.hex()


@dataclass
class RegKey:
    name: str
    timestamp: int
    values: list[RegValue] = field(default_factory=list)
    subkeys: list["RegKey"] = field(default_factory=list)

    def find(self, path: str) -> "RegKey | None":
        k: RegKey | None = self
        for part in [p for p in path.split("\\") if p]:
            k = next((s for s in k.subkeys if s.name.casefold() == part.casefold()), None) if k else None
        return k

    def value(self, name: str):
        v = next((v for v in self.values if v.name.casefold() == name.casefold()), None)
        return v.decoded() if v else None

    def walk(self, depth: int = 0):
        yield depth, self
        for s in self.subkeys:
            yield from s.walk(depth + 1)


class _Bad(Exception):
    def __init__(self, e: ParseError):
        self.e = e


class Hive:
    def __init__(self, b: bytes):
        self.b = b
        self.root_off = struct.unpack_from("<I", b, 0x24)[0]
        self.name = b[0x30:0x70].decode("utf-16-le", "replace").split("\0")[0]

    def cell(self, off: int) -> bytes:
        o = HBIN_BASE + off
        if o + 4 > len(self.b):
            raise _Bad(ParseError(OUT_OF_BOUNDS, f"celula 0x{off:x} fora do hive", o, "regf"))
        size = abs(struct.unpack_from("<i", self.b, o)[0])
        if size < 4 or o + size > len(self.b):
            raise _Bad(ParseError(TRUNCATED, f"celula 0x{off:x} com tamanho {size} invalido", o, "regf"))
        return self.b[o + 4:o + size]

    def _subkey_offsets(self, off: int, depth: int) -> list[int]:
        c = self.cell(off)
        if len(c) < 4:
            raise _Bad(ParseError(TRUNCATED, "lista de subchaves curta", HBIN_BASE + off, "regf"))
        sig, n = c[:2], struct.unpack_from("<H", c, 2)[0]
        step = {b"lf": 8, b"lh": 8, b"li": 4, b"ri": 4}.get(sig)
        if step is None:
            raise _Bad(ParseError(INVALID_VALUE, f"lista de subchaves desconhecida {sig!r}", HBIN_BASE + off, "regf"))
        if 4 + step * n > len(c):
            raise _Bad(ParseError(TRUNCATED, "lista de subchaves truncada", HBIN_BASE + off, "regf"))
        offs = [struct.unpack_from("<I", c, 4 + step * i)[0] for i in range(n)]
        if sig == b"ri":
            if depth > MAX_DEPTH:
                raise _Bad(ParseError(INVALID_VALUE, "ri aninhado demais", HBIN_BASE + off, "regf"))
            return [k for o in offs for k in self._subkey_offsets(o, depth + 1)]
        return offs

    def _value(self, off: int) -> RegValue:
        c = self.cell(off)
        if c[:2] != b"vk" or len(c) < 0x14:
            raise _Bad(ParseError(INVALID_VALUE, "celula vk esperada", HBIN_BASE + off, "regf"))
        nlen, dsize, doff, vtype, flags = struct.unpack_from("<HIIIH", c, 2)
        raw = c[0x14:0x14 + nlen]
        name = raw.decode("latin-1") if flags & 1 else raw.decode("utf-16-le", "replace")
        inline = bool(dsize & 0x80000000)
        dsize &= 0x7FFFFFFF
        data = struct.pack("<I", doff)[:dsize] if inline else self.cell(doff)[:dsize]
        return RegValue(name or "(padrao)", vtype, data)

    def _key(self, off: int, depth: int) -> RegKey:
        if depth > MAX_DEPTH:
            raise _Bad(ParseError(INVALID_VALUE, "arvore de chaves profunda demais (ciclo?)", HBIN_BASE + off, "regf"))
        c = self.cell(off)
        if c[:2] != b"nk" or len(c) < 0x4C:
            raise _Bad(ParseError(INVALID_VALUE, "celula nk esperada", HBIN_BASE + off, "regf"))
        flags, ts = struct.unpack_from("<HQ", c, 2)
        nsub = struct.unpack_from("<I", c, 0x14)[0]
        lsub = struct.unpack_from("<I", c, 0x1C)[0]
        nval, lval = struct.unpack_from("<II", c, 0x24)
        nlen = struct.unpack_from("<H", c, 0x48)[0]
        raw = c[0x4C:0x4C + nlen]
        name = raw.decode("latin-1") if flags & 0x20 else raw.decode("utf-16-le", "replace")
        k = RegKey(name, ts)
        if nval:
            vl = self.cell(lval)
            if 4 * nval > len(vl):
                raise _Bad(ParseError(TRUNCATED, "lista de valores truncada", HBIN_BASE + lval, "regf"))
            k.values = [self._value(struct.unpack_from("<I", vl, 4 * i)[0]) for i in range(nval)]
        if nsub:
            k.subkeys = [self._key(o, depth + 1) for o in self._subkey_offsets(lsub, 0)]
        return k


def parse_hive(b: bytes) -> Result[tuple[str, RegKey]]:
    if len(b) < 0x70:
        return err(TRUNCATED, f"hive com {len(b)} bytes", 0, "regf")
    if b[:4] != b"regf":
        return err(BAD_MAGIC, f"assinatura regf ausente: {b[:4]!r}", 0, "regf")
    h = Hive(b)
    try:
        return Ok((h.name, h._key(h.root_off, 0)))
    except _Bad as e:
        return Err(e.e)


def format_value(v: RegValue) -> str:
    d = v.decoded()
    if isinstance(d, int):
        return f"{v.type_name} {d:#x}"
    if isinstance(d, (str, list)):
        return f"{v.type_name} {d!r}"
    return f"{v.type_name} {v.data.hex(' ')}"


def dump_lines(name: str, root: RegKey) -> list[str]:
    out = [f"hive: nome interno {name!r}"]
    for depth, k in root.walk():
        pad = "  " * depth
        out.append(f"{pad}[{k.name}]  ({filetime(k.timestamp)})")
        for v in k.values:
            out.append(f"{pad}  {v.name} = {format_value(v)}")
    return out
