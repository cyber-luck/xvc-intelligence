"""Cenarios sinteticos obrigatorios (Secao 11 do plano) e PE minimo conhecido.

Os bytes esperados sao conhecidos de antemao; os testes verificam
exatamente o que foi recuperado, nunca mais.
"""
from __future__ import annotations

import gzip
import os
import struct
from pathlib import Path


def make_minimal_pe(*, machine: int = 0x8664, magic: int = 0x20B, characteristics: int = 0x0002,
                    subsystem: int = 3, sections: int = 3, text_size: int = 0x2000,
                    entry_rva: int | None = None) -> bytes:
    """PE sintetico com bytes de secao deterministas e conhecidos."""
    file_align, sect_align = 0x200, 0x1000
    if entry_rva is None:
        entry_rva = 0x1000
    pe_off = 0x80
    opt_size = 240 if magic == 0x20B else 224
    sect_off = pe_off + 24 + opt_size
    headers_size = (sect_off + 40 * sections + file_align - 1) // file_align * file_align
    names = [b".text", b".rdata", b".rsrc"]
    vs = [text_size, 0x400, 0x200]
    raw_ptrs = [headers_size]
    for i in range(1, sections):
        raw_ptrs.append(raw_ptrs[-1] + vs[i - 1])
    rvas = [sect_align]
    for i in range(1, sections):
        rvas.append((rvas[-1] + vs[i - 1] + sect_align - 1) // sect_align * sect_align)
    image_size = rvas[-1] + (vs[-1] + sect_align - 1) // sect_align * sect_align

    dos = bytearray(b"\x00" * 0x40)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", pe_off)
    dos_stub = bytes(dos) + b"\x00" * (pe_off - 0x40)

    coff = struct.pack("<HHIIIHH", machine, sections, 0x5C0F2A00, 0, 0, opt_size, characteristics)

    def opt_header() -> bytes:
        parts = [struct.pack("<HBB", magic, 10, 0), struct.pack("<III", text_size, 0x600, 0),
                 struct.pack("<I", entry_rva), struct.pack("<I", 0x1000)]
        if magic == 0x20B:
            parts.append(struct.pack("<Q", 0x140000000))
        else:
            parts.append(struct.pack("<II", 0, 0x1000000))
        parts.append(struct.pack("<II", sect_align, file_align))
        parts.append(struct.pack("<HHHHHH", 6, 0, 1, 0, 6, 0))
        parts.append(struct.pack("<I", 0))
        parts.append(struct.pack("<II", image_size, headers_size))
        parts.append(struct.pack("<I", 0))
        parts.append(struct.pack("<HH", subsystem, 0))
        if magic == 0x20B:
            parts += [struct.pack("<Q", 0x100000), struct.pack("<Q", 0x1000),
                      struct.pack("<Q", 0x100000), struct.pack("<Q", 0x1000)]
        else:
            parts += [struct.pack("<I", 0x100000), struct.pack("<I", 0x1000),
                      struct.pack("<I", 0x100000), struct.pack("<I", 0x1000)]
        parts.append(struct.pack("<II", 0, 16))
        parts.append(struct.pack("<II", 0, 0) * 16)
        return b"".join(parts)

    sect_table = b""
    for i in range(sections):
        sect_table += (names[i].ljust(8, b"\x00") + struct.pack("<IIII", vs[i], rvas[i], vs[i], raw_ptrs[i])
                       + struct.pack("<IIHHI", 0, 0, 0, 0, 0x60000020 if i == 0 else 0x40000040))
    head = dos_stub + b"PE\x00\x00" + coff + opt_header() + sect_table
    assert len(head) <= headers_size
    head += b"\x00" * (headers_size - len(head))

    def fill(tag: str, n: int) -> bytes:
        step = tag.encode() + b"0123456789"
        return (step * (n // len(step) + 1))[:n]

    total = raw_ptrs[-1] + vs[-1]
    body = bytearray(b"\x00" * total)
    body[0:len(head)] = head
    for i in range(sections):
        blob = fill(f"SEC{i}", vs[i])
        body[raw_ptrs[i]:raw_ptrs[i] + vs[i]] = blob
    return bytes(body)


def build_scenarios(root: Path) -> dict:
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    made: dict[str, dict] = {}

    def put(name: str, relpath: str, data: bytes, expect: dict) -> Path:
        d = root / name
        d.mkdir(parents=True, exist_ok=True)
        f = d / relpath
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(data)
        entry = made.setdefault(name, {"dir": str(d), "files": {}})
        meta = {"file": str(f), "size": len(data), **expect}
        entry["files"][relpath] = meta
        entry.update(meta)
        return f

    pe = make_minimal_pe()

    put("s01_pe_at_start", "container.bin", pe,
        {"pe_candidates": 1, "complete": True, "recovered_bytes": len(pe)})
    put("s02_pe_embedded", "container.bin", os.urandom(0x3000) + pe + os.urandom(0x1000),
        {"pe_candidates": 1, "complete": True, "pe_offset": 0x3000, "recovered_bytes": len(pe)})
    put("s03_pe_truncated", "cut.bin", pe[: len(pe) // 3],
        {"pe_candidates": 1, "complete": False, "truncated": True})
    put("s04_fake_mz", "fake.bin", b"MZ" + os.urandom(0x3E) + struct.pack("<I", 0x400) + b"\x00" * 0x600 + b"PE\x00\x00" + os.urandom(0x100),
        {"pe_candidates": 0})
    put("s05_random", "random.bin", os.urandom(1 << 20),
        {"pe_candidates": 0})
    comp = gzip.compress(pe)
    put("s06_compressed_pe", "stream.gz", comp,
        {"pe_candidates": 0, "decompressed_pe": 1, "recovered_bytes": len(pe)})
    put("s07_multi_container", "multi.bin", pe + os.urandom(0x100) + make_minimal_pe(machine=0x014C, magic=0x10B) + b"MZ" + os.urandom(0x200),
        {"pe_candidates": 2})
    dup = pe[:0x1800] + b"\x00" * 0x400 + pe[0x1C00:]
    put("s08_partial_dup", "a.bin", pe, {"pe_candidates": 1})
    put("s08_partial_dup", "b.bin", dup, {"pe_candidates": 1, "partial_overlap": True})
    put("s09_conflict_sources", "a.bin", pe, {"pe_candidates": 1})
    put("s09_conflict_sources", "b.bin", pe[:0x1000] + bytes(b ^ 0xFF for b in pe[0x1000:0x1800]) + pe[0x1800:],
        {"pe_candidates": 1, "conflicting_range": [0x1000, 0x1800]})
    put("s10_high_entropy_metadata", "blob.bin", os.urandom(0x8000),
        {"pe_candidates": 0, "note": "entropia alta sem PE; sem compressao valida"})
    big = make_minimal_pe(text_size=0x400000)
    big = big + os.urandom(0x200000)
    put("s11_bigger_than_memory", "big.bin", big,
        {"pe_candidates": 1, "complete": True, "streaming": True})
    put("s12_overwrite_guard", "target.bin", pe, {"pe_candidates": 1})
    put("s13_interrupt_resume", "data.bin", pe + os.urandom(0x100),
        {"pe_candidates": 1, "resume": True})
    put("s13_interrupt_resume", "extra1.bin", os.urandom(0x2000), {"pe_candidates": 0})
    put("s13_interrupt_resume", "extra2.bin", os.urandom(0x2000), {"pe_candidates": 0})
    put("s14_roundtrip", "original.bin", pe, {"pe_candidates": 1, "complete": True})
    put("s14_roundtrip", "frag_full.bin", pe, {"pe_candidates": 1})
    put("s14_roundtrip", "frag_part.bin", os.urandom(0x500) + pe[0x800:],
        {"pe_candidates": 0, "partial_source": True, "orig_start": 0x800, "frag_offset": 0x500})

    manifest = {"schema": "alpha_recovery.scenarios/1", "root": str(root), "scenarios": made,
                "original_pe_sha256": __import__("hashlib").sha256(pe).hexdigest(),
                "original_pe_size": len(pe)}
    (root / "expected.json").write_text(__import__("json").dumps(manifest, indent=2), encoding="utf-8")
    return manifest
