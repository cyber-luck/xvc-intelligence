"""Fase 7: validacao independente de candidatos PE e classificacao final.

Um PE parseavel nao significa que e o executavel original nem que pode
funcionar no Windows. Binarios reconstruidos nunca sao executados.
"""
from __future__ import annotations

import struct
from pathlib import Path

from xvcintel.core.result import Ok
from xvcintel.formats.pe import parse_pe

MACHINES_OK = {0x014C, 0x8664, 0xAA64, 0x01C4}


def validate_pe(path: Path, *, expect_machine: int | None = None, expect_magic: int | None = None) -> dict:
    path = Path(path)
    size = path.stat().st_size
    with open(path, "rb") as fh:
        data = fh.read(min(size, 64 << 20))
    checks: list[dict] = []

    def chk(cid: str, ok: bool, detail: str = "") -> None:
        checks.append({"id": cid, "ok": bool(ok), "detail": detail})

    chk("MZ", data[:2] == b"MZ")
    lfanew = struct.unpack_from("<I", data, 0x3C)[0] if len(data) >= 0x40 else -1
    chk("e_lfanew_bounds", 0x40 <= lfanew <= len(data) - 24, f"0x{lfanew:X}")
    chk("PE_signature", 0 <= lfanew and data[lfanew:lfanew + 4] == b"PE\x00\x00")
    if not all(c["ok"] for c in checks):
        return {"path": str(path), "valid": False, "checks": checks, "classification_input": None}
    machine, nsec = struct.unpack_from("<HH", data, lfanew + 4)
    opt_size = struct.unpack_from("<H", data, lfanew + 20)[0]
    chk("machine_known", machine in MACHINES_OK, f"0x{machine:04X}")
    if expect_machine is not None:
        chk("machine_expected", machine == expect_machine, f"0x{machine:04X} vs 0x{expect_machine:04X}")
    chk("sections_range", 1 <= nsec <= 96, str(nsec))
    opt_off = lfanew + 24
    magic = struct.unpack_from("<H", data, opt_off)[0]
    chk("optional_magic", magic in (0x10B, 0x20B), f"0x{magic:04X}")
    if expect_magic is not None:
        chk("magic_expected", magic == expect_magic, f"0x{magic:04X}")
    sect_off = opt_off + opt_size
    chk("section_table_in_file", sect_off + 40 * nsec <= len(data))
    file_align = struct.unpack_from("<I", data, opt_off + 36)[0]
    sect_align = struct.unpack_from("<I", data, opt_off + 32)[0]
    chk("alignments_pow2", file_align and not (file_align & (file_align - 1)) and sect_align and not (sect_align & (sect_align - 1)),
        f"file=0x{file_align:X} sect=0x{sect_align:X}")
    image_size = struct.unpack_from("<I", data, opt_off + 56)[0]
    chk("image_size_positive", 0 < image_size < (1 << 32), f"0x{image_size:X}")
    max_extent = 0
    for i in range(nsec):
        s = sect_off + i * 40
        raw_size, raw_off = struct.unpack_from("<II", data, s + 16)
        if raw_size:
            chk_s = raw_off + raw_size <= size
            checks.append({"id": f"section_{i}_in_file", "ok": bool(chk_s),
                           "detail": f"raw 0x{raw_off:X}+0x{raw_size:X} vs {size}"})
            max_extent = max(max_extent, raw_off + raw_size)
    r = parse_pe(data, deep=True)
    if isinstance(r, Ok):
        pe = r.value
        chk("xvcintel_deep_parse", True,
            f"machine=0x{pe.machine:04x} sections={len(pe.sections)} imports={len(pe.imports or [])} debug={len(pe.debug or [])}")
        chk("rva_offset_map_consistent", not pe.problems, "; ".join(pe.problems[:3]))
    else:
        chk("xvcintel_deep_parse", False, str(r.error))
    pefile_note = None
    try:
        import pefile as _pefile
        pf = _pefile.PE(str(path), fast_load=True)
        try:
            pefile_note = {"machine_match": pf.FILE_HEADER.Machine == machine,
                           "sections_match": pf.FILE_HEADER.NumberOfSections == nsec}
        finally:
            pf.close()  # pefile mantem um mmap aberto; no Windows isso trava o arquivo
        chk("pefile_cross_check", bool(pefile_note["machine_match"] and pefile_note["sections_match"]))
    except ImportError:
        pefile_note = "pefile nao instalado; comparacao externa nao executada"
    truncated = max_extent > size
    return {
        "path": str(path), "size": size, "valid": all(c["ok"] for c in checks),
        "truncated": truncated, "checks": checks, "pefile_note": pefile_note,
        "note": "PE parseavel nao e o executavel original nem garantia de funcionamento; binarios reconstruidos nao sao executados",
    }


CLASSIFICATIONS = ("COMPLETE_VERIFIED", "COMPLETE_UNVERIFIED", "PARTIAL_RECOVERED",
                   "STRUCTURE_ONLY", "METADATA_ONLY", "NO_RECOVERABLE_PE")


def classify_recovery(coverage: dict, *, validated_complete: bool, metadata_recovered: bool,
                      identity_verified: bool | None = None) -> str:
    """Classificacao final com separacao rigida entre recuperacao e identidade.

    COMPLETE_VERIFIED exige TODOS: bytes 100% com prova, PE valido, tamanho
    exato e IDENTIDADE VERIFICADA (evidencia confiavel de correspondencia
    exata ao alvo). Sem identidade verificada, a classificacao maxima para
    um arquivo completo e COMPLETE_UNVERIFIED.
    """
    by = coverage.get("by_class_bytes", {})
    total = coverage.get("total_bytes", 0)
    exact = by.get("EXACT_RECOVERED", 0) + by.get("MATCHED_COPY", 0)
    inferred = by.get("STRUCTURAL_INFERENCE", 0)
    if validated_complete and total and exact == total:
        if identity_verified is None:
            return "COMPLETE_VERIFIED"
        return "COMPLETE_VERIFIED" if identity_verified else "COMPLETE_UNVERIFIED"
    if exact > 0:
        return "PARTIAL_RECOVERED"
    if inferred > 0:
        return "STRUCTURE_ONLY"
    return "METADATA_ONLY" if metadata_recovered else "NO_RECOVERABLE_PE"
