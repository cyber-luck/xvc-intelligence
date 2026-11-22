"""Fase 3A: PE carving com validacao estrita.

Um candidato so e aceito com MZ + e_lfanew valido + PE\\0\\0 + COFF +
Optional Header + Section Table coerentes com os limites fisicos
(regras herdadas de recovery/bin_pe_recovery/scripts/bin_pe_recovery.py, reutilizadas por import).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from _bootstrap import load_bin_pe_recovery, read_head, write_exclusive

_bpr = load_bin_pe_recovery()


def pe_summary(path: Path, offset: int = 0) -> dict | None:
    """Resumo estrito do PE em `offset` (None se nao for PE valido)."""
    return _bpr.parse_pe_file(Path(path), offset, _bpr.DEFAULT_MAX_PE_SIZE if hasattr(_bpr, "DEFAULT_MAX_PE_SIZE") else 512 << 20)


def carve_file(path: Path, *, out_dir: Path | None = None, extract_partial: bool = False,
               max_scan: int = 0, max_mz: int = 200000, extract_max_bytes: int = 512 << 20) -> dict:
    """Varre MZ, valida PE em cada hit e extrai candidatos com gravacao exclusiva."""
    path = Path(path)
    size = path.stat().st_size
    cap = size if max_scan == 0 else min(size, max_scan)
    found, limit_hit = _bpr.scan_offsets(path, cap, max_mz, 64, False)
    candidates = []
    extractions = []
    for off in found.get("mz", []):
        pe = pe_summary(path, off)
        if not pe:
            continue
        pe["origin"] = {"kind": "direct_bytes", "file": str(path), "offset": off}
        candidates.append(pe)
        if out_dir is None or (pe["truncated"] and not extract_partial):
            continue
        extent = min(pe["minimum_file_extent"], pe["available_bytes"])
        if extent > extract_max_bytes:
            pe["extraction_skipped"] = "extent_above_limit"
            continue
        blob = bytearray()
        with open(path, "rb") as fh:
            fh.seek(off)
            remaining = extent
            while remaining > 0:
                b = fh.read(min(4 << 20, remaining))
                if not b:
                    break
                blob.extend(b)
                remaining -= len(b)
        suffix = ".partial.bin" if pe["truncated"] else pe.get("suggested_extension", ".bin")
        name = f"direct_{path.stem[:24]}_0x{off:012x}{suffix}"
        dest = write_exclusive(out_dir / name, bytes(blob))
        extractions.append({
            "name": dest.name, "bytes": len(blob),
            "sha256": hashlib.sha256(bytes(blob)).hexdigest(),
            "source": str(path), "source_offset": off,
            "truncated": pe["truncated"], "transform": "identity_carve",
        })
    return {
        "source": str(path), "size": size, "bytes_scanned": cap,
        "entire_file_scanned": cap == size,
        "raw_mz_hits": len(found.get("mz", [])),
        "max_candidates_reached": limit_hit,
        "pe_candidates": candidates,
        "extractions": extractions,
    }
