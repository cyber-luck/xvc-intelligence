"""Fase 1: inventario binario profundo, recursivo, com cache por arquivo.

Por arquivo: formato por conteudo, tamanho, SHA-256 (completo ou
head+tail rotulado como parcial), entropia por janelas, assinaturas e
contagem de magics de compressao. Nada e classificado como PE so por 'MZ':
a validacao estrita fica em pe_carver.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from _bootstrap import (
    DEFAULT_CHUNK, MAX_SINGLE_READ, entropy, iter_file, read_head, utc_now,
)

HASH_FULL_CAP = 8 << 30
BIG_WINDOW = 16 << 20
ENTROPY_WINDOW = 64 * 1024
ENTROPY_SAMPLES = 12
ENTROPY_FILE_CAP = 16 << 30
SIGNATURE_SCAN_CAP = 1 << 30

HEAD_SIGNATURES = [
    (b"MZ", "MZ"),
    (b"regf", "REGF"),
    (b"PK\x03\x04", "ZIP"),
    (b"\x1f\x8b\x08", "GZIP"),
    (b"\xfd7zXZ\x00", "XZ"),
    (b"\x28\xb5\x2f\xfd", "ZSTD"),
    (b"\x04\x22\x4d\x18", "LZ4"),
    (b"BZh", "BZIP2"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"RPF7", "RPF7"),
    (b"<?xml", "XML"),
    (b"\x00\x01\x00\x00", "ICO"),
]
OFFSET_SIGNATURES = [(0x200, b"msft-xvd", "MSFT-XVD"), (0x200, b"MSFT-XVC", "MSFT-XVC")]
COMPRESSED_MAGICS = [b"\x1f\x8b\x08", b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd", b"\x04\x22\x4d\x18", b"BZh"]

EXCLUDE_DIRS = {".git", "__pycache__", ".pytest_cache", ".cache", "$RECYCLE.BIN", "System Volume Information"}


def _sha_head_tail(path: Path, window: int) -> dict:
    size = os.path.getsize(path)
    head = read_head(path, window)
    h_head = hashlib.sha256(head).hexdigest()
    if size <= window:
        return {"mode": "head_only_unavoidably_partial", "sha256_head": h_head, "head_bytes": len(head)}
    with open(path, "rb") as fh:
        fh.seek(max(0, size - window))
        tail = fh.read(window)
    return {
        "mode": "head_tail_partial",
        "sha256_head": h_head,
        "sha256_tail": hashlib.sha256(tail).hexdigest(),
        "window_bytes": window,
    }


def _entropy_profile(path: Path, size: int) -> dict:
    window = ENTROPY_WINDOW
    if size <= 0:
        return {"samples": [], "mean": None, "min": None, "max": None}
    one = min(size, window)
    offsets = {0, max(0, size - one)}
    n = min(ENTROPY_SAMPLES, max(1, size // one))
    if size > one:
        for i in range(1, max(1, n)):
            offsets.add(min(size - one, (size - one) * i // max(1, n - 1)))
    vals = []
    with open(path, "rb") as fh:
        for off in sorted(offsets):
            fh.seek(off)
            data = fh.read(one)
            if data:
                vals.append({"offset": off, "bytes": len(data), "entropy": round(entropy(data), 5)})
    es = [v["entropy"] for v in vals]
    return {
        "samples": vals,
        "mean": round(sum(es) / len(es), 5) if es else None,
        "min": round(min(es), 5) if es else None,
        "max": round(max(es), 5) if es else None,
    }


def _detect_format(path: Path, size: int) -> dict:
    head = read_head(path, 0x400)
    kinds = []
    for sig, name in HEAD_SIGNATURES:
        if head.startswith(sig):
            kinds.append(name)
    for off, sig, name in OFFSET_SIGNATURES:
        if len(head) >= off + len(sig) and head[off:off + len(sig)] == sig:
            kinds.append(name)
    if head.startswith(b"MZ") and len(head) >= 0x40:
        lfanew = int.from_bytes(head[0x3c:0x40], "little")
        if 0x40 <= lfanew <= len(head) - 4 and head[lfanew:lfanew + 4] == b"PE\x00\x00":
            machine = int.from_bytes(head[lfanew + 4:lfanew + 6], "little")
            nsec = int.from_bytes(head[lfanew + 6:lfanew + 8], "little")
            opt = int.from_bytes(head[lfanew + 20:lfanew + 22], "little")
            magic = int.from_bytes(head[lfanew + 24:lfanew + 26], "little") if opt >= 26 else None
            kinds.append(f"PE(machine=0x{machine:04x},sections={nsec},magic=0x{magic:04x})" if magic else "PE")
    elif head.startswith(b"MZ"):
        lfanew = int.from_bytes(head[0x3c:0x40], "little") if len(head) >= 0x40 else -1
        kinds.append(f"MZ_sem_PE_valido(lfanew=0x{max(lfanew, 0):x})")
    if head.startswith(b"regf"):
        kinds.append("hive_regf")
    if kinds and kinds[0] == "XML":
        tag = head.split(b">", 1)[0][:120].decode("ascii", "replace")
        kinds.append(f"xml_root~{tag.strip()[-40:]}")
    return {"kinds": kinds, "primary": kinds[0] if kinds else "unknown_bin"}


def _count_compressed_magics(path: Path, cap: int) -> dict:
    counts = {m.hex(): 0 for m in COMPRESSED_MAGICS}
    scanned = 0
    with open(path, "rb") as fh:
        overlap = 8
        pos = 0
        step = 8 << 20
        while pos < cap:
            fh.seek(pos)
            chunk = fh.read(min(step + overlap, cap - pos))
            if not chunk:
                break
            owned = min(step, cap - pos)
            for m in COMPRESSED_MAGICS:
                counts[m.hex()] += chunk[:owned + len(m) - 1].count(m)
            pos += owned
            scanned += owned
    return {"scanned_bytes": scanned, "magic_counts": counts}


def _mz_scan_hit_offsets(path: Path, cap: int, max_hits: int = 64) -> dict:
    hits: list[int] = []
    scanned = 0
    limit_hit = False
    with open(path, "rb") as fh:
        pos = 0
        step = 8 << 20
        overlap = 1
        while pos < cap:
            fh.seek(pos)
            chunk = fh.read(min(step + overlap, cap - pos))
            if not chunk:
                break
            owned = min(step, cap - pos)
            idx = 0
            while True:
                idx = chunk.find(b"MZ", idx, owned + 1)
                if idx < 0:
                    break
                if len(hits) < max_hits:
                    hits.append(pos + idx)
                else:
                    limit_hit = True
                    break
                idx += 2
            pos += owned
            scanned += owned
    return {"scanned_bytes": scanned, "hit_offsets": hits, "limit_reached": limit_hit}


def scan_file(path: Path, *, hash_full_cap: int = HASH_FULL_CAP,
              signature_cap: int = SIGNATURE_SCAN_CAP, deep: bool = True) -> dict:
    path = Path(path)
    size = os.path.getsize(path)
    st = os.stat(path)
    rec: dict = {
        "path": str(path.resolve()),
        "name": path.name,
        "size": size,
        "mtime_utc": st.st_mtime,
    }
    if size <= hash_full_cap:
        h = hashlib.sha256()
        for b in iter_file(path, 0, size):
            h.update(b)
        rec["sha256"] = h.hexdigest()
        rec["sha256_mode"] = "full"
    else:
        rec["sha256_partial"] = _sha_head_tail(path, BIG_WINDOW)
        rec["sha256_mode"] = "head_tail_partial_rotulado"
    fmt = _detect_format(path, size)
    rec["format"] = fmt["primary"]
    rec["format_kinds"] = fmt["kinds"]
    if deep:
        rec["entropy"] = _entropy_profile(path, size)
        if size <= signature_cap:
            rec["mz_scan"] = _mz_scan_hit_offsets(path, size)
            rec["compressed_magic_counts"] = _count_compressed_magics(path, size)
        else:
            rec["mz_scan"] = _scan_capped(path, size, signature_cap)
            rec["compressed_magic_counts"] = _count_compressed_magics(path, signature_cap)
    rec["high_entropy_note"] = (
        "entropia alta nao e prova de criptografia; ver regras do projeto"
        if (rec.get("entropy") or {}).get("max", 0) > 7.9 else ""
    )
    return rec


def _scan_capped(path: Path, size: int, cap: int) -> dict:
    return {**_mz_scan_hit_offsets(path, cap), "cap_bytes": cap, "note": "varredura limitada; ausencia nao e conclusao do arquivo inteiro"}


def scan_tree(roots, *, excludes: set[str] | None = None, cache_path: Path | None = None,
              progress=None, stop_after: int | None = None) -> dict:
    """Varredura recursiva com cache (retomavel) chaveado por (caminho, tamanho, mtime)."""
    excludes = EXCLUDE_DIRS | (excludes or set())
    cache: dict = {}
    if cache_path and Path(cache_path).is_file():
        try:
            cache = json.loads(Path(cache_path).read_text(encoding="utf-8"))
        except (ValueError, OSError):
            cache = {}
    records: list[dict] = []
    files: list[Path] = []
    for root in roots:
        root = Path(root)
        if root.is_file():
            files.append(root)
        elif root.is_dir():
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = sorted(d for d in dirnames if d not in excludes)
                for fn in sorted(filenames):
                    files.append(Path(dirpath) / fn)
    files.sort(key=lambda p: str(p).lower())
    scanned = 0
    cached = 0
    interrupted = False
    for i, f in enumerate(files):
        if stop_after is not None and scanned >= stop_after:
            _save_cache(cache_path, cache)
            interrupted = True
            break
        key = str(f.resolve()).lower()
        try:
            st = os.stat(f)
        except OSError:
            continue
        cval = cache.get(key)
        if cval and cval.get("size") == st.st_size and abs(cval.get("mtime_utc", 0) - st.st_mtime) < 1:
            records.append(cval)
            cached += 1
        else:
            rec = scan_file(f)
            cache[key] = rec
            records.append(rec)
            scanned += 1
        if progress:
            progress(i + 1, len(files), f)
    _save_cache(cache_path, cache)
    if interrupted:
        raise StopScan(f"varredura interrompida apos {scanned} arquivos novos (cache preservado em {cache_path})")
    by_format: dict[str, int] = {}
    for r in records:
        by_format[r["format"]] = by_format.get(r["format"], 0) + 1
    inventory = {
        "schema": "alpha_recovery.binary_inventory/1",
        "generated_utc": utc_now(),
        "roots": [str(Path(r).resolve()) for r in roots],
        "policy": {
            "sha256_full_under_bytes": HASH_FULL_CAP,
            "arquivos_maiores": "sha256 head+tail rotulado como parcial, nunca apresentado como hash completo",
            "entropia": f"amostragem de ate {ENTROPY_SAMPLES} janelas de 64 KB por arquivo, sempre executada",
            "assinaturas_max_bytes": SIGNATURE_SCAN_CAP,
            "nota_entropia": "entropia alta nao e prova de criptografia",
        },
        "summary": {
            "files": len(records),
            "bytes": sum(r["size"] for r in records),
            "by_format": dict(sorted(by_format.items())),
            "from_cache": cached,
            "fresh_scans": scanned,
        },
        "files": records,
    }
    return inventory


class StopScan(Exception):
    """Varredura interrompida intencionalmente; o cache foi preservado."""


def _save_cache(cache_path: Path | None, cache: dict) -> None:
    if not cache_path:
        return
    import json as _json
    Path(cache_path).parent.mkdir(parents=True, exist_ok=True)
    Path(cache_path).write_text(_json.dumps(cache, indent=2, sort_keys=True), encoding="utf-8")


def inventory_summary_lines(inv: dict) -> list[str]:
    s = inv["summary"]
    out = [f"arquivos: {s['files']}  bytes: {s['bytes']:,}",
           f"cache: {s['from_cache']}  novas varreduras: {s['fresh_scans']}"]
    for k, v in s["by_format"].items():
        out.append(f"  {k}: {v}")
    return out
