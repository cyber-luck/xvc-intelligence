"""Fase 3B: recuperacao de dados comprimidos, com limites rigorosos.

So tenta descompressao onde ha magic de fluxo conhecido; entropia alta
jamais e tratada como compressao. Limites de entrada, saida e numero de
fluxos; codecs opcionais (zstd/lz4) dependem de dependencia instalada.
"""
from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from _bootstrap import load_bin_pe_recovery, write_exclusive

_bpr = load_bin_pe_recovery()

CODECS = ("gzip", "xz", "bzip2", "zstd", "lz4", "zlib")


def scan_compressed(path: Path, *, out_dir: Path | None = None, max_scan: int = 0,
                    max_streams: int = 64, max_input: int = 64 << 20, max_output: int = 256 << 20,
                    deep_zlib: bool = False) -> dict:
    path = Path(path)
    size = path.stat().st_size
    cap = size if max_scan == 0 else min(size, max_scan)
    patterns = list(_bpr.MAGICS.items())
    if deep_zlib:
        patterns += [("zlib", bytes((0x78, v))) for v in (0x01, 0x5E, 0x9C, 0xDA)]
    found: dict[str, list[int]] = {name: [] for name, _ in patterns}
    with open(path, "rb") as fh:
        pos, step = 0, 4 << 20
        overlap = 8
        while pos < cap:
            chunk = fh.read(min(step + overlap, cap - pos))
            if not chunk:
                break
            owned = min(step, cap - pos)
            for name, sig in patterns:
                idx = 0
                while len(found[name]) < 4096:
                    idx = chunk.find(sig, idx, owned + len(sig) - 1)
                    if idx < 0:
                        break
                    found[name].append(pos + idx)
                    idx += 1
            pos += owned
            fh.seek(pos)
    streams = []
    extractions = []
    attempted = 0
    for codec in CODECS:
        for off in found.get(codec, []):
            if attempted >= max_streams:
                break
            attempted += 1
            blob, error = _bpr.decompress_limited(path, off, codec, max_input, max_output)
            entry = {"offset": off, "codec": codec, "status": error or "decompressed",
                     "decoded_bytes": len(blob) if blob is not None else 0}
            if blob is not None:
                entry["decoded_sha256"] = hashlib.sha256(blob).hexdigest()
                hits = _bpr.analyse_buffer_pe(blob, 512 << 20)
                entry["pe_candidates"] = hits
                for i, pe in enumerate(hits):
                    if out_dir is None or (pe["truncated"] and not True):
                        continue
                    extent = min(pe["minimum_file_extent"], len(blob) - pe["offset"])
                    data = blob[pe["offset"]:pe["offset"] + extent]
                    suffix = ".partial.bin" if pe["truncated"] else pe.get("suggested_extension", ".bin")
                    dest = write_exclusive(out_dir / f"{codec}_0x{off:012x}_pe{i:02d}{suffix}", data)
                    extractions.append({
                        "name": dest.name, "bytes": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "source": str(path), "source_offset": off, "codec": codec,
                        "decoded_offset": pe["offset"],
                        "truncated": pe["truncated"],
                        "transform": f"decompress:{codec}",
                    })
            streams.append(entry)
    zip_entries = []
    if cap >= 4 and zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as archive:
                for member in archive.infolist()[:max_streams]:
                    if member.is_dir():
                        continue
                    ent = {"codec": "zip", "member": member.filename, "status": "listed_only",
                           "compressed_size": member.compress_size, "file_size": member.file_size}
                    zip_entries.append(ent)
        except (OSError, zipfile.BadZipFile) as exc:
            zip_entries.append({"codec": "zip", "status": f"invalid_archive:{type(exc).__name__}"})
    return {
        "source": str(path), "size": size, "bytes_scanned": cap,
        "streams_attempted": attempted, "streams": streams, "zip_members": zip_entries,
        "extractions": extractions,
        "limitations": ["magics sem descompressao bem-sucedida nao sao dados comprimidos",
                        "entropia alta nunca e tratada como compressao"],
    }
