"""Correspondencia por blocos entre regioes de dois arquivos (streaming).

Compara SHA-256 por bloco alinhado entre (arquivoA, offsetA, lenA) e
(arquivoB, offsetB, lenB). Nunca afirma equivalencia de plaintext a partir
de igualdade de ciphertext: a igualdade demonstrada e dos bytes gravados.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from _bootstrap import entropy

BLOCK = 1 << 20


def block_match(path_a: Path, off_a: int, path_b: Path, off_b: int, length: int, *, block: int = BLOCK) -> dict:
    total = 0
    equal_blocks = 0
    intervals: list[tuple[int, int]] = []
    cur_start: int | None = None
    first_divergence = None
    mismatch_samples: list[dict] = []
    with open(path_a, "rb") as fa, open(path_b, "rb") as fb:
        pos = 0
        while pos < length:
            n = min(block, length - pos)
            fa.seek(off_a + pos)
            fb.seek(off_b + pos)
            ba = fa.read(n)
            bb = fb.read(n)
            if not ba and not bb:
                break
            n = min(len(ba), len(bb), n)
            if n == 0:
                break
            same = ba[:n] == bb[:n]
            total += 1
            if same:
                equal_blocks += 1
                if cur_start is None:
                    cur_start = pos
            else:
                if cur_start is not None:
                    intervals.append((cur_start, pos))
                    cur_start = None
                if first_divergence is None:
                    first_divergence = pos
                if len(mismatch_samples) < 8:
                    mismatch_samples.append({
                        "relative_offset": pos,
                        "sha256_a": hashlib.sha256(ba[:n]).hexdigest(),
                        "sha256_b": hashlib.sha256(bb[:n]).hexdigest(),
                    })
            pos += n
    if cur_start is not None:
        intervals.append((cur_start, pos))
    return {
        "bytes_compared": pos if pos else 0,
        "blocks_compared": total,
        "blocks_equal": equal_blocks,
        "pct_equal_blocks": round(100.0 * equal_blocks / total, 4) if total else None,
        "equal_intervals": [{"start": s, "end": e} for s, e in intervals],
        "first_divergence_relative": first_divergence,
        "mismatch_block_samples": mismatch_samples,
        "interpretation": "igualdade de bytes gravados entre as duas fontes; nao e declara sobre plaintext quando a regiao e cifrada",
    }


def describe_region(path: Path, offset: int, length: int, *, window: int = 65536) -> dict:
    with open(path, "rb") as fh:
        fh.seek(offset)
        data = fh.read(min(window, length))
    return {
        "offset": offset, "length": length, "sampled_bytes": len(data),
        "entropy": round(entropy(data), 5) if data else None,
        "all_zero": bool(data) and data.count(0) == len(data),
        "head_hex": data[:32].hex(),
    }
