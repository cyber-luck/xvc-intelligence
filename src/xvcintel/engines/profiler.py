"""Perfil binario dos arquivos (classificacao do xvc_probe.py original, inalterada).

Entropia alta NAO prova criptografia: o estado OPAQUE so diz que a amostra nao
tem assinatura conhecida e tem entropia >= 7.9.
"""
from __future__ import annotations

from ..core.util import PAGE, entropy
from ..formats.layout import DRIVE
from ..formats.pe import legacy_pe_header
from ..formats.xvcinfo import NO_KEY
from .package import Package

SAMPLE_SIZE = 0x10000
MIN_ENTROPY_SAMPLE = 0x1000
OPAQUE_ENTROPY = 7.9
STRUCTURED_ENTROPY = 7.0
SIGNATURES = [
    (b"MZ", "MZ"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"regf", "registry hive"),
    (b"\xef\xbb\xbf<?xml", "XML"),
    (b"<?xml", "XML"),
    (b"mrm_pri", "PRI"),
]


def classify(sample: bytes, size: int) -> tuple[str | None, float | None, str]:
    sig = next((name for magic, name in SIGNATURES if sample.startswith(magic)), None)
    if sig == "MZ":
        pe = legacy_pe_header(sample)
        if pe and pe["pe_signature"]:
            sig = "PE"
    h = entropy(sample) if sample else None
    if size == 0:
        state = "EMPTY"
    elif sig:
        state = "PLAINTEXT_SIGNATURE"
    elif len(sample) < MIN_ENTROPY_SAMPLE:
        state = "TOO_SMALL"
    elif h >= OPAQUE_ENTROPY:
        state = "OPAQUE"
    elif h < STRUCTURED_ENTROPY:
        state = "STRUCTURED"
    else:
        state = "MIXED"
    return sig, h, state


def encryption_status(key_id: int, state: str) -> str:
    if key_id == NO_KEY:
        return "NO_KEY_PER_REGION"
    if state == "OPAQUE":
        return "LIKELY_ENCRYPTED_UNVERIFIED"
    if state == "PLAINTEXT_SIGNATURE":
        return "INCONSISTENT_PLAINTEXT_WITH_KEY"
    return "UNKNOWN"


def profile_files(pkg: Package) -> list[dict]:
    drive_off = pkg.layout.get(DRIVE).offset
    files = []
    for r in pkg.rows:
        reg = r.region
        n = min(SAMPLE_SIZE, r.size)
        sample = pkg.src.read_at(r.start, n)
        sig, h, state = classify(sample, r.size)
        key_id = reg.key_id if reg else None
        files.append({
            "filename": r.name,
            "segment_index": r.index,
            "region_id": f"0x{reg.id:X}" if reg else None,
            "key_id": key_id,
            "relative_page": f"0x{(r.start - drive_off) // PAGE:X}",
            "absolute_offset": f"0x{r.start:X}",
            "end_offset_exclusive": f"0x{r.end:X}",
            "size": r.size,
            "sample_size": len(sample),
            "signature": sig,
            "pe_signature_found": sig == "PE",
            "pe": legacy_pe_header(sample),
            "entropy_64kb": round(h, 3) if h is not None else None,
            "content_state": state,
            "encryption_status": encryption_status(key_id, state) if key_id is not None else "UNKNOWN",
        })
    return files


def classification_rules() -> dict:
    return {
        "sample": f"primeiros {SAMPLE_SIZE} bytes de cada arquivo",
        "signatures": sorted({name for _, name in SIGNATURES} | {"PE"}),
        "PE": "MZ com e_lfanew valido e PE\\0\\0; so 'MZ' quando falta o PE\\0\\0",
        "OPAQUE": f"sem assinatura, amostra >= {MIN_ENTROPY_SAMPLE} bytes, entropia >= {OPAQUE_ENTROPY}",
        "STRUCTURED": f"sem assinatura, entropia < {STRUCTURED_ENTROPY}",
        "MIXED": "entre STRUCTURED e OPAQUE",
        "TOO_SMALL": f"amostra < {MIN_ENTROPY_SAMPLE} bytes, sem assinatura",
        "LIKELY_ENCRYPTED_UNVERIFIED": "regiao com KeyId e conteudo OPAQUE; algoritmo nao verificado",
        "NO_KEY_PER_REGION": "regiao com KeyId 0xFFFF",
    }
