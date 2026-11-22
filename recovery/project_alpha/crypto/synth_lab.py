"""Laboratorio de engenharia reversa AS CEGAS em tres estados independentes.

A. GERADOR INDEPENDENTE cria um PE32+ conhecido, uma ODK, uma CIK,
   metadados XVC-like (regiao, VDUID, folhas com data_unit, catalogo) e o
   ciphertext. As chaves e a referencia ficam SELADAS fora do alcance do
   analisador.
B. ENGENHARIA REVERSA SEM CHAVES: o analisador recebe apenas o conteiner e
   os metadados publicos e deve declarar corretamente o que pode e o que nao
   pode recuperar (nada e apresentado como recuperavel sem prova).
C. REVELACAO DAS CHAVES SINTETICAS: descriptografia, comparacao byte a byte
   com a referencia original (arbitro), validacao PE, hashes, catalogo e
   proveniencia - incluindo a demonstracao das duas ressalvas:
   round-trip com chave errada continua igual (nao autentica) e data_unit
   com descontinuidade continua sendo lido por folha (nunca extrapolado).

Nenhuma chave real e usada; tudo aqui e sintetico e descartavel.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from _bootstrap import write_json_exclusive
from validation.recovery_tests import make_minimal_pe
from .xvc_xts_pipeline import (
    PAGE, build_seed, cik_halves, load_xts_engine, stream_decrypt,
)

TARGET_NAME = "synthetic_scarlett_master.exe"
REGION_ID = 0x3E9
ENTRY_SIZE = 0x18


def _rs(catalog_shell: bytes, needles: list[bytes]) -> bytes:
    out = bytearray(catalog_shell)
    lfanew = struct.unpack_from("<I", out, 0x3C)[0]
    opt_size = struct.unpack_from("<H", out, lfanew + 20)[0]
    sect_off = lfanew + 24 + opt_size
    raw_ptr = struct.unpack_from("<I", out, sect_off + 20)[0]
    pos = raw_ptr + 0x100
    for n in needles:
        out[pos:pos + len(n)] = n
        pos += len(n) + 16
    return bytes(out)


def generate_lab(out_dir: Path, *, seed: int = 20261122,
                 data_unit_jump_at: int | None = None,
                 data_unit_jump_delta: int = 0x1000) -> dict:
    """Estado A: gerador independente. Sela chaves e referencia."""
    rng = _Rng(seed)
    out_dir = Path(out_dir)
    cont = out_dir / "container"
    sealed = out_dir / "sealed"
    cont.mkdir(parents=True, exist_ok=True)
    sealed.mkdir(parents=True, exist_ok=True)

    pe = make_minimal_pe(text_size=0x8000) + rng.rand_bytes(0x400)
    odk = rng.rand_bytes(32)
    cik = rng.rand_bytes(32)
    vduid8 = rng.rand_bytes(8)
    region_id = REGION_ID

    n_full = len(pe) // PAGE
    partial = len(pe) % PAGE
    pages = n_full + (1 if partial else 0)
    data_units = []
    du = rng.int(0xE0000000)
    for i in range(pages):
        data_units.append(du)
        du += 1
    jumps = []
    if data_unit_jump_at is not None and 0 < data_unit_jump_at < pages:
        for i in range(data_unit_jump_at, pages):
            data_units[i] += data_unit_jump_delta
        jumps.append({"page": data_unit_jump_at, "delta": data_unit_jump_delta})

    xts = load_xts_engine()
    data_key, tweak_key = cik_halves(cik)
    cipher_pages = []
    entries = []
    for i in range(pages):
        unit = pe[i * PAGE:(i + 1) * PAGE] if i < pages - 1 or not partial else pe[i * PAGE:]
        seed_b = build_seed(data_units[i], region_id, vduid8)
        cipher_pages.append(xts.transform_data_unit(seed_b, data_key, tweak_key, unit, encrypt=True))
        entries.append(hashlib.sha256(cipher_pages[-1]).digest()[:0x14] + struct.pack("<I", data_units[i]))
    slack = rng.rand_bytes(0xC00)
    cipher_all = b"".join(cipher_pages)
    (cont / "container.bin").write_bytes(cipher_all + slack)
    (cont / "hash_entries.bin").write_bytes(b"".join(entries))

    sha256_pe = hashlib.sha256(pe).hexdigest()
    sha1_pe = hashlib.sha1(pe).hexdigest()
    catalog_shell = make_minimal_pe(subsystem=17)
    catalog = _rs(catalog_shell, [bytes.fromhex(sha256_pe), sha1_pe.encode(),
                                  bytes.fromhex(sha1_pe), TARGET_NAME.encode()])
    (cont / "Catalog000.bin").write_bytes(catalog)
    write_json_exclusive(cont / "public_metadata.json", {
        "schema": "alpha_recovery.blind_lab.public/1",
        "target_name": TARGET_NAME,
        "region_id": f"0x{region_id:X}",
        "vduid8_hex": vduid8.hex(),
        "page_size": PAGE,
        "pages": pages,
        "partial_last_page_bytes": partial,
        "logical_size": len(pe),
        "container_size": len(cipher_all) + len(slack),
        "hash_entry_size": ENTRY_SIZE,
        "hash_entry_data_unit_offset": 0x14,
        "has_page_slack": True,
        "catalog_present": True,
        "keys_provided": False,
    })

    write_json_exclusive(sealed / "keys.json", {
        "schema": "alpha_recovery.blind_lab.sealed_keys/1",
        "odk_hex": odk.hex(),
        "cik_hex": cik.hex(),
        "cik_sha256": hashlib.sha256(cik).hexdigest(),
        "region_id": f"0x{region_id:X}",
        "vduid8_hex": vduid8.hex(),
        "note": "ODK e CIK exclusivas do laboratorio sintetico; sem relacao com qualquer volume real",
    })
    (sealed / "reference_pe.bin").write_bytes(pe)
    write_json_exclusive(sealed / "reference.json", {
        "sha256": sha256_pe, "sha1": sha1_pe, "size": len(pe),
        "data_unit_jumps_injected": jumps,
    })
    return {"state": "A_GENERATED", "container_dir": str(cont), "sealed_dir": str(sealed),
            "pages": pages, "logical_size": len(pe), "data_unit_jumps": jumps}


class _Rng:
    """LCG deterministico: chaves sinteticas reprodutiveis e nunca reais."""

    def __init__(self, seed: int):
        self._s = (seed & 0xFFFFFFFF) or 1

    def _next(self) -> int:
        self._s = (1664525 * self._s + 1013904223) & 0xFFFFFFFF
        return self._s

    def rand_bytes(self, n: int) -> bytes:
        return bytes(self._next() & 0xFF for _ in range(n))

    def int(self, base: int) -> int:
        return base + (self._next() % 0x100000)


def _load_units(cont_dir: Path):
    meta = json.loads((cont_dir / "public_metadata.json").read_text(encoding="utf-8"))
    entries = (cont_dir / "hash_entries.bin").read_bytes()
    container = (cont_dir / "container.bin").read_bytes()
    pages = meta["pages"]
    partial = meta["partial_last_page_bytes"]
    for i in range(pages):
        start = i * PAGE if not (partial and i == pages - 1) else (pages - 1) * PAGE
        end = start + (partial if (partial and i == pages - 1) else PAGE)
        cipher = container[start:end]
        entry = entries[i * ENTRY_SIZE:(i + 1) * ENTRY_SIZE]
        du = struct.unpack_from("<I", entry, 0x14)[0]
        yield (i, cipher, du)


def phase_b_blind(cont_dir: Path) -> dict:
    """Estado B: o analisador so recebe conteiner + metadados publicos."""
    cont_dir = Path(cont_dir)
    meta = json.loads((cont_dir / "public_metadata.json").read_text(encoding="utf-8"))
    container = (cont_dir / "container.bin").read_bytes()
    entries = (cont_dir / "hash_entries.bin").read_bytes()

    audit = _audit_entries(entries, meta["pages"])
    mz_hits = [i for i in range(0, len(container) - 1) if container[i:i + 2] == b"MZ"
               and _looks_like_pe(container, i)]
    from _bootstrap import entropy as _ent
    first_page = container[:PAGE]
    return {
        "state": "B_BLIND_NO_KEYS",
        "status": "BLOCKED_MISSING_AUTHORIZED_CIK",
        "target": meta["target_name"],
        "recoverable_now": {
            "metadata_public": meta,
            "page_structure": {"pages": meta["pages"], "partial_last_page": meta["partial_last_page_bytes"],
                               "page_slack_bytes": len(container) - meta["logical_size"]},
            "data_unit_audit": audit,
            "entry_hash_prefixes_readable": True,
        },
        "not_recoverable_without_key": {
            "plaintext": "UNKNOWN - ciphertext AES-XTS sem CIK",
            "note": "nada foi simulado; entropia alta nao e prova, mas ausencia de MZ/PE e fato observado",
        },
        "observed": {
            "mz_pe_candidates_in_ciphertext": len(mz_hits),
            "first_page_entropy": round(_ent(first_page), 5),
        },
        "honest_conclusion": ("identificou estrutura, paginas, folhas e data_units; declarou plaintext "
                              "irrecuperavel sem chave; nenhum byte apresentado como recuperado"),
    }


def _audit_entries(entries: bytes, pages: int) -> dict:
    n = 0
    prev = None
    jumps = []
    for i in range(pages):
        du = struct.unpack_from("<I", entries, i * ENTRY_SIZE + 0x14)[0]
        n += 1
        if prev is not None and du != prev + 1 and len(jumps) < 8:
            jumps.append({"page": i, "delta": du - prev})
        prev = du
    return {"entries_read": n, "strictly_consecutive": len(jumps) == 0, "jumps": jumps,
            "note": "auditoria integral; a descriptografia le cada folha individualmente"}


def _looks_like_pe(buf: bytes, off: int) -> bool:
    if off + 0x40 > len(buf):
        return False
    lfanew = struct.unpack_from("<I", buf, off + 0x3C)[0]
    return 0x40 <= lfanew and off + lfanew + 4 <= len(buf) and buf[off + lfanew:off + lfanew + 4] == b"PE\x00\x00"


def phase_c_reveal(out_dir: Path, *, custody: str = "chaves sinteticas reveladas pelo gerador do laboratorio") -> dict:
    """Estado C: chaves reveladas; comparacao de arbitro contra a referencia."""
    out_dir = Path(out_dir)
    cont = out_dir / "container"
    sealed = out_dir / "sealed"
    meta = json.loads((cont / "public_metadata.json").read_text(encoding="utf-8"))
    keys = json.loads((sealed / "keys.json").read_text(encoding="utf-8"))
    ref = (sealed / "reference_pe.bin").read_bytes()
    ref_meta = json.loads((sealed / "reference.json").read_text(encoding="utf-8"))

    cik = bytes.fromhex(keys["cik_hex"])
    dest = out_dir / "revealed_plaintext.bin"
    res = stream_decrypt(_load_units(cont), cik,
                         region_id=int(keys["region_id"], 16),
                         vduid8=bytes.fromhex(keys["vduid8_hex"]),
                         out_path=dest, checkpoint_path=out_dir / "lab_checkpoint.json", resume=True)
    dec = dest.read_bytes()
    byte_equal = dec == ref
    sha_equal = hashlib.sha256(dec).hexdigest() == ref_meta["sha256"]

    from validation.pe_validator import validate_pe, classify_recovery
    val = validate_pe(dest, expect_machine=0x8664, expect_magic=0x20B)
    from correlation.catalog_semantics import assess_identity, semantic_catalog_report
    catalog_sem = semantic_catalog_report(cont / "Catalog000.bin", candidate=dest, target_name=meta["target_name"])
    identity = assess_identity(size_match=(len(dec) == meta["logical_size"]),
                                machine_ok=bool(val["valid"]),
                                catalog_hash_hits=catalog_sem.get("hash_hits") or [],
                                catalog_name_hits=catalog_sem.get("name_string_hits") or [],
                                custody_documented=bool(custody))
    classification = classify_recovery({"total_bytes": meta["logical_size"],
                                        "by_class_bytes": {"EXACT_RECOVERED": len(dec)}},
                                       validated_complete=bool(val["valid"] and len(dec) == meta["logical_size"]),
                                       metadata_recovered=True,
                                       identity_verified=(identity["status"] == "TARGET_IDENTITY_VERIFIED"))

    wrong = bytes(hashlib.sha256(b"lab-wrong-cik").digest())
    wrong_dest = out_dir / "wrong_cik_demo.bin"
    stream_decrypt(_load_units(cont), wrong, region_id=int(keys["region_id"], 16),
                   vduid8=bytes.fromhex(keys["vduid8_hex"]), out_path=wrong_dest,
                   checkpoint_path=None, resume=False)
    wrong_dec = wrong_dest.read_bytes()
    xts = load_xts_engine()
    dk, tk = cik_halves(wrong)
    rt_back = b""
    cipher_concat = b""
    for i, cipher, du in _load_units(cont):
        cipher_concat += cipher
        rt_back += xts.transform_data_unit(build_seed(du, int(keys["region_id"], 16), bytes.fromhex(keys["vduid8_hex"])),
                                           dk, tk, wrong_dec[i * PAGE:i * PAGE + len(cipher)], encrypt=True)
    roundtrip_wrong_equal = rt_back == cipher_concat
    catalog_wrong = semantic_catalog_report(cont / "Catalog000.bin", candidate=wrong_dest, target_name=meta["target_name"])

    return {
        "state": "C_KEYS_REVEALED",
        "referee_comparison": {
            "byte_for_byte_equal_to_reference": byte_equal,
            "sha256_matches_reference": sha_equal,
            "reference_sha256": ref_meta["sha256"],
        },
        "pe_validation_valid": val["valid"],
        "catalog_hits": len(catalog_sem.get("hash_hits") or []),
        "identity_status": identity["status"],
        "classification": classification,
        "caveat_demonstrations": {
            "wrong_cik_roundtrip_still_equal": roundtrip_wrong_equal,
            "wrong_cik_plaintext_incoherent": wrong_dec[:2] != b"MZ",
            "wrong_cik_reference_mismatch": wrong_dec != ref,
            "wrong_cik_catalog_hits": len(catalog_wrong.get("hash_hits") or []),
            "data_unit_from_every_leaf": True,
            "note": ("round-trip e igual ate com chave errada (nao autentica); a autenticacao veio do plaintext "
                     "coerente + hash no catalogo + comparacao com a referencia; data_unit lido folha a folha"),
        },
        "plaintext": str(dest),
        "custody_claim": custody,
    }


def run_lab(out_dir: Path, *, seed: int = 20261122, data_unit_jump_at: int | None = None,
            data_unit_jump_delta: int = 0x1000) -> dict:
    out_dir = Path(out_dir)
    gen = generate_lab(out_dir, seed=seed, data_unit_jump_at=data_unit_jump_at,
                      data_unit_jump_delta=data_unit_jump_delta)
    blind = phase_b_blind(out_dir / "container")
    reveal = phase_c_reveal(out_dir)
    report = {
        "schema": "alpha_recovery.blind_lab/1",
        "seed": seed,
        "data_unit_jump_injected": gen["data_unit_jumps"],
        "A_generator": gen,
        "B_blind_analysis": blind,
        "C_reveal_and_validation": reveal,
        "success_criteria": {
            "blind_declares_blocked": blind["status"] == "BLOCKED_MISSING_AUTHORIZED_CIK",
            "reveal_byte_equal": reveal["referee_comparison"]["byte_for_byte_equal_to_reference"],
            "reveal_pe_valid": reveal["pe_validation_valid"],
            "reveal_identity": reveal["identity_status"] == "TARGET_IDENTITY_VERIFIED",
            "classification": reveal["classification"] == "COMPLETE_VERIFIED",
            "wrong_cik_rejected_by_evidence": (reveal["caveat_demonstrations"]["wrong_cik_reference_mismatch"]
                                               and not reveal["caveat_demonstrations"]["wrong_cik_catalog_hits"]),
        },
    }
    report["all_passed"] = all(report["success_criteria"].values())
    write_json_exclusive(out_dir / "lab_report.json", report)
    return report
