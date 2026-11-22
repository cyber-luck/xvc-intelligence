"""Laboratorio as cegas A/B/C e as duas ressalvas tecnicas.

Ressalva 1: data_unit vem de CADA folha; auditoria integral caracteriza, mas
a execucao nunca extrapola (testado com descontinuidade injetada).
Ressalva 2: round-trip com CIK errada continua igual (XTS e permutacao);
autenticacao vem do plaintext coerente + evidencia independente.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

try:
    from crypto.synth_lab import phase_b_blind, phase_c_reveal, run_lab
    _HAVE = True
except FileNotFoundError:
    _HAVE = False

pytestmark = pytest.mark.skipif(not _HAVE, reason="xts_primitive_kat.py indisponivel")


def test_lab_full_cycle_passes_all_criteria(tmp_path):
    report = run_lab(tmp_path / "lab")
    assert report["A_generator"]["pages"] > 1
    b = report["B_blind_analysis"]
    assert b["status"] == "BLOCKED_MISSING_AUTHORIZED_CIK"
    assert b["observed"]["mz_pe_candidates_in_ciphertext"] == 0
    assert b["recoverable_now"]["data_unit_audit"]["entries_read"] == report["A_generator"]["pages"]
    c = report["C_reveal_and_validation"]
    assert c["referee_comparison"]["byte_for_byte_equal_to_reference"] is True
    assert c["referee_comparison"]["sha256_matches_reference"] is True
    assert c["pe_validation_valid"] is True
    assert c["identity_status"] == "TARGET_IDENTITY_VERIFIED"
    assert c["classification"] == "COMPLETE_VERIFIED"
    assert report["all_passed"] is True


def test_lab_caveat2_wrong_cik_roundtrip_still_equal_but_rejected(tmp_path):
    report = run_lab(tmp_path / "lab2")
    d = report["C_reveal_and_validation"]["caveat_demonstrations"]
    assert d["wrong_cik_roundtrip_still_equal"] is True, "XTS reversivel com qualquer chave (ressalva 2)"
    assert d["wrong_cik_plaintext_incoherent"] is True
    assert d["wrong_cik_reference_mismatch"] is True
    assert d["wrong_cik_catalog_hits"] == 0, "sem hit no catalogo, chave errada e rejeitada por evidencia"


def test_lab_caveat1_data_unit_jump_does_not_break_decryption(tmp_path):
    report = run_lab(tmp_path / "lab3", data_unit_jump_at=3, data_unit_jump_delta=0x777)
    assert report["data_unit_jump_injected"], "descontinuidade injetada"
    b = report["B_blind_analysis"]
    assert b["recoverable_now"]["data_unit_audit"]["strictly_consecutive"] is False
    assert b["recoverable_now"]["data_unit_audit"]["jumps"], "auditoria integral detecta o salto"
    c = report["C_reveal_and_validation"]
    assert c["referee_comparison"]["byte_for_byte_equal_to_reference"] is True, \
        "descriptografia le cada folha; salto nao afeta a execucao (ressalva 1)"
    assert c["classification"] == "COMPLETE_VERIFIED"


def test_lab_blind_phase_rejects_any_plaintext_claim(tmp_path):
    from crypto.synth_lab import generate_lab
    generate_lab(tmp_path / "lab4")
    b = phase_b_blind(tmp_path / "lab4" / "container")
    assert b["not_recoverable_without_key"]["plaintext"].startswith("UNKNOWN")
    assert "nada foi simulado" in b["not_recoverable_without_key"]["note"]
