"""Regressao das melhorias finais: catalogo semantico, identidade separada,
proveniencia de fonte, reconciliacao de tamanho e COMPLETE_UNVERIFIED."""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from correlation.catalog_semantics import (
    assess_identity, authenticode_digests, file_digests, semantic_catalog_report,
)
from reconstruction.provenance import size_reconciliation, page_slack_info, source_provenance_report
from validation.pe_validator import classify_recovery
from validation.recovery_tests import make_minimal_pe


def _flip_byte(data: bytes, off: int) -> bytes:
    out = bytearray(data)
    out[off] ^= 0xFF
    return bytes(out)


def _make_catalog(needles: list[bytes]) -> bytes:
    """Catalogo sintetico: PE subsystem 17 com needles gravadas na secao."""
    pe = bytearray(make_minimal_pe(subsystem=17))
    lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
    opt_size = struct.unpack_from("<H", pe, lfanew + 20)[0]
    opt = lfanew + 24
    sect_off = opt + opt_size
    raw_ptr = struct.unpack_from("<I", pe, sect_off + 20)[0]
    pos = raw_ptr + 0x100
    for n in needles:
        pe[pos:pos + len(n)] = n
        pos += len(n) + 16
    return bytes(pe)


def test_authenticode_digest_excludes_cert_table(tmp_path):
    pe = make_minimal_pe()
    f = tmp_path / "plain.exe"
    f.write_bytes(pe)
    d0 = authenticode_digests(f)
    assert d0["sha1"] == hashlib.sha1(pe).hexdigest()
    assert d0["sha256"] == hashlib.sha256(pe).hexdigest()
    assert d0["cert_table_excluded"] is None

    signed = bytearray(pe)
    lfanew = struct.unpack_from("<I", signed, 0x3C)[0]
    opt = lfanew + 24
    dd_off = opt + 112
    cert_off = len(pe)
    cert_len = 64
    struct.pack_into("<II", signed, dd_off + 4 * 8, cert_off, cert_len)
    signed += b"\xAA" * cert_len
    f2 = tmp_path / "signed.exe"
    f2.write_bytes(bytes(signed))
    d1 = authenticode_digests(f2)
    assert d1["cert_table_excluded"] == {"file_offset": cert_off, "length": cert_len}
    expected_blob = bytes(signed)[:cert_off]
    assert d1["sha256"] == hashlib.sha256(expected_blob).hexdigest()
    assert d1["sha1"] == hashlib.sha1(expected_blob).hexdigest()
    assert d1["sha256"] != hashlib.sha256(f2.read_bytes()).hexdigest()


def test_same_size_same_version_different_hash_is_not_identity(tmp_path):
    original = make_minimal_pe()
    forgery = _flip_byte(original, 0x1000 + 0x10)
    assert len(original) == len(forgery)
    assert hashlib.sha256(original).digest() != hashlib.sha256(forgery).digest()

    raw256 = hashlib.sha256(original).hexdigest()
    raw1 = hashlib.sha1(original).hexdigest()
    catalog = tmp_path / "Catalog000.bin"
    catalog.write_bytes(_make_catalog([bytes.fromhex(raw256), raw1.encode(), b"game_scarlett_master.exe"]))

    rep_orig = semantic_catalog_report(catalog, candidate=_write(tmp_path, "orig.exe", original),
                                       target_name="game_scarlett_master.exe")
    assert rep_orig["hash_hits"], "o original deve ter hits no catalogo sintetico"
    assert any(h["digest_kind"] == "file_raw" and h["form"] == "raw_bytes" for h in rep_orig["hash_hits"])
    assert rep_orig["name_string_hits"]

    forgery_path = _write(tmp_path, "forgery.exe", forgery)
    rep_forg = semantic_catalog_report(catalog, candidate=forgery_path, target_name="game_scarlett_master.exe")
    assert rep_forg["hash_hits"] == [], "falsificacao de mesmo tamanho/versao NAO pode ter hit de hash"

    id_forg = assess_identity(size_match=True, machine_ok=True,
                              catalog_hash_hits=rep_forg["hash_hits"],
                              catalog_name_hits=rep_forg["name_string_hits"],
                              custody_documented=True)
    assert id_forg["status"] == "TARGET_IDENTITY_UNVERIFIED"
    cov = {"total_bytes": len(forgery), "by_class_bytes": {"EXACT_RECOVERED": len(forgery)}}
    assert classify_recovery(cov, validated_complete=True, metadata_recovered=True,
                             identity_verified=False) == "COMPLETE_UNVERIFIED"


def test_catalog_without_association_keeps_identity_unverified(tmp_path):
    pe = make_minimal_pe()
    catalog = tmp_path / "Catalog000.bin"
    catalog.write_bytes(_make_catalog([b"\x00" * 64]))
    rep = semantic_catalog_report(catalog, candidate=_write(tmp_path, "cand.exe", pe),
                                  target_name="game_scarlett_master.exe")
    assert rep["hash_hits"] == []
    assert rep["name_string_hits"] == []
    ident = assess_identity(size_match=True, machine_ok=True, catalog_hash_hits=[],
                           catalog_name_hits=[], custody_documented=True)
    assert ident["status"] == "TARGET_IDENTITY_UNVERIFIED"
    for e in ident["evidence"]:
        if e["id"] in ("size_exact", "machine_compatible", "custody_documented"):
            assert e["ok"] is True
        else:
            assert e["ok"] is False


def test_unverified_provenance_blocks_complete_verified(tmp_path):
    pe = make_minimal_pe()
    raw256 = hashlib.sha256(pe).hexdigest()
    catalog = tmp_path / "Catalog000.bin"
    catalog.write_bytes(_make_catalog([bytes.fromhex(raw256)]))
    rep = semantic_catalog_report(catalog, candidate=_write(tmp_path, "c.exe", pe))
    assert rep["hash_hits"]

    ident_no_custody = assess_identity(size_match=True, machine_ok=True,
                                       catalog_hash_hits=rep["hash_hits"],
                                       catalog_name_hits=[], custody_documented=False)
    assert ident_no_custody["status"] == "TARGET_IDENTITY_UNVERIFIED"
    cov = {"total_bytes": len(pe), "by_class_bytes": {"EXACT_RECOVERED": len(pe)}}
    assert classify_recovery(cov, validated_complete=True, metadata_recovered=True,
                            identity_verified=False) == "COMPLETE_UNVERIFIED"

    ident_full = assess_identity(size_match=True, machine_ok=True,
                                 catalog_hash_hits=rep["hash_hits"],
                                 catalog_name_hits=[], custody_documented=True)
    assert ident_full["status"] == "TARGET_IDENTITY_VERIFIED"
    assert classify_recovery(cov, validated_complete=True, metadata_recovered=True,
                             identity_verified=True) == "COMPLETE_VERIFIED"


def test_source_recovered_never_conflated_with_identity():
    idn = assess_identity(size_match=False, machine_ok=True, catalog_hash_hits=[],
                          catalog_name_hits=[], custody_documented=True)
    assert idn["status"] == "TARGET_IDENTITY_UNVERIFIED"
    assert "SOURCE_RECOVERED" in idn["warning"]


def test_size_reconciliation_page_slack_real_case():
    stored = 120181760
    actual = 120184832
    recon = size_reconciliation(stored, actual, tail_matches_xvc_continuation=True)
    assert recon["delta"] == 3072
    assert recon["page_math"]["bytes_to_next_page_boundary"] == 3072
    hyp = recon["hypotheses"][0]
    assert hyp["id"] == "page_slack_included_by_extraction"
    assert hyp["delta_matches"] is True
    assert hyp["level"] == "CONFIRMED"
    assert "truncamento" in recon["policy"]


def test_size_reconciliation_no_truncation_on_mismatch(tmp_path):
    recon = size_reconciliation(1000, 900)
    assert recon["delta"] == -100
    assert recon["hypotheses"][0]["id"] == "truncated_copy"
    f = tmp_path / "x.bin"
    f.write_bytes(b"\x00" * 900)
    assert f.stat().st_size == 900


def test_size_reconciliation_exact():
    recon = size_reconciliation(1000, 1000)
    assert recon["delta"] == 0
    assert recon["hypotheses"][0]["id"] == "exact_match"


def test_page_slack_math():
    info = page_slack_info(120181760)
    assert info["file_end_within_page"] == 0x400
    assert info["bytes_to_next_page_boundary"] == 0xC00
    assert info["size_page_aligned"] == 120184832


def test_source_provenance_claim_is_not_proof(tmp_path):
    f = tmp_path / "src.exe"
    f.write_bytes(make_minimal_pe())
    rep = source_provenance_report(f, custody_claim="obtida do detentor em 2026-11-22",
                                   digests=file_digests(f))
    assert rep["custody_claim_is_not_proof"] is True
    assert rep["custody_claim"].startswith("obtida")
    assert rep["source"]["digests"]["sha256"] == hashlib.sha256(f.read_bytes()).hexdigest()
    assert any("SOURCE_RECOVERED" in s for s in rep["statements"])


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p
