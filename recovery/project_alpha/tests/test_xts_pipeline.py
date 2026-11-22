"""Fase 3: matriz sintetica obrigatoria do pipeline XTS (XVC).

A CIK de teste e gerada exclusivamente aqui e nao tem relacao com nenhum
volume real. A igualdade com o plaintext ORIGINAL CONHECIDO e exigida alem
do round-trip, conforme especificacao.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from _bootstrap import write_exclusive

try:
    from crypto.xvc_xts_pipeline import (
        SyntheticVolume, build_seed, load_cik, load_validate_xts, stream_decrypt,
    )
    _HAVE_XTS = True
except FileNotFoundError:
    _HAVE_XTS = False

pytestmark = pytest.mark.skipif(not _HAVE_XTS, reason="validate_xts.py (motor G:) indisponivel")


@pytest.fixture(scope="module")
def known_pe() -> bytes:
    from validation.recovery_tests import make_minimal_pe
    pe = make_minimal_pe(text_size=0x8000)
    return pe + b"\xCD" * 0x400


@pytest.fixture(scope="module")
def volume(known_pe) -> SyntheticVolume:
    return SyntheticVolume(plaintext=known_pe, region_id=0x3E9, vduid8=b"\x11" * 8,
                           page_slack=b"\xAB" * 0x100)


def test_seed_layout():
    seed = build_seed(0xE5046EA2, 0x3E9, b"\x01\x02\x03\x04\x05\x06\x07\x08")
    assert seed == bytes.fromhex("a26e04e5") + bytes.fromhex("e9030000") + b"\x01\x02\x03\x04\x05\x06\x07\x08"
    assert len(seed) == 16


def test_load_cik_binary_and_hex(tmp_path):
    cik = hashlib.sha256(b"test-cik").digest()
    b = tmp_path / "cik.bin"
    b.write_bytes(cik)
    got, fp = load_cik(b)
    assert got == cik and fp == hashlib.sha256(cik).hexdigest()
    h = tmp_path / "cik.hex"
    h.write_text(cik.hex())
    got2, _ = load_cik(h)
    assert got2 == cik
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"\x00" * 31)
    with pytest.raises(ValueError):
        load_cik(bad)


def test_decrypt_equals_known_plaintext(volume, known_pe):
    dec = volume.decrypt_with(volume.cik)
    assert dec == known_pe, "igualdade byte a byte com o plaintext original e obrigatoria"
    assert dec[:2] == b"MZ"
    assert dec != b"".join(volume.pages)


def test_reencrypt_equals_ciphertext(volume):
    xts = load_validate_xts()
    from crypto.xvc_xts_pipeline import cik_halves
    data_key, tweak_key = cik_halves(volume.cik)
    re = b"".join(
        xts.transform_data_unit(build_seed(volume.data_units[i], volume.region_id, volume.vduid8),
                                data_key, tweak_key, volume.plaintext_units[i], encrypt=True)
        for i in range(len(volume.pages)))
    assert re == b"".join(volume.pages)


def test_wrong_cik_fails(volume, known_pe):
    wrong = hashlib.sha256(b"wrong-cik").digest()
    dec = volume.decrypt_with(wrong)
    assert dec != known_pe
    assert dec[:2] != b"MZ"


def test_wrong_region_id_fails(volume, known_pe):
    assert volume.decrypt_with(volume.cik, region_id=0x123) != known_pe


def test_wrong_vduid_fails(volume, known_pe):
    assert volume.decrypt_with(volume.cik, vduid8=b"\x99" * 8) != known_pe


def test_wrong_data_unit_fails(volume, known_pe):
    assert volume.decrypt_with(volume.cik, data_unit_offset=1) != known_pe


def test_tampered_page_detected_by_leaf_before_decryption(volume):
    tampered = bytearray(volume.pages[0])
    tampered[0x10] ^= 0xFF
    leaf = volume.entries[0][:0x14]
    assert hashlib.sha256(bytes(tampered)).digest()[:0x14] != leaf


def test_page_slack_excluded_from_plaintext(volume, known_pe):
    assert len(volume.ciphertext) == len(known_pe) + len(volume.page_slack)
    assert len(volume.decrypt_with(volume.cik)) == len(known_pe)


def test_stream_decrypt_roundtrip_and_resume(volume, known_pe, tmp_path):
    out = tmp_path / "plain.bin"
    ckpt = tmp_path / "ck.json"
    units = [(i, volume.pages[i], volume.data_units[i]) for i in range(len(volume.pages))]
    res1 = stream_decrypt(iter(units), volume.cik, region_id=volume.region_id,
                          vduid8=volume.vduid8, out_path=out, checkpoint_path=ckpt,
                          resume=True, stop_after=2)
    assert res1["interrupted"] and res1["units_done"] == 2
    assert ckpt.is_file()
    res2 = stream_decrypt(iter(units), volume.cik, region_id=volume.region_id,
                          vduid8=volume.vduid8, out_path=out, checkpoint_path=ckpt, resume=True)
    assert not res2["interrupted"]
    assert out.read_bytes() == known_pe
    assert res2["sha256_plaintext"] == hashlib.sha256(known_pe).hexdigest()
    assert not ckpt.exists()


def test_stream_decrypt_rejects_corrupted_checkpoint(volume, known_pe, tmp_path):
    out = tmp_path / "plain2.bin"
    ckpt = tmp_path / "ck2.json"
    units = [(i, volume.pages[i], volume.data_units[i]) for i in range(len(volume.pages))]
    res1 = stream_decrypt(iter(units), volume.cik, region_id=volume.region_id,
                          vduid8=volume.vduid8, out_path=out, checkpoint_path=ckpt,
                          resume=True, stop_after=2)
    assert res1["interrupted"]
    with open(out, "ab") as fh:
        fh.write(b"\x00" * 16)
    res2 = stream_decrypt(iter(units), volume.cik, region_id=volume.region_id,
                           vduid8=volume.vduid8, out_path=out, checkpoint_path=ckpt, resume=True)
    assert out.read_bytes() == known_pe, "checkpoint divergente deve reiniciar do zero, nunca misturar"


def test_run_synthetic_validation_all_pass():
    from crypto.xvc_xts_pipeline import run_synthetic_validation
    res = run_synthetic_validation()
    assert res["all_passed"], [r for r in res["results"] if not r["ok"]]
    assert any(r["test"] == "decrypt_equals_known_plaintext" and r["ok"] for r in res["results"])
