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
        SyntheticVolume, build_seed, load_cik, load_xts_engine, stream_decrypt,
    )
    _HAVE_XTS = True
except FileNotFoundError:
    _HAVE_XTS = False

pytestmark = pytest.mark.skipif(not _HAVE_XTS, reason="xts_primitive_kat.py indisponivel")


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
    xts = load_xts_engine()
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


# Vetor oficial do xvdtool (emoose/xvdtool @ 6fc2886, LibXboxOne.Tests/AesXtsTests.cs +
# Resources/DataBlobs/xts_{plain,cipher}.bin). Fixa o layout da CIK: tweak(16) || dados(16).
# Este teste nao existia quando cik_halves invertia as metades (erro so visivel com dados reais).
XVDTOOL_CIK = bytes.fromhex("8221d4acf4319d95e28e722e82a3b5e232ba06dd968615913f6bf810d08916a0")
XVDTOOL_VDUID8 = bytes.fromhex("34ff8790cadb1422")
XVDTOOL_PLAIN = b"SOME PLAINTEXT DATA BEFORE XTS TRANSFORMATION   " * 256
XVDTOOL_PLAIN_SHA256 = "aeebe0d184dfda4b9c3490ffc0b9a7f5f2b1469e9ca5521d0c519585dbac8412"
XVDTOOL_CIPHER_SHA256 = "e1c91a60d28906b7b9c99ec05cf44889b1315d3430560c7d7d1edd57ac08d9e3"
XVDTOOL_CIPHER_HEAD32 = "93ba1b6d50445ceb324c77f033b4cb6d909e4afd0767d0496a9b8134881f7ad5"


def _xvdtool_encrypt(engine, data_key, tweak_key) -> bytes:
    return b"".join(
        engine.transform_data_unit(build_seed(u, 1, XVDTOOL_VDUID8), data_key, tweak_key,
                                   XVDTOOL_PLAIN[u * 0x1000:(u + 1) * 0x1000], True)
        for u in range(3))


def test_xvdtool_official_vector():
    import hashlib
    from crypto.xvc_xts_pipeline import cik_halves, load_xts_primitive
    assert hashlib.sha256(XVDTOOL_PLAIN).hexdigest() == XVDTOOL_PLAIN_SHA256
    dk, tk = cik_halves(XVDTOOL_CIK)
    assert (tk, dk) == (XVDTOOL_CIK[:16], XVDTOOL_CIK[16:])
    for engine in (load_xts_engine(), load_xts_primitive()):
        ct = _xvdtool_encrypt(engine, dk, tk)
        assert ct[:32].hex() == XVDTOOL_CIPHER_HEAD32
        assert hashlib.sha256(ct).hexdigest() == XVDTOOL_CIPHER_SHA256


def test_xvdtool_vector_rejects_inverted_split():
    import hashlib
    ct = _xvdtool_encrypt(load_xts_engine(), XVDTOOL_CIK[:16], XVDTOOL_CIK[16:])
    assert hashlib.sha256(ct).hexdigest() != XVDTOOL_CIPHER_SHA256


def test_engine_matches_reference_port():
    import os
    from crypto.xvc_xts_pipeline import load_xts_primitive
    eng, port = load_xts_engine(), load_xts_primitive()
    for length in (16, 3072, 0x1000):
        dk, tk, seed, pt = os.urandom(16), os.urandom(16), os.urandom(16), os.urandom(length)
        ct = eng.transform_data_unit(seed, dk, tk, pt, True)
        assert ct == port.transform_data_unit(seed, dk, tk, pt, True)
        assert eng.transform_data_unit(seed, dk, tk, ct, False) == pt
    k = os.urandom(16)  # chaves iguais: OpenSSL recusa, o motor recorre ao porte
    pt = os.urandom(64)
    assert eng.transform_data_unit(bytes(16), k, k, pt, True) == port.transform_data_unit(bytes(16), k, k, pt, True)
    with pytest.raises(ValueError):
        eng.transform_data_unit(bytes(16), os.urandom(16), os.urandom(16), b"x" * 17, True)
