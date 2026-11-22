"""FASE 9 - o laboratorio criptografico valida as premissas do PROJECT_ALPHA.

Tudo roda sobre conteineres LAB_SYNTHETIC gerados em diretorio temporario.
Nada aqui abre o pacote real nem aplica chave sintetica a ele.
"""
import sys
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("cryptography", reason="crypto_lab precisa de 'cryptography'")

LAB = Path(__file__).resolve().parents[2] / "crypto_lab"
sys.path.insert(0, str(LAB))


@pytest.fixture(scope="module")
def lab():
    td = tempfile.mkdtemp(prefix="alpha_lab_")
    import lab_common
    lab_common.allow_test_root(Path(td))
    import lab_encryptor
    g = lab_encryptor.generate(Path(td) / "gen", 31337)
    yield g
    import shutil
    shutil.rmtree(td, ignore_errors=True)


def test_reconstructor_locates_every_file_exactly(lab):
    from correlation.evidence_graph import xvc_storage_facts
    facts = xvc_storage_facts(Path(lab["public"]) / "lab_xvc_encrypted.bin")
    truth = lab["truth"]["xvc"]
    for f in truth["files"]:
        row = next(r for r in facts["files"] if r["filename"] == f["name"])
        assert int(row["absolute_offset"], 16) == f["container_offset"]
        assert row["size"] == f["size"]
        assert row["key_id"] == f["key_id"]


def test_reconstructor_classifies_encrypted_target_as_metadata_only(lab, tmp_path):
    import shadow_pe_reconstructor as spr
    out = tmp_path / "shadow"
    rc = spr.main(["run-all", "--xvc", str(Path(lab["public"]) / "lab_xvc_encrypted.bin"), "--disk", lab["public"],
                   "--target", "lab_plaintext.exe", "--out", str(out)])
    assert rc == 0
    import json
    m = json.loads((out / "metrics.json").read_text(encoding="utf-8"))
    assert m["classification"] == "METADATA_ONLY"
    assert m["bytes_original_with_proof"] == 0
    assert not (out / "shadow_pe_partial.bin").exists()


def test_carver_separates_plaintext_from_ciphertext(lab):
    from scanners.pe_carver import carve_file
    plain = carve_file(Path(lab["sealed"]) / "lab_plaintext.exe")
    enc = carve_file(Path(lab["public"]) / "lab_xvc_encrypted.bin")
    assert any(c["offset"] == 0 for c in plain["pe_candidates"])
    assert enc["pe_candidates"] == []


def test_leaf_data_unit_model_matches_truth(lab):
    from xvcintel.core.reader import FileSource
    from xvcintel.engines.package import load_package
    import lab_hash_tree as HT
    p = Path(lab["public"]) / "lab_xvc_encrypted.bin"
    src = FileSource(str(p))
    try:
        pkg = load_package(src).value
        data = p.read_bytes()
        tr = pkg.layout.get("hash tree")
        tree = data[tr.offset:tr.end]
        for f in lab["truth"]["xvc"]["files"]:
            if f["data_units"]:
                got = [HT.data_unit_of_page(tree, pkg.layout.geometry, f["hashed_index_first_page"] + i)
                       for i in range(f["pages"])]
                assert got == f["data_units"]
    finally:
        src.close()
