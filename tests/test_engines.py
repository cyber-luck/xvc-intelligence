"""Motores sobre o pacote sintetico: layout, mapa, integridade, paginas, perfil e grafo."""
import struct

import pytest

from xvcintel.core.reader import BytesSource
from xvcintel.core.result import Err, Ok
from xvcintel.engines.configs import load_configs
from xvcintel.engines.fingerprint import fingerprint_executable
from xvcintel.engines.graph import Graph, build_graph, query_lines
from xvcintel.engines.integrity import IntegrityOptions, run_integrity
from xvcintel.engines.package import load_package
from xvcintel.engines.pages import PageOptions, RleModel, build_runs, run_pages
from xvcintel.evidence.model import CONFIRMED, FAIL, INFERRED, PASS, UNKNOWN

import synthxvc


def by_id(checks):
    return {c.id: c for c in checks}


def load(data: bytes):
    r = load_package(BytesSource(data))
    assert isinstance(r, Ok), r
    return r.value


def mutate(data: bytes, off: int, new: bytes) -> bytes:
    b = bytearray(data)
    b[off:off + len(new)] = new
    return bytes(b)


# ------------------------------------------------------------------ layout e mapa
def test_layout_and_structure_pass(synth, synth_pkg):
    assert synth_pkg.layout.end == synth.info["file_end"] == synth_pkg.size
    assert synth_pkg.layout.get("drive data").offset == synth.info["off_drive"]
    assert all(c.status == PASS for c in synth_pkg.checks), [c for c in synth_pkg.checks if c.status != PASS]
    assert synth_pkg.errors == []


def test_file_map(synth, synth_pkg):
    assert len(synth_pkg.rows) == synth.info["n_files"] == 9
    assert all(ok for _, ok, _ in synth_pkg.file_checks)
    exe = synth_pkg.row("game_scarlett_master.exe")
    assert exe.index == 5 and exe.start == synth.info["exe_offset"] and exe.region.id == 0x3E9
    assert [r.name for r in synth_pkg.rows] == [n for n, _ in synth.info["files"]]
    slack = [n for n, ok, d in synth_pkg.file_checks if n.startswith("arquivos ocupam")]
    assert slack and "seg 8 sobra 0x1000" in [d for n, _, d in synth_pkg.file_checks if n == slack[0]][0]


def test_wrong_mdu_is_detected(synth):
    bad = load(mutate(synth.data, 0x470, b"\x00"))
    c = by_id(bad.checks)
    assert c["layout.xvcinfo_anchor"].status == FAIL        # achado so pela busca de ancora
    assert bad.xvcinfo is not None                          # fallback registrado como falha
    assert c["layout.mdu_vs_region"].status == FAIL


def test_truncated_package(synth):
    assert isinstance(load_package(BytesSource(synth.data[:0x800])), Err)
    p = load(synth.data[:synth.info["off_drive"] + 0x3000])
    assert any(c.status == FAIL for c in p.checks)          # layout nao fecha / regioes passam do fim


def test_malformed_xvcinfo_reported(synth):
    p = load(mutate(synth.data, synth.info["off_xvc"] + 0xD14, struct.pack("<I", 0xFFFFFF)))
    assert p.xvcinfo is None and any("RegionCount" in e for e in p.errors)


# ------------------------------------------------------------------ integridade
def test_integrity_all_pass(synth_pkg):
    res = by_id(run_integrity(synth_pkg, IntegrityOptions(full_leaf_level=True)))
    for cid in ("integrity.top_hash", "integrity.link_L0_to_L1", "integrity.region_hash", "integrity.segment_hash",
                "embedded.pduid_link", "embedded.top_hash"):
        assert res[cid].status == PASS, (cid, res[cid].detail)
    assert res["integrity.leaf_vs_data"].counts["keyed_bad"] == 0
    assert res["integrity.leaf_vs_data"].counts["keyed_ok"] > 0 and res["integrity.leaf_vs_data"].counts["plain_ok"] > 0
    assert res["integrity.region_hash"].counts["tested"] == 7


def test_integrity_cap_reports_skips(synth_pkg):
    res = by_id(run_integrity(synth_pkg, IntegrityOptions(cap_bytes=0x2000)))
    assert res["integrity.segment_hash"].status == "PARTIAL"
    assert res["integrity.segment_hash"].counts["skipped_by_cap"] > 0
    assert "pulad" in res["integrity.region_hash"].detail


def test_corrupted_exe_page_detected(synth):
    p = load(mutate(synth.data, synth.info["exe_offset"], b"\xFF\xFE"))
    res = by_id(run_integrity(p))
    assert res["integrity.segment_hash"].status == FAIL and 5 in [r["segment"] for r in res["integrity.segment_hash"].data["segments"] if r["match"] is False]
    assert res["integrity.region_hash"].status == FAIL
    assert res["integrity.leaf_vs_data"].status == FAIL
    assert res["integrity.top_hash"].status == PASS          # a arvore em si nao mudou


def test_corrupted_tree_detected(synth):
    g = synth.info["geometry"]
    leaf_page = synth.info["off_ht"] + g.level_start(0) * 0x1000
    p = load(mutate(synth.data, leaf_page + 5, b"\x00\x01"))
    res = by_id(run_integrity(p, IntegrityOptions(full_leaf_level=True)))
    assert res["integrity.link_L0_to_L1"].status == FAIL
    p2 = load(mutate(synth.data, synth.info["off_ht"] + 9, b"\x55"))
    assert by_id(run_integrity(p2))["integrity.top_hash"].status == FAIL


# ------------------------------------------------------------------ paginas
def test_rle_model_full_and_sampled(synth_pkg, synth):
    for full in (True, False):
        res = by_id(run_pages(synth_pkg, PageOptions(full_scan=full)))
        c = res["pages.rle_model"]
        assert c.counts["exceptions_in_keyed"] == 0, c.detail
        assert c.status == (PASS if full else "PARTIAL")
    runs = build_runs(synth_pkg)
    m = RleModel(runs)
    for p, du in synth.info["du_of"].items():
        assert m.predict(p) == du


def test_value_eq_leaf_and_reuse(synth_pkg):
    res = by_id(run_pages(synth_pkg))
    v = res["pages.value_eq_leaf_du"]
    assert v.status == PASS and v.counts["mismatches"] == 1 and v.counts["mismatches_in_keyed_regions"] == 0
    assert res["pages.no_redundant_entries"].counts["redundant"] == 0
    reuse = res["pages.data_unit_reuse"]
    assert reuse.counts["pages_sharing"] == 2 and reuse.counts["pairs_same_du"] == reuse.counts["pairs_checked"] >= 1
    t = res["pages.transitions"]
    assert t.counts["backward"] >= 1


def test_segment_value_exception_reported(synth_pkg):
    c = by_id(run_pages(synth_pkg))["pages.segment_values"]
    ex = c.data["exceptions"]
    assert [e["segment"] for e in ex] == [4] and ex[0]["value_minus_du"] == -1
    assert ex[0]["file"] == "appdata0.rpf" and ex[0]["value_in_any_run"] is False


def test_rle_violation_detected(synth):
    """Altera a unidade de dados de uma folha de pagina com KeyId: o modelo tem que falhar."""
    pkg = load(synth.data)
    exe_page = synth.info["exe_offset"] // 0x1000 + 2
    from xvcintel.engines.treeio import TreeReader
    off = TreeReader(pkg.src, pkg.layout).leaf_offset(exe_page)
    bad = load(mutate(synth.data, off + 0x14, struct.pack("<I", 0x12345678)))
    c = by_id(run_pages(bad, PageOptions(full_scan=True)))["pages.rle_model"]
    assert c.status == FAIL and c.counts["exceptions_in_keyed"] == 1


# ------------------------------------------------------------------ perfil e grafo
def test_fingerprint_profile(synth_pkg, synth):
    prof = fingerprint_executable(synth_pkg)
    st, ig = prof["storage"], prof["integrity"]
    assert st["segment_index"]["value"] == 5 and st["region_id"]["value"] == "0x3E9"
    assert st["absolute_offset"]["value"] == f"0x{synth.info['exe_offset']:X}"
    assert ig["segment_hash"]["value"]["match"] is True and ig["region_hash"]["value"]["match"] is True
    assert ig["leaf_hashes_sampled"]["level"] == CONFIRMED
    assert prof["identity"]["application_id_consistent_across_3_configs"]["value"] is True
    assert prof["identity"]["package_version_header_vs_config"]["level"] == CONFIRMED
    assert prof["launch_config"]["persistent_local_storage_MB"]["level"] == CONFIRMED
    # nada de conteudo PE e afirmado
    assert all(v["level"] == UNKNOWN and v["value"] is None for v in prof["pe_content"].values())
    assert prof["stored_content"]["mz_signature_at_0"]["value"] is False
    assert prof["stored_content"]["encryption_inference"]["level"] == INFERRED
    assert [d["name"] for d in prof["co_packaged_dlls"]["items"]] == ["vcruntime140.dll", "XCurl.dll"]
    assert "NAO prova" in prof["co_packaged_dlls"]["note"]
    assert prof["code_catalog"]["pe_subsystem"] == "XBOX_CODE_CATALOG"


def test_fingerprint_missing_target(synth_pkg):
    assert "error" in fingerprint_executable(synth_pkg, "nao_existe.exe")


def test_graph_evidence_and_query(synth_pkg, tmp_path):
    g = build_graph(synth_pkg, run_integrity(synth_pkg))
    assert all(e["confidence"] in (CONFIRMED, INFERRED, UNKNOWN) and e["evidence"].get("source") for e in g.edges)
    # import nunca e afirmado a partir de nomes de DLL
    assert all(e["confidence"] == UNKNOWN for e in g.edges if e["relation"] == "IMPORTS")
    rels = {e["relation"] for e in g.neighbors("file:game_scarlett_master.exe")}
    assert {"STORES_FILE", "DECLARES_EXECUTABLE", "DECLARES_APPLICATION", "CO_PACKAGED_WITH"} <= rels
    p = tmp_path / "g.json"
    g.save(str(p))
    g2 = Graph.load(str(p))
    assert len(g2.nodes) == len(g.nodes) and len(g2.edges) == len(g.edges)
    lines = query_lines(g2, "game_scarlett_master.exe")
    assert lines[0].startswith("== no file:game_scarlett_master.exe") and any("segment:5" in l for l in lines)
    assert query_lines(g2, "inexistente_xyz")[0].startswith("nenhum")
    seg5 = g2.nodes["segment:5"]
    assert seg5["hash_verified"] is True


def test_configs(synth_pkg):
    c = load_configs(synth_pkg)
    assert c.game_config["TitleId"] == "7952987A" and c.game_config["StoreId"] == "9NL3WWNZLZZN"
    assert c.manifest["applications"][0]["EntryPoint"] == "GamingProxyApp.Application.EntryPoint"
    assert c.hive["executables"][0]["Name"] == "game_scarlett_master.exe"
    assert c.summary["PackageFeatures"]["GDKVersion"] == "10.0.26100.7822"
