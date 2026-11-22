"""Integracao com o pacote real (somente leitura). Pulados sem XVC_PATH.

    set XVC_PATH=G:\\...\\pacote.xvc        (XVC_FULL=1 liga as varreduras completas de ~1,3 GB)
"""
import json
import os
from pathlib import Path

import pytest

from xvcintel.engines.configs import load_configs
from xvcintel.engines.fingerprint import fingerprint_executable
from xvcintel.engines.graph import build_graph
from xvcintel.engines.integrity import IntegrityOptions, run_integrity
from xvcintel.engines.pages import PageOptions, run_pages
from xvcintel.evidence.findings import build_findings
from xvcintel.evidence.model import PASS
from xvcintel.evidence.reports import compare_files_reports, files_report
from xvcintel.formats.xvd_header import product_id_storeid_test

pytestmark = pytest.mark.real
FULL = os.environ.get("XVC_FULL") == "1"
FIX = Path(__file__).parent / "fixtures"


def by_id(cs):
    return {c.id: c for c in cs}


def test_header_and_layout(real_pkg):
    h, lay = real_pkg.header, real_pkg.layout
    assert h.mutable_data_page_count == 1 and h.volume_flags == 0x41
    assert h.package_version_str == "1.0.2.1" and h.persistent_local_storage_size == 0x800
    offs = {r.name: (r.offset, r.size) for r in lay.regions}
    assert offs["hash tree"] == (0x14BF6000, 0x4EE2A000)
    assert offs["user data"] == (0x63A20000, 0x7000)
    assert offs["XvcInfo"] == (0x63A27000, 0x1A4000)
    assert offs["drive data"] == (0x63BCB000, 0x34135FB000)
    assert lay.end == real_pkg.size == 0x34771C6000
    assert lay.geometry.level_pages == (321211, 1890, 12, 1)
    assert all(c.status == PASS for c in real_pkg.checks), [c.id for c in real_pkg.checks if c.status != PASS]


def test_all_108_files_and_regression(real_pkg):
    assert len(real_pkg.rows) == 108 and all(ok for _, ok, _ in real_pkg.file_checks)
    base = json.loads((FIX / "xvc_files_report_baseline.json").read_text(encoding="utf-8"))
    r = compare_files_reports(base, files_report(real_pkg, keep_legacy_source_note=True))
    assert r["passed"] and r["field_differences"] == [] and r["source_differences"] == {}


def test_integrity(real_pkg):
    res = by_id(run_integrity(real_pkg, IntegrityOptions(full_leaf_level=FULL)))
    assert res["integrity.top_hash"].status == PASS
    assert res["integrity.link_L2_to_L3"].status == PASS and res["integrity.link_L1_to_L2"].status == PASS
    assert res["integrity.link_L0_to_L1"].counts["mismatches"] == 0
    assert res["integrity.leaf_vs_data"].counts["keyed_bad"] == res["integrity.leaf_vs_data"].counts["plain_bad"] == 0
    rh = res["integrity.region_hash"]
    assert rh.counts["ok"] == rh.counts["tested"] >= 11
    sh = res["integrity.segment_hash"]
    assert sh.counts["ok"] == sh.counts["tested"] == 49
    assert res["embedded.pduid_link"].status == PASS and res["embedded.top_hash"].status == PASS


def test_pages(real_pkg):
    res = by_id(run_pages(real_pkg, PageOptions(full_scan=FULL)))
    v = res["pages.value_eq_leaf_du"]
    assert v.counts["entries"] == 76_469 and v.counts["mismatches"] == 1
    assert v.data["mismatches"][0]["page"] == "0x63BCB"
    rle = res["pages.rle_model"]
    assert rle.counts["exceptions_in_keyed"] == 0
    if FULL:
        ex = rle.data["exceptions_by_region"]
        assert ex["0x40000002"]["count"] == 2457 and ex["0x40000003"]["count"] == 933 and rle.counts["exceptions"] == 3390
        assert rle.counts["keyed_checked"] == 54_601_906 and rle.counts["checked"] == 54_605_307
    assert res["pages.no_redundant_entries"].counts["redundant"] == 0
    segs = res["pages.segment_values"].data["exceptions"]
    assert [(e["segment"], e["value_minus_du"]) for e in segs][:2] == [(78, -1), (90, -37)]
    assert segs[2]["segment"] == 107 and not any(e["value_in_any_run"] for e in segs)


def test_executable_profile(real_pkg):
    prof = fingerprint_executable(real_pkg)
    st = prof["storage"]
    assert st["segment_index"]["value"] == 12 and st["region_id"]["value"] == "0x3E9"
    assert st["absolute_offset"]["value"] == "0x64917000" and st["size"]["value"] == 120_181_760
    assert st["key_id_index"]["value"] == 0
    assert prof["integrity"]["segment_hash"]["value"]["match"] is True
    assert prof["stored_content"]["mz_signature_at_0"]["value"] is False
    assert all(v["level"] == "UNKNOWN" for v in prof["pe_content"].values())
    assert len(prof["co_packaged_dlls"]["items"]) == 16


def test_product_id_and_graph(real_pkg):
    cfg = load_configs(real_pkg)
    t = product_id_storeid_test(real_pkg.header.product_id, cfg.game_config["StoreId"])
    assert t["contains_all_12_in_order_split_7_5"]
    g = build_graph(real_pkg)
    assert sum(1 for n in g.nodes.values() if n["kind"] == "file") == 108
    assert sum(1 for n in g.nodes.values() if n["kind"] == "region") == 31
    fs = build_findings(real_pkg, run_integrity(real_pkg) + run_pages(real_pkg), fingerprint_executable(real_pkg), cfg)
    assert {f.id for f in fs} >= {"F-HDR-01", "F-PT-02", "F-EXE-01", "F-PT-07-seg78", "F-PT-07-seg90", "F-PT-07-seg107"}
