"""Suite sintetica obrigatoria (14 cenarios) do Shadow PE Reconstructor.

Os bytes esperados sao conhecidos de antemao (expected.json): os testes
verificam exatamente o que foi recuperado, nunca mais, e os controles
negativos falham se a ferramenta inventar bytes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from _bootstrap import SafetyError, guard_output_dir, write_exclusive
from scanners.binary_scanner import scan_tree, StopScan
from scanners.pe_carver import carve_file
from scanners.compression_scanner import scan_compressed
from correlation.block_matching import block_match
from reconstruction.interval_map import (
    IntervalMap, EXACT_RECOVERED, MATCHED_COPY, STRUCTURAL_INFERENCE,
    ENCRYPTED_UNKNOWN, CONFLICTING_EVIDENCE, MISSING, UNVERIFIED,
)
from validation.pe_validator import validate_pe, classify_recovery
from validation.recovery_tests import build_scenarios, make_minimal_pe


@pytest.fixture(scope="module")
def scenarios(tmp_path_factory):
    root = tmp_path_factory.mktemp("alpha_scenarios")
    return build_scenarios(root), (root / "expected.json")


def _sha(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _exp(meta, key):
    return meta[key]


def test_s01_pe_at_start(scenarios):
    made, _ = scenarios
    m = made["scenarios"]["s01_pe_at_start"]
    res = carve_file(Path(m["file"]), max_scan=0)
    assert len(res["pe_candidates"]) == 1
    pe = res["pe_candidates"][0]
    assert pe["truncated"] is False
    assert pe["offset"] == 0
    assert pe["minimum_file_extent"] == _exp(m, "recovered_bytes")


def test_s02_pe_embedded(scenarios):
    made, _ = scenarios
    m = made["scenarios"]["s02_pe_embedded"]
    res = carve_file(Path(m["file"]), max_scan=0)
    assert len(res["pe_candidates"]) == 1
    pe = res["pe_candidates"][0]
    assert pe["offset"] == _exp(m, "pe_offset")


def test_s03_truncated_not_extracted_by_default(scenarios, tmp_path):
    made, _ = scenarios
    m = made["scenarios"]["s03_pe_truncated"]
    res = carve_file(Path(m["file"]), out_dir=tmp_path / "f", max_scan=0)
    assert len(res["pe_candidates"]) == 1
    assert res["pe_candidates"][0]["truncated"] is True
    assert res["extractions"] == []


def test_s04_fake_mz_rejected(scenarios):
    made, _ = scenarios
    m = made["scenarios"]["s04_fake_mz"]
    res = carve_file(Path(m["file"]), max_scan=0)
    assert len(res["pe_candidates"]) == _exp(m, "pe_candidates")


def test_s05_random_no_candidates(scenarios):
    made, _ = scenarios
    m = made["scenarios"]["s05_random"]
    res = carve_file(Path(m["file"]), max_scan=0)
    assert len(res["pe_candidates"]) == 0


def test_s06_compressed_pe(scenarios):
    made, _ = scenarios
    m = made["scenarios"]["s06_compressed_pe"]
    res = scan_compressed(Path(m["file"]), max_scan=0)
    streams = [s for s in res["streams"] if s["status"] == "decompressed"]
    assert len(streams) == 1
    assert streams[0]["decoded_bytes"] == _exp(m, "recovered_bytes")
    assert sum(len(s.get("pe_candidates", [])) for s in res["streams"]) == 1


def test_s07_multi_container(scenarios):
    made, _ = scenarios
    m = made["scenarios"]["s07_multi_container"]
    res = carve_file(Path(m["file"]), max_scan=0)
    assert len(res["pe_candidates"]) == _exp(m, "pe_candidates")
    machines = {c["machine"] for c in res["pe_candidates"]}
    assert machines == {"0x8664", "0x014c"}


def test_s08_partial_duplication(scenarios):
    made, _ = scenarios
    root = Path(made["scenarios"]["s08_partial_dup"]["dir"])
    a, b = root / "a.bin", root / "b.bin"
    m = block_match(a, 0, b, 0, a.stat().st_size, block=0x400)
    assert m["equal_intervals"][0] == {"start": 0, "end": 0x1800}
    assert m["first_divergence_relative"] == 0x1800


def test_s09_conflicting_evidence():
    total = 0x8000
    im = IntervalMap(total, base_label=MISSING)
    im.add(0, total, EXACT_RECOVERED, evidence=[{"sha256": "a" * 64, "source_file": "a.bin"}])
    im.add(0x1000, 0x1800, EXACT_RECOVERED, evidence=[{"sha256": "b" * 64, "source_file": "b.bin"}])
    resolved = im.resolve()
    by_cls = {iv["classification"]: iv for iv in resolved}
    assert CONFLICTING_EVIDENCE in by_cls
    assert by_cls[CONFLICTING_EVIDENCE]["start"] == 0x1000
    assert by_cls[CONFLICTING_EVIDENCE]["end"] == 0x1800
    assert im.conflicts and im.conflicts[0]["start"] == 0x1000


def test_s09_inference_never_overrides_exact():
    im = IntervalMap(0x1000, base_label=MISSING)
    im.add(0, 0x1000, STRUCTURAL_INFERENCE)
    im.add(0x400, 0x800, EXACT_RECOVERED, evidence=[{"sha256": "c" * 64}])
    resolved = im.resolve()
    for iv in resolved:
        if iv["start"] < 0x800 and iv["end"] > 0x400:
            assert iv["classification"] == EXACT_RECOVERED


def test_s10_high_entropy_no_pe_no_compression(scenarios):
    made, _ = scenarios
    m = made["scenarios"]["s10_high_entropy_metadata"]
    res = carve_file(Path(m["file"]), max_scan=0)
    assert len(res["pe_candidates"]) == 0
    comp = scan_compressed(Path(m["file"]), max_scan=0)
    assert all(s["status"] != "decompressed" for s in comp["streams"])


def test_s11_bigger_than_memory(scenarios):
    made, _ = scenarios
    m = made["scenarios"]["s11_bigger_than_memory"]
    f = Path(m["file"])
    assert f.stat().st_size > (2 << 20)
    res = carve_file(f, out_dir=None, max_scan=0)
    assert len(res["pe_candidates"]) == 1
    assert res["pe_candidates"][0]["truncated"] is False


def test_s12_overwrite_refused(scenarios, tmp_path):
    made, _ = scenarios
    m = made["scenarios"]["s12_overwrite_guard"]
    f = Path(m["file"])
    dest = tmp_path / "frag.bin"
    write_exclusive(dest, b"x")
    with pytest.raises(SafetyError):
        write_exclusive(dest, b"y")
    with pytest.raises(SafetyError):
        guard_output_dir(f.parent, [f])


def test_s13_interrupt_and_resume(scenarios, tmp_path):
    made, _ = scenarios
    d = Path(made["scenarios"]["s13_interrupt_resume"]["dir"])
    files = sorted(p for p in d.iterdir() if p.is_file())
    assert len(files) == 3
    cache = tmp_path / "cache.json"
    with pytest.raises(StopScan):
        scan_tree([d], cache_path=cache, stop_after=1)
    cached_now = len(json.loads(cache.read_text(encoding="utf-8")))
    assert cached_now == 1
    inv1 = scan_tree([d], cache_path=cache)
    assert inv1["summary"]["files"] == 3
    assert inv1["summary"]["from_cache"] == 1
    assert inv1["summary"]["fresh_scans"] == 2
    inv2 = scan_tree([d], cache_path=cache)
    assert inv2["summary"]["from_cache"] == 3
    assert inv2["summary"]["fresh_scans"] == 0


def test_s14_roundtrip_known_original(scenarios, tmp_path):
    made, _ = scenarios
    root = Path(made["scenarios"]["s14_roundtrip"]["dir"])
    original = root / "original.bin"
    frag_full = root / "frag_full.bin"
    frag_part = root / "frag_part.bin"
    assert _sha(frag_full) == made["original_pe_sha256"]
    part_off_in_frag = 0x500
    orig_start = 0x800
    total = made["original_pe_size"]
    m = block_match(frag_part, part_off_in_frag, original, orig_start, total - orig_start, block=0x400)
    assert m["pct_equal_blocks"] == 100.0
    im = IntervalMap(total, base_label=MISSING)
    im.add(0, total, EXACT_RECOVERED,
           evidence=[{"sha256": _sha(frag_full), "source_file": str(frag_full)}])
    im.add(orig_start, total, MATCHED_COPY,
           evidence=[{"note": "verificado por blocos contra frag_part", "blocks_equal": m["blocks_equal"]}],
           source_file=str(frag_part), source_offset=part_off_in_frag,
           transform="block_match")
    resolved = im.resolve()
    cov = im.coverage(resolved)
    assert cov["by_class_bytes"][EXACT_RECOVERED] == total
    assert cov["by_class_bytes"][MATCHED_COPY] == 0
    val = validate_pe(frag_full)
    assert val["valid"] is True
    cls = classify_recovery(cov, validated_complete=val["valid"], metadata_recovered=True)
    assert cls == "COMPLETE_VERIFIED"


def test_s14_partial_only_yields_partial(tmp_path):
    pe = make_minimal_pe()
    frag = pe[:0x3000]
    (tmp_path / "part.bin").write_bytes(frag)
    im = IntervalMap(len(pe), base_label=MISSING)
    im.add(0, len(frag), EXACT_RECOVERED,
           evidence=[{"sha256": hashlib.sha256(frag).hexdigest(), "source_file": str(tmp_path / "part.bin")}])
    resolved = im.resolve()
    cov = im.coverage(resolved)
    assert cov["by_class_bytes"][EXACT_RECOVERED] == len(frag)
    assert cov["by_class_bytes"][MISSING] == len(pe) - len(frag)
    assert classify_recovery(cov, validated_complete=False, metadata_recovered=True) == "PARTIAL_RECOVERED"


def test_validator_on_synthetic_pe(tmp_path):
    pe = make_minimal_pe()
    f = tmp_path / "synth.exe"
    f.write_bytes(pe)
    res = validate_pe(f, expect_machine=0x8664, expect_magic=0x20B)
    assert res["valid"] is True, [c for c in res["checks"] if not c["ok"]]
    pe32 = make_minimal_pe(machine=0x014C, magic=0x10B)
    f2 = tmp_path / "synth32.exe"
    f2.write_bytes(pe32)
    assert validate_pe(f2, expect_machine=0x014C)["valid"] is True


def test_no_recoverable_pe_classification():
    cov = {"total_bytes": 100, "by_class_bytes": {ENCRYPTED_UNKNOWN: 100}}
    assert classify_recovery(cov, validated_complete=False, metadata_recovered=False) == "NO_RECOVERABLE_PE"
    assert classify_recovery(cov, validated_complete=False, metadata_recovered=True) == "METADATA_ONLY"


def test_extraction_bytes_match_original(scenarios, tmp_path):
    made, _ = scenarios
    m = made["scenarios"]["s01_pe_at_start"]
    out = tmp_path / "recovered_fragments"
    res = carve_file(Path(m["file"]), out_dir=out, max_scan=0)
    assert len(res["extractions"]) == 1
    assert _sha(out / res["extractions"][0]["name"]) == made["original_pe_sha256"]
