"""Relatorios (schema 1 compativel, achados, HTML, regressao) e CLI/wrappers."""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from xvcintel.cli import SafetyError, guard_output, main
from xvcintel.engines.configs import load_configs
from xvcintel.engines.fingerprint import fingerprint_executable
from xvcintel.engines.integrity import run_integrity
from xvcintel.engines.pages import run_pages
from xvcintel.evidence.findings import build_findings
from xvcintel.evidence.html_report import render_html
from xvcintel.evidence.model import LEVELS
from xvcintel.evidence.reports import compare_files_reports, files_report, findings_report

ROOT = Path(__file__).parents[1]
FIX = ROOT / "tests" / "fixtures"


@pytest.fixture(scope="module")
def baseline():
    return json.loads((FIX / "xvc_files_report_baseline.json").read_text(encoding="utf-8"))


def test_files_report_schema_matches_baseline(synth_pkg, baseline):
    rep = files_report(synth_pkg)
    assert set(rep) == set(baseline)
    assert set(rep["source"]) == set(baseline["source"])
    assert rep["classification_rules"] == baseline["classification_rules"]
    assert [c["name"] for c in rep["validation"]["checks"]] == [c["name"] for c in baseline["validation"]["checks"]]
    assert set(rep["files"][0]) == set(baseline["files"][0])
    by = {f["filename"]: f for f in rep["files"]}
    assert by["Catalog000.bin"]["signature"] == "PE" and by["Catalog000.bin"]["pe"] == \
        next(f for f in baseline["files"] if f["filename"] == "Catalog000.bin")["pe"]
    assert by["game_scarlett_master.exe"]["content_state"] == "OPAQUE"
    assert by["game_scarlett_master.exe"]["encryption_status"] == "LIKELY_ENCRYPTED_UNVERIFIED"
    assert by["MicrosoftGame.Config"]["encryption_status"] == "NO_KEY_PER_REGION"
    assert by["Update.alignmentchunk"]["content_state"] == "TOO_SMALL"


def test_regression_compare(baseline):
    same = compare_files_reports(baseline, json.loads(json.dumps(baseline)))
    assert same["passed"] and not same["field_differences"]
    mod = json.loads(json.dumps(baseline))
    mod["files"][12]["absolute_offset"] = "0x0"
    del mod["files"][0]
    r = compare_files_reports(baseline, mod)
    assert not r["passed"] and r["missing_in_new"] == ["microsoft_gameconfig.bin"]
    assert {"file": "game_scarlett_master.exe", "field": "absolute_offset", "old": "0x64917000", "new": "0x0"} in r["field_differences"]


def test_findings_and_html(synth_pkg):
    checks = run_integrity(synth_pkg) + run_pages(synth_pkg)
    cfg = load_configs(synth_pkg)
    prof = fingerprint_executable(synth_pkg, configs=cfg)
    fs = build_findings(synth_pkg, checks, prof, cfg)
    ids = [f.id for f in fs]
    assert len(ids) == len(set(ids))
    assert all(f.level in LEVELS for f in fs)
    d = {f.id: f for f in fs}
    assert d["F-HDR-01"].level == "CONFIRMED" and d["F-HT-02"].level == "CONFIRMED"
    assert d["F-EXE-03"].level == "UNKNOWN"                 # conteudo do executavel
    assert d["F-PT-07-seg4"].level == "UNKNOWN"
    assert d["F-HDR-08"].level == "CONFIRMED"
    # todo achado nao-UNKNOWN cita teste ou evidencia
    assert all(f.tests or f.evidence for f in fs if f.level != "UNKNOWN")
    # toda hipotese/incognita diz como confirma-la ou refuta-la
    assert all(f.how_to_test for f in fs if f.level != "CONFIRMED"), [f.id for f in fs if f.level != "CONFIRMED" and not f.how_to_test]
    rep = findings_report(synth_pkg, checks, fs, None, {"x": 1})
    html = render_html(rep, prof, {"nodes": 1, "edges": 2, "by_confidence": {}})
    assert "<script src" not in html and "<link" not in html
    assert not re.search(r"""(src|href)=["']?https?:""", html)
    assert "F-EXE-03" in html and "game_scarlett_master.exe" in html


def test_guard_output(tmp_path):
    pkg = tmp_path / "dir" / "p.xvc"
    pkg.parent.mkdir()
    pkg.write_bytes(b"x")
    with pytest.raises(SafetyError):
        guard_output(str(pkg.parent / "out.json"), str(pkg))
    with pytest.raises(SafetyError):
        guard_output(str(pkg), str(pkg))
    assert guard_output(str(tmp_path / "out.json"), str(pkg))


def test_cli_analyze_and_query(synth_file, tmp_path, capsys):
    out = tmp_path / "rep"
    rc = main(["analyze", str(synth_file), "--out", str(out), "--full-leaf", "--full-pages",
               "--baseline", str(FIX / "xvc_files_report_baseline.json")])
    assert rc == 0
    for name in ("findings.json", "xvc_files_report.json", "executable_profile.json", "graph.json", "report.html",
                 "regression.json"):
        assert (out / name).exists(), name
    reg = json.loads((out / "regression.json").read_text(encoding="utf-8"))
    assert reg["file_count_old"] == 108 and reg["file_count_new"] == 9 and not reg["passed"]
    capsys.readouterr()
    assert main(["query", "--graph", str(out / "graph.json"), "--node", "game_scarlett_master.exe"]) == 0
    assert "STORES_FILE" in capsys.readouterr().out
    # saida dentro da pasta do pacote e recusada
    assert main(["graph", str(synth_file), "--out", str(synth_file.parent / "g.json")]) == 2


def test_cli_misc(synth_file, tmp_path, capsys):
    assert main(["header", str(synth_file)]) == 0
    assert main(["layout", str(synth_file)]) == 0
    assert main(["xvcinfo", str(synth_file)]) == 0
    assert main(["files", str(synth_file), "--list"]) == 0
    assert main(["integrity", str(synth_file), "--full-leaf"]) == 0
    assert main(["pages", str(synth_file), "--full-pages"]) == 0
    assert main(["fingerprint", str(synth_file), "--json", str(tmp_path / "p.json")]) == 0
    assert main(["userdata", str(synth_file), "--extract", str(tmp_path / "ud")]) == 0
    assert (tmp_path / "ud" / "SegmentMetadata.bin").exists()
    assert main(["regf", str(FIX / "userdata_files" / "microsoft_gameconfig.bin")]) == 0
    assert main(["pe", str(FIX / "Catalog000.bin")]) == 0
    assert main(["pe", str(FIX / "pe" / "png.bin")]) == 1
    assert main(["regress", str(FIX / "xvc_files_report_baseline.json"), str(FIX / "xvc_files_report_baseline.json")]) == 0


def _run(*args):
    return subprocess.run([sys.executable, "-I", *args], capture_output=True, text=True, encoding="utf-8",
                          errors="replace", cwd=str(ROOT))


def test_probe_wrapper_json_report(synth_file, tmp_path, baseline):
    out = tmp_path / "files.json"
    r = _run("scripts/xvc_probe.py", str(synth_file), "--skip-scan", "--list-files", "--json-report", str(out))
    assert r.returncode == 0, r.stderr
    assert "validacao dos intervalos de arquivo" in r.stdout
    rep = json.loads(out.read_text(encoding="utf-8"))
    assert set(rep) == set(baseline) and set(rep["files"][0]) == set(baseline["files"][0])
    assert len(rep["files"]) == 9


def test_probe_wrapper_scan(synth_file):
    r = _run("scripts/xvc_probe.py", str(synth_file), "--scan-end", "0x40000")
    assert r.returncode == 0, r.stderr
    assert "strings de regiao" in r.stdout and "'msft-xvd'" in r.stdout


def test_pe_check_wrapper_exit_codes():
    assert _run("scripts/pe_check.py", str(FIX / "pe" / "s_amd64_ok.bin")).returncode == 0
    assert _run("scripts/pe_check.py", str(FIX / "pe" / "s_raw_fora.bin")).returncode == 1
    assert _run("scripts/pe_check.py", str(FIX / "pe" / "vazio.bin")).returncode == 1
    r = _run("scripts/regf_dump.py", str(FIX / "userdata_files" / "microsoft_gameconfig.bin"))
    assert r.returncode == 0 and "game_scarlett_master.exe" in r.stdout


def test_launcher_runs_isolated():
    r = _run("xvcintel.py", "pe", str(FIX / "Catalog000.bin"))
    assert r.returncode == 0 and "XBOX_CODE_CATALOG" in r.stdout
