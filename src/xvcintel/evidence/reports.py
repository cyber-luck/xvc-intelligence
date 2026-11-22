"""Relatorios JSON: relatorio de arquivos (schema 1, compativel com o xvc_probe.py
original), relatorio de achados e comparacao de regressao."""
from __future__ import annotations

import datetime
import json

from ..engines.package import Package
from ..engines.profiler import classification_rules, profile_files
from ..formats.layout import DRIVE
from .model import CheckResult, Finding

LEGACY_SOURCE_NOTE = "layout calculado do cabecalho XVD (MDU pela regiao XVC-MDU)"


def files_report(pkg: Package, keep_legacy_source_note: bool = True) -> dict:
    """Mesmo schema (schema_version 1) e mesmas chaves do relatorio original."""
    note = LEGACY_SOURCE_NOTE if keep_legacy_source_note else \
        "layout calculado do cabecalho XVD (MutableDataPageCount em 0x470, conferido com a regiao XVC-MDU)"
    return {
        "schema_version": 1,
        "source": {
            "path": str(pkg.path),
            "size": pkg.size,
            "vduid": str(pkg.header.vduid),
            "drive_data_offset": f"0x{pkg.layout.get(DRIVE).offset:X}",
            "drive_data_offset_source": note,
        },
        "classification_rules": classification_rules(),
        "validation": {
            "passed": all(ok for _, ok, _ in pkg.file_checks),
            "checks": [{"name": n, "passed": ok, "detail": d} for n, ok, d in pkg.file_checks],
        },
        "files": profile_files(pkg),
    }


def findings_report(pkg: Package, checks: list[CheckResult], findings: list[Finding], regression: dict | None,
                    options: dict, tests_summary: dict | None = None) -> dict:
    by_level: dict[str, int] = {}
    for f in findings:
        by_level[f.level] = by_level.get(f.level, 0) + 1
    return {
        "schema": "xvcintel.findings/1",
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "source": {"path": pkg.path, "size": pkg.size, "vduid": str(pkg.header.vduid),
                   "bytes_read": getattr(pkg.src, "stats", None).bytes_read if getattr(pkg.src, "stats", None) else None},
        "options": options,
        "read_only": "o pacote foi aberto apenas em modo 'rb'; nenhuma escrita, decifragem ou uso de chave",
        "summary": {"findings_by_level": by_level,
                    "checks_by_status": _count(c.status for c in checks + pkg.checks)},
        "findings": [f.to_dict() for f in findings],
        "checks": [c.to_dict() for c in pkg.checks + checks],
        "file_map_checks": [{"name": n, "passed": ok, "detail": d} for n, ok, d in pkg.file_checks],
        "regression": regression,
        "tests": tests_summary,
        "next_investigations": NEXT_INVESTIGATIONS,
    }


NEXT_INVESTIGATIONS = [
    "Obter, por via legitima, um PE legivel de game_scarlett_master.exe (build de desenvolvimento ou dump autorizado) "
    "e rodar `xvcintel pe` nele; sem isso nenhuma estrutura interna do executavel e acessivel.",
    "Comparar com outra versao do mesmo pacote (ex.: 1.0.2.0): testar se paginas/unidades de dados sao herdadas "
    "(explicaria a reutilizacao de unidades de dados e as excecoes dos segmentos 78/90).",
    "Rodar --full-leaf/--full-pages e aumentar --cap-mb para cobrir as 15 regioes e 59 segmentos acima do limite.",
    "Decodificar a BAT do dynamic header do XVD embutido (EraOS) para fechar seu layout.",
    "Testar outras serializacoes para o hash compartilhado XVC-HD/XVC-MD e para OriginalXvcDataHash.",
]


def _count(items) -> dict:
    d: dict = {}
    for i in items:
        d[i] = d.get(i, 0) + 1
    return d


def compare_files_reports(old: dict, new: dict) -> dict:
    """Regressao: mesmo conjunto de arquivos e mesmos campos por arquivo."""
    out: dict = {"schema_keys_equal": set(old) == set(new), "file_count_old": len(old.get("files", [])),
                 "file_count_new": len(new.get("files", [])), "field_differences": [], "source_differences": {},
                 "validation_equal": old.get("validation") == new.get("validation"),
                 "classification_rules_equal": old.get("classification_rules") == new.get("classification_rules")}
    for k in set(old.get("source", {})) | set(new.get("source", {})):
        if old.get("source", {}).get(k) != new.get("source", {}).get(k):
            out["source_differences"][k] = {"old": old.get("source", {}).get(k), "new": new.get("source", {}).get(k)}
    om = {f["filename"]: f for f in old.get("files", [])}
    nm = {f["filename"]: f for f in new.get("files", [])}
    out["missing_in_new"] = sorted(set(om) - set(nm))
    out["added_in_new"] = sorted(set(nm) - set(om))
    for name in sorted(set(om) & set(nm)):
        a, b = om[name], nm[name]
        if set(a) != set(b):
            out["field_differences"].append({"file": name, "keys": sorted(set(a) ^ set(b))})
        for k in sorted(set(a) & set(b)):
            if a[k] != b[k]:
                out["field_differences"].append({"file": name, "field": k, "old": a[k], "new": b[k]})
    out["passed"] = (out["schema_keys_equal"] and not out["missing_in_new"] and not out["added_in_new"]
                     and not out["field_differences"] and out["validation_equal"])
    return out


def write_json(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
