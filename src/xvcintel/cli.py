"""CLI do XVC Intelligence Engine (somente leitura do pacote).

Exemplos:
  python -I xvcintel.py analyze PACOTE.xvc --out reports --baseline tests/fixtures/xvc_files_report_baseline.json
  python -I xvcintel.py fingerprint PACOTE.xvc --name game_scarlett_master.exe
  python -I xvcintel.py query --graph reports/graph.json --node game_scarlett_master.exe
  python -I xvcintel.py pe C:/Windows/System32/notepad.exe
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys
import time

from .core.reader import FileSource
from .core.result import Err, Ok
from .engines.configs import load_configs
from .engines.fingerprint import DEFAULT_TARGET, fingerprint_executable, profile_lines
from .engines.graph import Graph, build_graph, query_lines
from .engines.integrity import IntegrityOptions, run_integrity
from .engines.package import Package, header_lines, layout_lines, load_package
from .engines.pages import PageOptions, run_pages
from .evidence.findings import build_findings
from .evidence.html_report import render_html
from .evidence.reports import compare_files_reports, files_report, findings_report, write_json
from .formats.pe import parse_pe, report_lines
from .formats.regf import dump_lines, parse_hive
from .formats.userdata import safe_basename


class SafetyError(Exception):
    pass


def guard_output(path: str, package: str | None) -> str:
    """Recusa gravar dentro da pasta do pacote (o pacote e seus vizinhos nunca sao tocados)."""
    out = os.path.abspath(path)
    if package:
        pkg_dir = os.path.dirname(os.path.abspath(package))
        if os.path.normcase(out).startswith(os.path.normcase(pkg_dir) + os.sep) or \
                os.path.normcase(out) == os.path.normcase(os.path.abspath(package)):
            raise SafetyError(f"recusado: saida {out} fica dentro da pasta do pacote {pkg_dir}")
    return out


def _open(path: str) -> Package:
    src = FileSource(path)
    r = load_package(src)
    if isinstance(r, Err):
        raise SystemExit(f"erro ao ler o pacote: {r.error}")
    return r.value


def _print_checks(checks) -> None:
    for c in checks:
        print(f"   [{c.status:<7}] {c.id:<34} {c.detail[:300]}")
        if c.coverage:
            print(f"   {'':<10}{'':<34} cobertura: {c.coverage[:200]}")


def cmd_header(a) -> int:
    p = _open(a.path)
    print("== cabecalho XVD")
    print("\n".join(header_lines(p.header)))
    if p.embedded_header:
        print(f"== cabecalho do XVD embutido @ 0x{p.layout.get('XVD embutido').offset:X}")
        print("\n".join(header_lines(p.embedded_header)))
    return 0


def cmd_layout(a) -> int:
    p = _open(a.path)
    print("\n".join(layout_lines(p.layout, p.size)))
    _print_checks(p.checks)
    return 0 if all(c.status != "FAIL" for c in p.checks) else 1


def cmd_xvcinfo(a) -> int:
    p = _open(a.path)
    xi = p.xvcinfo
    if not xi:
        print("XvcInfo indisponivel:", p.errors)
        return 1
    print(f"== XvcInfo @ 0x{xi.base_offset:X}")
    for k, v in xi.fields.items():
        print(f"   {k:<22} 0x{v:X}")
    for i, k in enumerate(xi.keys):
        print(f"   KeyId[{i}] {k}")
    print(f"== {len(xi.regions)} regioes")
    for r in xi.regions:
        segs = xi.region_segments(r)
        print(f"   {r.index:>2} 0x{r.id:>8X} key={'-' if not r.keyed else r.key_id:>2} flags=0x{r.flags:X} "
              f"seg={r.first_segment_index:>3} n={len(segs):>3} 0x{r.offset:012X} +0x{r.length:X} {r.hash.hex()} {r.description}")
    print(f"== {len(xi.segments)} segmentos em +0x{xi.seg_off:X}; array por segmento em +0x{xi.segval_off:X}; "
          f"tabela de paginas ({len(xi.page_table)}) em +0x{xi.table_off:X}")
    return 0


def cmd_files(a) -> int:
    p = _open(a.path)
    for n, ok, d in p.file_checks:
        print(f"   [{'OK' if ok else 'FALHA'}] {n}" + (f"  ({d})" if d else ""))
    if a.list:
        for r in p.rows:
            print(f"   {r.index:>3}  0x{r.region.id if r.region else 0:<10X} 0x{r.start:<12X} 0x{r.size:<11X} {r.name}")
    return 0 if all(ok for _, ok, _ in p.file_checks) else 1


def _integrity_opts(a) -> IntegrityOptions:
    return IntegrityOptions(cap_bytes=int(a.cap_mb * 1024 * 1024), full_leaf_level=a.full_leaf,
                            leaf_level_samples=a.samples, random_data_pages=a.samples // 2)


def cmd_integrity(a) -> int:
    p = _open(a.path)
    res = run_integrity(p, _integrity_opts(a))
    _print_checks(res)
    return 0 if all(c.status != "FAIL" for c in res) else 1


def cmd_pages(a) -> int:
    p = _open(a.path)
    res = run_pages(p, PageOptions(full_scan=a.full_pages))
    _print_checks(res)
    for c in res:
        if c.id == "pages.segment_values" and c.data.get("exceptions"):
            print(json.dumps(c.data["exceptions"], indent=1, ensure_ascii=False))
    return 0 if all(c.status != "FAIL" for c in res) else 1


def cmd_fingerprint(a) -> int:
    p = _open(a.path)
    prof = fingerprint_executable(p, a.name, cap_bytes=int(a.cap_mb * 1024 * 1024))
    print("\n".join(profile_lines(prof)))
    if a.json:
        write_json(guard_output(a.json, a.path), prof)
    return 0


def cmd_graph(a) -> int:
    p = _open(a.path)
    g = build_graph(p)
    g.save(guard_output(a.out, a.path))
    print(f"grafo: {len(g.nodes)} nos, {len(g.edges)} arestas -> {os.path.abspath(a.out)}")
    return 0


def cmd_query(a) -> int:
    g = Graph.load(a.graph)
    print("\n".join(query_lines(g, a.node, a.relation)))
    return 0


def cmd_pe(a) -> int:
    with open(a.file, "rb") as f:
        data = f.read()
    r = parse_pe(data)
    if isinstance(r, Err):
        print(f"Nao e um PE legivel: {r.error}")
        return 1
    print("\n".join(report_lines(r.value)))
    if a.json:
        write_json(a.json, r.value.to_dict())
    return 1 if r.value.problems else 0


def cmd_regf(a) -> int:
    with open(a.file, "rb") as f:
        r = parse_hive(f.read())
    if isinstance(r, Err):
        print(f"hive invalido: {r.error}")
        return 1
    print("\n".join(dump_lines(*r.value)))
    return 0


def cmd_userdata(a) -> int:
    p = _open(a.path)
    ud = p.userdata
    if not ud:
        print("user data indisponivel", p.errors)
        return 1
    print(f"PackageFullName {ud.package_full_name!r}  FileCount {len(ud.files)}")
    for f in ud.files:
        print(f"   +0x{f.start:04x} 0x{f.size:<6x} {f.path}")
    if a.extract:
        out = guard_output(a.extract, a.path)
        os.makedirs(out, exist_ok=True)
        for f in ud.files:
            name = safe_basename(f.path)
            if name:
                with open(os.path.join(out, name), "wb") as o:
                    o.write(f.data)
        print(f"extraidos em {out}")
    return 0


def cmd_regress(a) -> int:
    with open(a.old, encoding="utf-8") as f:
        old = json.load(f)
    with open(a.new, encoding="utf-8") as f:
        new = json.load(f)
    r = compare_files_reports(old, new)
    print(json.dumps(r, indent=1, ensure_ascii=False))
    return 0 if r["passed"] else 1


def cmd_analyze(a) -> int:
    t0 = time.time()
    out = guard_output(a.out, a.path)
    os.makedirs(out, exist_ok=True)
    p = _open(a.path)
    cfg = load_configs(p)
    iopt = _integrity_opts(a)
    popt = PageOptions(full_scan=a.full_pages)
    print("== integridade")
    checks = run_integrity(p, iopt)
    _print_checks(checks)
    print("== paginas")
    pchecks = run_pages(p, popt)
    _print_checks(pchecks)
    checks += pchecks
    prof = fingerprint_executable(p, a.name, cap_bytes=iopt.cap_bytes, configs=cfg)
    g = build_graph(p, checks, cfg)
    fr = files_report(p, keep_legacy_source_note=False)
    regression = None
    if a.baseline:
        with open(a.baseline, encoding="utf-8") as f:
            regression = compare_files_reports(json.load(f), fr)
        regression["baseline"] = os.path.abspath(a.baseline)
    tests_summary = None
    if a.tests_json and os.path.exists(a.tests_json):
        with open(a.tests_json, encoding="utf-8") as f:
            tests_summary = json.load(f)
    findings = build_findings(p, checks, prof, cfg)
    opts = {"cap_bytes": iopt.cap_bytes, "full_leaf_level": iopt.full_leaf_level, "full_page_scan": popt.full_scan,
            "leaf_level_samples": iopt.leaf_level_samples, "seed": iopt.seed}
    rep = findings_report(p, checks, findings, regression, opts, tests_summary)
    gstats = {"nodes": len(g.nodes), "edges": len(g.edges),
              "by_confidence": dict(collections.Counter(e["confidence"] for e in g.edges))}
    write_json(os.path.join(out, "findings.json"), rep)
    write_json(os.path.join(out, "xvc_files_report.json"), fr)
    write_json(os.path.join(out, "executable_profile.json"), prof)
    g.save(os.path.join(out, "graph.json"))
    with open(os.path.join(out, "report.html"), "w", encoding="utf-8") as f:
        f.write(render_html(rep, prof, gstats))
    if regression:
        write_json(os.path.join(out, "regression.json"), regression)
    print(f"== achados: {rep['summary']['findings_by_level']}; checagens: {rep['summary']['checks_by_status']}")
    if regression:
        print(f"== regressao: {'OK' if regression['passed'] else 'DIFERENCAS'}; source: {regression['source_differences']}")
    print(f"== relatorios em {out} ({time.time() - t0:.1f} s, {p.src.stats.bytes_read / 2**20:.0f} MB lidos)")
    return 0 if not any(c.status == "FAIL" for c in checks + p.checks) else 1


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="xvcintel", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)

    def pkg(name, fn, help_):
        s = sp.add_parser(name, help=help_)
        s.add_argument("path")
        s.set_defaults(fn=fn)
        return s

    def caps(s):
        s.add_argument("--cap-mb", type=float, default=160, help="limite por regiao/segmento para hash completo (MB)")
        s.add_argument("--full-leaf", action="store_true", help="confere todas as paginas L0 contra L1")
        s.add_argument("--samples", type=int, default=64, help="amostras de paginas L0 / paginas de dados")

    pkg("header", cmd_header, "cabecalho XVD (e do XVD embutido)")
    pkg("layout", cmd_layout, "layout calculado + checagens estruturais")
    pkg("xvcinfo", cmd_xvcinfo, "campos, regioes e segmentos do XvcInfo")
    s = pkg("files", cmd_files, "mapa de arquivos e validacao")
    s.add_argument("--list", action="store_true")
    caps(pkg("integrity", cmd_integrity, "verificacoes de hash"))
    s = pkg("pages", cmd_pages, "tabela de paginas x unidades de dados")
    s.add_argument("--full-pages", action="store_true", help="varre todas as folhas do drive data")
    s = pkg("fingerprint", cmd_fingerprint, "perfil individual de um executavel")
    s.add_argument("--name", default=DEFAULT_TARGET)
    s.add_argument("--cap-mb", type=float, default=160)
    s.add_argument("--json")
    s = pkg("graph", cmd_graph, "grava o grafo de conhecimento")
    s.add_argument("--out", required=True)
    s = pkg("userdata", cmd_userdata, "lista/extrai os arquivos do user data")
    s.add_argument("--extract", metavar="DIR")
    s = pkg("analyze", cmd_analyze, "roda tudo e grava JSON/HTML")
    caps(s)
    s.add_argument("--full-pages", action="store_true")
    s.add_argument("--out", default="reports")
    s.add_argument("--name", default=DEFAULT_TARGET)
    s.add_argument("--baseline", help="relatorio de arquivos anterior para regressao")
    s.add_argument("--tests-json", help="resumo dos testes pytest a incluir no relatorio")
    s = sp.add_parser("query", help="consulta o grafo")
    s.add_argument("--graph", required=True)
    s.add_argument("--node", required=True)
    s.add_argument("--relation")
    s.set_defaults(fn=cmd_query)
    s = sp.add_parser("pe", help="analisa um arquivo PE legivel")
    s.add_argument("file")
    s.add_argument("--json")
    s.set_defaults(fn=cmd_pe)
    s = sp.add_parser("regf", help="despeja um hive de registro")
    s.add_argument("file")
    s.set_defaults(fn=cmd_regf)
    s = sp.add_parser("regress", help="compara dois relatorios de arquivos (schema 1)")
    s.add_argument("old")
    s.add_argument("new")
    s.set_defaults(fn=cmd_regress)
    return ap


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    try:
        return a.fn(a)
    except SafetyError as ex:
        print(str(ex), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
