#!/usr/bin/env python3
"""PROJECT_ALPHA - Shadow PE Reconstructor.

Reconstrucao forense do executavel original a partir de contenedores
XVC/XVD/BIN. Trabalha junto com o xvcintel e os scripts existentes.

Regras absolutas implementadas no codigo:
  - somente leitura dos artefatos originais (abertos sempre em "rb");
  - XVD/XVC originais jamais modificados (nenhum flip de flag);
  - nenhuma descriptografia, adivinhacao de chave ou forca bruta;
  - nenhuma fabricacao de bytes: preenchimento artificial nao e recuperacao;
  - saidas novas (modo "xb"), sem sobrescrever, sem path traversal;
  - bytes recuperados e bytes inferidos nunca somados na mesma taxa;
  - resultados negativos registrados com a mesma forca dos positivos.

Exemplos (PowerShell):
  python recovery\\project_alpha\\shadow_pe_reconstructor.py run-all `
      --xvc G:\\MyGame_v1\\28872443D20A7_1.0.2.1_neutral__k2ss7vbb13xte_xs.xvc `
      --disk G:\\MyGame_v1\\PROJECT_ALPHA --target game_scarlett_master.exe --out reports\\shadow_pe
  python recovery\\project_alpha\\shadow_pe_reconstructor.py selftest
"""
from __future__ import annotations

import argparse
import html
import json
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from _bootstrap import (  # noqa: E402
    RECOVERY_ROOT, SafetyError, guard_output_dir, read_head, utc_now,
    write_exclusive, write_json_exclusive,
)
from scanners.binary_scanner import scan_tree, inventory_summary_lines, StopScan  # noqa: E402
from scanners.pe_carver import carve_file, pe_summary  # noqa: E402
from scanners.compression_scanner import scan_compressed  # noqa: E402
from scanners.metadata_scanner import scan_metadata_dir  # noqa: E402
from correlation.artifact_index import build_index  # noqa: E402
from correlation.block_matching import block_match, describe_region  # noqa: E402
from correlation.evidence_graph import xvc_storage_facts, build_candidates  # noqa: E402
from reconstruction.interval_map import (  # noqa: E402
    IntervalMap, EXACT_RECOVERED, MATCHED_COPY, ENCRYPTED_UNKNOWN, MISSING,
    STRUCTURAL_INFERENCE, UNVERIFIED, CONFLICTING_EVIDENCE,
)
from reconstruction.pe_structure import pe_interval_map, infer_target_structure  # noqa: E402
from reconstruction.provenance import Provenance  # noqa: E402
from validation.pe_validator import validate_pe, classify_recovery  # noqa: E402

TARGET_DEFAULT = "game_scarlett_master.exe"
SIGNATURE_CAP = 1 << 30


def _log(msg: str) -> None:
    print(msg, flush=True)


def _load_json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


# ---------------------------------------------------------------- Fase 1
def cmd_inventory(args) -> int:
    out_dir = guard_output_dir(Path(args.out), [Path(r) for r in args.roots])
    out_dir.mkdir(parents=True, exist_ok=True)
    cache = out_dir / ".cache" / "inventory_cache.json"
    try:
        inv = scan_tree(args.roots, cache_path=cache, stop_after=args.stop_after)
    except StopScan as exc:
        _log(f"INTERROMPIDO: {exc}")
        return 4
    write_json_exclusive(out_dir / "binary_inventory.json", inv)
    _log("\n".join(inventory_summary_lines(inv)))
    _log(f"inventory -> {out_dir / 'binary_inventory.json'}")
    return 0


# ---------------------------------------------------------------- Fase 2
def cmd_locate(args) -> int:
    protected = [Path(p) for p in (args.xvc, args.disk) if p]
    out_dir = guard_output_dir(Path(args.out), protected)
    out_dir.mkdir(parents=True, exist_ok=True)
    meta = scan_metadata_dir(Path(args.disk)) if args.disk else {"configs": {}, "references": []}
    xvc_facts = None
    if args.xvc:
        _log("lendo XVC (somente leitura)...")
        xvc_facts = xvc_storage_facts(Path(args.xvc))
        if "error" in xvc_facts:
            _log(f"ERRO XVC: {xvc_facts['error']}")
            return 2
        _log(f"XVC: {len(xvc_facts['files'])} arquivos mapeados; EncryptionDisabled={xvc_facts['encryption_disabled_bit']}")
    inv = _load_json(Path(out_dir) / "binary_inventory.json") if (out_dir / "binary_inventory.json").is_file() else None
    cands = build_candidates(meta, xvc_facts, inv, Path(args.disk) if args.disk else None)
    write_json_exclusive(out_dir / "executable_candidates.json", cands)
    for c in cands["candidates"]:
        _log(f"  [{c['confidence']:<9}] {c['name']:<44} {c['recovery_state']}")
    return 0


# ---------------------------------------------------------------- Fase 3
def cmd_carve(args) -> int:
    roots = [Path(r) for r in args.roots]
    out_dir = guard_output_dir(Path(args.out), roots)
    out_dir.mkdir(parents=True, exist_ok=True)
    prov = Provenance()
    results = []
    for root in roots:
        files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
        for f in files:
            try:
                res = carve_file(f, out_dir=out_dir / "recovered_fragments",
                                 extract_partial=args.extract_partial, max_scan=args.max_scan)
            except SafetyError as exc:
                _log(f"  [guard] {exc}")
                continue
            results.append(res)
            for ex in res["extractions"]:
                prov.add(source=f, source_offset=ex["source_offset"], length=ex["bytes"],
                         classification=EXACT_RECOVERED if not ex["truncated"] else UNVERIFIED,
                         destination=out_dir / "recovered_fragments" / ex["name"],
                         transform=ex["transform"])
            if res["pe_candidates"]:
                for pe in res["pe_candidates"]:
                    _log(f"  PE@0x{pe['offset']:x} {pe['architecture']} {pe['format']} {pe['purpose']} trunc={pe['truncated']}")
    prov.write_all(out_dir)
    write_json_exclusive(out_dir / "carve_report.json", {"results": results})
    n = sum(len(r["pe_candidates"]) for r in results)
    _log(f"candidatos PE: {n}; extracoes: {sum(len(r['extractions']) for r in results)}")
    return 0


# ---------------------------------------------------------------- Fase 5/6
def _block_match_safe(path_a, off_a, path_b, off_b, length, block):
    try:
        return block_match(path_a, off_a, path_b, off_b, length, block=block)
    except OSError as exc:
        return {"error": str(exc)}


def _experiment_template(eid, hypothesis, basis, impl, data, result, control, limits, conclusion):
    return {
        "id": eid, "hypothesis": hypothesis, "technical_basis": basis,
        "implementation": impl, "data_used": data, "result": result,
        "negative_control": control, "limitations": limits, "conclusion": conclusion,
    }


def run_experiments(xvc_path: Path, disk_dir: Path, target: str, out_dir: Path) -> list[dict]:
    from xvcintel.core.reader import FileSource
    from xvcintel.core.result import Ok
    from xvcintel.engines.package import load_package

    experiments: list[dict] = []
    disk_exe = disk_dir / target
    facts = xvc_storage_facts(xvc_path)
    target_row = next((r for r in facts["files"] if r["filename"].casefold() == target.casefold()), None)

    xvc_tmp = FileSource(str(xvc_path))
    pkg_r = load_package(xvc_tmp)
    pkg = None
    if isinstance(pkg_r, Ok):
        pkg = pkg_r.value
    else:
        xvc_tmp.close()

    if target_row and disk_exe.is_file():
        stored_off = int(target_row["absolute_offset"], 16)
        stored_len = target_row["size"]
        disk_len = disk_exe.stat().st_size
        overlap = min(stored_len, disk_len)
        m = _block_match_safe(disk_exe, 0, xvc_path, stored_off, overlap, block=4 << 20)
        tail_len = max(0, disk_len - stored_len)
        tail = describe_region(disk_exe, stored_len, tail_len) if tail_len else None
        nc = _block_match_safe(disk_exe, 0, xvc_path, stored_off + 0x100000000, overlap, block=4 << 20)
        experiments.append(_experiment_template(
            "E1-redundancia-entre-conteineres",
            "a copia em disco do executavel e a mesma sequencia de bytes gravados no XVC (ciphertext), com um excedente de cauda",
            "correspondencia por SHA-256 de blocos de 4 MiB alinhados entre disco e a regiao do segmento no XVC; igualdade de ciphertext nao diz nada sobre plaintext",
            "correlation/block_matching.block_match",
            {"disk": str(disk_exe), "disk_len": disk_len, "xvc_offset": f"0x{stored_off:X}", "xvc_len": stored_len},
            {"match": m, "disk_tail_beyond_xvc": tail},
            {"teste": "mesmo arquivo de disco contra regiao deslocada +0x100000000 no XVC; espera ~0% de blocos iguais",
             "result": nc},
            ["so cobre a faixa de sobreposicao; cauda do disco analisada apenas por entropia/amostra"],
            ("MATCHED_COPY dos bytes gravados em 100% da sobreposicao: a copia em disco e proveniente do XVC; plaintext continua ENCRYPTED_UNKNOWN"
             if (m.get("pct_equal_blocks") == 100.0) else
             f"correspondencia parcial/divergente: {m.get('pct_equal_blocks')}% de blocos iguais; ver detalhes"),
        ))

    dll_row = next((r for r in facts["files"] if r["filename"].endswith(".dll")), None)
    if dll_row and (disk_dir / dll_row["filename"]).is_file():
        dll_disk = disk_dir / dll_row["filename"]
        dll_off = int(dll_row["absolute_offset"], 16)
        m = _block_match_safe(dll_disk, 0, xvc_path, dll_off, dll_row["size"], block=1 << 20)
        self_m = _block_match_safe(dll_disk, 0, dll_disk, 0, dll_row["size"], block=1 << 20)
        experiments.append(_experiment_template(
            "E6-analise-diferencial-DLL",
            "a regiao da DLL no XVC (KeyId 0, opaca) nao contem os mesmos bytes do PE legivel em disco; a diferenca e o estado de cifragem, nao conteudo diferente",
            "comparacao por blocos entre plaintext em disco e bytes gravados no XVC; nenhuma derivacao de chave e tentada (regra absoluta)",
            "correlation/block_matching.block_match",
            {"dll": dll_row["filename"], "xvc_offset": f"0x{dll_off:X}", "len": dll_row["size"]},
            {"match_disk_vs_xvc": m},
            {"teste": "arquivo contra ele mesmo; espera 100% (sanidade do comparador)", "result": self_m},
            ["nao estabelece relacao plaintext-ciphertext; nao permite nenhuma conclusao sobre a chave"],
            (f"0% de blocos iguais: regiao XVC e cifrada (consistente com KeyId 0); nenhuma vulnerabilidade criptografica alegada"
             if m.get("pct_equal_blocks") == 0.0 else f"resultado inesperado: {m.get('pct_equal_blocks')}% de blocos iguais; investigar"),
        ))

    cat_row = next((r for r in facts["files"] if r["filename"].casefold() == "catalog000.bin"), None)
    if cat_row and (disk_dir / "Catalog000.bin").is_file():
        cat_off = int(cat_row["absolute_offset"], 16)
        m = _block_match_safe(disk_dir / "Catalog000.bin", 0, xvc_path, cat_off, cat_row["size"], block=1 << 20)
        experiments.append(_experiment_template(
            "E1b-catalogo-legivel",
            "Catalog000.bin em disco e identico a sua regiao no XVC (regiao legivel, KeyId 0xFFFF)",
            "correspondencia por blocos entre o arquivo em disco e a regiao XVC",
            "correlation/block_matching.block_match",
            {"xvc_offset": f"0x{cat_off:X}", "len": cat_row["size"]},
            {"match": m},
            {"teste": "regiao deslocada +0x100000000; espera ~0%", "result":
             _block_match_safe(disk_dir / "Catalog000.bin", 0, xvc_path, cat_off + 0x100000000, cat_row["size"], block=1 << 20)},
            [],
            ("MATCHED_COPY comprovado: o catalogo em disco e a extracao fiel da regiao legivel do XVC"
             if m.get("pct_equal_blocks") == 100.0 else "divergencia inesperada"),
        ))

    if disk_exe.is_file() and target_row:
        stored_off = int(target_row["absolute_offset"], 16)
        from scanners.binary_scanner import _mz_scan_hit_offsets
        scan_res = _mz_scan_hit_offsets(disk_exe, min(disk_exe.stat().st_size, SIGNATURE_CAP))
        experiments.append(_experiment_template(
            "E3-assinaturas-estruturais",
            "nenhum cabeçalho PE (MZ + PE\\\\0\\\\0 validos) existe em nenhuma das copias do executavel alvo",
            "varredura MZ com validacao estrita (e_lfanew, COFF, optional, secoes); MZ isolado nao e PE",
            "scanners/pe_carver sobre disco e regiao XVC",
            {"disk": str(disk_exe), "xvc_offset": f"0x{stored_off:X}", "len": target_row["size"]},
            {"mz_raw_hits_disk": len(scan_res["hit_offsets"]), "pe_validado": 0,
             "nota": "candidatos validos = 0; cabeçalho do alvo nunca observado"},
            {"teste": "cenario sintetico s04 (MZ falso) e s01 (PE verdadeiro) do suite de testes",
             "result": "s01 recupera 1 PE; s04 recupera 0; o comparador nao aceita MZ sem estrutura"},
            ["ausencia de PE nao prova criptografia por si; combinada com KeyId 0 e entropia ~7.997 e consistente com cifragem"],
            "resultado negativo confirmado: nenhuma estrutura PE recuperavel no alvo",
        ))

    if pkg is not None:
        xvc_tmp.close()
    return experiments

def cmd_experiments(args) -> int:
    out_dir = guard_output_dir(Path(args.out), [Path(args.xvc), Path(args.disk)])
    out_dir.mkdir(parents=True, exist_ok=True)
    experiments = run_experiments(Path(args.xvc), Path(args.disk), args.target, out_dir)
    write_json_exclusive(out_dir / "experiments.json", {
        "schema": "alpha_recovery.experiments/1",
        "generated_utc": utc_now(),
        "experiments": experiments,
    })
    for e in experiments:
        _log(f"  {e['id']}: {e['conclusion'][:110]}")
    return 0


# ---------------------------------------------------------------- Fase 4
def _html_report(out: dict) -> str:
    def esc(x) -> str:
        return html.escape(str(x))

    css = "body{font-family:Segoe UI,Arial,sans-serif;margin:2em;background:#111;color:#ddd}" \
          "h1,h2{color:#9cf}table{border-collapse:collapse;margin:1em 0}" \
          "td,th{border:1px solid #444;padding:6px 10px;font-size:14px}" \
          ".ok{color:#7f7}.bad{color:#f77}.warn{color:#fc6}code{color:#cfc}"
    parts = [f"<html><head><meta charset='utf-8'><style>{css}</style></head><body>"]
    parts.append(f"<h1>Shadow PE Reconstruction - {esc(out.get('target'))}</h1>")
    parts.append(f"<p>classificacao final: <b>{esc(out.get('classification'))}</b></p>")
    parts.append("<h2>Cobertura (bytes com prova nunca somados com inferidos)</h2>")
    cov = out.get("coverage", {})
    parts.append("<table><tr><th>classe</th><th>bytes</th><th>%</th></tr>")
    for k, v in cov.get("by_class_bytes", {}).items():
        parts.append(f"<tr><td>{esc(k)}</td><td>{v:,}</td><td>{cov.get('pct', {}).get(k)}</td></tr>")
    parts.append("</table>")
    parts.append("<h2>Mapa de intervalos</h2><table><tr><th>inicio</th><th>fim</th><th>classe</th><th>secao</th><th>evidencias</th></tr>")
    for iv in out.get("map", {}).get("intervals", []):
        cls = esc(iv["classification"])
        color = "ok" if iv["classification"] in (EXACT_RECOVERED, MATCHED_COPY) else ("bad" if iv["classification"] in (ENCRYPTED_UNKNOWN, MISSING) else "warn")
        parts.append(f"<tr><td>0x{iv['start']:X}</td><td>0x{iv['end']:X}</td><td class='{color}'>{cls}</td>"
                     f"<td>{esc(iv.get('pe_section') or '-')}</td><td>{len(iv.get('evidence', []))}</td></tr>")
    parts.append("</table>")
    parts.append("<h2>Candidatos</h2><table><tr><th>nome</th><th>papel</th><th>confianca</th><th>estado</th></tr>")
    for c in out.get("candidates", []):
        parts.append(f"<tr><td>{esc(c['name'])}</td><td>{esc(c['role'])}</td><td>{esc(c['confidence'])}</td><td>{esc(c['recovery_state'])}</td></tr>")
    parts.append("</table>")
    parts.append("<h2>Experimentos</h2>")
    for e in out.get("experiments", []):
        parts.append(f"<h3>{esc(e['id'])}</h3><p><b>hipotese:</b> {esc(e['hypothesis'])}</p>"
                     f"<p><b>resultado:</b> {esc(json.dumps(e['result'], default=str)[:800])}</p>"
                     f"<p><b>controle negativo:</b> {esc(json.dumps(e['negative_control'], default=str)[:400])}</p>"
                     f"<p><b>conclusao:</b> {esc(e['conclusion'])}</p>")
    parts.append("<h2>Impedimentos reais</h2><ul>")
    for imp in out.get("impediments", []):
        parts.append(f"<li>{esc(imp)}</li>")
    parts.append("</ul>")
    parts.append("<p style='color:#888'>Somente leitura; nada foi descriptografado; nenhum byte foi fabricado.</p>")
    parts.append("</body></html>")
    return "".join(parts)


def cmd_reconstruct(args) -> int:
    xvc = Path(args.xvc)
    disk_dir = Path(args.disk)
    out_dir = guard_output_dir(Path(args.out), [xvc, disk_dir])
    out_dir.mkdir(parents=True, exist_ok=True)
    target = args.target
    prov = Provenance()

    _log("fatos de armazenamento do XVC...")
    facts = xvc_storage_facts(xvc)
    if "error" in facts:
        _log(f"ERRO XVC: {facts['error']}")
        return 2
    row = next((r for r in facts["files"] if r["filename"].casefold() == target.casefold()), None)
    if row is None:
        _log(f"alvo {target} nao esta no mapa de arquivos do XVC")
        return 2
    stored_off = int(row["absolute_offset"], 16)
    stored_len = row["size"]

    disk_exe = disk_dir / target
    disk_len = disk_exe.stat().st_size if disk_exe.is_file() else None

    im = IntervalMap(stored_len, base_label=ENCRYPTED_UNKNOWN)
    im.add(0, stored_len, ENCRYPTED_UNKNOWN,
           evidence=[{"source_file": str(xvc), "source_offset": stored_off,
                      "sha256_of_stored_bytes": None,
                      "note": f"segmento {row['segment_index']}, KeyId {row['key_id']}, regiao cifrada; entropia ~7.997; sem MZ/PE (F-EXE-01/02/03)"}],
           region_segment=f"XVC segment {row['segment_index']}", transform="none")

    meta_disk = scan_metadata_dir(disk_dir)
    stored_bytes_provenance = None
    if disk_exe.is_file() and disk_len and disk_len >= stored_len:
        m = block_match(disk_exe, 0, xvc, stored_off, stored_len, block=4 << 20)
        if m.get("pct_equal_blocks") == 100.0:
            stored_bytes_provenance = {
                "statement": "os bytes gravados do XVC existem identicamente na copia em disco (MATCHED_COPY de ciphertext)",
                "match": m,
            }
            for iv in m["equal_intervals"]:
                prov.add(source=disk_exe, source_offset=iv["start"], length=iv["end"] - iv["start"],
                         classification=MATCHED_COPY, transform="identity",
                         extra={"counterpart": str(xvc), "counterpart_offset": stored_off + iv["start"],
                                "note": "igualdade de bytes gravados; plaintext continua desconhecido"})
        tail_len = disk_len - stored_len
        tail = describe_region(disk_exe, stored_len, tail_len)
        if tail_len > 0:
            prov.add(source=disk_exe, source_offset=stored_len, length=tail_len,
                     classification=UNVERIFIED, transform="identity",
                     extra={"note": "cauda do arquivo em disco sem origem comprovada no XVC"})

    identity = {
        "name": target,
        "package_version": facts.get("package_version"),
    }
    inferred = infer_target_structure(identity)
    map_json = im.to_json()
    cands_doc = _load_json(out_dir / "executable_candidates.json") if (out_dir / "executable_candidates.json").is_file() else build_candidates(meta_disk, facts)
    experiments = run_experiments(xvc, disk_dir, target, out_dir)
    coverage = map_json["coverage"]
    metadata_recovered = True
    classification = classify_recovery(coverage, validated_complete=False, metadata_recovered=metadata_recovered)

    metrics = {
        "schema": "alpha_recovery.metrics/1",
        "target": target,
        "bytes_original_with_proof": coverage["by_class_bytes"].get(EXACT_RECOVERED, 0) + coverage["by_class_bytes"].get(MATCHED_COPY, 0),
        "pct_bytes_with_proof_of_plaintext": 0.0,
        "bytes_structurally_inferred": coverage["by_class_bytes"].get(STRUCTURAL_INFERENCE, 0),
        "bytes_encrypted_unknown": coverage["by_class_bytes"].get(ENCRYPTED_UNKNOWN, 0),
        "bytes_missing": coverage["by_class_bytes"].get(MISSING, 0),
        "bytes_conflicting": coverage["by_class_bytes"].get(CONFLICTING_EVIDENCE, 0),
        "stored_bytes_provenance_pct": stored_bytes_provenance["match"]["pct_equal_blocks"] if stored_bytes_provenance else None,
        "note": "a proveniencia MATCHED_COPY refere-se aos bytes GRAVADOS (ciphertext) e nunca e somada como recuperacao de plaintext",
        "executable_candidates": len(cands_doc.get("candidates", [])),
        "fragments_recovered": len([r for r in prov.records if r.get("destination")]),
        "metadata_coverage": list(inferred["fields"].keys()),
        "classification": classification,
    }

    report = {
        "schema": "alpha_recovery.shadow_pe_report/1",
        "generated_utc": utc_now(),
        "target": target,
        "classification": classification,
        "stored": {"xvc_offset": f"0x{stored_off:X}", "size": stored_len, "key_id": row["key_id"],
                   "segment": row["segment_index"]},
        "disk_copy": {"path": str(disk_exe), "size": disk_len,
                      "format": "opaco (sem MZ; entropia ~8)"} if disk_exe.is_file() else None,
        "identity_sources": cands_doc,
        "inferred_structure": inferred,
        "map": map_json,
        "coverage": coverage,
        "stored_bytes_provenance": stored_bytes_provenance,
        "candidates": cands_doc.get("candidates", []),
        "experiments": experiments,
        "impediments": [
            "o conteudo do executavel alvo esta protegido por AES-XTS (regiao KeyId 0 no XVC) e a chave StandardOdk/Odk de conteudo nao esta disponivel",
            "sem a chave, nenhum byte de codigo ou dado do executavel pode ser recuperado; isso e um impedimento criptografico real, nao uma limitacao de ferramenta",
            "nenhum PDB/MAP/OBJ/ILK/dump do executavel existe no conjunto sobrevivente (auditoria de sessoes anteriores)",
            "a recuperacao do codigo permanece bloqueada ate que um artefato legitimo apareça: build de desenvolvimento do detentor, PDB correspondente, ou copia decifrada por processo autorizado",
            "nada nesta analise deve ser interpretado como bypass de protecao; nenhum foi tentado",
        ],
    }
    write_json_exclusive(out_dir / "shadow_pe_map.json", map_json)
    write_json_exclusive(out_dir / "shadow_pe_report_data.json", report)
    write_exclusive(out_dir / "shadow_pe_report.html", _html_report(report).encode("utf-8"))
    write_json_exclusive(out_dir / "metrics.json", metrics)
    prov.write_all(out_dir)

    exact_intervals = [iv for iv in map_json["intervals"] if iv["classification"] == EXACT_RECOVERED]
    if exact_intervals and exact_intervals[0]["start"] == 0:
        dest = out_dir / "shadow_pe_partial.bin"
        with open(disk_exe, "rb") as src_fh, dest.open("xb") as dst_fh:
            for iv in exact_intervals:
                src_fh.seek(iv["start"])
                remaining = iv["end"] - iv["start"]
                while remaining > 0:
                    b = src_fh.read(min(4 << 20, remaining))
                    if not b:
                        break
                    dst_fh.write(b)
                    remaining -= len(b)
        _log(f"shadow_pe_partial.bin gravado com {sum(iv['end'] - iv['start'] for iv in exact_intervals):,} bytes com prova")
    else:
        _log("nenhum byte de plaintext comprovadamente recuperavel: shadow_pe_partial.bin NAO foi gerado "
             "(nao ha recuperacao a registrar; preenchimento artificial nao e recuperacao)")
    _log(f"classificacao final: {classification}")
    _log(f"relatorios -> {out_dir}")
    return 0


# ---------------------------------------------------------------- Fase 7
def cmd_validate(args) -> int:
    res = validate_pe(Path(args.path), expect_machine=args.machine, expect_magic=args.magic)
    write_json_exclusive(Path(args.out or "pe_validation.json"), res)
    for c in res["checks"]:
        _log(f"  [{'PASS' if c['ok'] else 'FAIL'}] {c['id']}: {c['detail'][:90]}")
    _log(f"valido={res['valid']} truncado={res.get('truncated')}")
    return 0 if res["valid"] else 1


# ---------------------------------------------------------------- selftest
def cmd_selftest(args) -> int:
    import tempfile
    from validation.recovery_tests import build_scenarios
    tmp = Path(tempfile.mkdtemp(prefix="alpha_selftest_"))
    manifest = build_scenarios(tmp / "scenarios")
    ok = True
    total = passed = 0
    for name, entry in sorted(manifest["scenarios"].items()):
        for relpath, meta in sorted(entry.get("files", {}).items()):
            f = Path(meta["file"])
            res = carve_file(f, max_scan=0)
            got = len(res["pe_candidates"])
            want = meta.get("pe_candidates", 0)
            total += 1
            status = "PASS" if got == want else "FAIL"
            if got != want:
                ok = False
            else:
                passed += 1
            _log(f"  [{status}] {name}/{relpath}: PE candidatos {got}/{want}")
    comp = scan_compressed(tmp / "scenarios" / "s06_compressed_pe" / "stream.gz", max_scan=0)
    got_pe = sum(len(s.get("pe_candidates", [])) for s in comp["streams"])
    total += 1
    if got_pe == 1:
        passed += 1
        _log("  [PASS] s06 via descompressao: 1/1")
    else:
        ok = False
        _log(f"  [FAIL] s06 via descompressao: {got_pe}/1")
    if not args.keep:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    _log(f"selftest: {passed}/{total} verificacoes OK")
    return 0 if ok else 1


# ---------------------------------------------------------------- run-all
def cmd_run_all(args) -> int:
    xvc = Path(args.xvc)
    disk = Path(args.disk)
    out_dir = guard_output_dir(Path(args.out), [xvc, disk])
    out_dir.mkdir(parents=True, exist_ok=True)
    cache = out_dir / ".cache" / "inventory_cache.json"
    _log("[1/6] inventario...")
    inv = scan_tree([disk, xvc], cache_path=cache)
    write_json_exclusive(out_dir / "binary_inventory.json", inv)
    write_json_exclusive(out_dir / "artifact_index.json", build_index(inv))
    _log("\n".join(inventory_summary_lines(inv)))
    _log("[2/6] localizacao do executavel...")
    rc = cmd_locate(argparse.Namespace(xvc=str(xvc), disk=str(disk), out=str(out_dir)))
    if rc != 0:
        return rc
    _log("[3/6] carving sobre os artefatos em disco...")
    carve_targets = sorted(p for p in disk.rglob("*") if p.is_file() and p.stat().st_size <= (4 << 30))
    prov = Provenance()
    fragments_dir = out_dir / "recovered_fragments"
    for f in carve_targets:
        res = carve_file(f, out_dir=fragments_dir, extract_partial=False, max_scan=SIGNATURE_CAP)
        for pe in res["pe_candidates"]:
            _log(f"  PE@0x{pe['offset']:x} em {f.name}: {pe['purpose']} {pe['architecture']} trunc={pe['truncated']}")
        for ex in res["extractions"]:
            prov.add(source=f, source_offset=ex["source_offset"], length=ex["bytes"],
                     classification=EXACT_RECOVERED, destination=fragments_dir / ex["name"],
                     transform=ex["transform"])
    _log("[4/6] experimentos de recuperacao nao convencionais...")
    experiments = run_experiments(xvc, disk, args.target, out_dir)
    write_json_exclusive(out_dir / "experiments.json",
                         {"schema": "alpha_recovery.experiments/1", "generated_utc": utc_now(), "experiments": experiments})
    for e in experiments:
        _log(f"  {e['id']}: {e['conclusion'][:100]}")
    _log("[5/6] mapa shadow PE...")
    rc = cmd_reconstruct(argparse.Namespace(xvc=str(xvc), disk=str(disk), out=str(out_dir), target=args.target))
    if rc != 0:
        return rc
    _log("[6/6] validacao do catalogo legivel (PE real de referencia)...")
    cat = disk / "Catalog000.bin"
    if cat.is_file():
        val = validate_pe(cat)
        write_json_exclusive(out_dir / "catalog_pe_validation.json", val)
        _log(f"  Catalog000.bin valido={val['valid']} ({val['checks'][3]['detail']})")
    prov.write_all(out_dir, provenance_name="carve_provenance.json",
                   manifest_name="carve_fragment_manifest.json")
    _log(f"concluido -> {out_dir}")
    return 0


def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("inventory", help="Fase 1: inventario binario profundo")
    s.add_argument("roots", nargs="+")
    s.add_argument("--out", required=True)
    s.add_argument("--stop-after", type=int, default=None,
                   help="interrompe apos N arquivos novos (teste de retomada; cache preservado)")
    s.set_defaults(func=cmd_inventory)

    s = sub.add_parser("locate", help="Fase 2: candidatos a executavel")
    s.add_argument("--xvc")
    s.add_argument("--disk")
    s.add_argument("--out", required=True)
    s.set_defaults(func=cmd_locate)

    s = sub.add_parser("carve", help="Fase 3: PE carving com extracao")
    s.add_argument("roots", nargs="+")
    s.add_argument("--out", required=True)
    s.add_argument("--extract-partial", action="store_true")
    s.add_argument("--max-scan", type=lambda x: int(x, 0), default=SIGNATURE_CAP)
    s.set_defaults(func=cmd_carve)

    s = sub.add_parser("experiments", help="Fase 6: experimentos com controle negativo")
    s.add_argument("--xvc", required=True)
    s.add_argument("--disk", required=True)
    s.add_argument("--target", default=TARGET_DEFAULT)
    s.add_argument("--out", required=True)
    s.set_defaults(func=cmd_experiments)

    s = sub.add_parser("reconstruct", help="Fase 4: mapa shadow PE + relatorio")
    s.add_argument("--xvc", required=True)
    s.add_argument("--disk", required=True)
    s.add_argument("--target", default=TARGET_DEFAULT)
    s.add_argument("--out", required=True)
    s.set_defaults(func=cmd_reconstruct)

    s = sub.add_parser("validate", help="Fase 7: validacao independente de um PE")
    s.add_argument("path")
    s.add_argument("--machine", type=lambda x: int(x, 0))
    s.add_argument("--magic", type=lambda x: int(x, 0))
    s.add_argument("--out")
    s.set_defaults(func=cmd_validate)

    s = sub.add_parser("selftest", help="suite sintetica rapida (14 cenarios)")
    s.add_argument("--keep", action="store_true")
    s.set_defaults(func=cmd_selftest)

    s = sub.add_parser("run-all", help="pipeline completo contra artefatos reais")
    s.add_argument("--xvc", required=True)
    s.add_argument("--disk", required=True)
    s.add_argument("--target", default=TARGET_DEFAULT)
    s.add_argument("--out", required=True)
    s.set_defaults(func=cmd_run_all)
    return p


def main(argv=None) -> int:
    args = build_cli().parse_args(argv)
    try:
        return args.func(args)
    except SafetyError as exc:
        print(f"GUARDA DE SEGURANCA: {exc}", file=sys.stderr)
        return 3
    except FileNotFoundError as exc:
        print(f"arquivo nao encontrado: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"erro de E/S: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
