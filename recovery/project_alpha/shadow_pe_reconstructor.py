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
from correlation.catalog_semantics import (  # noqa: E402
    assess_identity, authenticode_digests, file_digests, semantic_catalog_report,
)
from correlation.evidence_graph import xvc_storage_facts, build_candidates  # noqa: E402
from reconstruction.interval_map import (  # noqa: E402
    IntervalMap, EXACT_RECOVERED, MATCHED_COPY, ENCRYPTED_UNKNOWN, MISSING,
    STRUCTURAL_INFERENCE, UNVERIFIED, CONFLICTING_EVIDENCE,
)
from reconstruction.pe_structure import pe_interval_map, infer_target_structure  # noqa: E402
from reconstruction.provenance import (  # noqa: E402
    Provenance, size_reconciliation, source_provenance_report,
)
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


def _stream_entropy(path: Path, offset: int, length: int) -> dict:
    """Entropia de Shannon (bits/byte) de uma faixa inteira, lida em streaming (somente leitura)."""
    import collections
    import math
    counts: collections.Counter = collections.Counter()
    done = 0
    with open(path, "rb") as fh:
        fh.seek(offset)
        while done < length:
            b = fh.read(min(4 << 20, length - done))
            if not b:
                break
            counts.update(b)
            done += len(b)
    n = sum(counts.values())
    h = -sum((v / n) * math.log2(v / n) for v in counts.values()) if n else 0.0
    return {"source": str(path), "offset": offset, "length_requested": length, "bytes_measured": n,
            "complete": n == length, "bits_per_byte": round(h, 6), "distinct_byte_values": len(counts)}


def _control_offset(container_size: int, off: int, length: int, shift: int = 0x100000000) -> int | None:
    """Offset de controle negativo dentro do conteiner e sem sobreposicao com [off, off+length)."""
    for cand in (off + shift, off - shift, off + length, off - length):
        if 0 <= cand and cand + length <= container_size and (cand + length <= off or cand >= off + length):
            return cand
    return None


def _negative_control(path_a: Path, path_b: Path, off_b: int, length: int, block: int) -> dict:
    size_b = Path(path_b).stat().st_size
    ctrl = _control_offset(size_b, off_b, length)
    if ctrl is None:
        return {"teste": "regiao deslocada no XVC", "result": {"error": "nenhum offset de controle cabe no conteiner"}}
    return {"teste": f"mesmo arquivo contra regiao nao sobreposta do XVC em 0x{ctrl:X} (deslocamento {ctrl - off_b:+#x}); espera ~0% de blocos iguais",
            "control_offset": f"0x{ctrl:X}",
            "result": _block_match_safe(path_a, 0, path_b, ctrl, length, block=block)}


def _carve_counts(path: Path) -> dict:
    res = carve_file(path, max_scan=0)
    return {"source": str(path), "bytes_scanned": res["bytes_scanned"],
            "entire_file_scanned": res["entire_file_scanned"], "raw_mz_hits": res["raw_mz_hits"],
            "mz_limit_reached": res["max_candidates_reached"], "pe_validated": len(res["pe_candidates"]),
            "pe_offsets": [pe["origin"]["offset"] for pe in res["pe_candidates"][:16]]}


def run_experiments(xvc_path: Path, disk_dir: Path, target: str, facts: dict | None = None) -> list[dict]:
    experiments: list[dict] = []
    disk_exe = disk_dir / target
    facts = facts or xvc_storage_facts(xvc_path)
    target_row = next((r for r in facts["files"] if r["filename"].casefold() == target.casefold()), None)
    e1_identical = False

    if target_row and disk_exe.is_file():
        stored_off = int(target_row["absolute_offset"], 16)
        stored_len = target_row["size"]
        disk_len = disk_exe.stat().st_size
        overlap = min(stored_len, disk_len)
        m = _block_match_safe(disk_exe, 0, xvc_path, stored_off, overlap, block=4 << 20)
        e1_identical = m.get("pct_equal_blocks") == 100.0 and overlap == stored_len
        tail_len = max(0, disk_len - stored_len)
        tail = describe_region(disk_exe, stored_len, tail_len) if tail_len else None
        experiments.append(_experiment_template(
            "E1-redundancia-entre-conteineres",
            "a copia em disco do executavel e a mesma sequencia de bytes gravados no XVC (ciphertext), com um excedente de cauda",
            "correspondencia por SHA-256 de blocos de 4 MiB alinhados entre disco e a regiao do segmento no XVC; igualdade de ciphertext nao diz nada sobre plaintext",
            "correlation/block_matching.block_match",
            {"disk": str(disk_exe), "disk_len": disk_len, "xvc_offset": f"0x{stored_off:X}", "xvc_len": stored_len},
            {"match": m, "disk_tail_beyond_xvc": tail},
            _negative_control(disk_exe, xvc_path, stored_off, overlap, 4 << 20),
            ["so cobre a faixa de sobreposicao; cauda do disco analisada apenas por entropia/amostra",
             "disco e XVC identicos sao a MESMA evidencia, nao dois testemunhos independentes"],
            ("MATCHED_COPY dos bytes gravados em 100% da sobreposicao: a copia em disco e proveniente do XVC; plaintext continua ENCRYPTED_UNKNOWN"
             if e1_identical else
             f"correspondencia parcial/divergente: {m.get('pct_equal_blocks')}% de blocos iguais; ver detalhes"),
        ))

    dll_row = next((r for r in facts["files"]
                    if r["filename"].casefold().endswith(".dll") and (disk_dir / r["filename"]).is_file()
                    and pe_summary(disk_dir / r["filename"], 0)), None)
    if dll_row:
        dll_disk = disk_dir / dll_row["filename"]
        dll_off = int(dll_row["absolute_offset"], 16)
        kid = dll_row.get("key_id")
        m = _block_match_safe(dll_disk, 0, xvc_path, dll_off, dll_row["size"], block=1 << 20)
        self_m = _block_match_safe(dll_disk, 0, dll_disk, 0, dll_row["size"], block=1 << 20)
        pct = m.get("pct_equal_blocks")
        if pct == 0.0 and kid == 0:
            concl = "0% de blocos iguais com KeyId 0 conferido: a regiao XVC contem bytes transformados (consistente com cifragem); nenhuma vulnerabilidade criptografica alegada"
        elif pct == 0.0:
            concl = f"0% de blocos iguais, mas KeyId={kid!r} (nao 0): diferenca nao atribuivel a cifragem por esta evidencia"
        else:
            concl = f"resultado inesperado: {pct}% de blocos iguais (KeyId={kid!r}); investigar"
        experiments.append(_experiment_template(
            "E6-analise-diferencial-DLL",
            "a regiao da DLL no XVC (KeyId 0, opaca) nao contem os mesmos bytes do PE legivel em disco; a diferenca e o estado de cifragem, nao conteudo diferente",
            "comparacao por blocos entre plaintext em disco (PE validado) e bytes gravados no XVC; nenhuma derivacao de chave e tentada (regra absoluta)",
            "correlation/block_matching.block_match",
            {"dll": dll_row["filename"], "xvc_offset": f"0x{dll_off:X}", "len": dll_row["size"], "key_id": kid},
            {"match_disk_vs_xvc": m},
            {"teste": "arquivo contra ele mesmo; espera 100% (sanidade do comparador)", "result": self_m},
            ["nao estabelece relacao plaintext-ciphertext; nao permite nenhuma conclusao sobre a chave"],
            concl,
        ))

    cat_row = next((r for r in facts["files"] if r["filename"].casefold() == "catalog000.bin"), None)
    cat_disk = next((p for p in disk_dir.iterdir() if p.is_file() and p.name.casefold() == "catalog000.bin"), None)
    if cat_row and cat_disk:
        cat_off = int(cat_row["absolute_offset"], 16)
        m = _block_match_safe(cat_disk, 0, xvc_path, cat_off, cat_row["size"], block=1 << 20)
        experiments.append(_experiment_template(
            "E1b-catalogo-legivel",
            f"Catalog000.bin em disco e identico a sua regiao no XVC (KeyId {cat_row.get('key_id')!r})",
            "correspondencia por blocos entre o arquivo em disco e a regiao XVC",
            "correlation/block_matching.block_match",
            {"xvc_offset": f"0x{cat_off:X}", "len": cat_row["size"], "key_id": cat_row.get("key_id")},
            {"match": m},
            _negative_control(cat_disk, xvc_path, cat_off, cat_row["size"], 1 << 20),
            [],
            ("MATCHED_COPY comprovado: o catalogo em disco e a extracao fiel da regiao legivel do XVC"
             if m.get("pct_equal_blocks") == 100.0 else "divergencia inesperada"),
        ))

    if target_row:
        stored_off = int(target_row["absolute_offset"], 16)
        stored_len = target_row["size"]
        _log("  E3: entropia medida da regiao do alvo no XVC...")
        ent = _stream_entropy(xvc_path, stored_off, stored_len)
        scan = _carve_counts(disk_exe) if disk_exe.is_file() else None
        positive = _carve_counts(cat_disk) if cat_disk else None
        positive_ok = bool(positive and positive["pe_validated"] >= 1)
        covered = bool(scan and scan["entire_file_scanned"] and e1_identical)
        if scan is None:
            concl = "nao executado: copia em disco do alvo ausente; regiao XVC nao varrida por PE"
        elif not positive_ok:
            concl = "INCONCLUSIVO: o controle positivo (PE real conhecido) nao foi detectado; o detector nao esta comprovado"
        elif scan["pe_validated"] == 0 and covered:
            concl = (f"resultado negativo medido: 0 PE validos entre {scan['raw_mz_hits']} ocorrencias de MZ no arquivo inteiro; "
                     "cobre tambem a regiao XVC por identidade de bytes (E1)")
        elif scan["pe_validated"] == 0:
            concl = (f"0 PE validos entre {scan['raw_mz_hits']} MZ na copia em disco; a regiao XVC so fica coberta se E1 for 100% "
                     f"(E1 identico={e1_identical}; varredura completa={scan['entire_file_scanned']})")
        else:
            concl = f"{scan['pe_validated']} PE validos encontrados no alvo: investigar offsets {scan['pe_offsets']}"
        experiments.append(_experiment_template(
            "E3-assinaturas-estruturais",
            "nenhum cabecalho PE (MZ + PE\\0\\0 validos) existe em nenhuma das copias do executavel alvo",
            "varredura MZ no arquivo inteiro com validacao estrita (e_lfanew, COFF, optional, secoes) via scanners/pe_carver; MZ isolado nao e PE; entropia medida na regiao gravada do XVC",
            "scanners/pe_carver.carve_file + _stream_entropy",
            {"disk": str(disk_exe), "xvc_offset": f"0x{stored_off:X}", "len": stored_len},
            {"scan_disk_copy": scan, "entropy_xvc_region": ent, "xvc_region_covered_via_E1": covered},
            {"teste": "controle positivo executado: o mesmo detector sobre Catalog000.bin (PE real conhecido); espera >= 1 PE",
             "result": positive, "passed": positive_ok},
            ["ausencia de PE nao prova criptografia por si; combinada com KeyId e entropia medida e consistente com cifragem (INFERIDO)"],
            concl,
        ))
    return experiments

def cmd_experiments(args) -> int:
    out_dir = guard_output_dir(Path(args.out), [Path(args.xvc), Path(args.disk)])
    out_dir.mkdir(parents=True, exist_ok=True)
    experiments = run_experiments(Path(args.xvc), Path(args.disk), args.target)
    write_json_exclusive(out_dir / "experiments.json", {
        "schema": "alpha_recovery.experiments/1",
        "generated_utc": utc_now(),
        "experiments": experiments,
    })
    for e in experiments:
        _log(f"  {e['id']}: {e['conclusion'][:110]}")
    return 0


# ---------------------------------------------------------------- Fase 4
def _file_hashes(path: Path) -> tuple[str, str]:
    import hashlib
    h256, h1 = hashlib.sha256(), hashlib.sha1()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(4 << 20)
            if not b:
                break
            h256.update(b)
            h1.update(b)
    return h256.hexdigest(), h1.hexdigest()


def _catalog_hash_check(catalog: Path, sha256_hex: str, sha1_hex: str) -> dict | None:
    """Presenca dos hashes do PE candidato no catalogo de codigo Xbox legivel.

    O catalogo descreve o conteudo DEScifrado; por isso a busca com hashes do
    plaintext e a verificacao independente de identidade correta (a busca com
    hashes dos bytes gravados da negativa, F-EXE-04).
    """
    if not catalog.is_file():
        return None
    blob = read_head(catalog, catalog.stat().st_size)
    return {
        "catalog": str(catalog),
        "sha256_raw_present": blob.find(bytes.fromhex(sha256_hex)) >= 0,
        "sha1_raw_present": blob.find(bytes.fromhex(sha1_hex)) >= 0,
        "sha256_hex_ascii_present": (sha256_hex.encode() in blob) or (sha256_hex.upper().encode() in blob),
        "sha1_hex_ascii_present": (sha1_hex.encode() in blob) or (sha1_hex.upper().encode() in blob),
        "note": "presenca do hash no catalogo legivel = verificacao independente de identidade contra o conteudo decifrado",
    }


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
    ident = out.get("identity") or {}
    ti = ident.get("target_identity") or {}
    if ti:
        parts.append(f"<h2>Identidade: {esc(ti.get('status'))}</h2>"
                     f"<p>{esc(ident.get('warning') or '')}</p>"
                     "<table><tr><th>evidencia</th><th>ok</th><th>peso</th><th>detalhe</th></tr>")
        for e in ti.get("evidence", []):
            parts.append(f"<tr><td>{esc(e['id'])}</td><td class=\"{'ok' if e['ok'] else 'bad'}\">{e['ok']}</td>"
                         f"<td>{esc(e['weight'])}</td><td>{esc(e['detail'])}</td></tr>")
        parts.append("</table>")
    sr = out.get("size_reconciliation")
    if sr:
        parts.append(f"<h2>Reconciliacao de tamanho</h2><p>esperado {sr['expected_size_stored']:,} B / "
                     f"real {sr['actual_size']:,} B / delta {sr['delta']:+d} B — sem truncamento automatico</p><ul>")
        for h in sr.get("hypotheses", []):
            parts.append(f"<li>{esc(h['id'])}: {esc(h.get('level'))} — {esc(h.get('detail'))}</li>")
        parts.append("</ul>")
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

    authorized_copy = None
    identity_assessment = None
    size_recon = None
    catalog_sem = None
    disk_pe = pe_summary(disk_exe, 0) if disk_exe.is_file() else None
    if disk_pe and not disk_pe.get("truncated"):
        _log("a copia em disco e um PE LEGIVEL: validando e separando SOURCE_RECOVERED de TARGET_IDENTITY...")
        val = validate_pe(disk_exe, expect_machine=0x8664, expect_magic=0x20B)
        sha256_hex, sha1_hex = _file_hashes(disk_exe)
        catalog_sem = semantic_catalog_report(disk_dir / "Catalog000.bin", candidate=disk_exe, target_name=target)
        fd = catalog_sem.get("candidate_digests", {}) or {}
        raw_digests = (fd.get("file_raw") or {})
        auth_digests = (fd.get("authenticode") or {})
        hash_hits = catalog_sem.get("hash_hits") or []
        auth_hit = any(h.get("digest_kind") == "authenticode" for h in hash_hits)
        raw_hit = any(h.get("digest_kind") == "file_raw" for h in hash_hits)
        identity_assessment = assess_identity(
            size_match=disk_len == stored_len,
            machine_ok=bool(disk_pe.get("machine") == "0x8664"),
            catalog_hash_hits=hash_hits,
            catalog_name_hits=catalog_sem.get("name_string_hits") or [],
            custody_documented=bool(getattr(args, "provenance", None)),
        )
        authorized_copy = {
            "path": str(disk_exe), "size": disk_len, "expected_size": stored_len,
            "size_match": disk_len == stored_len,
            "pe_valid": val["valid"], "pe_checks_failed": [c["id"] for c in val["checks"] if not c["ok"]],
            "machine": disk_pe.get("machine"), "format": disk_pe.get("format"),
            "sha256": sha256_hex, "sha1": sha1_hex,
            "digests": {"file_raw": raw_digests, "authenticode": auth_digests},
            "catalog_hash_hit": {"any": bool(hash_hits), "authenticode": auth_hit, "file_raw": raw_hit,
                                 "hits": hash_hits},
            "provenance_note": getattr(args, "provenance", None),
        }
        size_recon = size_reconciliation(stored_len, disk_len)
        im = IntervalMap(stored_len, base_label=MISSING)
        im.add(0, min(disk_len, stored_len), EXACT_RECOVERED,
               evidence=[{"sha256": sha256_hex, "source_file": str(disk_exe),
                           "note": "bytes plaintext com prova: PE validado nesta copia; correspondencia ao alvo e conceito separado (identity)"}],
               source_file=str(disk_exe), source_offset=0, transform="identity")
        _log(f"  identidade: {identity_assessment['status']} (catalogo: hits={len(hash_hits)}, "
             f"authenticode={auth_hit}, bruto={raw_hit})")

    experiments = getattr(args, "experiments", None)
    if experiments is None:
        experiments = run_experiments(xvc, disk_dir, target, facts=facts)
    by_id = {e["id"]: e for e in experiments}
    e3 = by_id.get("E3-assinaturas-estruturais", {}).get("result", {})
    ent = e3.get("entropy_xvc_region") or {}
    scan = e3.get("scan_disk_copy") or {}
    h_txt = f"{ent['bits_per_byte']:.6f}" if ent.get("bits_per_byte") is not None else "nao medida"
    pe_txt = (f"{scan['pe_validated']} PE validos / {scan['raw_mz_hits']} MZ (arquivo inteiro={scan['entire_file_scanned']})"
              if scan else "varredura PE nao executada")

    if not authorized_copy:
        im = IntervalMap(stored_len, base_label=ENCRYPTED_UNKNOWN)
        im.add(0, stored_len, ENCRYPTED_UNKNOWN,
               evidence=[{"source_file": str(xvc), "source_offset": stored_off,
                          "sha256_of_stored_bytes": None,
                          "note": (f"segmento {row['segment_index']}, KeyId {row['key_id']}; entropia medida {h_txt} bits/byte "
                                   f"sobre {ent.get('bytes_measured', 0):,} bytes; {pe_txt} (E3); cifragem INFERIDA, nao verificada")}],
               region_segment=f"XVC segment {row['segment_index']}", transform="none")

    meta_disk = scan_metadata_dir(disk_dir)
    stored_bytes_provenance = None
    if disk_exe.is_file() and not authorized_copy and disk_len and disk_len >= stored_len:
        e1_match = by_id.get("E1-redundancia-entre-conteineres", {}).get("result", {}).get("match")
        m = e1_match if e1_match and e1_match.get("bytes_compared") == stored_len else \
            block_match(disk_exe, 0, xvc, stored_off, stored_len, block=4 << 20)
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
        if tail_len > 0:
            describe_region(disk_exe, stored_len, tail_len)
        tail_match = None
        if tail_len > 0 and stored_off + stored_len + tail_len <= xvc.stat().st_size:
            tail_match = block_match(disk_exe, stored_len, xvc, stored_off + stored_len,
                                     tail_len, block=0x1000).get("pct_equal_blocks") == 100.0
        size_recon = size_reconciliation(stored_len, disk_len, tail_matches_xvc_continuation=tail_match)
        if tail_len > 0:
            prov.add(source=disk_exe, source_offset=stored_len, length=tail_len,
                     classification=(MATCHED_COPY if tail_match else UNVERIFIED), transform="identity",
                     extra={"counterpart": str(xvc), "counterpart_offset": stored_off + stored_len,
                            "note": ("cauda igual a continuacao da regiao no XVC (page slack da alocacao do segmento)"
                                     if tail_match else "cauda sem origem comprovada no XVC")})
        if tail_len > 0:
            _log(f"  cauda de {tail_len} byte(s): {'IGUAL a continuacao do XVC (page slack)' if tail_match else 'sem correspondencia no XVC'} (ver size_reconciliation.json)")

    identity = {
        "name": target,
        "package_version": facts.get("package_version"),
    }
    inferred = infer_target_structure(identity)
    map_json = im.to_json()
    cands_doc = _load_json(out_dir / "executable_candidates.json") if (out_dir / "executable_candidates.json").is_file() else build_candidates(meta_disk, facts)
    coverage = map_json["coverage"]
    target_cand = next((c for c in cands_doc.get("candidates", []) if c.get("name", "").casefold() == target.casefold()), None)
    metadata_recovered = bool(target_cand and target_cand.get("confidence") == "CONFIRMED")
    validated_complete = bool(authorized_copy and authorized_copy["pe_valid"] and authorized_copy["size_match"])
    identity_verified = bool(identity_assessment and identity_assessment["status"] == "TARGET_IDENTITY_VERIFIED")
    classification = classify_recovery(coverage, validated_complete=validated_complete,
                                       metadata_recovered=metadata_recovered,
                                       identity_verified=(identity_verified if authorized_copy else None))
    proven = coverage["by_class_bytes"].get(EXACT_RECOVERED, 0) + coverage["by_class_bytes"].get(MATCHED_COPY, 0)
    frag_dir = out_dir / "recovered_fragments"
    carve_total = sum(1 for p in frag_dir.iterdir() if p.is_file()) if frag_dir.is_dir() else 0

    metrics = {
        "schema": "alpha_recovery.metrics/1",
        "target": target,
        "bytes_original_with_proof": proven,
        "pct_bytes_with_proof_of_plaintext": round(100.0 * proven / stored_len, 6) if stored_len else 0.0,
        "bytes_structurally_inferred": coverage["by_class_bytes"].get(STRUCTURAL_INFERENCE, 0),
        "bytes_encrypted_unknown": coverage["by_class_bytes"].get(ENCRYPTED_UNKNOWN, 0),
        "bytes_missing": coverage["by_class_bytes"].get(MISSING, 0),
        "bytes_conflicting": coverage["by_class_bytes"].get(CONFLICTING_EVIDENCE, 0),
        "stored_bytes_provenance_pct": stored_bytes_provenance["match"]["pct_equal_blocks"] if stored_bytes_provenance else None,
        "note": "a proveniencia MATCHED_COPY refere-se aos bytes GRAVADOS (ciphertext) e nunca e somada como recuperacao de plaintext",
        "executable_candidates": len(cands_doc.get("candidates", [])),
        "fragments_recovered": len([r for r in prov.records if r.get("destination")]),
        "fragments_recovered_note": "fragmentos DO ALVO; o carving de outros arquivos fica em carve_fragments_total",
        "carve_fragments_total": carve_total,
        "target_entropy_bits_per_byte": ent.get("bits_per_byte"),
        "target_pe_validated": scan.get("pe_validated"),
        "target_raw_mz_hits": scan.get("raw_mz_hits"),
        "metadata_recovered": metadata_recovered,
        "metadata_coverage": list(inferred["fields"].keys()),
        "authorized_copy": authorized_copy,
        "source_recovered_bytes": proven,
        "target_identity_status": identity_assessment["status"] if identity_assessment else None,
        "classification": classification,
    }

    src_prov = None
    if disk_exe.is_file():
        digests = (authorized_copy or {}).get("digests") or {
            "sha1": (authorized_copy or {}).get("sha1"), "sha256": (authorized_copy or {}).get("sha256")}
        if not authorized_copy:
            d1, d2 = _file_hashes(disk_exe)
            digests = {"sha1": d1, "sha256": d2}
        src_prov = source_provenance_report(
            disk_exe, custody_claim=getattr(args, "provenance", None), digests=digests,
            extra={"stored_bytes_equal_to_xvc_region": bool(stored_bytes_provenance),
                   "note": ("copia de ciphertext: proveniencia dos bytes gravados por E1 (blocos identicos)"
                            if stored_bytes_provenance else "copia plaintext em disco")})
    if size_recon is None and disk_exe.is_file():
        size_recon = size_reconciliation(stored_len, disk_len)
    if catalog_sem is None and (disk_dir / "Catalog000.bin").is_file():
        catalog_sem = semantic_catalog_report(disk_dir / "Catalog000.bin", target_name=target)

    report = {
        "schema": "alpha_recovery.shadow_pe_report/1",
        "generated_utc": utc_now(),
        "target": target,
        "classification": classification,
        "stored": {"xvc_offset": f"0x{stored_off:X}", "size": stored_len, "key_id": row["key_id"],
                   "segment": row["segment_index"]},
        "disk_copy": {"path": str(disk_exe), "size": disk_len,
                      "format": f"{pe_txt}; bytes identicos a regiao XVC (E1)",
                      "e3_scan": scan or None} if disk_exe.is_file() else None,
        "identity_sources": cands_doc,
        "identity": {
            "source_recovered": ({"path": str(disk_exe), "size": disk_len,
                                   "sha256": (authorized_copy or {}).get("sha256"),
                                   "pe_valid": (authorized_copy or {}).get("pe_valid")} if disk_exe.is_file() else None),
            "target_identity": identity_assessment,
            "warning": "SOURCE_RECOVERED != TARGET_IDENTITY_VERIFIED; PE valido nao e correspondencia comprovada a build",
        },
        "authorized_copy": authorized_copy,
        "inferred_structure": inferred,
        "map": map_json,
        "coverage": coverage,
        "stored_bytes_provenance": stored_bytes_provenance,
        "size_reconciliation": size_recon,
        "catalog_semantics": catalog_sem,
        "candidates": cands_doc.get("candidates", []),
        "experiments": experiments,
        "impediments": (
            [
                "copias de origem nao estabelecida nao podem ser tratadas como copia autorizada; documente a custodia via --provenance (a declaracao sozinha nao e prova)",
                (f"identidade: {identity_assessment['status'] if identity_assessment else 'UNKNOWN'} — "
                 "COMPLETE_VERIFIED exige tamanho exato + maquina compativel + hash (Authenticode ou bruto) presente no catalogo legivel + custodia documentada; "
                 "sem isso a classificacao maxima e COMPLETE_UNVERIFIED"),
                "a verificacao criptografica da assinatura do catalogo (se existisse) nao foi executada: sem dependencia criptografica, apenas presenca e detectada",
            ] if authorized_copy else
            [
                (f"INFERIDO (nao verificado pela ferramenta): o conteudo do alvo esta cifrado — KeyId {row['key_id']} no XVC, "
                 f"entropia medida {h_txt} bits/byte, {pe_txt}, E6 mostra PE legivel != sua regiao XVC; "
                 "o esquema esperado para XVD/XVC e AES-XTS e a chave de conteudo nao esta disponivel"),
                "se a inferencia acima estiver correta, nenhum byte de codigo ou dado do executavel e recuperavel sem a chave; impedimento criptografico, nao limitacao de ferramenta",
                "nenhum PDB/MAP/OBJ/ILK/dump do executavel existe no conjunto sobrevivente (auditoria de sessoes anteriores)",
                "a recuperacao do codigo permanece bloqueada ate que um artefato legitimo apareça: build de desenvolvimento do detentor, PDB correspondente, ou copia decifrada por processo autorizado",
                "nada nesta analise deve ser interpretado como bypass de protecao; nenhum foi tentado",
            ]
        ),
    }
    write_json_exclusive(out_dir / "shadow_pe_map.json", map_json)
    write_json_exclusive(out_dir / "shadow_pe_report_data.json", report)
    write_exclusive(out_dir / "shadow_pe_report.html", _html_report(report).encode("utf-8"))
    write_json_exclusive(out_dir / "metrics.json", metrics)
    if src_prov is not None:
        write_json_exclusive(out_dir / "source_provenance.json", src_prov)
        _log("source_provenance.json gravado (claim de custodia registrada como claim, nao como prova)")
    if size_recon is not None:
        write_json_exclusive(out_dir / "size_reconciliation.json", size_recon)
        hyp = size_recon["hypotheses"][0]
        _log(f"size_reconciliation.json: delta {size_recon['delta']:+d} B; hipotese '{hyp['id']}' nivel {hyp.get('level')}")
    if catalog_sem is not None:
        write_json_exclusive(out_dir / "catalog_semantic.json", catalog_sem)
    prov.write_all(out_dir)

    exact_intervals = [iv for iv in map_json["intervals"] if iv["classification"] == EXACT_RECOVERED]
    if exact_intervals and exact_intervals[0]["start"] == 0 and disk_exe.is_file():
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


# ---------------------------------------------------------------- Fase cripto
def _extract_catalog_from_xvc(pipeline, out_dir: Path) -> Path | None:
    row = pipeline.pkg.row("Catalog000.bin")
    if row is None:
        return None
    dest = out_dir / "Catalog000.extracted.bin"
    if dest.exists():
        return dest
    with open(dest, "xb") as fh:
        for b in pipeline.src.iter_chunks(row.start, row.size):
            fh.write(b)
    return dest


def validate_plaintext(plaintext_path: Path, *, expected_size: int, custody_claim: str | None,
                       pipeline, out_dir: Path) -> dict:
    """Fase 5: validacao completa do plaintext com a escada de identidade."""
    from correlation.catalog_semantics import (
        assess_identity, authenticode_digests, file_digests, semantic_catalog_report,
    )
    from reconstruction.provenance import source_provenance_report
    val = validate_pe(plaintext_path, expect_machine=0x8664, expect_magic=0x20B)
    digests = {"file_raw": file_digests(plaintext_path), "authenticode": authenticode_digests(plaintext_path)}
    rsds = _rsds_summary(plaintext_path)
    catalog_path = _extract_catalog_from_xvc(pipeline, out_dir)
    catalog_sem = semantic_catalog_report(catalog_path, candidate=plaintext_path,
                                          target_name=plaintext_path.name.replace(".plaintext.bin", "")) \
        if catalog_path else None
    hash_hits = (catalog_sem or {}).get("hash_hits") or []
    name_hits = (catalog_sem or {}).get("name_string_hits") or []
    identity = assess_identity(
        size_match=plaintext_path.stat().st_size == expected_size,
        machine_ok=bool(val["valid"]),
        catalog_hash_hits=hash_hits, catalog_name_hits=name_hits,
        custody_documented=bool(custody_claim))
    cov = {"total_bytes": expected_size,
           "by_class_bytes": {"EXACT_RECOVERED": plaintext_path.stat().st_size}}
    classification = classify_recovery(cov, validated_complete=bool(val["valid"]
                                      and plaintext_path.stat().st_size == expected_size),
                                      metadata_recovered=True,
                                      identity_verified=(identity["status"] == "TARGET_IDENTITY_VERIFIED"))
    src_prov = source_provenance_report(plaintext_path, custody_claim=custody_claim,
                                        digests={"sha1": digests["file_raw"]["sha1"],
                                                 "sha256": digests["file_raw"]["sha256"]},
                                        extra={"origin": "descriptografia XTS com CIK externa; round-trip verificado"})
    return {
        "schema": "alpha_recovery.xvc_plaintext_validation/1",
        "plaintext": str(plaintext_path),
        "size": plaintext_path.stat().st_size, "expected_size": expected_size,
        "pe_validation": val, "digests": digests, "rsds": rsds,
        "source_provenance": src_prov,
        "classification": classification,
        "identity": identity,
        "warning": "SOURCE_RECOVERED != TARGET_IDENTITY_VERIFIED; PE valido nunca e promovido automaticamente a COMPLETE_VERIFIED",
    }


def _rsds_summary(path: Path) -> list[dict]:
    try:
        from correlation.identity_report import rsds_records
        return rsds_records(path)
    except Exception as exc:
        return [{"error": f"{type(exc).__name__}: {exc}"}]


def cmd_decrypt(args) -> int:
    """Diagnostico criptografico; descriptografia somente com CIK externa legitima."""
    from crypto.xvc_xts_pipeline import XvcXtsPipeline, load_cik
    out_dir = guard_output_dir(Path(args.out), [Path(args.xvc)])
    out_dir.mkdir(parents=True, exist_ok=True)
    with XvcXtsPipeline(args.xvc) as pipeline:
        storage = pipeline.validate_storage(args.target)
        if not storage["sha256_matches_prior_evidence"]:
            _log(f"ALERTA: hash dos bytes gravados diverge da evidencia anterior: {storage['sha256_stored_bytes']}")
        keymap = pipeline.key_mapping(args.target)
        keymap["data_unit_model"] = pipeline.data_unit_model(args.target)
        keymap["data_unit_full_audit"] = pipeline.audit_data_units(args.target)
        write_json_exclusive(out_dir / "xvc_crypto_key_mapping.json", keymap)
        _log(f"armazenamento: offset 0x{int(storage['offset'], 16):X} tamanho {storage['size']:,} "
             f"KeyId {storage['key_id']} hash gravado {storage['sha256_stored_bytes'][:16]}...")
        aud = keymap["data_unit_full_audit"]
        _log(f"auditoria integral de data_unit: {aud['pages_audited']:,} folhas, "
             f"consecutivas={aud['strictly_consecutive']}, saltos={len(aud['jumps'])} "
             f"(a descriptografia le cada folha, nunca extrapola)")
        report = {
            "schema": "alpha_recovery.xvc_decryption_report/1",
            "target": args.target,
            "storage": storage,
            "key_mapping": keymap,
            "roundtrip": None, "plaintext": None, "plaintext_validation": None,
        }
        if not args.cik_file:
            report["status"] = "BLOCKED_MISSING_AUTHORIZED_CIK"
            report["note"] = ("nenhuma CIK fornecida; nada foi simulado, nenhum byte decifrado; "
                              "o pipeline permanece operacional em modo diagnostico")
            write_json_exclusive(out_dir / "xvc_decryption_report.json", report)
            _log("status: BLOCKED_MISSING_AUTHORIZED_CIK (diagnostico somente-leitura concluido)")
            return 4
        cik, fingerprint = load_cik(Path(args.cik_file))
        if args.cik_sha256 and fingerprint.lower() != args.cik_sha256.lower():
            _log(f"CIK rejeitada: fingerprint {fingerprint} != esperado")
            return 3
        _log(f"CIK externa carregada (fingerprint {fingerprint[:16]}...; bytes jamais impressos)")
        dec = pipeline.decrypt_target(args.target, cik, out_dir, expected_size=storage["size"])
        report["status"] = dec.get("status", "DECRYPTED")
        report["decryption"] = dec
        _log(f"descriptografia: {dec.get('plaintext_bytes', 0):,} bytes em {dec.get('elapsed_seconds')}s "
             f"sha256 {dec.get('plaintext_sha256', '')[:16]}...")
        if dec.get("status") == "DECRYPTED":
            _log("verificacao round-trip (re-cifracao contra os bytes gravados)...")
            rt = pipeline.encrypt_verify(Path(dec["output"]), args.target, cik)
            report["roundtrip"] = rt
            _log(f"round-trip: {'IGUAL byte a byte' if rt['roundtrip_equal'] else 'DIVERGENTE'} "
                 f"({rt['pages_checked']} paginas)")
            if rt["roundtrip_equal"]:
                pv = validate_plaintext(Path(dec["output"]), expected_size=storage["size"],
                                        custody_claim=args.provenance, pipeline=pipeline, out_dir=out_dir)
                report["plaintext_validation"] = pv
                write_json_exclusive(out_dir / "xvc_plaintext_validation.json", pv)
                if pv.get("identity"):
                    write_json_exclusive(out_dir / "catalog_identity_verification.json", {
                        "schema": "alpha_recovery.catalog_identity_verification/1",
                        "identity": pv["identity"],
                        "catalog_hits": (pv.get("digests") or {}).get("file_raw"),
                    })
                from reconstruction.provenance import Provenance
                prov = Provenance()
                prov.add(source=Path(args.xvc), source_offset=int(storage["offset"], 16),
                         length=storage["size"], classification=EXACT_RECOVERED,
                         destination=dec["output"], transform="xts_decrypt(externa)",
                         extra={"cik_sha256_fingerprint": fingerprint})
                prov.write_all(out_dir)
                _log(f"validacao: {pv['classification']} | identidade: {pv['identity']['status']}")
        write_json_exclusive(out_dir / "xvc_decryption_report.json", report)
        _log(f"relatorios -> {out_dir}")
        return 0
    return 2


def cmd_xts_tests(args) -> int:
    """Matriz sintetica obrigatoria do motor XTS (Fase 3)."""
    from crypto.xvc_xts_pipeline import run_synthetic_validation
    res = run_synthetic_validation()
    out = Path(args.out) if args.out else Path("xvc_xts_test_results.json")
    write_json_exclusive(out, res)
    for r in res["results"]:
        _log(f"  [{'PASS' if r['ok'] else 'FAIL'}] {r['test']}: {r['detail'][:80]}")
    _log(f"xts-tests: {res['passed']}/{res['total']} -> {out}")
    return 0 if res["all_passed"] else 1


def cmd_blind_lab(args) -> int:
    """Laboratorio de engenharia reversa as cegas: estados A/B/C."""
    from crypto.synth_lab import run_lab
    out_dir = Path(args.out)
    report = run_lab(out_dir, seed=args.seed, data_unit_jump_at=args.jump_at)
    _log(f"A gerador: {report['A_generator']['pages']} paginas, "
         f"{report['A_generator']['logical_size']:,} bytes; saltos de data_unit injetados: {report['data_unit_jump_injected'] or 'nenhum'}")
    b = report["B_blind_analysis"]
    _log(f"B as cegas: status={b['status']}; MZ/PE no ciphertext={b['observed']['mz_pe_candidates_in_ciphertext']}; "
         f"data_units auditados={b['recoverable_now']['data_unit_audit']['entries_read']} "
         f"(linear={b['recoverable_now']['data_unit_audit']['strictly_consecutive']})")
    c = report["C_reveal_and_validation"]
    _log(f"C revelacao: byte-a-byte={c['referee_comparison']['byte_for_byte_equal_to_reference']} "
         f"PE valido={c['pe_validation_valid']} identidade={c['identity_status']} -> {c['classification']}")
    d = c["caveat_demonstrations"]
    _log(f"   ressalvas: round-trip com CIK errada ainda igual={d['wrong_cik_roundtrip_still_equal']} "
         f"(nao autentica); rejeicao por evidencia={d['wrong_cik_reference_mismatch'] and not d['wrong_cik_catalog_hits']}")
    _log(f"blind-lab: {'TODOS OS CRITERIOS OK' if report['all_passed'] else 'FALHA EM CRITERIOS'} -> {out_dir / 'lab_report.json'}")
    return 0 if report["all_passed"] else 1


def cmd_hunt(args) -> int:
    """Registro de artefatos autorizados da build (PEs+RSDS, PDBs, pares, subprodutos)."""
    from correlation.artifact_hunt import hunt, hunt_summary_lines
    report = hunt(args.roots)
    out_dir = Path(args.out)
    write_json_exclusive(out_dir / "artifact_hunt_report.json", report)
    _log("\n".join("  " + l for l in hunt_summary_lines(report)))
    _log(f"relatorio -> {out_dir / 'artifact_hunt_report.json'}")
    return 0


def cmd_reconcile_dlls(args) -> int:
    """Reconciliacao de proveniencia das DLLs (manifesto x segmento x disco)."""
    from correlation.provenance_reconciliation import reconcile_dlls
    rep = reconcile_dlls(Path(args.xvc), Path(args.disk),
                         prior_records=Path(args.prior_records) if args.prior_records else None)
    if "error" in rep:
        _log(f"ERRO: {rep['error']}")
        return 2
    out_dir = Path(args.out)
    write_json_exclusive(out_dir / "dll_provenance_reconciliation.json", rep)
    for r in rep["rows"]:
        ident = r.get("build_identity") or {}
        cc = ident.get("prior_session_crosscheck", {}).get("status", "-")
        guid = ident.get("rsds", [{}])[0].get("guid", "-")[:8] if ident.get("rsds") else "-"
        _log(f"  {r['dll']:<36} chunk {r['manifest_chunk']} seg {r['segment']:>2} KeyId {r['key_id']} "
             f"tam {'=' if r['size_match'] else 'X'} -> {r['classification']:<24} "
             f"RSDS {guid}.. prior={cc}")
    s = rep["summary"]
    _log(f"resumo: {s['by_classification']} | tamanhos exatos (so metadados): {s['sizes_exactly_equal']}/{s['dlls']}")
    _log(f"tabela-canonical: " + ", ".join(f"{t['object']}={t['classification']}" for t in rep["classification_table"]))
    _log(f"conclusao: {rep['hybrid_assembly_conclusion'][:200]}")
    _log(f"relatorio -> {out_dir / 'dll_provenance_reconciliation.json'}")
    return 0


# ---------------------------------------------------------------- Fase 7
def cmd_identity(args) -> int:
    """Relatorio independente de identidade: evidencias de build, PDB e manifesto."""
    from correlation.identity_report import build_identity_report, cross_validate_rsds_pdb
    out_dir = guard_output_dir(Path(args.out), [Path(args.xvc), Path(args.disk)])
    out_dir.mkdir(parents=True, exist_ok=True)
    prior = None
    if args.prior and Path(args.prior).is_file():
        prior = f"evidencia previa reaproveitada de {args.prior}"
    rep = build_identity_report(xvc_path=Path(args.xvc), disk_dir=Path(args.disk),
                                target=args.target, prior=prior)
    if "error" in rep:
        _log(f"ERRO: {rep['error']}")
        return 2
    write_json_exclusive(out_dir / "identity_report.json", rep)
    corr = rep.get("manifest_correspondence", {})
    _log(f"identidade declarada: {rep['declared_identity']['name']} "
         f"versao {rep['declared_identity']['package_version']} "
         f"(consistente={rep['declared_identity']['version_consistent']})")
    _log(f"manifesto x pacote: {corr.get('confirmed_in_xvc')}/{corr.get('layout_files')} confirmados; "
         f"faltando: {corr.get('missing_from_xvc') or 'nenhum'}")
    _log(f"ordem dos chunks == ordem dos segmentos: {corr.get('layout_chunk_order_equals_segment_order')}")
    _log(f"RSDS de dependencias: {len(rep['dependency_build_environment']['records'])} registro(s) (ambiente de build, nao do alvo)")
    _log(f"PDB do alvo: {rep['target_pdb']['status']}")
    if args.pdb_pair:
        pe, pdb = (part.strip() for part in args.pdb_pair.split("=", 1)) if "=" in args.pdb_pair else (None, None)
        if pe and pdb:
            val = cross_validate_rsds_pdb(Path(pe), Path(pdb))
            write_json_exclusive(out_dir / "pdb_cross_validation.json", val)
            _log(f"PDB pair: {val['verdict']} (guid_match={val.get('guid_match')}, age_match={val.get('age_match')})")
    _log(f"relatorio -> {out_dir / 'identity_report.json'}")
    return 0


def cmd_catalog(args) -> int:
    """Validacao semantica do Catalog000.bin, opcionalmente contra um candidato."""
    rep = semantic_catalog_report(Path(args.path), candidate=Path(args.candidate) if args.candidate else None,
                                 target_name=args.target_name)
    rep["generated_utc"] = utc_now()
    out = Path(args.out) if args.out else Path("catalog_semantic.json")
    write_json_exclusive(out, rep)
    _log(f"catalogo: {rep.get('size')} bytes, subsystem={rep.get('pe', {}).get('subsystem_name')}")
    _log(f"  assinatura: presente={rep['signature']['security_directory_present']} "
         f"verificacao_executada={rep['signature']['cryptographic_verification_performed']}")
    _log(f"  strings do alvo: {len(rep.get('name_string_hits') or [])} hit(s)")
    if rep.get("hash_hits"):
        for h in rep["hash_hits"]:
            _log(f"  hash hit: {h['digest_kind']}/{h['alg']} forma {h['form']} @0x{h['offset']:x}")
    else:
        _log("  hash hits: nenhum (sem candidato com correspondencia comprovada no catalogo)")
    _log(f"relatorio -> {out}")
    return 0


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
    experiments = run_experiments(xvc, disk, args.target)
    write_json_exclusive(out_dir / "experiments.json",
                         {"schema": "alpha_recovery.experiments/1", "generated_utc": utc_now(), "experiments": experiments})
    for e in experiments:
        _log(f"  {e['id']}: {e['conclusion'][:100]}")
    _log("[5/6] mapa shadow PE...")
    rc = cmd_reconstruct(argparse.Namespace(xvc=str(xvc), disk=str(disk), out=str(out_dir), target=args.target,
                                            experiments=experiments, provenance=getattr(args, "provenance", None)))
    if rc != 0:
        return rc
    _log("[6/6] validacao do catalogo legivel (PE real de referencia)...")
    cat = disk / "Catalog000.bin"
    if cat.is_file():
        val = validate_pe(cat)
        write_json_exclusive(out_dir / "catalog_pe_validation.json", val)
        passed = sum(1 for c in val.get("checks", []) if c.get("ok"))
        _log(f"  Catalog000.bin valido={val['valid']} ({passed}/{len(val.get('checks', []))} checagens)")
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
    s.add_argument("--provenance", default=None,
                   help="custodia da copia autorizada (obrigatoria para COMPLETE_VERIFIED quando a copia e plaintext)")
    s.set_defaults(func=cmd_reconstruct)

    s = sub.add_parser("validate", help="Fase 7: validacao independente de um PE")
    s.add_argument("path")
    s.add_argument("--machine", type=lambda x: int(x, 0))
    s.add_argument("--magic", type=lambda x: int(x, 0))
    s.add_argument("--out")
    s.set_defaults(func=cmd_validate)

    s = sub.add_parser("catalog", help="validacao semantica do Catalog000.bin (com ou sem candidato)")
    s.add_argument("path")
    s.add_argument("--candidate", default=None, help="PE candidato para busca de hashes (bruto e Authenticode)")
    s.add_argument("--target-name", default=TARGET_DEFAULT)
    s.add_argument("--out", default="catalog_semantic.json")
    s.set_defaults(func=cmd_catalog)

    s = sub.add_parser("identity", help="relatorio independente de identidade (build, PDB, manifesto)")
    s.add_argument("--xvc", required=True)
    s.add_argument("--disk", required=True)
    s.add_argument("--target", default=TARGET_DEFAULT)
    s.add_argument("--out", required=True)
    s.add_argument("--prior", default=None, help="arquivo de evidencia previa a citar (nao reexecuta nada)")
    s.add_argument("--pdb-pair", default=None, help="validacao GUID/age: PE=PDB (demonstracao ou candidato)")
    s.set_defaults(func=cmd_identity)

    s = sub.add_parser("decrypt", help="diagnostico XTS do alvo; descriptografia SO com CIK externa legitima")
    s.add_argument("--xvc", required=True)
    s.add_argument("--target", default=TARGET_DEFAULT)
    s.add_argument("--out", required=True)
    s.add_argument("--cik-file", default=None,
                   help="arquivo com CIK de 32 bytes (binario ou 64 hex) fornecido legitimamente; sem ele, modo diagnostico")
    s.add_argument("--cik-sha256", default=None, help="fingerprint esperado da CIK (verificacao antes do uso)")
    s.add_argument("--provenance", default=None, help="custodia da CIK/coputa (obrigatorio para COMPLETE_VERIFIED)")
    s.set_defaults(func=cmd_decrypt)

    s = sub.add_parser("xts-tests", help="matriz sintetica obrigatoria do motor XTS (Fase 3)")
    s.add_argument("--out", default="xvc_xts_test_results.json")
    s.set_defaults(func=cmd_xts_tests)

    s = sub.add_parser("blind-lab", help="laboratorio as cegas A/B/C (gerador, RE sem chaves, revelacao)")
    s.add_argument("--out", required=True)
    s.add_argument("--seed", type=int, default=20261122)
    s.add_argument("--jump-at", type=int, default=None,
                   help="pagina onde injetar descontinuidade de data_unit (prova que nada e extrapolado)")
    s.set_defaults(func=cmd_blind_lab)

    s = sub.add_parser("hunt-artifacts", help="registro de artefatos autorizados da build (exe/PDB/subprodutos)")
    s.add_argument("roots", nargs="+")
    s.add_argument("--out", required=True)
    s.set_defaults(func=cmd_hunt)

    s = sub.add_parser("reconcile-dlls", help="proveniencia das DLLs: manifesto x segmento x disco (sem chaves)")
    s.add_argument("--xvc", required=True)
    s.add_argument("--disk", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--prior-records", default=None,
                   help="pe_debug_records.json de sessao anterior para cross-check de identidade de build")
    s.set_defaults(func=cmd_reconcile_dlls)

    s = sub.add_parser("selftest", help="suite sintetica rapida (14 cenarios)")
    s.add_argument("--keep", action="store_true")
    s.set_defaults(func=cmd_selftest)

    s = sub.add_parser("run-all", help="pipeline completo contra artefatos reais")
    s.add_argument("--xvc", required=True)
    s.add_argument("--disk", required=True)
    s.add_argument("--target", default=TARGET_DEFAULT)
    s.add_argument("--out", required=True)
    s.add_argument("--provenance", default=None,
                   help="custodia da copia autorizada (obrigatoria para COMPLETE_VERIFIED quando a copia e plaintext)")
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
