"""FORENSIC ANALYZER - FASE 6: engenharia reversa as cegas.

Recebe SOMENTE a pasta publica (conteineres + lab_manifest.json). Nao recebe
chaves, nao le o plaintext, nao le lab_ground_truth.json.

Prova da separacao: um audit hook do Python (sys.addaudithook) registra todo
"open"/"os.listdir"/"os.scandir" feito durante a fase cega - inclusive pelas
ferramentas do projeto, que rodam no mesmo processo. O relatorio lista os
caminhos tocados e falha se algum estiver na pasta selada ou for um arquivo de
verdade/chave/plaintext.

Ferramentas executadas:
  tools/inspect_xvd.py, tools/validate_xts.py               (criadas pelo laboratorio)
  recovery/bin_pe_recovery/scripts/xvc_probe.py               (wrapper xvcintel)
  recovery/bin_pe_recovery/scripts/bin_pe_recovery.py scan    (carving PE)
  recovery/bin_pe_recovery/scripts/pe_check.py                (validacao PE)
  recovery/project_alpha/shadow_pe_reconstructor.py run-all   (reconstrutor)
"""
from __future__ import annotations

import argparse
import contextlib
import io
import re
import runpy
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_common  # noqa: E402
from lab_common import (ALPHA_ROOT, BIN_PE_SCRIPTS, GENERATED, GROUND_TRUTH_NAME, KEYSTORE_NAME, PAGE,  # noqa: E402
                        PUBLIC_DIRNAME, REPORTS, SEALED_DIRNAME, TOOLS_ROOT, entropy, read_json, sha256_file, utc_now,
                        write_json)

FORBIDDEN_NAMES = {GROUND_TRUTH_NAME, KEYSTORE_NAME, "lab_plaintext.exe", "lab_plaintext_build_b.exe"}
GENERIC_TOKENS = [b"MZ", b"PE\0\0", b"This program cannot", b".text", b".rdata", b".data", b"KERNEL32", b"kernel32",
                  b"USER32", b"LAB_SYNTHETIC", b"LABID-"]

# ------------------------------------------------------------------ auditoria
_AUDIT = {"active": False, "events": []}


def _hook(event, args):
    if not _AUDIT["active"]:
        return
    if event in ("open", "os.listdir", "os.scandir"):
        p = args[0] if args else None
        if isinstance(p, (str, bytes, Path)) and not isinstance(p, int):
            _AUDIT["events"].append((event, str(p if not isinstance(p, bytes) else p.decode(errors="replace"))))


_HOOK_INSTALLED = False


def _install_hook():
    global _HOOK_INSTALLED
    if not _HOOK_INSTALLED:
        sys.addaudithook(_hook)
        _HOOK_INSTALLED = True


def audit_summary(sealed_hint: Path | None) -> dict:
    paths = Counter()
    for ev, p in _AUDIT["events"]:
        try:
            rp = str(Path(p).resolve())
        except (OSError, ValueError):
            rp = p
        paths[(ev, rp)] += 1
    violations = []
    for (ev, p), n in paths.items():
        name = Path(p).name
        in_sealed = sealed_hint is not None and (Path(p) == sealed_hint or sealed_hint in Path(p).parents)
        if name in FORBIDDEN_NAMES or in_sealed:
            violations.append({"event": ev, "path": p, "count": n})
    data_paths = sorted({p for (ev, p) in paths if ev == "open" and not p.endswith((".py", ".pyc", ".pth"))
                         and "site-packages" not in p and "__pycache__" not in p and not p.startswith(sys.base_prefix)})
    return {"events_recorded": sum(paths.values()), "distinct_paths": len(paths),
            "data_files_opened": [_rel(p) for p in data_paths], "violations": violations,
            "separation_respected": not violations}


def _rel(p: str) -> str:
    try:
        return str(Path(p).resolve().relative_to(lab_common.REPO_ROOT))
    except ValueError:
        return p


# ------------------------------------------------------------------ execucao das ferramentas
def run_script(script: Path, argv: list[str], log: Path) -> dict:
    old_argv, old_path = sys.argv[:], sys.path[:]
    buf = io.StringIO()
    code = 0
    sys.argv = [str(script), *argv]
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            try:
                runpy.run_path(str(script), run_name="__main__")
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
            except Exception as e:  # registrado, nao escondido
                code = f"exception: {type(e).__name__}: {e}"
    finally:
        sys.argv, sys.path[:] = old_argv, old_path
    log.write_text(buf.getvalue(), encoding="utf-8")
    return {"script": _rel(str(script)), "argv": [_rel(a) if Path(a).exists() else a for a in argv],
            "exit": code, "log": _rel(str(log)), "log_tail": buf.getvalue().strip().splitlines()[-6:]}


# ------------------------------------------------------------------ analises proprias
def page_entropy_profile(data: bytes, ranges: list[tuple[str, int, int]]) -> list[dict]:
    out = []
    for label, off, ln in ranges:
        ents = [entropy(data[o:o + PAGE]) for o in range(off, off + ln, PAGE)]
        if not ents:
            continue
        out.append({"range": label, "pages": len(ents), "min": round(min(ents), 4),
                    "mean": round(sum(ents) / len(ents), 4), "max": round(max(ents), 4),
                    "pages_above_7_9": sum(1 for e in ents if e > 7.9)})
    return out


def token_scan(buf: bytes) -> dict:
    return {t.decode(errors="replace"): buf.count(t) for t in GENERIC_TOKENS}


def printable_runs(buf: bytes, n: int = 8) -> dict:
    found = re.findall(rb"[\x20-\x7e]{%d,}" % n, buf)
    return {"count": len(found), "sample": [f.decode() for f in found[:5]],
            "expected_random": round(len(buf) * (95 / 256) ** n * (1 - 95 / 256), 2)}


def analyze(public_dir: Path, work: Path, sealed_hint: Path | None = None) -> dict:
    public_dir = Path(public_dir).resolve()
    if public_dir.name == SEALED_DIRNAME:
        raise lab_common.LabSafetyError("o analisador cego nao pode receber a pasta selada")
    names = {p.name for p in public_dir.iterdir()}
    if names & FORBIDDEN_NAMES:
        raise lab_common.LabSafetyError(f"pasta publica contem material proibido: {sorted(names & FORBIDDEN_NAMES)}")
    work = lab_common.fresh_dir(work)
    logs = work / "logs"
    logs.mkdir()
    _install_hook()
    _AUDIT["events"].clear()
    _AUDIT["active"] = True
    try:
        rep = _analyze(public_dir, work, logs)
    finally:
        _AUDIT["active"] = False
    rep["access_audit"] = audit_summary(sealed_hint)
    return rep


def _analyze(pub: Path, work: Path, logs: Path) -> dict:
    sys.path.insert(0, str(TOOLS_ROOT))
    import inspect_xvd
    import validate_xts
    from xvcintel.core.reader import BytesSource
    from xvcintel.engines.package import load_package

    manifest = read_json(pub / "lab_manifest.json")
    containers = sorted(p for p in pub.iterdir() if p.suffix == ".bin")
    rep: dict = {"schema": "crypto_lab.blind_analysis/1", "generated_utc": utc_now(), "input_dir": _rel(str(pub)),
                 "inputs": [{"file": p.name, "size": p.stat().st_size, "sha256": sha256_file(p)} for p in containers],
                 "manifest_public": {k: manifest[k] for k in ("marker", "banner", "compatibility_claim", "not_included")},
                 "keys_available": False, "tools": {}, "containers": {}}

    xvc_path = pub / "lab_xvc_encrypted.bin"
    xvd_path = pub / "lab_xvd_encrypted.bin"

    for p in containers:
        tag = "xvc" if p == xvc_path else "xvd"
        data = p.read_bytes()
        c: dict = {"file": p.name, "signatures": {"offset0": data[:16].hex(), "magic_0x200": data[0x200:0x208].decode(errors="replace"),
                                                  "lab_marker_at_0": data[:13] == b"LAB_SYNTHETIC"}}
        c["inspect_xvd"] = inspect_xvd.inspect(p)
        lab_common.write_json(work / f"inspect_xvd_{tag}.json", c["inspect_xvd"])
        c["validate_xts"] = validate_xts.validate(p)
        lab_common.write_json(work / f"validate_xts_{tag}.json", c["validate_xts"])
        pkg = load_package(BytesSource(data, p.name)).value
        lay = pkg.layout
        ranges = []
        enc_bytes = bytearray()
        plain_bytes = bytearray()
        if pkg.xvcinfo:
            for r in pkg.xvcinfo.regions:
                ranges.append((f"0x{r.id:X} {r.description or ''} KeyId={r.key_id}", r.offset, r.length))
                (enc_bytes if r.keyed else plain_bytes).extend(data[r.offset:r.end])
        else:
            ud = lay.get("user data").offset
            ranges.append(("cabecalho (claro)", 0, 0x3000))
            ranges.append(("user data .. fim (cifra declarada)", ud, len(data) - ud))
            enc_bytes.extend(data[ud:])
            plain_bytes.extend(data[:0x3000])
        c["entropy_profile"] = page_entropy_profile(data, ranges)
        c["generic_tokens_in_encrypted_ranges"] = token_scan(bytes(enc_bytes))
        c["generic_tokens_in_plain_ranges"] = token_scan(bytes(plain_bytes))
        c["printable_runs_in_encrypted_ranges"] = printable_runs(bytes(enc_bytes))
        rep["containers"][tag] = c

    # ---- arquivos do XVC: em claro (extraiveis) x cifrados (so bytes gravados)
    data = xvc_path.read_bytes()
    pkg = load_package(BytesSource(data, xvc_path.name)).value
    pub_out = work / "extracted_public"
    ct_out = work / "extracted_ciphertext"
    pub_out.mkdir()
    ct_out.mkdir()
    files = []
    for row in pkg.rows:
        stored = data[row.start:row.start + row.size]
        keyed = bool(row.region and row.region.keyed)
        dest = (ct_out / (row.name + ".stored.bin")) if keyed else (pub_out / row.name)
        with open(dest, "xb") as fh:
            fh.write(stored)
        files.append({"name": row.name, "size": row.size, "offset": row.start, "region": f"0x{row.region.id:X}",
                      "key_id": row.region.key_id, "encrypted_by_keyid": keyed, "stored_path": _rel(str(dest)),
                      "stored_starts_with_MZ": stored[:2] == b"MZ", "entropy": round(entropy(stored), 4),
                      "size_mod_0x200": row.size % 0x200})
    rep["xvc_files"] = files

    # ---- ferramentas do projeto
    T = rep["tools"]
    T["xvc_probe_xvc"] = run_script(BIN_PE_SCRIPTS / "xvc_probe.py",
                                    [str(xvc_path), "--list-files", "--json-report", str(work / "xvc_probe_xvc.json")],
                                    logs / "xvc_probe_xvc.log")
    T["xvc_probe_xvd"] = run_script(BIN_PE_SCRIPTS / "xvc_probe.py",
                                    [str(xvd_path), "--json-report", str(work / "xvc_probe_xvd.json")],
                                    logs / "xvc_probe_xvd.log")
    carve = {}
    for p in containers:
        tag = "xvc" if p == xvc_path else "xvd"
        jp = work / f"bin_pe_recovery_{tag}.json"
        T[f"bin_pe_recovery_{tag}"] = run_script(BIN_PE_SCRIPTS / "bin_pe_recovery.py",
                                                 ["scan", str(p), "--json", str(jp), "--compressed",
                                                  "--extract-dir", str(work / f"carved_{tag}")],
                                                 logs / f"bin_pe_recovery_{tag}.log")
        carve[tag] = _carve_summary(jp)
    rep["pe_carving"] = carve
    pe_checks = {}
    for f in sorted(list(pub_out.iterdir()) + list(ct_out.iterdir())):
        jp = work / f"pe_check_{f.name}.json"
        T[f"pe_check_{f.name}"] = run_script(BIN_PE_SCRIPTS / "pe_check.py", [str(f), "--json", str(jp)],
                                             logs / f"pe_check_{f.name}.log")
        pe_checks[f.name] = {"exit": T[f"pe_check_{f.name}"]["exit"], **_pe_check_summary(jp, T[f"pe_check_{f.name}"])}
    rep["pe_check"] = pe_checks
    shadow = {}
    for target in ("lab_plaintext.exe", "lab_plaintext_build_b.exe"):
        od = work / f"shadow_pe_{target.split('.')[0]}"
        T[f"shadow_pe_{target}"] = run_script(ALPHA_ROOT / "shadow_pe_reconstructor.py",
                                              ["run-all", "--xvc", str(xvc_path), "--disk", str(pub), "--target", target,
                                               "--out", str(od)], logs / f"shadow_pe_{target}.log")
        shadow[target] = _shadow_summary(od)
    rep["shadow_pe_reconstructor"] = shadow

    rep["build_distinction"] = _build_distinction(data, files)
    rep["classification"] = _classify(rep)
    rep["observable"], rep["unknown"] = _observable_unknown(rep)
    rep["recovery_claim"] = {
        "target_plaintext_bytes_recovered": {"lab_plaintext.exe": 0, "lab_plaintext_build_b.exe": 0,
                                             "xvd_embedded_pe": 0},
        "public_plaintext_bytes_read": sum(f["size"] for f in files if not f["encrypted_by_keyid"]),
        "note": ("nenhum byte de codigo dos executaveis foi recuperado sem chave; os bytes publicos lidos sao "
                 "arquivos de regiao sem KeyId e NAO contam como recuperacao do alvo"),
    }
    return rep


def _carve_summary(jp: Path) -> dict:
    if not jp.is_file():
        return {"report": None}
    r = read_json(jp)
    cands = r.get("pe_candidates") or []
    scan = r.get("scan", {})
    raw_mz = scan.get("raw_mz_hits")
    return {"raw_mz_hits": raw_mz, "bytes_scanned": scan.get("bytes_scanned"),
            "entire_file_scanned": scan.get("entire_file_scanned"),
            "expected_random_mz_hits": round(scan.get("bytes_scanned", 0) / 65536, 1),
            "pe_candidates": len(cands), "mz_hits_rejected": (raw_mz or 0) - len(cands),
            "candidates": [{k: c.get(k) for k in ("offset", "truncated", "purpose", "architecture", "size")}
                           for c in cands[:10]],
            "capability": r.get("capability"), "header_kind": r.get("header_kind")}


def _pe_check_summary(jp: Path, run: dict | None = None) -> dict:
    if not jp.is_file():
        msg = (run or {}).get("log_tail", [""])[-1] if run else ""
        return {"is_pe": False, "conclusion": msg or "ferramenta recusou: nao e PE"}
    r = read_json(jp)
    return {"is_pe": bool(r.get("machine") or r.get("sections")),
            "conclusion": r.get("conclusion") or r.get("error"), "problems": r.get("problems")}


def _shadow_summary(od: Path) -> dict:
    m = od / "metrics.json"
    if not m.is_file():
        return {"metrics": None}
    mm = read_json(m)
    return {k: mm.get(k) for k in ("classification", "bytes_original_with_proof", "pct_bytes_with_proof_of_plaintext",
                                   "bytes_encrypted_unknown", "target_entropy_bits_per_byte", "target_pe_validated",
                                   "target_raw_mz_hits", "metadata_recovered", "executable_candidates")} | {
        "partial_pe_written": (od / "shadow_pe_partial.bin").is_file()}


def _build_distinction(data: bytes, files: list[dict]) -> dict:
    a = next(f for f in files if f["name"] == "lab_plaintext.exe")
    b = next(f for f in files if f["name"] == "lab_plaintext_build_b.exe")
    pa = [data[a["offset"] + i:a["offset"] + i + PAGE] for i in range(0, a["size"], PAGE)]
    pb = [data[b["offset"] + i:b["offset"] + i + PAGE] for i in range(0, b["size"], PAGE)]
    same_pos = sum(1 for x, y in zip(pa, pb) if x == y)
    return {
        "size_equal": a["size"] == b["size"], "pages": (len(pa), len(pb)),
        "regions": (a["region"], b["region"]), "key_ids": (a["key_id"], b["key_id"]),
        "identical_ciphertext_pages_same_position": same_pos,
        "verdict": "INDETERMINADO sem chave",
        "reason": ("ciphertexts diferentes nao provam builds diferentes: RegionId, KeyId (CIK) e data units diferem "
                   "entre as regioes, entao ate plaintexts identicos dariam ciphertexts diferentes; tamanhos iguais "
                   "tambem nao provam o mesmo build"),
    }


def _classify(rep: dict) -> list[dict]:
    out = []
    carve_xvc = rep["pe_carving"].get("xvc", {})
    for f in rep["xvc_files"]:
        ev = []
        if f["encrypted_by_keyid"]:
            ev.append(f"KeyId {f['key_id']} no XvcInfo (declaracao de metadado)")
        ev.append(f"entropia {f['entropy']} bits/byte")
        ev.append("comeca com MZ" if f["stored_starts_with_MZ"] else "nao comeca com MZ")
        pc = rep["pe_check"].get(Path(f["stored_path"]).name, {})
        ev.append("pe_check: PE" if pc.get("is_pe") else "pe_check: nao e PE")
        if f["encrypted_by_keyid"]:
            cls = "CIFRADO (INFERIDO por evidencias independentes; nao ha prova criptografica sem chave)"
        elif f["stored_starts_with_MZ"] and not pc.get("is_pe"):
            cls = "EM CLARO, cabecalho MZ/PE INVALIDO (falso positivo rejeitado)"
        else:
            cls = "EM CLARO (legivel sem chave)"
        out.append({"file": f["name"], "classification": cls, "evidence": ev})
    out.append({"file": "lab_xvd_encrypted.bin (drive)", "classification":
                "CIFRADO (INFERIDO): flag de cifra, user data nao parseavel, entropia ~7.95, folhas no formato 0x14+data unit",
                "evidence": [f"carving: {rep['pe_carving'].get('xvd', {}).get('pe_candidates')} candidatos PE"]})
    out.append({"file": "_carving_xvc", "classification": f"{carve_xvc.get('pe_candidates')} candidatos PE no XVC",
                "evidence": [str(carve_xvc.get('candidates'))]})
    return out


def _observable_unknown(rep: dict) -> tuple[list[str], list[str]]:
    xvc = rep["containers"]["xvc"]
    xvd = rep["containers"]["xvd"]
    vx = xvc["validate_xts"]
    vd = xvd["validate_xts"]
    obs = [
        "marcador LAB_SYNTHETIC na area de assinatura e no ProductId (conteineres sinteticos)",
        "cabecalho XVD inteiro: flags, VDUID, tamanhos, slot de ODK, KeyMaterial selado (XVD) / vazio (XVC)",
        f"XVC: {len(rep['xvc_files'])} arquivos com nome, tamanho exato, offset, regiao, KeyId e GUID da CIK",
        "XVC: quais regioes estao cifradas (KeyId != 0xFFFF) e com qual GUID de chave",
        (f"arvore de hashes integra nos dois conteineres: XVD {vd['hash_tree']['leaves']['keyed_ok']} folhas cifradas ok, "
         f"XVC {vx['hash_tree']['leaves']['keyed_ok']} cifradas + {vx['hash_tree']['leaves']['plain_ok']} em claro ok, "
         f"0 falhas"),
        "data unit de cada pagina cifrada (entry+0x14): XVD sequencial a partir de 0; XVC 0x3E9 com 2 runs nao sequenciais; 0x3EA sequencial",
        "todas as entradas do tweak (section id, VDUID[0:8], data unit) por pagina",
        "entropia ~7.95 bits/byte em todas as paginas cifradas (consistente com cifra, nao prova)",
        "arquivos de regiao sem KeyId (notas publicas, isca MZ) legiveis integralmente",
        "XVD: so o tamanho do drive alinhado em pagina e o tamanho do user data (0x%X)" %
        xvd["inspect_xvd"]["header"]["user_data_length"],
    ]
    unk = [
        "qualquer byte de plaintext dos executaveis (codigo, dados, cabecalhos)",
        "secoes PE, imports, exports, recursos, strings, ponto de entrada, timestamp",
        "se o conteudo cifrado e de fato um PE (so o nome .exe e o tamanho sugerem; INFERIDO)",
        "XVD: nome e tamanho exato do PE (o descritor no user data esta cifrado)",
        "se lab_plaintext.exe e lab_plaintext_build_b.exe sao o mesmo build ou builds diferentes",
        "as CIKs (o KeyMaterial selado exige a ODK; as CIKs XVC exigem o armazenamento por GUID)",
        "se a cifra e mesmo AES-XTS com estas chaves: sem chave nao ha teste; a estrutura so e CONSISTENTE com o modelo",
    ]
    return obs, unk


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--public", default=str(GENERATED / PUBLIC_DIRNAME))
    ap.add_argument("--work", default=str(REPORTS / "work" / "blind"))
    ap.add_argument("--report", default=str(REPORTS / "blind_analysis.json"))
    ap.add_argument("--sealed-hint", default=str(GENERATED / SEALED_DIRNAME),
                    help="usado SO pela auditoria para detectar violacoes; o analisador nunca abre esta pasta")
    a = ap.parse_args(argv)
    rep = analyze(Path(a.public), lab_common.assert_inside_lab(Path(a.work)), Path(a.sealed_hint).resolve())
    write_json(lab_common.assert_inside_lab(Path(a.report)), rep)
    au = rep["access_audit"]
    print(f"[blind] separacao respeitada: {au['separation_respected']} ({au['events_recorded']} eventos auditados)")
    print(f"[blind] bytes de plaintext do alvo recuperados: {rep['recovery_claim']['target_plaintext_bytes_recovered']}")
    return 0 if au["separation_respected"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
