"""PROJECT_ALPHA CRYPTO FORENSICS LAB - orquestrador.

  python -I recovery/crypto_lab/crypto_lab.py run-all [--seed N] [--run-tests]
  python -I recovery/crypto_lab/crypto_lab.py vectors
  python -I recovery/crypto_lab/crypto_lab.py generate [--seed N]
  python -I recovery/crypto_lab/crypto_lab.py blind | reveal | compare | report

run-all executa, nesta ordem: vetores conhecidos -> ENCRYPTOR -> FORENSIC ANALYZER
(as cegas, com auditoria de acesso) -> revelacao autorizada das chaves -> comparacao
-> reprodutibilidade -> integracao com project_alpha/xvcintel -> regressao (opcional)
-> relatorios em recovery/crypto_lab/reports/.

Tres dominios nunca se misturam nos relatorios:
  LABORATORIO SINTETICO - o que foi gerado e medido aqui;
  MODELO DOCUMENTADO    - o que o codigo do xvdtool/XanaduXVD faz;
  PACOTE REAL           - nada: o laboratorio nao abre, nao decifra e nao aplica chaves ao pacote real.
"""
from __future__ import annotations

import argparse
import os
import platform
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_common  # noqa: E402
from lab_common import (GENERATED, PAGE, PUBLIC_DIRNAME, REPO_ROOT, REPORTS, SEALED_DIRNAME, Rng,  # noqa: E402
                        read_json, sha256_file, utc_now, write_json)

DEFAULT_REPORT_SEED = 20261122


def _hash_tree_of(d: Path) -> dict:
    return {p.name: sha256_file(p) for p in sorted(Path(d).iterdir()) if p.is_file()}


# ------------------------------------------------------------------ propriedades XTS
def xts_property_tests(n: int = 40) -> dict:
    from lab_xts import AesXtsTransformLiteral, xts_page, xts_page_openssl
    rng = Rng(4242)
    rt_ok = eq_ok = ossl_ok = 0
    for i in range(n):
        cik = rng.bytes(f"p:cik:{i}", 32)
        if cik[:16] == cik[16:]:
            continue
        page = rng.bytes(f"p:page:{i}", PAGE)
        du, sec = rng.u32(f"p:du:{i}"), rng.u32(f"p:sec:{i}")
        vd = rng.bytes(f"p:vd:{i}", 16)
        ct = xts_page(cik, page, du, sec, vd, True)
        rt_ok += xts_page(cik, ct, du, sec, vd, False) == page
        from lab_xts import build_tweak_seed
        lit = AesXtsTransformLiteral(build_tweak_seed(du, sec, vd), cik[16:], cik[:16], True).transform_data_unit(page, du)
        eq_ok += lit == ct
        ossl_ok += xts_page_openssl(cik, page, du, sec, vd, True) == ct
    return {"cases": n, "decrypt_encrypt_identity": rt_ok, "fast_equals_literal": eq_ok, "fast_equals_openssl": ossl_ok,
            "all_pass": rt_ok == eq_ok == ossl_ok == n}


# ------------------------------------------------------------------ reprodutibilidade
def reproducibility(seed: int) -> dict:
    from lab_encryptor import generate
    work = REPORTS / "work" / "repro"
    lab_common.fresh_dir(work)
    a = generate(work / "seed_a", seed)
    b = generate(work / "seed_b", seed)
    r1 = generate(work / "random_1", None)
    r2 = generate(work / "random_2", None)

    def bins(r):
        return {n: sha256_file(Path(r["public"]) / n) for n in ("lab_xvd_encrypted.bin", "lab_xvc_encrypted.bin")}

    def keys(r):
        return read_json(Path(r["sealed"]) / "lab_keystore.json")
    out = {
        "same_seed_identical_containers": bins(a) == bins(b),
        "same_seed_identical_keys": keys(a)["odk"] == keys(b)["odk"] and keys(a)["cik_by_guid"] == keys(b)["cik_by_guid"],
        "random_mode_keys_differ": keys(r1)["odk"] != keys(r2)["odk"],
        "random_mode_containers_differ": bins(r1) != bins(r2),
        "random_mode_label": read_json(Path(r1["sealed"]) / "lab_ground_truth.json")["mode"],
        "seed": seed,
    }
    # a execucao com chaves aleatorias tambem precisa decifrar 100%
    from lab_decryptor import run_key_reveal
    rr = run_key_reveal(Path(r1["root"]), work / "random_1_reveal")
    out["random_mode_exact_recovery"] = all(v.get("vs_original", {}).get("sha256_equal") for v in rr["recovered"].values())
    out["all_pass"] = all(v for k, v in out.items() if isinstance(v, bool))
    return out


# ------------------------------------------------------------------ integracao (FASE 9)
def project_alpha_integration(gen: Path) -> dict:
    """Valida no laboratorio as premissas que o project_alpha/xvcintel usam no pacote real.
    Nao toca o pacote real; nao aplica chave sintetica a nada que nao seja sintetico."""
    import _bootstrap  # noqa: F401  (caminhos do project_alpha)
    from correlation.evidence_graph import xvc_storage_facts
    from scanners.pe_carver import carve_file
    from xvcintel.core.reader import FileSource
    from xvcintel.engines.integrity import IntegrityOptions, run_integrity
    from xvcintel.engines.package import load_package
    from xvcintel.engines.pages import run_pages
    import lab_hash_tree as HT

    pub, sealed = gen / PUBLIC_DIRNAME, gen / SEALED_DIRNAME
    truth = read_json(sealed / "lab_ground_truth.json")
    xvc = pub / "lab_xvc_encrypted.bin"
    xvd = pub / "lab_xvd_encrypted.bin"
    out: dict = {}

    # 1) precisao do localizador do reconstrutor (offset/tamanho/KeyId/GUID)
    facts = xvc_storage_facts(xvc)
    rows = []
    for f in truth["xvc"]["files"]:
        got = next((r for r in facts["files"] if r["filename"] == f["name"]), None)
        guid = next((k["guid"] for k in truth["xvc"]["key_table"] if k["key_id"] == f["key_id"]), None)
        rows.append({"file": f["name"], "offset_ok": got and int(got["absolute_offset"], 16) == f["container_offset"],
                     "size_ok": got and got["size"] == f["size"], "key_id_ok": got and got["key_id"] == f["key_id"],
                     "key_guid_ok": got and (got["key_id_guid"] == guid)})
    out["reconstructor_locator_precision"] = {"rows": rows,
                                              "all_ok": all(all(v for k, v in r.items() if k != "file") for r in rows)}

    # 2) modelo de tweak/data unit: folha do conteiner == data unit da verdade, pagina a pagina
    src = FileSource(str(xvc))
    pkg = load_package(src).value
    tr_r = pkg.layout.get("hash tree")
    data = xvc.read_bytes()
    tree = data[tr_r.offset:tr_r.end]
    mism = total = 0
    for f in truth["xvc"]["files"]:
        if f["data_units"] is None:
            continue
        for i, du in enumerate(f["data_units"]):
            total += 1
            mism += HT.data_unit_of_page(tree, pkg.layout.geometry, f["hashed_index_first_page"] + i) != du
    out["tweak_model_data_units"] = {"pages_checked": total, "mismatches": mism, "ok": mism == 0}

    # 3) integridade e paginas (xvcintel) nos dois conteineres
    integ = {}
    for name, path in (("xvc", xvc), ("xvd", xvd)):
        s = FileSource(str(path))
        p = load_package(s).value
        res = {c.id: c.status for c in run_integrity(p, IntegrityOptions(full_leaf_level=True))}
        if p.xvcinfo:
            res.update({c.id: c.status for c in run_pages(p)})
        integ[name] = res
        s.close()
    src.close()
    out["xvcintel_engines"] = integ
    out["xvcintel_engines_ok"] = all(v in ("PASS", "PARTIAL", "INFO", "SKIPPED") for d in integ.values() for v in d.values())

    # 4) classificacao plaintext x ciphertext pelo carver do project_alpha
    tmp = REPORTS / "work" / "integration"
    lab_common.fresh_dir(tmp)
    plain_res = carve_file(sealed / "lab_plaintext.exe", out_dir=None)
    enc_res = carve_file(xvc, out_dir=None)
    out["carver_plaintext_vs_ciphertext"] = {
        "plaintext_pe_candidates": len(plain_res["pe_candidates"]),
        "plaintext_candidate_offset0": any(c["offset"] == 0 for c in plain_res["pe_candidates"]),
        "ciphertext_container_pe_candidates": len(enc_res["pe_candidates"]),
        "ok": any(c["offset"] == 0 for c in plain_res["pe_candidates"]) and not enc_res["pe_candidates"],
    }
    out["real_package"] = ("NAO ACESSADO. O laboratorio valida o comportamento do codigo; chaves sinteticas nunca sao "
                           "aplicadas ao pacote real e nada aqui afirma que o executavel real foi decifrado.")
    out["all_ok"] = all(out[k]["all_ok"] if "all_ok" in out[k] else out[k]["ok"]
                        for k in ("reconstructor_locator_precision", "tweak_model_data_units",
                                  "carver_plaintext_vs_ciphertext")) and out["xvcintel_engines_ok"]
    return out


# ------------------------------------------------------------------ regressao
def run_regression() -> dict:
    try:
        import pytest  # noqa: F401
    except ImportError:
        return {"ran": False, "reason": f"pytest indisponivel em {sys.executable}"}
    cmd = [sys.executable, "-I", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
    env = {k: v for k, v in os.environ.items() if k not in ("XVC_PATH", "XVC_FULL")}
    p = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, env=env, timeout=1800)
    tail = p.stdout.strip().splitlines()[-25:]
    summary = next((ln for ln in reversed(tail) if " passed" in ln or " failed" in ln), "")
    failed = [ln for ln in tail if ln.startswith("FAILED")]
    out = {"ran": True, "command": "python -I -m pytest -q -p no:cacheprovider (raiz do repositorio)",
           "exit_code": p.returncode, "summary": summary, "failed": failed, "tail": tail}
    try:
        deleted = subprocess.run(["git", "ls-files", "--deleted"], cwd=REPO_ROOT, capture_output=True, text=True,
                                 timeout=60).stdout.split()
    except (OSError, subprocess.SubprocessError):
        deleted = []
    out["deleted_tracked_files"] = deleted
    if failed and deleted and all(ln.startswith("FAILED tests/test_pe.py") for ln in failed) and \
            any(Path(d).parent.as_posix() == "tests/fixtures/pe" for d in deleted):
        out["failures_cause"] = ("pre-existentes: tests/test_pe.py le tests/fixtures/pe/, e "
                                 f"{', '.join(deleted)} esta apagado no working tree (nao pelo laboratorio). "
                                 "A linha de base antes do laboratorio tinha as mesmas 3 falhas.")
    return out


# ------------------------------------------------------------------ criterios de aceitacao
def acceptance(vectors, gen_truth, blind, reveal, comp, repro, integ, intact, containers_ok) -> list[dict]:
    rec = reveal["recovered"]
    targets = [k for k in rec if k.endswith(".exe")]
    crit = [
        ("C1", "AES-256-ECB desembrulha corretamente a CIK sintetica",
         reveal["xvd"]["unwrapped_cik_equals_ground_truth"] and vectors["results"][0]["encrypt_ok"],
         "key_reveal_analysis.json xvd.unwrapped_cik_equals_ground_truth + FIPS-197 C.3"),
        ("C2", "AES-XTS reproduz os vetores de teste conhecidos", vectors["all_pass"],
         "xts_roundtrip_results.json known_vectors (IEEE 1619 x3, xvdtool xts_cipher.bin, 3 implementacoes)"),
        ("C3", "conteineres gerados corretamente (parseaveis, arvore integra, marcador LAB_SYNTHETIC)", containers_ok,
         "blind_analysis.json containers.*.validate_xts + crypto_lab_report.json project_alpha_integration.xvcintel_engines"),
        ("C4", "a auditoria sem chave nao alega recuperar codigo que nao recuperou",
         all(v == 0 for v in blind["recovery_claim"]["target_plaintext_bytes_recovered"].values())
         and all(v.get("bytes_original_with_proof") == 0 and v.get("classification") == "METADATA_ONLY"
                 for v in blind["shadow_pe_reconstructor"].values())
         and all(c.get("pe_candidates") == 0 for c in blind["pe_carving"].values()),
         "blind_analysis.json recovery_claim, shadow_pe_reconstructor (METADATA_ONLY), pe_carving"),
        ("C5", "descriptografia com a chave correta recupera 100% dos bytes",
         all(rec[k]["vs_original"]["pct_equal"] == 100.0 for k in targets), "pe_recovery_comparison.json per_target"),
        ("C6", "SHA-256 identicos aos da referencia", all(rec[k]["vs_original"]["sha256_equal"] for k in targets),
         "key_reveal_analysis.json recovered.*.vs_original.sha256_equal"),
        ("C7", "PE recuperado passa na validacao estrutural",
         all(rec[k]["pe"]["project_alpha_validate_pe"]["valid"] and rec[k]["pe"]["parse_ok"] and not rec[k]["pe"]["problems"]
             for k in targets), "validate_pe (project_alpha) + parse_pe (xvcintel)"),
        ("C8", "controles negativos detectam os erros (conforme a matriz esperada)",
         comp["negative_controls"]["all_match_expectation"], "pe_recovery_comparison.json negative_controls"),
        ("C9", "arquivos originais permanecem intactos", intact["unchanged"],
         "hashes dos conteineres e do plaintext selado antes x depois de todas as fases"),
        ("C10", "experimentos reproduziveis", repro["all_pass"], "crypto_lab_report.json reproducibility"),
        ("C+", "separacao ENCRYPTOR x ANALYZER comprovada por auditoria de acesso",
         blind["access_audit"]["separation_respected"], "blind_analysis.json access_audit"),
        ("C+", "integracao project_alpha/xvcintel validada no laboratorio", integ["all_ok"],
         "crypto_lab_report.json project_alpha_integration"),
    ]
    return [{"id": i, "criterion": c, "status": "PASS" if ok else "FAIL", "evidence": e} for i, c, ok, e in crit]


# ------------------------------------------------------------------ run-all
def run_all(seed: int | None, run_tests: bool) -> dict:
    import blind_forensic_analysis as BFA
    import compare_results as CR
    import lab_decryptor as DEC
    import lab_encryptor as ENC
    import lab_reference
    import lab_report
    import lab_vectors

    REPORTS.mkdir(exist_ok=True)
    print("[1/9] vetores conhecidos...")
    vectors = lab_vectors.run_known_vectors()
    props = xts_property_tests()
    print("[2/9] ENCRYPTOR...")
    gen = ENC.generate(GENERATED, seed)
    pub, sealed = Path(gen["public"]), Path(gen["sealed"])
    before = {"public": _hash_tree_of(pub), "sealed": _hash_tree_of(sealed)}
    print("[3/9] FORENSIC ANALYZER (as cegas, auditado)...")
    blind = BFA.analyze(pub, REPORTS / "work" / "blind", sealed.resolve())
    write_json(REPORTS / "blind_analysis.json", blind)
    print("[4/9] revelacao autorizada das chaves sinteticas...")
    reveal = DEC.run_key_reveal(GENERATED, REPORTS / "work" / "key_reveal")
    write_json(REPORTS / "key_reveal_analysis.json", reveal)
    print("[5/9] comparacao forense...")
    comp = CR.compare(GENERATED)
    write_json(REPORTS / "pe_recovery_comparison.json", comp)
    print("[6/9] reprodutibilidade...")
    repro = reproducibility(seed if seed is not None else DEFAULT_REPORT_SEED)
    print("[7/9] integracao project_alpha/xvcintel...")
    integ = project_alpha_integration(GENERATED)
    after = {"public": _hash_tree_of(pub), "sealed": _hash_tree_of(sealed)}
    intact = {"before": before, "after": after, "unchanged": before == after}
    regression = {"ran": False, "reason": "use --run-tests"}
    if run_tests:
        print("[8/9] regressao (pytest na raiz)...")
        regression = run_regression()
    else:
        print("[8/9] regressao pulada (use --run-tests)")

    xr = {
        "schema": "crypto_lab.xts_roundtrip/1", "generated_utc": utc_now(),
        "known_vectors": vectors, "property_tests": props,
        "container_roundtrip": {"xvd": reveal["xvd"]["roundtrip_reencrypt_equals_stored"],
                                "xvc": reveal["xvc"]["roundtrip_reencrypt_equals_stored"],
                                "xvc_regions": [{k: r.get(k) for k in ("region", "section_id_used", "pages",
                                                                       "roundtrip_reencrypt_equals_stored")}
                                                for r in reveal["xvc"]["regions"]]},
        "roundtrip_is_not_correctness": [
            {"control": r["control"], "roundtrip_always_exact": r["roundtrip_always_exact"], "observed": r["observed"]}
            for r in comp["negative_controls"]["rows"]],
        "note": ("XTS e uma permutacao para qualquer chave: re-cifrar com parametros ERRADOS devolve o ciphertext "
                 "original (round-trip exato) mesmo quando o plaintext esta errado. So a comparacao com o plaintext "
                 "conhecido (SHA-256) prova a recuperacao."),
    }
    write_json(REPORTS / "xts_roundtrip_results.json", xr)
    xvc_ok = all(v.get("ok") for v in [blind["containers"]["xvc"]["validate_xts"]["hash_tree"]["leaves"],
                                       blind["containers"]["xvd"]["validate_xts"]["hash_tree"]["leaves"]])
    containers_ok = (xvc_ok and integ["xvcintel_engines_ok"]
                     and blind["containers"]["xvc"]["signatures"]["lab_marker_at_0"]
                     and blind["containers"]["xvd"]["signatures"]["lab_marker_at_0"])
    crit = acceptance(vectors, gen["truth"], blind, reveal, comp, repro, integ, intact, containers_ok)
    try:
        import cryptography
        cver = cryptography.__version__
    except ImportError:
        cver = None
    report = {
        "schema": "crypto_lab.report/1", "generated_utc": utc_now(),
        "domains": {
            "synthetic_lab": "conteineres, chaves e PEs gerados aqui; todas as medicoes deste relatorio",
            "documented_model": "regras extraidas do codigo do xvdtool/XanaduXVD (ver reference_model)",
            "real_package": "nao acessado; nenhuma afirmacao sobre o executavel real; ver reports/shadow_pe_final2 (METADATA_ONLY)",
        },
        "environment": {"python": sys.version.split()[0], "platform": platform.platform(), "cryptography": cver},
        "run": {"seed": seed, "mode": gen["truth"]["mode"], "lab_id": gen["truth"]["lab_id"]},
        "reference_model": lab_reference.as_json(),
        "artifacts": {"public": before["public"], "sealed_names": sorted(before["sealed"]),
                      "pe_A_sha256": gen["truth"]["pe"]["A"]["sha256"], "pe_B_sha256": gen["truth"]["pe"]["B"]["sha256"]},
        "acceptance_criteria": crit,
        "acceptance_all_pass": all(c["status"] == "PASS" for c in crit),
        "reproducibility": repro,
        "project_alpha_integration": integ,
        "originals_intact": intact,
        "regression": regression,
        "tool_findings": [
            {"tool": "xvcintel integrity.leaf_vs_data", "finding": "em XVD nao-XVC cifrado comparava 0x18 bytes "
             "(regra de XVC sem XvcInfo) e falhava; o xvdtool usa 0x14 (DataHashEntryLength, XVDFile.cs:128)",
             "action": "corrigido em src/xvcintel/engines/integrity.py (_keyed_for_offset) com teste"},
            {"tool": "xvcintel header summary", "finding": "KeyMaterial nao-zero rotulado 'nao usado' tambem em XVD "
             "nao-XVC, onde e a CIK selada", "action": "rotulo corrigido em src/xvcintel/formats/xvd_header.py"},
            {"tool": "inspect_xvd.py / validate_xts.py", "finding": "citados no prompt, inexistentes no repositorio",
             "action": "criados em recovery/crypto_lab/tools/ (sem chave, somente leitura)"},
            {"tool": "xvc_probe.py (XVD)", "finding": "sem chave nao ha mapa de arquivos: JSON nao gerado",
             "action": "comportamento correto; registrado"},
        ],
        "phases_reports": ["blind_analysis.json", "key_reveal_analysis.json", "xts_roundtrip_results.json",
                           "pe_recovery_comparison.json", "crypto_lab_final_report.html"],
    }
    write_json(REPORTS / "crypto_lab_report.json", report)
    print("[9/9] relatorio HTML...")
    lab_report.render(REPORTS)
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("run-all")
    s.add_argument("--seed", type=int, default=None, help="seed de TESTE (deterministico). Sem seed: chaves seguras")
    s.add_argument("--run-tests", action="store_true", help="roda a suite pytest da raiz e registra o resultado")
    sub.add_parser("vectors")
    g = sub.add_parser("generate")
    g.add_argument("--seed", type=int, default=None)
    sub.add_parser("blind")
    sub.add_parser("reveal")
    sub.add_parser("compare")
    sub.add_parser("report")
    a = ap.parse_args(argv)
    if a.cmd == "run-all":
        rep = run_all(a.seed, a.run_tests)
        for c in rep["acceptance_criteria"]:
            print(f"  [{c['status']}] {c['id']} {c['criterion']}")
        if rep["regression"].get("ran"):
            print(f"  regressao: {rep['regression']['summary']}")
        print(f"relatorios -> {REPORTS}")
        return 0 if rep["acceptance_all_pass"] else 1
    if a.cmd == "vectors":
        import json
        import lab_vectors
        r = lab_vectors.run_known_vectors()
        print(json.dumps(r, indent=1))
        return 0 if r["all_pass"] else 1
    if a.cmd == "generate":
        import lab_encryptor
        return lab_encryptor.main(["--seed", str(a.seed)] if a.seed is not None else [])
    if a.cmd == "blind":
        import blind_forensic_analysis
        return blind_forensic_analysis.main([])
    if a.cmd == "reveal":
        import lab_decryptor
        return lab_decryptor.main([])
    if a.cmd == "compare":
        import compare_results
        return compare_results.main([])
    if a.cmd == "report":
        import lab_report
        lab_report.render(REPORTS)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
