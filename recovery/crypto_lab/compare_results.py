"""FASE 8 - comparacao forense: antes (as cegas) x depois (revelacao das chaves).

Aqui a verdade de referencia PODE ser lida: a fase cega ja terminou.

Calcula: bytes/percentual de plaintext recuperado, secoes, imports, strings,
falsos positivos (carving, isca, strings aleatorias, classificador por entropia),
hashes, diferencas, distincao de builds, e o experimento de vazamento do XTS
deterministico (mesma chave + mesmo tweak => paginas iguais denunciam plaintext igual).

Distingue explicitamente CONHECER O ALGORITMO de CONHECER A CHAVE.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_common  # noqa: E402
from lab_common import (GENERATED, GROUND_TRUTH_NAME, PAGE, PUBLIC_DIRNAME, REPORTS, SEALED_DIRNAME, Rng, entropy,  # noqa: E402
                        read_json, utc_now, write_json)
from lab_xts import crypt_section  # noqa: E402

ENTROPY_THRESHOLD = 7.9

# matriz esperada dos controles negativos (PASS = plaintext identico ao original)
EXPECTED_CONTROLS = {
    "wrong_cik": {"xvd": {"lab_plaintext.exe": "FAIL"}, "xvc": {"lab_plaintext.exe": "FAIL", "lab_plaintext_build_b.exe": "FAIL"}},
    "wrong_odk": {"xvd": {"lab_plaintext.exe": "FAIL"}},
    "wrong_vduid": {"xvd": {"lab_plaintext.exe": "FAIL"}, "xvc": {"lab_plaintext.exe": "FAIL", "lab_plaintext_build_b.exe": "FAIL"}},
    "wrong_region_id": {"xvd": {"lab_plaintext.exe": "FAIL"}, "xvc": {"lab_plaintext.exe": "FAIL", "lab_plaintext_build_b.exe": "FAIL"}},
    # numeracao sequencial a partir de 0 coincide com o indice da pagina: o erro NAO e detectavel ali
    "data_unit_page_index": {"xvd": {"lab_plaintext.exe": "PASS"},
                             "xvc": {"lab_plaintext.exe": "FAIL", "lab_plaintext_build_b.exe": "PASS"}},
    "data_unit_plus_one": {"xvd": {"lab_plaintext.exe": "FAIL"}, "xvc": {"lab_plaintext.exe": "FAIL", "lab_plaintext_build_b.exe": "FAIL"}},
    "swapped_cik_halves": {"xvd": {"lab_plaintext.exe": "FAIL"}, "xvc": {"lab_plaintext.exe": "FAIL", "lab_plaintext_build_b.exe": "FAIL"}},
    "wrong_region_key": {"xvc": {"lab_plaintext.exe": "PASS", "lab_plaintext_build_b.exe": "FAIL"}},
    "missing_key": {"xvc": {"lab_plaintext.exe": "FAIL", "lab_plaintext_build_b.exe": "FAIL"}},
}
EXPECTED_NOTES = {
    "data_unit_page_index": ("PASS esperado no XVD e no build B: a numeracao deles e sequencial a partir de 0 e coincide "
                             "com o indice da pagina. So a numeracao NAO sequencial (build A) expoe o erro - por isso o "
                             "laboratorio inclui as duas."),
    "wrong_region_key": "PASS esperado no build A: a regiao 0x3E9 continua com a sua propria CIK; so 0x3EA recebe a errada.",
}


def evaluate_controls(controls: list[dict]) -> dict:
    rows, all_match = [], True
    for c in controls:
        exp = EXPECTED_CONTROLS.get(c["control"], {})
        obs = {}
        for tag, res in c["results"].items():
            if not res.get("applicable"):
                continue
            obs[tag] = {n: f["plaintext_validation"] for n, f in res["files"].items()}
        match = obs == exp
        all_match &= match
        rows.append({"control": c["control"], "expected": exp, "observed": obs, "matches_expectation": match,
                     "roundtrip_always_exact": all(r.get("roundtrip_reencrypt_equals_stored") in (True, None)
                                                   for r in c["results"].values() if r.get("applicable")),
                     "note": EXPECTED_NOTES.get(c["control"])})
    return {"all_match_expectation": all_match, "rows": rows}


def entropy_classifier(gen: Path, truth: dict) -> dict:
    """Classificador ingenuo 'cifrado se entropia > 7.9' contra a verdade."""
    pub, sealed = gen / PUBLIC_DIRNAME, gen / SEALED_DIRNAME
    tp = fp = tn = fn = 0
    for name, prof in (("lab_xvd_encrypted.bin", "xvd"), ("lab_xvc_encrypted.bin", "xvc")):
        data = (pub / name).read_bytes()
        t = truth[prof]
        ud_off = t["layout"]["user_data"][0]
        enc_ranges = []
        if prof == "xvd":
            enc_ranges.append((ud_off, len(data)))
        else:
            enc_ranges += [(r["offset"], r["offset"] + r["length"]) for r in t["regions"] if r["encrypted"]]
        for off in range(ud_off, len(data), PAGE):
            is_enc = any(a <= off < b for a, b in enc_ranges)
            pred = entropy(data[off:off + PAGE]) > ENTROPY_THRESHOLD
            tp += is_enc and pred
            fn += is_enc and not pred
            fp += (not is_enc) and pred
            tn += (not is_enc) and not pred
    # o mesmo classificador sobre o PLAINTEXT do PE (nada ali esta cifrado)
    pe = (sealed / "lab_plaintext.exe").read_bytes()
    pe_pages = [pe[i:i + PAGE] for i in range(0, len(pe), PAGE)]
    pe_fp = sum(1 for p in pe_pages if len(p) == PAGE and entropy(p) > ENTROPY_THRESHOLD)
    return {
        "threshold_bits_per_byte": ENTROPY_THRESHOLD,
        "containers_hashed_pages": {"true_positive": tp, "false_negative": fn, "false_positive": fp, "true_negative": tn},
        "plaintext_pe_pages": {"pages": len(pe_pages), "classified_encrypted_but_plaintext": pe_fp,
                               "false_positive_rate": round(pe_fp / len(pe_pages), 4)},
        "conclusion": (f"{pe_fp} de {len(pe_pages)} paginas do PE EM CLARO (dados aleatorios controlados da .data) "
                       "seriam classificadas como 'cifradas' por entropia: entropia alta nao prova criptografia"),
    }


def xts_leakage_experiment(gen: Path, truth: dict) -> dict:
    """Mesmo plaintext de pagina + mesma chave + mesmo tweak => mesmo ciphertext (XTS deterministico)."""
    sealed = gen / SEALED_DIRNAME
    a = lab_common.pad_page((sealed / "lab_plaintext.exe").read_bytes())
    b = lab_common.pad_page((sealed / "lab_plaintext_build_b.exe").read_bytes())
    n = len(a) // PAGE
    eq_plain = [i for i in range(n) if a[i * PAGE:(i + 1) * PAGE] == b[i * PAGE:(i + 1) * PAGE]]
    cik = Rng(99).bytes("leak:cik", 32)
    vd = bytes(range(16))
    dus = list(range(n))

    def eq_ct(sec_a, sec_b, dus_a, dus_b, vd_b=vd):
        ca = crypt_section(cik, a, dus_a, sec_a, vd, True)
        cb = crypt_section(cik, b, dus_b, sec_b, vd_b, True)
        return [i for i in range(n) if ca[i * PAGE:(i + 1) * PAGE] == cb[i * PAGE:(i + 1) * PAGE]]

    same = eq_ct(0x3E9, 0x3E9, dus, dus)
    diff_region = eq_ct(0x3E9, 0x3EA, dus, dus)
    diff_du = eq_ct(0x3E9, 0x3E9, dus, [d + 0x10000 for d in dus])
    diff_vduid = eq_ct(0x3E9, 0x3E9, dus, dus, vd_b=bytes(reversed(range(16))))
    return {
        "pages": n, "plaintext_equal_pages": len(eq_plain), "plaintext_different_pages": n - len(eq_plain),
        "scenarios": {
            "same_key_same_tweak": {"equal_ciphertext_pages": len(same), "matches_plaintext_equality": same == eq_plain},
            "same_key_different_region_id": {"equal_ciphertext_pages": len(diff_region)},
            "same_key_different_data_units": {"equal_ciphertext_pages": len(diff_du)},
            "same_key_different_vduid": {"equal_ciphertext_pages": len(diff_vduid)},
        },
        "different_pages_plaintext": [i for i in range(n) if i not in eq_plain],
        "conclusion": ("Com chave E tweak (RegionId, VDUID, data unit) iguais, o XTS revela SEM CHAVE quais paginas "
                       "mudaram entre dois builds (nao o conteudo). Mudando qualquer entrada do tweak, nenhuma pagina "
                       "coincide. No conteiner do laboratorio os builds estao em regioes/chaves diferentes: nada vaza."),
    }


def compare(gen: Path | None = None, blind_path: Path | None = None, reveal_path: Path | None = None) -> dict:
    gen = Path(gen or GENERATED)
    blind = read_json(blind_path or REPORTS / "blind_analysis.json")
    reveal = read_json(reveal_path or REPORTS / "key_reveal_analysis.json")
    truth = read_json(gen / SEALED_DIRNAME / GROUND_TRUTH_NAME)
    pub = gen / PUBLIC_DIRNAME
    containers_bytes = b"".join((pub / n).read_bytes() for n in ("lab_xvd_encrypted.bin", "lab_xvc_encrypted.bin"))

    targets = {"xvd/lab_plaintext.exe": "A", "xvc/lab_plaintext.exe": "A", "xvc/lab_plaintext_build_b.exe": "B"}
    per_target = {}
    for key, variant in targets.items():
        t = truth["pe"][variant]
        rv = reveal["recovered"][key]
        pe = rv["pe"]
        tstr = t["strings"]
        blind_strings = [s for s in tstr if s.encode() in containers_bytes]
        per_target[key] = {
            "ground_truth": {"size": t["size"], "sha256": t["sha256"], "sections": [s["name"] for s in t["sections"]],
                             "imports": t["imports"], "strings": len(tstr)},
            "blind": {"bytes_recovered": 0, "pct_recovered": 0.0, "sections_identified": 0, "imports_identified": 0,
                      "ground_truth_strings_found_in_ciphertext": len(blind_strings), "pe_valid": False,
                      "size_known": key.startswith("xvc/"),
                      "size_source": "SegmentMetadata (metadado em claro)" if key.startswith("xvc/") else
                                     "desconhecido: descritor cifrado; so o limite superior (DriveSize) e visivel"},
            "after_key_reveal": {"bytes_recovered": rv["vs_original"]["bytes_equal"],
                                 "pct_recovered": rv["vs_original"]["pct_equal"],
                                 "sha256_equal": rv["vs_original"]["sha256_equal"],
                                 "bytes_different": rv["vs_original"]["bytes_total"] - rv["vs_original"]["bytes_equal"],
                                 "sections_identified": len(pe.get("sections", [])),
                                 "sections_match_truth": pe.get("sections") == [s["name"] for s in t["sections"]],
                                 "imports_identified": sum(len(v) for v in pe.get("imports", {}).values()),
                                 "imports_match_truth": pe.get("imports") == t["imports"],
                                 "ground_truth_strings_found": len(rv["ground_truth_strings_found"]),
                                 "pe_valid_project_alpha": pe["project_alpha_validate_pe"]["valid"],
                                 "pe_problems": pe.get("problems")},
        }

    carve = blind["pe_carving"]
    mz_total = sum((c.get("raw_mz_hits") or 0) for c in carve.values())
    cand_total = sum(c.get("pe_candidates", 0) for c in carve.values())
    pr = blind["containers"]["xvc"]["printable_runs_in_encrypted_ranges"]
    false_pos = {
        "pe_carving": {"raw_mz_hits_total": mz_total, "accepted_as_pe": cand_total,
                       "false_positive_rate": round(cand_total / mz_total, 6) if mz_total else 0.0,
                       "expected_random_mz_hits": sum(c.get("expected_random_mz_hits", 0) for c in carve.values())},
        "decoy_fake_pe": {"rejected_by_pe_check": not blind["pe_check"]["lab_decoy_fake_pe.bin"]["is_pe"],
                          "reason": blind["pe_check"]["lab_decoy_fake_pe.bin"].get("conclusion")},
        "printable_strings_in_ciphertext_xvc": {"count": pr["count"], "expected_random": pr["expected_random"],
                                                 "ground_truth_strings_among_them": 0,
                                                 "note": "strings >= 8 imprimiveis no ciphertext sao acaso"},
        "entropy_classifier": entropy_classifier(gen, truth),
        "shadow_pe_false_claims": {t: v.get("bytes_original_with_proof") for t, v in blind["shadow_pe_reconstructor"].items()},
    }

    pa = lab_common.pad_page((gen / SEALED_DIRNAME / "lab_plaintext.exe").read_bytes())
    pb = lab_common.pad_page((gen / SEALED_DIRNAME / "lab_plaintext_build_b.exe").read_bytes())
    plain_diff = [i for i in range(len(pa) // PAGE) if pa[i * PAGE:(i + 1) * PAGE] != pb[i * PAGE:(i + 1) * PAGE]]
    builds = {
        "blind": blind["build_distinction"],
        "after_key_reveal": {
            "sha256_A": truth["pe"]["A"]["sha256"], "sha256_B": truth["pe"]["B"]["sha256"],
            "distinguishable": truth["pe"]["A"]["sha256"] != truth["pe"]["B"]["sha256"],
            "recovered_sha256_A": reveal["recovered"]["xvc/lab_plaintext.exe"]["sha256"],
            "recovered_sha256_B": reveal["recovered"]["xvc/lab_plaintext_build_b.exe"]["sha256"],
            "different_pages": plain_diff, "different_page_count": len(plain_diff),
            "declared_changes_B": truth["pe"]["B"]["changed_vs_A"],
        },
        "xts_determinism_leakage": xts_leakage_experiment(gen, truth),
    }

    total_target = sum(v["ground_truth"]["size"] for v in per_target.values())
    total_rec = sum(v["after_key_reveal"]["bytes_recovered"] for v in per_target.values())
    return {
        "schema": "crypto_lab.pe_recovery_comparison/1",
        "generated_utc": utc_now(),
        "summary": {
            "target_bytes_total": total_target,
            "blind_bytes_recovered": 0, "blind_pct": 0.0,
            "reveal_bytes_recovered": total_rec, "reveal_pct": round(100.0 * total_rec / total_target, 4),
            "all_sha256_equal": all(v["after_key_reveal"]["sha256_equal"] for v in per_target.values()),
            "blind_access_audit_respected": blind["access_audit"]["separation_respected"],
        },
        "per_target": per_target,
        "false_positives": false_pos,
        "build_distinction": builds,
        "negative_controls": evaluate_controls(reveal["negative_controls"]),
        "algorithm_vs_key": {
            "known_to_blind_analyzer": ["algoritmo completo (AES-XTS, modelo xvdtool, publico)",
                                        "seed do tweak de toda pagina (section id, VDUID[0:8], data unit)",
                                        "geometria da arvore e integridade do ciphertext",
                                        "nomes, tamanhos e offsets dos arquivos XVC"],
            "unknown_to_blind_analyzer": ["ODK", "CIK (XVD selada; XVC por GUID)"],
            "result": "conhecer o algoritmo e todas as entradas do tweak rendeu 0 bytes de plaintext; a chave e o unico segredo",
        },
        "impossible_without_keys": blind["unknown"],
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gen", default=str(GENERATED))
    ap.add_argument("--report", default=str(REPORTS / "pe_recovery_comparison.json"))
    a = ap.parse_args(argv)
    rep = compare(Path(a.gen))
    write_json(lab_common.assert_inside_lab(Path(a.report)), rep)
    s = rep["summary"]
    print(f"[compare] as cegas: {s['blind_bytes_recovered']} bytes; com chave: {s['reveal_bytes_recovered']} "
          f"({s['reveal_pct']}%); controles conforme esperado: {rep['negative_controls']['all_match_expectation']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
