"""Gera crypto_lab_final_report.html a partir dos JSONs da pasta reports/ (autocontido)."""
from __future__ import annotations

import html
import json
from pathlib import Path

import lab_common  # noqa: F401
from lab_common import read_json

CSS = """
:root{--bg:#f7f7f5;--fg:#1c1d1f;--muted:#5d6168;--card:#ffffff;--line:#dcdde0;--accent:#2f5bd3;
--ok:#1f7a3f;--okbg:#e5f4ea;--bad:#a8261b;--badbg:#fbe6e3;--warn:#8a5a00;--warnbg:#fdf1d6;--code:#eef0f3;}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){--bg:#141518;--fg:#e6e7ea;--muted:#a0a4ab;
--card:#1d1f23;--line:#33363c;--accent:#8aa8ff;--ok:#7fd49b;--okbg:#17301f;--bad:#ff9b8f;--badbg:#3a1a17;
--warn:#f3c66b;--warnbg:#33290f;--code:#262930;}}
:root[data-theme="dark"]{--bg:#141518;--fg:#e6e7ea;--muted:#a0a4ab;--card:#1d1f23;--line:#33363c;--accent:#8aa8ff;
--ok:#7fd49b;--okbg:#17301f;--bad:#ff9b8f;--badbg:#3a1a17;--warn:#f3c66b;--warnbg:#33290f;--code:#262930;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,
"Segoe UI",Roboto,sans-serif}main{max-width:1080px;margin:0 auto;padding:28px 16px 64px}
h1{font-size:1.75rem;margin:0 0 4px}h2{font-size:1.25rem;margin:36px 0 10px;padding-top:8px;border-top:1px solid var(--line)}
h3{font-size:1.02rem;margin:20px 0 8px}p{margin:6px 0 10px}.muted{color:var(--muted)}
code,.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.86em}
code{background:var(--code);padding:1px 5px;border-radius:4px;word-break:break-all}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0}
.grid{display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(220px,1fr))}
.kpi .v{font-size:1.6rem;font-weight:650}.kpi .l{color:var(--muted);font-size:.85rem}
.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--card);margin:10px 0}
table{border-collapse:collapse;width:100%;font-size:.88rem}th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;background:var(--code)}tr:last-child td{border-bottom:none}
.b{display:inline-block;padding:1px 8px;border-radius:999px;font-size:.78rem;font-weight:600;white-space:nowrap}
.ok{background:var(--okbg);color:var(--ok)}.bad{background:var(--badbg);color:var(--bad)}.warn{background:var(--warnbg);color:var(--warn)}
.na{background:var(--code);color:var(--muted)}
.domains{display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(240px,1fr))}
.domains .card h3{margin-top:0}.flow{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:8px 0}
.flow span.n{background:var(--code);border:1px solid var(--line);border-radius:6px;padding:4px 8px;font-size:.85rem}
.flow span.a{color:var(--muted)}ul{margin:6px 0 10px;padding-left:20px}li{margin:2px 0}
footer{margin-top:40px;color:var(--muted);font-size:.82rem}
"""


def e(x) -> str:
    return html.escape(str(x))


def badge(v) -> str:
    if v is True or v == "PASS":
        return '<span class="b ok">PASS</span>'
    if v is False or v == "FAIL":
        return '<span class="b bad">FAIL</span>'
    if v is None:
        return '<span class="b na">n/a</span>'
    s = str(v)
    cls = {"CONFIRMED_BY_CODE": "ok", "CONFIRMED_BY_VECTOR": "ok", "PROJECT_OBSERVATION": "warn", "HYPOTHESIS": "warn",
           "NOT_IMPLEMENTED": "na", "METADATA_ONLY": "warn"}.get(s, "na")
    return f'<span class="b {cls}">{e(s)}</span>'


def table(headers, rows) -> str:
    h = "".join(f"<th>{e(x)}</th>" for x in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<div class="table-wrap"><table><thead><tr>{h}</tr></thead><tbody>{body}</tbody></table></div>'


def ul(items) -> str:
    return "<ul>" + "".join(f"<li>{e(i)}</li>" for i in items) + "</ul>"


def render(reports: Path) -> Path:
    reports = Path(reports)
    R = read_json(reports / "crypto_lab_report.json")
    B = read_json(reports / "blind_analysis.json")
    K = read_json(reports / "key_reveal_analysis.json")
    X = read_json(reports / "xts_roundtrip_results.json")
    C = read_json(reports / "pe_recovery_comparison.json")
    s = C["summary"]
    out = []
    out.append(f"""<header><h1>PROJECT_ALPHA · Crypto Forensics Lab</h1>
<p class="muted">Reprodução criptográfica XVD/XVC (modelo xvdtool) sobre artefatos <b>LAB_SYNTHETIC</b> ·
gerado {e(R['generated_utc'])} · modo <code>{e(R['run']['mode'])}</code> · seed <code>{e(R['run']['seed'])}</code> ·
lab_id <code>{e(R['run']['lab_id'])}</code></p></header>""")

    out.append(f"""<section class="domains">
<div class="card"><h3>Laboratório sintético</h3><p>{e(R['domains']['synthetic_lab'])}. Contêineres sem assinatura, marcados
<code>LAB_SYNTHETIC</code>; chaves geradas localmente. Toda medição deste relatório vem daqui.</p></div>
<div class="card"><h3>Modelo documentado</h3><p>{e(R['domains']['documented_model'])}. "Confirmado" significa que é assim
que a <i>ferramenta</i> de referência faz. Compatibilidade com o console <b>não</b> foi demonstrada.</p></div>
<div class="card"><h3>Pacote real</h3><p>{e(R['domains']['real_package'])}. Nenhuma chave sintética foi aplicada a ele.</p></div>
</section>""")

    au = B["access_audit"]
    ctl = C["negative_controls"]
    fp = C["false_positives"]["pe_carving"]
    out.append(f"""<section class="grid">
<div class="card kpi"><div class="v">{s['blind_bytes_recovered']} B</div><div class="l">plaintext do alvo recuperado às cegas</div></div>
<div class="card kpi"><div class="v">{s['reveal_pct']}%</div><div class="l">recuperado com a chave sintética ({s['reveal_bytes_recovered']:,} B, SHA-256 iguais)</div></div>
<div class="card kpi"><div class="v">{fp['accepted_as_pe']} / {fp['raw_mz_hits_total']}</div><div class="l">'MZ' no ciphertext aceitos como PE</div></div>
<div class="card kpi"><div class="v">{sum(r['matches_expectation'] for r in ctl['rows'])}/{len(ctl['rows'])}</div><div class="l">controles negativos conforme a matriz esperada</div></div>
<div class="card kpi"><div class="v">{len(au['violations'])}</div><div class="l">acessos proibidos na fase cega ({au['events_recorded']} eventos auditados)</div></div>
</section>""")

    out.append("<h2>Critérios de aceitação</h2>")
    out.append(table(["", "Critério", "Status", "Evidência"],
                     [[e(c["id"]), e(c["criterion"]), badge(c["status"]), f"<span class='muted'>{e(c['evidence'])}</span>"]
                      for c in R["acceptance_criteria"]]))
    reg = R["regression"]
    if reg.get("ran"):
        out.append(f"<p>Regressão (<code>{e(reg['command'])}</code>): <b>{e(reg['summary'])}</b>"
                   + (f" — falhas: {e('; '.join(reg['failed']))}" if reg["failed"] else "")
                   + (f"<br><span class='muted'>Causa: {e(reg['failures_cause'])}</span>" if reg.get("failures_cause") else "")
                   + "</p>")

    # ---------------- Fase 1
    rm = R["reference_model"]
    out.append("<h2>Fase 1 — Modelo de referência (lido no código)</h2>")
    out.append(f"<p>xvdtool <code>{e(rm['sources']['xvdtool']['commit'][:12])}</code> · XanaduXVD "
               f"<code>{e(rm['sources']['XanaduXVD']['commit'][:12])}</code>. {e(rm['disclaimer'])}</p>")
    out.append(table(["ID", "Status", "Tema", "Regra", "Fonte"],
                     [[e(r["id"]), badge(r["status"]), e(r["topic"]), e(r["rule"]),
                       "<br>".join(f"<code>{e(x['repo'])}:{e(x['file'])}:{e(x['lines'])}</code>" for x in r["source"])]
                      for r in rm["rules"]]))

    # ---------------- Fases 2-3
    out.append("<h2>Fases 2–3 — Perfis criptográficos e AES-XTS por página</h2>")
    out.append("""<div class="card"><h3>Perfil A — XVD com ODK/CIK</h3><div class="flow">
<span class="n">ODK (32 B)</span><span class="a">→ AES-256-ECB, sem padding →</span><span class="n">KeyMaterial @0x34C</span>
<span class="a">→ AES-256-ECB⁻¹(ODK) →</span><span class="n">CIK (32 B)</span><span class="a">→</span>
<span class="n">CIK[0:16] tweak · CIK[16:32] dados</span><span class="a">→</span><span class="n">AES-128-XTS, headerId = 1</span></div>
<h3>Perfil B — XVC por região</h3><div class="flow"><span class="n">Region.KeyId</span><span class="a">→ índice →</span>
<span class="n">XvcInfo.EncryptionKeyIds[KeyId] (GUID)</span><span class="a">→ keystore →</span><span class="n">CIK</span>
<span class="a">→</span><span class="n">AES-128-XTS, headerId = RegionId</span><span class="muted">(ODK não participa)</span></div>
<h3>Seed do tweak (16 bytes)</h3><p><code>[0:4] data_unit LE32</code> · <code>[4:8] section_id LE32</code> ·
<code>[8:16] VDUID[0:8]</code> → T₀ = AES(tweak_key, seed); Tᵢ₊₁ = Tᵢ·x em GF(2¹²⁸), redução 0x87; C = E(P⊕T)⊕T.
Unidade = 0x1000 bytes; data unit lido da folha (<code>entry+0x14</code>).</p></div>""")
    rows = []
    for r in X["known_vectors"]["results"]:
        rows.append([e(r["vector"])] + [badge(r.get(k)) for k in ("fast_ok", "literal_ok", "openssl_ok", "decrypt_ok")])
    out.append("<h3>Vetores conhecidos</h3>")
    out.append(table(["Vetor", "rápida", "literal (C#)", "OpenSSL", "decifra"], rows))
    pt = X["property_tests"]
    out.append(f"<p>Propriedades em {pt['cases']} páginas aleatórias: decifra∘cifra = identidade {pt['decrypt_encrypt_identity']}/{pt['cases']}, "
               f"rápida = literal {pt['fast_equals_literal']}/{pt['cases']}, rápida = OpenSSL {pt['fast_equals_openssl']}/{pt['cases']}. "
               "Nenhuma etapa difusiva foi implementada: nenhuma referência a implementa (H02).</p>")

    # ---------------- Fases 4-5
    out.append("<h2>Fases 4–5 — Executáveis e contêineres</h2>")
    gt = C["per_target"]
    pa = gt["xvc/lab_plaintext.exe"]["ground_truth"]
    pb = gt["xvc/lab_plaintext_build_b.exe"]["ground_truth"]
    out.append(table(["", "Build A (lab_plaintext.exe)", "Build B (lab_plaintext_build_b.exe)"], [
        ["Tamanho", f"{pa['size']:,} B", f"{pb['size']:,} B"],
        ["SHA-256", f"<code>{e(pa['sha256'])}</code>", f"<code>{e(pb['sha256'])}</code>"],
        ["Seções", e(", ".join(pa["sections"])), e(", ".join(pb["sections"]))],
        ["Imports", e("; ".join(f"{d}: {', '.join(f)}" for d, f in pa["imports"].items())), "idem"],
        ["Strings de teste", str(pa["strings"]), str(pb["strings"])],
    ]))
    out.append(table(["Contêiner público", "Tamanho", "SHA-256"],
                     [[e(i["file"]), f"{i['size']:,} B", f"<code>{e(i['sha256'])}</code>"] for i in B["inputs"]]))
    out.append(table(["Arquivo no XVC", "Região", "KeyId", "Tamanho", "Cifrado (KeyId)", "Entropia gravada"],
                     [[e(f["name"]), e(f["region"]), e(f["key_id"]), f"{f['size']:,}", badge(f["encrypted_by_keyid"]),
                       e(f["entropy"])] for f in B["xvc_files"]]))

    # ---------------- Fase 6
    out.append("<h2>Fase 6 — Engenharia reversa às cegas</h2>")
    out.append(f"<p>O analisador recebeu só <code>{e(B['input_dir'])}</code>. Separação respeitada: {badge(au['separation_respected'])} — "
               f"{au['events_recorded']} eventos de abertura/listagem auditados (<code>sys.addaudithook</code>), "
               f"{len(au['violations'])} em material selado.</p>")
    trows = []
    for k, t in B["tools"].items():
        trows.append([f"<code>{e(t['script'])}</code>", e(k), e(t["exit"]), f"<span class='muted'>{e(' | '.join(t['log_tail'][-2:]))[:220]}</span>"])
    out.append(table(["Ferramenta", "Execução", "Saída", "Final do log"], trows))
    out.append("<div class='grid'><div class='card'><h3>Observável sem chave</h3>" + ul(B["observable"]) +
               "</div><div class='card'><h3>Permanece desconhecido</h3>" + ul(B["unknown"]) + "</div></div>")
    out.append(table(["Item", "Classificação", "Evidências"],
                     [[e(c["file"]), e(c["classification"]), e("; ".join(c["evidence"]))] for c in B["classification"]
                      if not c["file"].startswith("_")]))
    sp = B["shadow_pe_reconstructor"]
    out.append(table(["Alvo (shadow_pe_reconstructor)", "Classificação", "Bytes com prova", "Bytes cifrados/desconhecidos", "Entropia"],
                     [[e(t), badge(v.get("classification")), e(v.get("bytes_original_with_proof")),
                       f"{v.get('bytes_encrypted_unknown') or 0:,}", e(v.get("target_entropy_bits_per_byte"))] for t, v in sp.items()]))

    # ---------------- Fase 7
    out.append("<h2>Fase 7 — Revelação controlada das chaves</h2>")
    xvd = K["xvd"]
    out.append(f"<p>XVD: CIK desembrulhada = verdade {badge(xvd['unwrapped_cik_equals_ground_truth'])}; divisão tweak/dados conforme "
               f"{badge(xvd['cik_split']['tweak_key_equals_truth'] and xvd['cik_split']['data_key_equals_truth'])}; round-trip "
               f"{badge(xvd['roundtrip_reencrypt_equals_stored'])}. XVC: round-trip {badge(K['xvc']['roundtrip_reencrypt_equals_stored'])}; "
               f"ODK usada: {e(K['xvc']['odk_used'])}.</p>")
    out.append(table(["Arquivo recuperado", "Bytes iguais", "SHA-256", "PE válido", "Seções", "Imports", "Strings de teste"],
                     [[e(k), f"{v['vs_original'].get('pct_equal', '—')}%" if 'pct_equal' in v['vs_original'] else "—",
                       badge(v["vs_original"]["sha256_equal"]),
                       badge(v["pe"]["project_alpha_validate_pe"]["valid"]) if "pe" in v else badge(None),
                       e(", ".join(v["pe"]["sections"])) if "pe" in v else "—",
                       e(sum(len(f) for f in v["pe"]["imports"].values())) if "pe" in v else "—",
                       f"{len(v['ground_truth_strings_found'])}/{v['ground_truth_strings_total']}" if "pe" in v else "—"]
                      for k, v in K["recovered"].items()]))
    out.append("<h3>Controles negativos</h3>")
    crow = []
    for r in ctl["rows"]:
        o = r["observed"]
        cells = []
        for tag, name in (("xvd", "lab_plaintext.exe"), ("xvc", "lab_plaintext.exe"), ("xvc", "lab_plaintext_build_b.exe")):
            v = o.get(tag, {}).get(name)
            cells.append(badge(v) if v else badge(None))
        crow.append([e(r["control"])] + cells + [badge(r["roundtrip_always_exact"]), badge(r["matches_expectation"]),
                                                 f"<span class='muted'>{e(r['note'] or '')}</span>"])
    out.append(table(["Controle", "XVD · A", "XVC · A", "XVC · B", "Round-trip exato", "= esperado", "Nota"], crow))
    out.append(f"<p class='muted'>{e(X['note'])}</p>")

    # ---------------- Fase 8
    out.append("<h2>Fase 8 — Comparação forense</h2>")
    mrows = []
    for k, v in gt.items():
        b, a = v["blind"], v["after_key_reveal"]
        mrows.append([e(k), f"{b['bytes_recovered']} / {a['bytes_recovered']:,}", f"{b['pct_recovered']}% / {a['pct_recovered']}%",
                      f"{b['sections_identified']} / {a['sections_identified']}", f"{b['imports_identified']} / {a['imports_identified']}",
                      f"{b['ground_truth_strings_found_in_ciphertext']} / {a['ground_truth_strings_found']}",
                      f"{a['bytes_different']}", e(b["size_source"])])
    out.append(table(["Alvo (às cegas / com chave)", "Bytes", "%", "Seções", "Imports", "Strings", "Bytes diferentes", "Tamanho às cegas"], mrows))
    ec = C["false_positives"]["entropy_classifier"]
    pr = C["false_positives"]["printable_strings_in_ciphertext_xvc"]
    out.append(f"""<div class="grid"><div class="card"><h3>Falsos positivos</h3><ul>
<li>Carving: {fp['raw_mz_hits_total']} ocorrências de 'MZ' no ciphertext (esperado ao acaso ≈ {fp['expected_random_mz_hits']}), {fp['accepted_as_pe']} aceitas como PE.</li>
<li>Isca com MZ/PE falso: rejeitada {badge(C['false_positives']['decoy_fake_pe']['rejected_by_pe_check'])} — {e(C['false_positives']['decoy_fake_pe']['reason'])}</li>
<li>Strings imprimíveis ≥ 8 no ciphertext do XVC: {pr['count']} (esperado ao acaso ≈ {pr['expected_random']}); nenhuma é string real.</li>
<li>Shadow PE: bytes alegados com prova = {e(', '.join(f'{k}: {v}' for k, v in C['false_positives']['shadow_pe_false_claims'].items()))}.</li></ul></div>
<div class="card"><h3>Entropia não prova cifra</h3><p>Classificador "cifrado se H &gt; {ec['threshold_bits_per_byte']}" nos contêineres:
{ec['containers_hashed_pages']['true_positive']} verdadeiros positivos, {ec['containers_hashed_pages']['false_negative']} falsos negativos,
{ec['containers_hashed_pages']['false_positive']} falsos positivos, {ec['containers_hashed_pages']['true_negative']} verdadeiros negativos
(aqui só acerta porque o laboratório não tem página em claro de alta entropia nos contêineres). No <b>plaintext</b> do PE: {ec['plaintext_pe_pages']['classified_encrypted_but_plaintext']} de
{ec['plaintext_pe_pages']['pages']} páginas seriam "cifradas" (dados aleatórios controlados da .data).</p></div></div>""")
    bd = C["build_distinction"]
    lk = bd["xts_determinism_leakage"]
    out.append("<h3>Distinção de builds</h3>")
    out.append(f"<p><b>Às cegas:</b> {e(bd['blind']['verdict'])} — {e(bd['blind']['reason'])}.</p>")
    out.append(f"<p><b>Com chave:</b> SHA-256 diferentes; {bd['after_key_reveal']['different_page_count']} páginas diferem "
               f"(<code>{e(bd['after_key_reveal']['different_pages'])}</code>): cabeçalho, .text, .rdata, as 2 páginas de .data alteradas e .rsrc.</p>")
    out.append(table(["Experimento XTS determinístico (mesma CIK)", "Páginas de ciphertext iguais"],
                     [[e(k), f"{v['equal_ciphertext_pages']}" + (f" (= {lk['plaintext_equal_pages']} páginas de plaintext iguais: "
                                                                  f"{'coincide' if v.get('matches_plaintext_equality') else 'não coincide'})"
                                                                  if 'matches_plaintext_equality' in v else "")]
                      for k, v in lk["scenarios"].items()]))
    out.append(f"<p class='muted'>{e(lk['conclusion'])}</p>")
    av = C["algorithm_vs_key"]
    out.append("<div class='card'><h3>Algoritmo × chave</h3><p><b>O analisador conhecia:</b></p>" + ul(av["known_to_blind_analyzer"]) +
               f"<p><b>Não conhecia:</b> {e(', '.join(av['unknown_to_blind_analyzer']))}. <b>{e(av['result'])}.</b></p></div>")

    # ---------------- Fase 9
    ig = R["project_alpha_integration"]
    out.append("<h2>Fase 9 — Integração com o PROJECT_ALPHA</h2>")
    out.append(table(["Validação no laboratório", "Resultado"], [
        ["Localizador do reconstrutor (offset/tamanho/KeyId/GUID de cada arquivo)", badge(ig["reconstructor_locator_precision"]["all_ok"])],
        [f"Modelo do tweak: data unit da folha = verdade ({ig['tweak_model_data_units']['pages_checked']} páginas)", badge(ig["tweak_model_data_units"]["ok"])],
        ["Motores xvcintel (integridade + páginas) nos dois contêineres", badge(ig["xvcintel_engines_ok"])],
        ["Carver: PE no plaintext encontrado; 0 no contêiner cifrado", badge(ig["carver_plaintext_vs_ciphertext"]["ok"])],
    ]))
    out.append(f"<p><b>Pacote real:</b> {e(ig['real_package'])}</p>")
    out.append(table(["Ferramenta", "Achado do laboratório", "Ação"],
                     [[e(f["tool"]), e(f["finding"]), e(f["action"])] for f in R["tool_findings"]]))
    rp = R["reproducibility"]
    out.append(f"<p>Reprodutibilidade: mesma seed ⇒ contêineres idênticos {badge(rp['same_seed_identical_containers'])}; "
               f"modo padrão com chaves aleatórias ⇒ chaves diferentes {badge(rp['random_mode_keys_differ'])} e recuperação exata "
               f"{badge(rp['random_mode_exact_recovery'])}. Originais intactos {badge(R['originals_intact']['unchanged'])}.</p>")

    out.append("""<h2>Limites</h2><ul>
<li>Contêineres sem assinatura RSA, sem XVD embutido, sem sistema de arquivos no drive do perfil A; nenhum console os aceitaria.</li>
<li>OriginalXvcDataHash não é reproduzido (o próprio xvdtool falha em pacotes retail, N02).</li>
<li>O flag RegionIdInXts e o bit DiffusiveDisabled são hipóteses (H01, H02): gravados/registrados, não interpretados.</li>
<li>Conformidade com o console Xbox não foi testada; o laboratório prova o comportamento do código de referência.</li>
<li>Nada aqui recupera, decifra ou afirma algo sobre o executável do pacote real.</li></ul>""")
    out.append(f"<footer>Relatórios: {e(', '.join(R['phases_reports']))} · crypto_lab_report.json · Python {e(R['environment']['python'])} · "
               f"cryptography {e(R['environment']['cryptography'])}</footer>")

    doc = (f'<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
           f'<title>Crypto Forensics Lab</title><style>{CSS}</style></head><body><main>{"".join(out)}</main></body></html>')
    p = reports / "crypto_lab_final_report.html"
    p.write_text(doc, encoding="utf-8")
    return p


if __name__ == "__main__":
    import sys
    from lab_common import REPORTS
    print(render(Path(sys.argv[1]) if len(sys.argv) > 1 else REPORTS))
    _ = json
