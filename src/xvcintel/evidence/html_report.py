"""Relatorio HTML autocontido (sem recursos externos: CSS e JS embutidos)."""
from __future__ import annotations

import html
import json

CSS = """
:root{--bg:#fbfaf7;--fg:#1d1d1b;--mut:#6b6a66;--line:#e2e0da;--card:#fff;--ok:#1f7a4d;--inf:#946200;--unk:#6b4fb0;--bad:#b3261e}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe7;--mut:#a3a19b;--line:#33322f;--card:#1e1e1c;--ok:#5cc28e;--inf:#e0b04f;--unk:#b29cf0;--bad:#f0857c}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 16px 64px}h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
.mut{color:var(--mut)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:16px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}.card b{font-size:22px;display:block}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);font-size:13.5px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{font-weight:600;background:transparent}
td code,pre{font:12.5px/1.45 ui-monospace,Consolas,monospace;word-break:break-all;white-space:pre-wrap}
.tag{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11.5px;font-weight:600;border:1px solid currentColor}
.CONFIRMED,.PASS{color:var(--ok)}.INFERRED,.PARTIAL,.INFO{color:var(--inf)}.UNKNOWN,.SKIPPED{color:var(--unk)}.FAIL{color:var(--bad)}
.filters button{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:4px 10px;margin:0 6px 8px 0;cursor:pointer}
.filters button.on{border-color:var(--fg)}.wrap{overflow-x:auto}details{margin:6px 0}summary{cursor:pointer}
"""

JS = """
document.querySelectorAll('.filters button').forEach(b=>b.addEventListener('click',()=>{
 document.querySelectorAll('.filters button').forEach(x=>x.classList.remove('on'));b.classList.add('on');
 const lv=b.dataset.level;document.querySelectorAll('#findings tbody tr').forEach(tr=>{
 tr.style.display=(lv==='ALL'||tr.dataset.level===lv)?'':'none';});}));
"""


def e(x) -> str:
    return html.escape("" if x is None else str(x))


def tag(level: str) -> str:
    return f'<span class="tag {e(level)}">{e(level)}</span>'


def render_html(report: dict, profile: dict | None, graph_stats: dict | None) -> str:
    s = report["summary"]
    fl = s["findings_by_level"]
    cs = s["checks_by_status"]
    parts = [f"<!doctype html><html lang='pt-BR'><head><meta charset='utf-8'>"
             f"<meta name='viewport' content='width=device-width,initial-scale=1'><title>XVC Intelligence</title>"
             f"<style>{CSS}</style></head><body><main>",
             "<h1>XVC Intelligence Engine</h1>",
             f"<div class='mut'>Pacote <code>{e(report['source']['path'])}</code> &middot; {report['source']['size']:,} bytes "
             f"&middot; VDUID {e(report['source']['vduid'])} &middot; gerado {e(report['generated_utc'])}</div>",
             f"<p class='mut'>{e(report['read_only'])}.</p>",
             "<div class='cards'>"]
    for lv in ("CONFIRMED", "INFERRED", "UNKNOWN"):
        parts.append(f"<div class='card'><span class='{lv}'>{lv}</span><b>{fl.get(lv, 0)}</b>achados</div>")
    for st in ("PASS", "PARTIAL", "FAIL", "SKIPPED", "INFO"):
        parts.append(f"<div class='card'><span class='{st}'>{st}</span><b>{cs.get(st, 0)}</b>checagens</div>")
    parts.append("</div>")

    parts.append("<h2>Achados</h2><div class='filters'>" + "".join(
        f"<button data-level='{lv}' class='{'on' if lv == 'ALL' else ''}'>{lv}</button>"
        for lv in ("ALL", "CONFIRMED", "INFERRED", "UNKNOWN")) + "</div>")
    parts.append("<div class='wrap'><table id='findings'><thead><tr><th>id</th><th>nivel</th><th>afirmacao</th>"
                 "<th>evidencia / testes</th></tr></thead><tbody>")
    for f in report["findings"]:
        ev = "; ".join(f"{x['source']} {x.get('field', '')} {x.get('offset_hex', '')}".strip() for x in f["evidence"])
        extra = ""
        if f.get("how_to_test"):
            extra += f"<div class='mut'>Como testar: {e(f['how_to_test'])}</div>"
        if f.get("notes"):
            extra += f"<div class='mut'>Nota: {e(f['notes'])}</div>"
        parts.append(f"<tr data-level='{e(f['level'])}'><td><code>{e(f['id'])}</code><br><span class='mut'>{e(f['category'])}</span></td>"
                     f"<td>{tag(f['level'])}</td><td>{e(f['statement'])}{extra}</td>"
                     f"<td><code>{e(ev)}</code><br><span class='mut'>{e(', '.join(f['tests']))}</span></td></tr>")
    parts.append("</tbody></table></div>")

    if profile and "error" not in profile:
        parts.append(f"<h2>Perfil: {e(profile['target'])}</h2>")
        for sec in ("identity", "storage", "integrity", "stored_content", "launch_config", "pe_content"):
            parts.append(f"<details {'open' if sec in ('storage', 'integrity', 'pe_content') else ''}><summary>{e(sec)}</summary>"
                         "<div class='wrap'><table><tbody>")
            for k, v in profile[sec].items():
                val = v["value"]
                if isinstance(val, (dict, list)):
                    val = json.dumps(val, ensure_ascii=False)
                parts.append(f"<tr><td><code>{e(k)}</code></td><td>{tag(v['level'])}</td><td><code>{e(val)}</code>"
                             f"<div class='mut'>{e(v['source'])}</div></td></tr>")
            parts.append("</tbody></table></div></details>")
        d = profile["co_packaged_dlls"]
        parts.append(f"<p><b>DLLs no mesmo pacote ({len(d['items'])})</b>: {e(', '.join(x['name'] for x in d['items']))}"
                     f"<br><span class='mut'>{e(d['note'])}</span></p>")

    parts.append("<h2>Checagens</h2><div class='wrap'><table><thead><tr><th>id</th><th>status</th><th>detalhe</th>"
                 "<th>cobertura</th></tr></thead><tbody>")
    for c in report["checks"]:
        parts.append(f"<tr><td><code>{e(c['id'])}</code><br>{e(c['title'])}</td><td>{tag(c['status'])}</td>"
                     f"<td>{e(c['detail'][:600])}</td><td class='mut'>{e(c['coverage'][:300])}</td></tr>")
    parts.append("</tbody></table></div>")

    reg = report.get("regression")
    if reg:
        parts.append("<h2>Regressao contra o relatorio anterior</h2>"
                     f"<p>{tag('PASS' if reg.get('passed') else 'FAIL')} arquivos: {reg['file_count_old']} &rarr; "
                     f"{reg['file_count_new']}; diferencas de campo: {len(reg['field_differences'])}; "
                     f"diferencas em source: {e(json.dumps(reg['source_differences'], ensure_ascii=False))}</p>")
    if report.get("tests"):
        parts.append(f"<h2>Testes automatizados</h2><pre>{e(json.dumps(report['tests'], indent=1, ensure_ascii=False))}</pre>")
    if graph_stats:
        parts.append(f"<h2>Grafo de conhecimento</h2><p>{graph_stats['nodes']} nos, {graph_stats['edges']} arestas; "
                     f"por confianca: {e(json.dumps(graph_stats['by_confidence']))}. Consulta: "
                     "<code>python xvcintel.py query --graph reports/graph.json --node game_scarlett_master.exe</code></p>")
    parts.append("<h2>Proximas investigacoes</h2><ol>" + "".join(f"<li>{e(x)}</li>" for x in report["next_investigations"]) + "</ol>")
    parts.append(f"</main><script>{JS}</script></body></html>")
    return "".join(parts)
