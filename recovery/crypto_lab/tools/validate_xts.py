"""validate_xts.py - validacao SEM CHAVE da estrutura XTS de um XVD/XVC.

Criado pelo crypto_lab: o prompt citava este modulo, mas ele nao existia no
repositorio. NAO aceita chaves e NAO decifra. Verifica o que a estrutura do
modelo xvdtool permite verificar so com os bytes gravados:

  * alinhamento das secoes cifradas em unidades de 0x1000 (um data unit por pagina);
  * arvore de hashes: topo, ligacoes entre niveis e TODAS as folhas
    (0x14 bytes para paginas cifradas, 0x18 para paginas em claro);
  * numeracao dos data units (entry+0x14): runs, sequencial x nao sequencial, repeticao;
  * entradas publicas do tweak por secao: section id (1 no XVD, RegionId no XVC),
    VDUID[0:8] e a faixa de data units - tudo publico; so as chaves faltam;
  * entropia por pagina (cifradas x em claro) - indicio, nunca prova;
  * paginas de ciphertext repetidas (XTS e deterministico).

Uso:  python -I recovery/crypto_lab/tools/validate_xts.py ARQUIVO [--json SAIDA]
"""
from __future__ import annotations

import argparse
import statistics
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lab_common  # noqa: E402
from lab_common import PAGE, entropy, sha256  # noqa: E402
import lab_hash_tree as HT  # noqa: E402

from xvcintel.core.reader import BytesSource  # noqa: E402
from xvcintel.core.result import Ok  # noqa: E402
from xvcintel.engines.package import load_package  # noqa: E402
from xvcintel.formats import layout as L  # noqa: E402

HIGH_ENTROPY = 7.9


def runs_of(values: list[int]) -> list[dict]:
    runs = []
    for i, v in enumerate(values):
        if runs and v == (runs[-1]["start_value"] + runs[-1]["length"]) & 0xFFFFFFFF:
            runs[-1]["length"] += 1
        else:
            runs.append({"first_page_in_section": i, "start_value": v, "length": 1})
    return runs


def _stats(xs: list[float]) -> dict:
    if not xs:
        return {"pages": 0}
    return {"pages": len(xs), "min": round(min(xs), 4), "mean": round(statistics.fmean(xs), 4), "max": round(max(xs), 4),
            f"above_{HIGH_ENTROPY}": sum(1 for x in xs if x > HIGH_ENTROPY)}


def validate(path: Path) -> dict:
    path = Path(path)
    data = path.read_bytes()
    out: dict = {"tool": "validate_xts", "keyless": True, "file": path.name}
    r = load_package(BytesSource(data, path.name))
    if not isinstance(r, Ok):
        out["error"] = str(r.error)
        return out
    pkg = r.value
    h = pkg.header
    lay = pkg.layout
    geo = lay.geometry
    tree_r = lay.get(L.HASH_TREE)
    tree = data[tree_r.offset:tree_r.end]
    ud = lay.get(L.USER_DATA).offset
    xi = pkg.xvcinfo

    # ---- secoes cifradas segundo o modelo
    sections = []
    if xi:
        for reg in xi.regions:
            if reg.keyed:
                sections.append({"name": f"regiao 0x{reg.id:X}", "section_id": reg.id, "offset": reg.offset,
                                 "length": reg.length, "key_id": reg.key_id})
    elif not h.encryption_disabled:
        sections.append({"name": "user data .. fim (XVD nao-XVC)", "section_id": 1, "offset": ud,
                         "length": len(data) - ud, "key_id": None})
    keyed_pages: set[int] = set()
    for s in sections:
        s["aligned_0x1000"] = s["offset"] % PAGE == 0 and s["length"] % PAGE == 0
        first = (s["offset"] - ud) // PAGE
        n = s["length"] // PAGE
        s["first_hashed_page"], s["pages"] = first, n
        keyed_pages |= set(range(first, first + n))
        if geo.levels:
            dus = [HT.data_unit_of_page(tree, geo, first + i) for i in range(n)]
            rr = runs_of(dus)
            s["data_units"] = {
                "runs": rr[:20], "run_count": len(rr),
                "sequential_single_run": len(rr) == 1,
                "equals_page_index_in_section": dus == list(range(n)),
                "duplicates_in_section": n - len(set(dus)),
            }
        s["tweak_inputs_public"] = {"section_id": f"0x{s['section_id']:X}",
                                    "vduid_0_8": h.vduid.bytes_le[:8].hex(),
                                    "data_unit_source": "folha nivel 0, entry+0x14" if h.integrity else "indice da pagina"}

    # ---- arvore
    tree_res = HT.verify_tree(tree, geo, h.top_hash_block_hash) if geo.levels else {"ok": None}
    leaves = HT.verify_leaves(tree, geo, lambda i: data[ud + i * PAGE:ud + (i + 1) * PAGE],
                              lambda i: i in keyed_pages) if geo.levels else {"ok": None}

    # ---- entropia e repeticao
    ent_keyed, ent_plain = [], []
    ct_hashes = Counter()
    for i in range(geo.hashed_pages):
        pg = data[ud + i * PAGE:ud + (i + 1) * PAGE]
        e = entropy(pg)
        if i in keyed_pages:
            ent_keyed.append(e)
            ct_hashes[sha256(pg)] += 1
        else:
            ent_plain.append(e)
    repeated = sum(c - 1 for c in ct_hashes.values() if c > 1)

    out.update({
        "encryption_declared": not h.encryption_disabled,
        "region_id_in_xts_flag": bool(h.volume_flags & 0x40),
        "xts_sections": sections,
        "hash_tree": {"levels": list(geo.level_pages), "top_ok": tree_res.get("top_ok"),
                      "links_checked": tree_res.get("links_checked"), "links_bad": len(tree_res.get("links_bad", [])),
                      "leaves": {k: v for k, v in leaves.items() if k != "bad"}, "bad_leaves": leaves.get("bad", [])[:20]},
        "entropy": {"encrypted_pages": _stats(ent_keyed), "plain_pages": _stats(ent_plain),
                    "warning": "entropia alta e indicio, nao prova de criptografia"},
        "repeated_ciphertext_pages": repeated,
        "conclusions": [
            "estrutura XTS consistente: secoes alinhadas em 0x1000" if all(s["aligned_0x1000"] for s in sections)
            else "ALERTA: secao cifrada desalinhada",
            "integridade conferida sobre o ciphertext gravado (nao diz nada sobre o plaintext)"
            if tree_res.get("ok") and leaves.get("ok") else "ALERTA: arvore de hashes nao confere",
            "todas as entradas do tweak sao publicas (section id, VDUID[0:8], data unit); faltam apenas as chaves AES",
        ],
    })
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    res = validate(Path(a.path))
    if a.json:
        lab_common.write_json(Path(a.json), res)
    for c in res.get("conclusions", [res.get("error", "")]):
        print(" -", c)
    return 0 if "error" not in res else 1


if __name__ == "__main__":
    raise SystemExit(main())
