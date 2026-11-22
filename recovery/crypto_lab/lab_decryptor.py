"""FASE 7 - revelacao controlada das chaves (execucao AUTORIZADA, so com as chaves
sinteticas geradas pelo proprio laboratorio).

Entrada: conteineres publicos + lab_keystore.json (ODK por slot, CIK por GUID).
A verdade de referencia (lab_ground_truth.json) so e lida DEPOIS, para comparar.

Passos por conteiner:
  XVD: ODK(slot do cabecalho) -> desembrulha KeyMaterial -> CIK -> XTS headerId=1,
       data unit da folha de cada pagina -> user data (descritor) + drive -> PE.
  XVC: para cada regiao com KeyId: KeyId -> GUID -> CIK do keystore -> XTS
       headerId=RegionId, data unit da folha -> arquivos pelo SegmentMetadata.
  Depois: re-cifra (round-trip), confere a arvore, grava o plaintext em arquivo novo.

Controles negativos (parametro `ctl`): CIK errada, ODK errada, VDUID errado,
RegionId errado, data unit errado, metades da CIK trocadas, CIK de outra regiao,
chave ausente. Um round-trip exato NAO prova a chave correta: XTS e uma
permutacao para QUALQUER chave; so a comparacao com o plaintext prova.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_common  # noqa: E402
from lab_common import (GENERATED, GROUND_TRUTH_NAME, KEYSTORE_NAME, PAGE, PUBLIC_DIRNAME, REPORTS, SEALED_DIRNAME,  # noqa: E402
                        Rng, assert_inside_lab, read_json, sha256_hex, utc_now, write_json)
import lab_hash_tree as HT  # noqa: E402
from lab_xts import crypt_section  # noqa: E402
from lab_xvc_profile import KeyNotAvailable, get_xvc_key  # noqa: E402
from lab_xvd_profile import SECTION_ID_XVD, unwrap_cik  # noqa: E402

from xvcintel.core.reader import BytesSource  # noqa: E402
from xvcintel.core.result import Ok  # noqa: E402
from xvcintel.engines.package import load_package  # noqa: E402
from xvcintel.formats import layout as L  # noqa: E402

CONTROLS = {
    "correct": "chaves corretas (linha de base)",
    "wrong_cik": "CIK aleatoria no lugar da correta",
    "wrong_odk": "ODK aleatoria (perfil XVD: desembrulha uma CIK errada sem erro)",
    "wrong_vduid": "VDUID com o primeiro byte trocado no tweak",
    "wrong_region_id": "RegionId/section id errado no tweak (XVD: 0 em vez de 1; XVC: ids das regioes trocados)",
    "data_unit_page_index": "data unit = indice da pagina na secao (ignora a folha)",
    "data_unit_plus_one": "data unit da folha + 1",
    "swapped_cik_halves": "metades tweak/dados da CIK trocadas",
    "wrong_region_key": "XVC: regiao 0x3EA decifrada com a CIK do KeyId 0",
    "missing_key": "XVC: GUID ausente do keystore (equivale a nao ter a chave)",
}


@dataclass
class Container:
    path: Path
    data: bytes
    pkg: object

    @property
    def header(self):
        return self.pkg.header

    @property
    def tree(self) -> bytes:
        r = self.pkg.layout.get(L.HASH_TREE)
        return self.data[r.offset:r.end]

    @property
    def user_data_offset(self) -> int:
        return self.pkg.layout.get(L.USER_DATA).offset

    def hashed_index(self, abs_offset: int) -> int:
        return (abs_offset - self.user_data_offset) // PAGE

    def leaf_du(self, hashed_index: int) -> int:
        return HT.data_unit_of_page(self.tree, self.pkg.layout.geometry, hashed_index)


def open_container(path: Path) -> Container:
    data = Path(path).read_bytes()
    r = load_package(BytesSource(data, Path(path).name))
    if not isinstance(r, Ok):
        raise ValueError(f"{path}: {r.error}")
    return Container(Path(path), data, r.value)


def _rand(label: str, n: int) -> bytes:
    return Rng(0xBAD).bytes(label, n)


def _swap(cik: bytes) -> bytes:
    return cik[16:] + cik[:16]


def _vduid_le(c: Container, ctl: str) -> bytes:
    v = bytearray(c.header.vduid.bytes_le)
    if ctl == "wrong_vduid":
        v[0] ^= 0xFF
    return bytes(v)


def _dus(c: Container, first_hashed: int, n: int, ctl: str) -> list[int]:
    if ctl == "data_unit_page_index":
        return list(range(n))
    base = [c.leaf_du(first_hashed + i) for i in range(n)]
    return [(d + 1) & 0xFFFFFFFF for d in base] if ctl == "data_unit_plus_one" else base


# ------------------------------------------------------------------ XVD
def decrypt_xvd(c: Container, keystore: dict, ctl: str = "correct") -> dict:
    h = c.header
    res = {"container": c.path.name, "profile": "A-XVD-ODK-CIK", "control": ctl, "steps": []}
    slot = f"0x{h.odk_keyslot_id:X}"
    odk_hex = keystore["odk"].get(slot)
    if odk_hex is None:
        res["error"] = f"ODK do slot {slot} ausente"
        return res
    odk = bytes.fromhex(odk_hex)
    if ctl == "wrong_odk":
        odk = _rand("odk", 32)
    cik = unwrap_cik(odk, h.key_material)
    res["steps"].append({"step": "unwrap_cik", "odk_slot": slot, "key_material": h.key_material.hex(),
                         "cik_sha256": sha256_hex(cik)})
    if ctl == "wrong_cik":
        cik = _rand("cik", 32)
    if ctl == "swapped_cik_halves":
        cik = _swap(cik)
    sec_id = 0 if ctl == "wrong_region_id" else SECTION_ID_XVD
    start = c.user_data_offset
    ct = c.data[start:]
    n = len(ct) // PAGE
    dus = _dus(c, 0, n, ctl)
    pt = crypt_section(cik, ct, dus, sec_id, _vduid_le(c, ctl), encrypt=False)
    res["steps"].append({"step": "xts_decrypt", "section_id": sec_id, "pages": n, "data_units_first": dus[:3],
                         "data_units_source": "pagina" if ctl == "data_unit_page_index" else "folha (entry+0x14)"})
    re_ct = crypt_section(cik, pt, dus, sec_id, _vduid_le(c, ctl), encrypt=True)
    res["roundtrip_reencrypt_equals_stored"] = re_ct == ct
    ud_len = h.user_data_length
    files = {}
    res["_drive_plain"] = pt[HT_pages(ud_len) * PAGE:]
    try:
        desc = json.loads(pt[:ud_len].decode())
        res["user_data_descriptor"] = desc
        drive0 = HT_pages(ud_len) * PAGE
        for f in desc["files"]:
            files[f["name"]] = pt[drive0 + f["drive_offset"]:drive0 + f["drive_offset"] + f["size"]]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as e:
        res["user_data_descriptor"] = None
        res["descriptor_error"] = f"user data decifrado nao e o descritor esperado ({type(e).__name__})"
    res["files"] = files
    res["cik_used_sha256"] = sha256_hex(cik)
    res["_cik"] = cik
    return res


def HT_pages(n: int) -> int:
    return (n + PAGE - 1) // PAGE


# ------------------------------------------------------------------ XVC
def decrypt_xvc(c: Container, keystore: dict, ctl: str = "correct") -> dict:
    xi = c.pkg.xvcinfo
    res = {"container": c.path.name, "profile": "B-XVC-REGION", "control": ctl, "steps": [], "regions": []}
    store = {g: bytes.fromhex(k) for g, k in keystore["cik_by_guid"].items()}
    if ctl == "missing_key":
        store = {}
    keyed = [r for r in xi.regions if r.keyed]
    id_swap = {}
    if ctl == "wrong_region_id" and len(keyed) >= 2:
        id_swap = {keyed[0].id: keyed[1].id, keyed[1].id: keyed[0].id}
    plain = bytearray(c.data)
    key_count = xi.fields["KeyCount"]
    roundtrip = True
    for r in xi.regions:
        if not r.keyed:
            continue
        rr = {"region": f"0x{r.id:X}", "key_id": r.key_id, "offset": r.offset, "length": r.length}
        key_id = r.key_id
        if ctl == "wrong_region_key" and r.id == 0x3EA:
            key_id = 0
        try:
            cik = get_xvc_key(xi.keys, key_count, key_id, store)
        except KeyNotAvailable as e:
            rr["status"] = f"sem chave: {e}"
            res["regions"].append(rr)
            roundtrip = None
            continue
        if cik is None:
            rr["status"] = "regiao sem cifra"
            res["regions"].append(rr)
            continue
        rr["key_guid"] = str(xi.keys[key_id])
        if ctl == "wrong_cik":
            cik = _rand(f"cik{r.id}", 32)
        if ctl == "swapped_cik_halves":
            cik = _swap(cik)
        sec_id = id_swap.get(r.id, r.id)
        first = c.hashed_index(r.offset)
        n = r.length // PAGE
        dus = _dus(c, first, n, ctl)
        ct = c.data[r.offset:r.end]
        pt = crypt_section(cik, ct, dus, sec_id, _vduid_le(c, ctl), encrypt=False)
        re_ct = crypt_section(cik, pt, dus, sec_id, _vduid_le(c, ctl), encrypt=True)
        rr.update({"status": "decifrada", "section_id_used": f"0x{sec_id:X}", "first_hashed_page": first,
                   "pages": n, "data_units_first": dus[:3], "roundtrip_reencrypt_equals_stored": re_ct == ct,
                   "cik_sha256": sha256_hex(cik)})
        roundtrip = roundtrip and (re_ct == ct) if roundtrip is not None else None
        plain[r.offset:r.end] = pt
        res["regions"].append(rr)
    res["roundtrip_reencrypt_equals_stored"] = roundtrip
    files = {}
    for row in c.pkg.rows:
        files[row.name] = bytes(plain[row.start:row.start + row.size])
    res["files"] = files
    res["file_regions"] = {row.name: {"region": f"0x{row.region.id:X}", "key_id": row.region.key_id,
                                      "encrypted": row.region.keyed} for row in c.pkg.rows}
    return res


# ------------------------------------------------------------------ verificacao
def pe_report(data: bytes, path: Path | None = None) -> dict:
    from lab_pe_generator import extract_strings
    from xvcintel.formats.pe import parse_pe
    out = {"sha256": sha256_hex(data), "size": len(data), "mz": data[:2] == b"MZ"}
    r = parse_pe(data)
    out["parse_ok"] = isinstance(r, Ok)
    if isinstance(r, Ok):
        pe = r.value
        out.update({"machine": f"0x{pe.machine:04X}", "magic": f"0x{pe.magic:X}" if pe.magic else None,
                    "sections": [s.name for s in pe.sections], "imports": {d.dll: d.functions for d in (pe.imports or [])},
                    "resources": pe.resources, "problems": pe.problems, "conclusion": pe.conclusion()})
    else:
        out["parse_error"] = str(r.error)
    if path is not None:
        from validation.pe_validator import validate_pe
        v = validate_pe(path, expect_machine=0x8664, expect_magic=0x20B)
        out["project_alpha_validate_pe"] = {"valid": v["valid"],
                                            "passed": sum(1 for x in v["checks"] if x["ok"]),
                                            "total": len(v["checks"]),
                                            "failed": [x["id"] for x in v["checks"] if not x["ok"]]}
    out["strings"] = sorted(set(extract_strings(data)))
    return out


def compare_file(recovered: bytes, original: bytes) -> dict:
    n = min(len(recovered), len(original))
    eq = sum(1 for a, b in zip(recovered[:n], original[:n]) if a == b)
    diff_pages = sorted({i // PAGE for i in range(n) if recovered[i] != original[i]}) if eq != n else []
    return {"bytes_total": len(original), "bytes_equal": eq, "pct_equal": round(100.0 * eq / len(original), 4),
            "sha256_equal": sha256_hex(recovered) == sha256_hex(original), "size_equal": len(recovered) == len(original),
            "pages_different": len(diff_pages), "first_different_pages": diff_pages[:10]}


def run_key_reveal(gen_root: Path | None = None, out_dir: Path | None = None) -> dict:
    gen_root = Path(gen_root or GENERATED)
    pub, sealed = gen_root / PUBLIC_DIRNAME, gen_root / SEALED_DIRNAME
    out_dir = assert_inside_lab(Path(out_dir or REPORTS / "work" / "key_reveal"))
    lab_common.fresh_dir(out_dir)
    keystore = read_json(sealed / KEYSTORE_NAME)
    xvd = open_container(pub / "lab_xvd_encrypted.bin")
    xvc = open_container(pub / "lab_xvc_encrypted.bin")
    stored_before = {p.name: sha256_hex(p.read_bytes()) for p in pub.iterdir() if p.suffix == ".bin"}

    # ---- execucao correta
    rx = decrypt_xvd(xvd, keystore)
    rc = decrypt_xvc(xvc, keystore)
    rec_dir = out_dir / "recovered"
    rec_dir.mkdir()
    written = {}
    for tag, res in (("xvd", rx), ("xvc", rc)):
        d = rec_dir / tag
        d.mkdir()
        for name, data in res["files"].items():
            p = d / name
            with open(p, "xb") as fh:                        # arquivo novo, nunca sobrescreve
                fh.write(data)
            written[f"{tag}/{name}"] = p

    # ---- arvore (sem chave, sobre o ciphertext gravado)
    tree_checks = {}
    for tag, c in (("xvd", xvd), ("xvc", xvc)):
        geo = c.pkg.layout.geometry
        t = HT.verify_tree(c.tree, geo, c.header.top_hash_block_hash)
        ud = c.user_data_offset
        if c.pkg.xvcinfo:
            def keyed(i, c=c):
                reg = c.pkg.xvcinfo.region_at(ud + i * PAGE)
                return bool(reg and reg.keyed)
        else:
            def keyed(i):
                return not c.header.encryption_disabled
        lv = HT.verify_leaves(c.tree, geo, lambda i, c=c: c.data[ud + i * PAGE:ud + (i + 1) * PAGE], keyed)
        tree_checks[tag] = {"top_and_links": {k: v for k, v in t.items() if k != "links_bad"},
                            "leaves": {k: v for k, v in lv.items() if k != "bad"}}

    # ---- comparacao com a verdade de referencia (lida so agora)
    truth = read_json(sealed / GROUND_TRUTH_NAME)
    originals = {"lab_plaintext.exe": (sealed / "lab_plaintext.exe").read_bytes(),
                 "lab_plaintext_build_b.exe": (sealed / "lab_plaintext_build_b.exe").read_bytes()}
    cik_true = bytes.fromhex(truth["xvd"]["cik"])
    comparisons = {}
    for key, p in written.items():
        name = p.name
        data = p.read_bytes()
        try:
            shown = str(p.relative_to(lab_common.LAB_ROOT))
        except ValueError:                      # execucao de teste em diretorio temporario
            shown = str(p)
        entry = {"recovered_path": shown, "sha256": sha256_hex(data)}
        if name in originals:
            entry["vs_original"] = compare_file(data, originals[name])
            entry["pe"] = pe_report(data, p)
            tstr = truth["pe"]["A" if name == "lab_plaintext.exe" else "B"]["strings"]
            entry["ground_truth_strings_found"] = [s for s in tstr if s.encode() in data]
            entry["ground_truth_strings_total"] = len(tstr)
            entry["pe"]["strings_min8_count"] = len(entry["pe"].pop("strings"))
        elif name in truth["public_files"]:
            entry["vs_original"] = {"sha256_equal": sha256_hex(data) == truth["public_files"][name],
                                    "note": "arquivo publico (regiao sem KeyId); legivel tambem sem chave"}
        comparisons[key] = entry

    # ---- controles negativos
    controls = []
    for ctl in CONTROLS:
        if ctl == "correct":
            continue
        row = {"control": ctl, "description": CONTROLS[ctl], "results": {}}
        for tag, c, fn in (("xvd", xvd, decrypt_xvd), ("xvc", xvc, decrypt_xvc)):
            if (tag == "xvd" and ctl in ("wrong_region_key", "missing_key")) or (tag == "xvc" and ctl == "wrong_odk"):
                row["results"][tag] = {"applicable": False}
                continue
            r = fn(c, keystore, ctl)
            per_file = {}
            for name, orig in originals.items():
                how = "pelo mapa/descritor decifrado"
                if name in r.get("files", {}):
                    got = r["files"][name]
                elif tag == "xvd" and name == "lab_plaintext.exe":
                    # descritor ilegivel: o decryptor nao sabe onde esta o PE; medimos pelo offset do drive
                    got = r["_drive_plain"][:len(orig)]
                    how = "descritor ilegivel; medido no inicio do drive decifrado"
                else:
                    continue
                cmpd = compare_file(got, orig)
                per_file[name] = {"sha256_equal": cmpd["sha256_equal"], "pct_bytes_equal": cmpd["pct_equal"],
                                  "mz_header": got[:2] == b"MZ", "pe_parse_ok": pe_report(got)["parse_ok"],
                                  "plaintext_validation": "PASS" if cmpd["sha256_equal"] else "FAIL",
                                  "extraction": how}
            res_row = {"applicable": True, "roundtrip_reencrypt_equals_stored": r.get("roundtrip_reencrypt_equals_stored"),
                       "files": per_file}
            if tag == "xvd":
                res_row["unwrapped_cik_equals_true_cik"] = r.get("_cik") == cik_true if ctl == "wrong_odk" else None
                res_row["user_data_descriptor_parsed"] = r.get("user_data_descriptor") is not None
            if tag == "xvc":
                res_row["regions"] = [{k: v for k, v in x.items() if k in ("region", "status", "section_id_used")}
                                      for x in r["regions"]]
            row["results"][tag] = res_row
        controls.append(row)

    stored_after = {p.name: sha256_hex(p.read_bytes()) for p in pub.iterdir() if p.suffix == ".bin"}
    rx.pop("_cik", None)
    rx.pop("_drive_plain", None)
    report = {
        "schema": "crypto_lab.key_reveal/1",
        "generated_utc": utc_now(),
        "authorization": "segunda execucao autorizada; somente chaves sinteticas do proprio laboratorio",
        "xvd": {"steps": rx["steps"], "user_data_descriptor": rx.get("user_data_descriptor"),
                "roundtrip_reencrypt_equals_stored": rx["roundtrip_reencrypt_equals_stored"],
                "unwrapped_cik_equals_ground_truth": rx["cik_used_sha256"] == sha256_hex(cik_true),
                "cik_split": {"tweak_key_equals_truth": cik_true[:16].hex() == truth["xvd"]["cik_tweak_key"],
                              "data_key_equals_truth": cik_true[16:].hex() == truth["xvd"]["cik_data_key"]}},
        "xvc": {"regions": rc["regions"], "file_regions": rc["file_regions"],
                "roundtrip_reencrypt_equals_stored": rc["roundtrip_reencrypt_equals_stored"],
                "odk_used": False},
        "hash_tree": tree_checks,
        "recovered": comparisons,
        "negative_controls": controls,
        "originals_untouched": {"before": stored_before, "after": stored_after, "unchanged": stored_before == stored_after},
    }
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gen", default=str(GENERATED))
    ap.add_argument("--out", default=str(REPORTS / "work" / "key_reveal"))
    ap.add_argument("--report", default=str(REPORTS / "key_reveal_analysis.json"))
    a = ap.parse_args(argv)
    rep = run_key_reveal(Path(a.gen), Path(a.out))
    write_json(assert_inside_lab(Path(a.report)), rep)
    ok = all(v.get("vs_original", {}).get("sha256_equal") for v in rep["recovered"].values())
    print(f"[decryptor] recuperacao exata: {ok}; relatorio -> {a.report}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
