"""inspect_xvd.py - inspecao SEM CHAVE de um XVD/XVC (somente leitura).

Criado pelo crypto_lab: o prompt citava este modulo, mas ele nao existia no
repositorio. Nao aceita chaves, nao decifra nada, abre o arquivo so com "rb".

Relata o que e observavel no cabecalho e nos metadados em claro:
flags (cifra/integridade declaradas), tipo de conteudo, VDUID, slot de ODK,
KeyMaterial (CIK selada: presente/ausente, entropia), tabela de GUIDs de CIK,
regioes com KeyId, mapa de arquivos e o marcador LAB_SYNTHETIC.

Uso:  python -I recovery/crypto_lab/tools/inspect_xvd.py ARQUIVO [--json SAIDA]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lab_common  # noqa: E402
from lab_common import LAB_MARKER, entropy, sha256_file  # noqa: E402

from xvcintel.core.reader import FileSource  # noqa: E402
from xvcintel.core.result import Ok  # noqa: E402
from xvcintel.engines.package import load_package  # noqa: E402
from xvcintel.formats.xvd_header import decode_flags  # noqa: E402

XVC_CONTENT_TYPES_XVDTOOL = {1, 6, 15, 16, 24, 25, 26}   # XvdFile.XvcContentTypes


def inspect(path: Path) -> dict:
    path = Path(path)
    out: dict = {"tool": "inspect_xvd", "keyless": True, "file": path.name, "size": path.stat().st_size,
                 "sha256": sha256_file(path)}
    with open(path, "rb") as fh:
        head = fh.read(0x1000)
    out["lab_marker"] = {"signature_area": LAB_MARKER in head[:0x200], "product_id": head[0x39C:0x3AC].startswith(LAB_MARKER)}
    if head[0x200:0x208] != b"msft-xvd":
        out["xvd_magic"] = False
        out["conclusion"] = "nao e XVD/XVC (magic msft-xvd ausente em 0x200)"
        return out
    out["xvd_magic"] = True
    src = FileSource(str(path))
    try:
        r = load_package(src)
        if not isinstance(r, Ok):
            out["error"] = str(r.error)
            return out
        pkg = r.value
        h = pkg.header
        km = h.key_material
        out["header"] = {
            "volume_flags": f"0x{h.volume_flags:X}", "flag_names": decode_flags(h.volume_flags),
            "encryption_declared": not h.encryption_disabled,
            "integrity_declared": h.integrity,
            "region_id_in_xts_flag": bool(h.volume_flags & 0x40),
            "content_type": h.content_type, "content_type_name": h.content_type_name,
            "is_xvc_by_xvcintel": h.is_xvc,
            "is_xvc_by_xvdtool_content_type": h.content_type in XVC_CONTENT_TYPES_XVDTOOL,
            "vduid": str(h.vduid), "vduid_bytes_le_0_8": h.vduid.bytes_le[:8].hex(),
            "odk_keyslot_id": f"0x{h.odk_keyslot_id:X}",
            "key_material": {"all_zero": not any(km), "entropy_bits_per_byte": round(entropy(km), 3),
                             "length": len(km),
                             "interpretation": ("vazio (XVC: CIKs por GUID, ODK nao usada)" if not any(km) else
                                                "CIK selada (AES-256-ECB com a ODK do slot); ilegivel sem a ODK")},
            "drive_size": h.drive_size, "user_data_length": h.user_data_length, "xvc_data_length": h.xvc_data_length,
            "top_hash_block_hash": h.top_hash_block_hash.hex(),
            "product_id": h.product_id.hex(),
        }
        out["layout"] = [{"name": rr.name, "offset": rr.offset, "size": rr.size} for rr in pkg.layout.regions]
        out["hash_tree_levels"] = list(pkg.layout.geometry.level_pages)
        out["user_data_parsed"] = pkg.userdata is not None
        out["parse_errors"] = pkg.errors
        xi = pkg.xvcinfo
        if xi:
            out["xvcinfo"] = {
                "content_id_equals_vduid": xi.content_id == h.vduid,
                "description": xi.description,
                "key_count": xi.fields["KeyCount"],
                "cik_guids": [str(g) for g in xi.keys],
                "regions": [{"id": f"0x{r.id:X}", "desc": r.description, "key_id": r.key_id, "encrypted_by_keyid": r.keyed,
                             "key_guid": str(xi.keys[r.key_id]) if r.keyed and r.key_id < len(xi.keys) else None,
                             "offset": r.offset, "length": r.length} for r in xi.regions],
            }
            out["files"] = [{"name": row.name, "size": row.size, "offset": row.start,
                             "region": f"0x{row.region.id:X}" if row.region else None,
                             "key_id": row.region.key_id if row.region else None,
                             "encrypted_by_keyid": bool(row.region and row.region.keyed)} for row in pkg.rows]
        out["observable_without_key"] = _observable(out)
    finally:
        src.close()
    return out


def _observable(o: dict) -> list[str]:
    h = o["header"]
    obs = [f"flags {h['volume_flags']} ({', '.join(h['flag_names']) or '-'}) - declaracao do cabecalho, nao prova",
           f"VDUID {h['vduid']} (entra no tweak: bytes 8..15 = {h['vduid_bytes_le_0_8']})",
           f"ODK slot {h['odk_keyslot_id']}; KeyMaterial: {h['key_material']['interpretation']}"]
    if "xvcinfo" in o:
        xi = o["xvcinfo"]
        obs.append(f"{xi['key_count']} GUID(s) de CIK: {', '.join(xi['cik_guids'])}")
        enc = [r["id"] for r in xi["regions"] if r["encrypted_by_keyid"]]
        obs.append(f"regioes com KeyId (cifradas segundo o XvcInfo): {enc}")
        obs.append(f"{len(o.get('files', []))} arquivos com nome, tamanho exato, offset e regiao")
    else:
        obs.append("sem XvcInfo: XVD nao-XVC; user data cifrado " +
                   ("(nao parseavel)" if not o.get("user_data_parsed") else "(parseado!)"))
    return obs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    res = inspect(Path(a.path))
    if a.json:
        lab_common.write_json(Path(a.json), res)
    for line in res.get("observable_without_key", [res.get("conclusion", res.get("error", ""))]):
        print(" -", line)
    return 0 if res.get("xvd_magic") else 1


if __name__ == "__main__":
    raise SystemExit(main())
