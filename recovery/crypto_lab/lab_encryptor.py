"""ENCRYPTOR - FASES 4 e 5.

Conhece o plaintext e as chaves sinteticas; cria os conteineres. Grava:

  <out>/public/  -> o que o FORENSIC ANALYZER pode ver
       lab_xvd_encrypted.bin, lab_xvc_encrypted.bin, lab_manifest.json
  <out>/sealed/  -> verdade de referencia, fora do alcance do analisador
       lab_plaintext.exe, lab_plaintext_build_b.exe, lab_ground_truth.json, lab_keystore.json

Sem --seed: chaves de secrets.token_bytes (seguras). Com --seed: tudo
deterministico (chaves de teste INSEGURAS, rotuladas como tal).
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))   # python -I nao inclui a pasta do script
import lab_common  # noqa: F401,E402
from lab_common import (GENERATED, GROUND_TRUTH_NAME, KEYSTORE_NAME, LAB_BANNER, LAB_MARKER_STR, PUBLIC_DIRNAME,
                        SEALED_DIRNAME, Rng, fresh_dir, sha256_hex, utc_now, write_json)
from lab_pe_generator import build_pe, extract_strings
from lab_xvc_profile import XVC_KEY_NONE, LabFile, LabRegion, build_xvc_container, gen_xvc_keys
from lab_xvd_profile import build_xvd_container, gen_cik, gen_odk

PE_A_NAME = "lab_plaintext.exe"
PE_B_NAME = "lab_plaintext_build_b.exe"
XVD_NAME = "lab_xvd_encrypted.bin"
XVC_NAME = "lab_xvc_encrypted.bin"
MANIFEST_NAME = "lab_manifest.json"
GENERATOR_VERSION = "crypto_lab/1.0"

# runs de data unit (pagina relativa ao arquivo, valor inicial)
DU_RUNS_A = [(0, 0x7A3C1000), (20, 0x00000400)]     # NAO sequencial: dois runs com salto
DU_RUNS_B = [(0, 0x00000000)]                        # sequencial a partir de 0


def decoy_fake_pe() -> bytes:
    """Arquivo publico com 'MZ' e 'PE\\0\\0' mas optional header invalido: isca para falso positivo."""
    b = bytearray(0x400)
    b[0:2] = b"MZ"
    struct.pack_into("<I", b, 0x3C, 0x80)
    b[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", b, 0x84, 0x8664, 3)
    struct.pack_into("<H", b, 0x94, 0x10)            # SizeOfOptionalHeader curto demais
    b[0x200:0x200 + 64] = f"{LAB_MARKER_STR} decoy: cabecalho PE falso para medir falsos positivos".encode()[:64]
    return bytes(b)


def public_notes() -> bytes:
    return (f"{LAB_BANNER}\n"
            "Arquivo publico em regiao sem KeyId (0xFFFF): legivel sem chave.\n"
            "Os executaveis deste conteiner estao em regioes cifradas.\n").encode()


def pe_structure_record(pe_bytes: bytes) -> dict:
    """Registro estrutural ANTES da criptografia (xvcintel + project_alpha)."""
    from xvcintel.core.result import Ok
    from xvcintel.formats.pe import parse_pe
    r = parse_pe(pe_bytes)
    rec = {"sha256": sha256_hex(pe_bytes), "size": len(pe_bytes), "parse_ok": isinstance(r, Ok)}
    if isinstance(r, Ok):
        pe = r.value
        rec.update({
            "machine": f"0x{pe.machine:04X}", "magic": f"0x{pe.magic:X}", "sections": [s.name for s in pe.sections],
            "imports": {d.dll: d.functions for d in (pe.imports or [])}, "resources": pe.resources,
            "problems": pe.problems, "conclusion": pe.conclusion(),
        })
    rec["strings_min8"] = sorted(set(extract_strings(pe_bytes)))[:200]
    return rec


def generate(out_root: Path | None = None, seed: int | None = None) -> dict:
    out_root = Path(out_root or GENERATED)
    root = fresh_dir(out_root)
    pub = root / PUBLIC_DIRNAME
    sealed = root / SEALED_DIRNAME
    pub.mkdir()
    sealed.mkdir()
    rng = Rng(seed)
    lab_id = rng.bytes("id:lab", 8).hex()

    # ---- FASE 4: executaveis
    pe_a = build_pe(rng, lab_id, "A")
    pe_b = build_pe(rng, lab_id, "B")
    (sealed / PE_A_NAME).write_bytes(pe_a.data)
    (sealed / PE_B_NAME).write_bytes(pe_b.data)

    # ---- chaves
    odk = gen_odk(rng)
    cik_xvd = gen_cik(rng)
    xvc_keys = gen_xvc_keys(rng, 2)

    # ---- FASE 5: conteineres
    xvd = build_xvd_container(pe_a.data, PE_A_NAME, odk=odk, cik=cik_xvd, rng=rng)
    regions = [
        LabRegion(0x40000003, XVC_KEY_NONE, [LabFile("lab_public_notes.txt", public_notes()),
                                             LabFile("lab_decoy_fake_pe.bin", decoy_fake_pe())]),
        LabRegion(0x3E9, 0, [LabFile(PE_A_NAME, pe_a.data, DU_RUNS_A)]),
        LabRegion(0x3EA, 1, [LabFile(PE_B_NAME, pe_b.data, DU_RUNS_B)]),
    ]
    xvc = build_xvc_container(regions, keys=xvc_keys, rng=rng)
    (pub / XVD_NAME).write_bytes(xvd.data)
    (pub / XVC_NAME).write_bytes(xvc.data)

    manifest = {
        "schema": "crypto_lab.manifest/1",
        "marker": LAB_MARKER_STR,
        "banner": LAB_BANNER,
        "generator": GENERATOR_VERSION,
        "containers": [
            {"file": XVD_NAME, "profile": "A-XVD-ODK-CIK", "size": len(xvd.data), "sha256": sha256_hex(xvd.data)},
            {"file": XVC_NAME, "profile": "B-XVC-REGION", "size": len(xvc.data), "sha256": sha256_hex(xvc.data)},
        ],
        "public_algorithm_model": "AES-XTS por pagina de 0x1000 conforme xvdtool (o algoritmo e publico; as chaves nao)",
        "not_included": ["chaves (ODK, CIK)", "plaintext", "verdade de referencia"],
        "compatibility_claim": "nenhuma: conteineres sinteticos sem assinatura; nao sao pacotes Xbox oficiais",
    }
    write_json(pub / MANIFEST_NAME, manifest)

    keystore = {
        "schema": "crypto_lab.keystore/1",
        "marker": LAB_MARKER_STR,
        "warning": ("chaves SINTETICAS do laboratorio" + (" (DETERMINISTICAS, INSEGURAS: seed de teste)" if rng.deterministic
                                                         else " (aleatorias, secrets.token_bytes)")),
        "odk": {f"0x{0x1AB5:X}": odk.hex()},
        "cik_by_guid": {str(g): k.hex() for g, k in xvc_keys},
        "note": "a CIK do perfil XVD NAO esta aqui: ela deve ser desembrulhada do KeyMaterial com a ODK",
    }
    write_json(sealed / KEYSTORE_NAME, keystore)

    truth = {
        "schema": "crypto_lab.ground_truth/1",
        "marker": LAB_MARKER_STR,
        "generated_utc": utc_now(),
        "mode": "deterministic-test-seed" if rng.deterministic else "secure-random-keys",
        "seed": seed,
        "content_seed": rng.content_seed,
        "lab_id": lab_id,
        "odk": odk.hex(),
        "pe": {"A": {**pe_a.info, "file": PE_A_NAME, "structure_before_encryption": pe_structure_record(pe_a.data)},
               "B": {**pe_b.info, "file": PE_B_NAME, "structure_before_encryption": pe_structure_record(pe_b.data)}},
        "xvd": xvd.truth,
        "xvc": xvc.truth,
        "public_files": {"lab_public_notes.txt": sha256_hex(public_notes()),
                         "lab_decoy_fake_pe.bin": sha256_hex(decoy_fake_pe())},
        "containers": manifest["containers"],
    }
    write_json(sealed / GROUND_TRUTH_NAME, truth)
    return {"root": str(root), "public": str(pub), "sealed": str(sealed), "truth": truth}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(GENERATED))
    ap.add_argument("--seed", type=int, default=None, help="seed de TESTE (chaves deterministicas e inseguras)")
    a = ap.parse_args(argv)
    r = generate(Path(a.out), a.seed)
    print(f"[encryptor] public -> {r['public']}\n[encryptor] sealed -> {r['sealed']}\n[encryptor] modo {r['truth']['mode']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
