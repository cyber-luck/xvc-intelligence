"""PERFIL A - XVD (nao-XVC) com ODK/CIK.

Fluxo reproduzido (xvdtool XVDFile.cs CryptHeaderCik 269-300, Decrypt 403-441,
Encrypt 444-515):

    ODK (32 B) --AES-256-ECB, sem padding, IV nulo--> KeyMaterial (CIK selada, 32 B)
    KeyMaterial --AES-256-ECB^-1(ODK)--> CIK
    CIK[0:16] = chave do tweak, CIK[16:32] = chave dos dados
    AES-XTS por pagina, headerId = 1, de UserDataOffset ate o fim do arquivo

Leiaute do conteiner sintetico:
    cabecalho 0x3000 | hash tree | user data (1 pagina) | drive data (PE cru, alinhado)
Tudo a partir do user data e cifrado (como no xvdtool). O drive nao tem sistema de
arquivos: o descritor LAB no user data (cifrado) informa onde esta o PE.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import lab_common  # noqa: F401
from lab_common import LAB_MARKER_STR, PAGE, Rng, pad_page, sha256_hex
import lab_hash_tree as HT
from lab_container import (CONTENT_TYPE_DATA, FLAG_READ_ONLY, LAB_ODK_SLOT, guid_from, make_header)
from lab_xts import aes_ecb_decrypt, aes_ecb_encrypt, crypt_section, split_cik

SECTION_ID_XVD = 1          # xvdtool: CryptSectionXts(..., 0x1, UserDataOffset, ...)
FLAGS_XVD = FLAG_READ_ONLY  # cifra ligada (EncryptionDisabled=0), integridade ligada


def gen_odk(rng: Rng) -> bytes:
    return rng.bytes("key:odk", 32)


def gen_cik(rng: Rng, label: str = "key:cik:xvd") -> bytes:
    return rng.bytes(label, 32)


def wrap_cik(odk: bytes, cik: bytes) -> bytes:
    """CryptHeaderCik(encrypt=true)."""
    if len(odk) != 32 or len(cik) != 32:
        raise ValueError("ODK e CIK tem 32 bytes")
    return aes_ecb_encrypt(odk, cik)


def unwrap_cik(odk: bytes, key_material: bytes) -> bytes:
    """CryptHeaderCik(encrypt=false). Nao ha verificacao de integridade: uma ODK
    errada produz 32 bytes 'validos' que so falham depois, na descriptografia."""
    if len(odk) != 32 or len(key_material) != 32:
        raise ValueError("ODK e KeyMaterial tem 32 bytes")
    return aes_ecb_decrypt(odk, key_material)


@dataclass
class XvdContainer:
    data: bytes
    truth: dict


def build_xvd_container(pe: bytes, pe_name: str, *, odk: bytes, cik: bytes, rng: Rng) -> XvdContainer:
    vduid = guid_from(rng.bytes("id:vduid:xvd", 16))
    descriptor = json.dumps({
        "marker": LAB_MARKER_STR, "profile": "A-XVD-ODK-CIK",
        "files": [{"name": pe_name, "drive_offset": 0, "size": len(pe)}],
    }, sort_keys=True).encode()
    user_data = pad_page(descriptor)
    drive = pad_page(pe)
    plain_section = user_data + drive
    n_pages = len(plain_section) // PAGE
    data_units = list(range(n_pages))       # sequencial = indice da pagina na secao (igual ao xvdtool sem integridade)
    cipher_section = crypt_section(cik, plain_section, data_units, SECTION_ID_XVD, vduid.bytes_le, encrypt=True)
    leaves = [HT.leaf_entry_encrypted(cipher_section[i * PAGE:(i + 1) * PAGE], data_units[i]) for i in range(n_pages)]
    tree, geo, top = HT.build(leaves)
    key_material = wrap_cik(odk, cik)
    hdr = make_header(flags=FLAGS_XVD, drive_size=len(drive), vduid=vduid, content_type=CONTENT_TYPE_DATA,
                      user_data_len=len(descriptor), xvc_len=0, mdu_pages=0, key_material=key_material,
                      odk_slot=LAB_ODK_SLOT, top_hash=top, pduid=rng.bytes("id:pduid:xvd", 16))
    data = bytes(hdr) + tree + cipher_section
    off_tree = len(hdr)
    off_ud = off_tree + len(tree)
    off_drive = off_ud + len(user_data)
    tk, dk = split_cik(cik)
    truth = {
        "profile": "A-XVD-ODK-CIK",
        "vduid": str(vduid), "vduid_bytes_le": vduid.bytes_le.hex(),
        "section_id": SECTION_ID_XVD,
        "odk_slot": LAB_ODK_SLOT,
        "key_material_offset": "0x34C",
        "key_material": key_material.hex(),
        "cik": cik.hex(), "cik_tweak_key": tk.hex(), "cik_data_key": dk.hex(),
        "layout": {"header": [0, len(hdr)], "hash_tree": [off_tree, len(tree)], "user_data": [off_ud, len(user_data)],
                   "drive": [off_drive, len(drive)], "file_size": len(data)},
        "hash_tree_levels": list(geo.level_pages), "hashed_pages": geo.hashed_pages,
        "data_units": {"rule": "sequencial: data_unit = indice da pagina desde o user data", "first": 0,
                       "last": n_pages - 1},
        "user_data_descriptor": json.loads(descriptor),
        "pe": {"name": pe_name, "container_offset": off_drive, "size": len(pe), "sha256": sha256_hex(pe)},
        "ciphertext_section_sha256": sha256_hex(cipher_section),
    }
    return XvdContainer(data, truth)


__all__ = ["SECTION_ID_XVD", "FLAGS_XVD", "gen_odk", "gen_cik", "wrap_cik", "unwrap_cik", "build_xvd_container",
           "XvdContainer", "uuid"]
