"""Vetores conhecidos (fixtures/known_vectors.json) contra tres implementacoes:
rapida (lab_xts.AesXtsTransform), literal (porte laco a laco do C#) e OpenSSL
(modo XTS nativo da biblioteca cryptography, quando aceita as chaves)."""
from __future__ import annotations

import lab_common  # noqa: F401
from lab_common import FIXTURES, read_json, sha256_hex
from lab_xts import (AesXtsTransform, AesXtsTransformLiteral, aes_ecb_decrypt, aes_ecb_encrypt, build_tweak_seed,
                     xts_page_openssl)


def load() -> dict:
    return read_json(FIXTURES / "known_vectors.json")


def run_known_vectors() -> dict:
    kv = load()
    results = []

    # FIPS-197 AES-256 (primitivo do desembrulho da CIK)
    f = kv["aes256_ecb_fips197"]
    ct = aes_ecb_encrypt(bytes.fromhex(f["key"]), bytes.fromhex(f["plaintext"]))
    pt = aes_ecb_decrypt(bytes.fromhex(f["key"]), ct)
    results.append({"vector": "FIPS-197 C.3 AES-256-ECB", "encrypt_ok": ct.hex() == f["ciphertext"],
                    "decrypt_ok": pt.hex() == f["plaintext"]})

    # IEEE 1619
    for v in kv["ieee1619"]:
        k1, k2 = bytes.fromhex(v["key1_data"]), bytes.fromhex(v["key2_tweak"])
        seed = build_tweak_seed(v["data_unit"], v["section_id"], bytes.fromhex(v["vduid8"]))
        p = bytes.fromhex(v["plaintext"])
        fast = AesXtsTransform(seed, k1, k2, True).transform_data_unit(p, v["data_unit"]).hex()
        lit = AesXtsTransformLiteral(seed, k1, k2, True).transform_data_unit(p, v["data_unit"]).hex()
        dec = AesXtsTransform(seed, k1, k2, False).transform_data_unit(bytes.fromhex(v["ciphertext"]), v["data_unit"]).hex()
        try:
            ossl = xts_page_openssl(k2 + k1, p, v["data_unit"], v["section_id"], bytes.fromhex(v["vduid8"]), True).hex()
            ossl_ok = ossl == v["ciphertext"]
        except ValueError:
            ossl_ok = None          # OpenSSL recusa Key1 == Key2
        results.append({"vector": v["name"], "fast_ok": fast == v["ciphertext"], "literal_ok": lit == v["ciphertext"],
                        "decrypt_ok": dec == v["plaintext"], "openssl_ok": ossl_ok})

    # xvdtool (AesXtsTests.cs + xts_cipher.bin)
    x = kv["xvdtool"]
    cik = bytes.fromhex(x["cik"])
    plain = (x["plaintext_unit"].encode() * 256)
    seed = build_tweak_seed(0, x["section_id"], bytes.fromhex(x["vduid8"]))
    fast = AesXtsTransform(seed, cik[16:], cik[:16], True)
    lit = AesXtsTransformLiteral(seed, cik[16:], cik[:16], True)
    ct_fast = b"".join(fast.transform_data_unit(plain[i * 0x1000:(i + 1) * 0x1000], du) for i, du in enumerate(x["data_units"]))
    ct_lit = b"".join(lit.transform_data_unit(plain[i * 0x1000:(i + 1) * 0x1000], du) for i, du in enumerate(x["data_units"]))
    ct_ossl = b"".join(xts_page_openssl(cik, plain[i * 0x1000:(i + 1) * 0x1000], du, x["section_id"],
                                        bytes.fromhex(x["vduid8"]), True) for i, du in enumerate(x["data_units"]))
    dec = AesXtsTransform(seed, cik[16:], cik[:16], False)
    pt_back = b"".join(dec.transform_data_unit(ct_fast[i * 0x1000:(i + 1) * 0x1000], du) for i, du in enumerate(x["data_units"]))
    # TestEncryptFail: data unit + 1 nao pode bater
    bad = AesXtsTransform(seed, cik[16:], cik[:16], True)
    ct_bad = b"".join(bad.transform_data_unit(plain[i * 0x1000:(i + 1) * 0x1000], du + 1) for i, du in enumerate(x["data_units"]))
    results.append({
        "vector": "xvdtool AesXtsTests (xts_plain.bin -> xts_cipher.bin, data units 0..2, headerId 1)",
        "plaintext_sha256_ok": sha256_hex(plain) == x["plaintext_sha256"],
        "fast_ok": sha256_hex(ct_fast) == x["ciphertext_sha256"] and ct_fast[:32].hex() == x["ciphertext_head32"],
        "literal_ok": sha256_hex(ct_lit) == x["ciphertext_sha256"],
        "openssl_ok": sha256_hex(ct_ossl) == x["ciphertext_sha256"],
        "decrypt_ok": pt_back == plain,
        "wrong_data_unit_differs": sha256_hex(ct_bad) != x["ciphertext_sha256"],
    })
    all_ok = all(v is not False for r in results for k, v in r.items() if k != "vector")
    return {"all_pass": all_ok, "results": results}
