#!/usr/bin/env python3
"""validate_xts/1.0: validate the XVD AES-XTS transform against independent references.

Scope: this validates the *cipher primitive* (xvdtool's AesXtsTransform.cs port) --
the GF(2^128) tweak multiplication, the AES-ECB tweak encryption, and the
XOR/AES/XOR structure -- against:
  (a) published IEEE P1619/D16 XTS-AES-128 known-answer vectors, and
  (b) OpenSSL's XTS implementation (via `cryptography`), bit-for-bit, over a
      randomized matrix including 4096-byte data units (the XVD page size).

It does NOT use any XVD file, any ODK/CIK, or any key material from the image.

IMPORTANT distinction this tool preserves:
  * Proving the XTS engine correct here is STRUCTURAL validation of the cipher.
  * It does NOT prove that the XVD tweak *seed* layout ([data_unit|section_id|
    VDUID]) is what EraOS actually uses -- that still requires a real decryption
    round-trip with a legitimate key. See crypto_audit in inspect_xvd.py.

Requires: Python 3.10+, `cryptography` (OpenSSL backend) for the oracle checks.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import struct
import sys

TOOL = "validate_xts/1.0"

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    _HAVE_CRYPTO = True
except ImportError:
    _HAVE_CRYPTO = False


# ----- Faithful port of xvdtool LibXboxOne/AesXtsTransform.cs ---------------------

def multiply_tweak(tweak: bytes) -> bytes:
    """Port of AesXtsTransform.MultiplyTweak (GF(2^128) multiply-by-alpha, 0x87)."""
    dl = 0
    out = bytearray(0x10)
    for i in range(0x10):
        cl = tweak[i]
        al = ((cl + cl) & 0xFF) | dl   # al = (al+al) | carry_in
        out[i] = al & 0xFF
        dl = cl >> 7                    # carry_out for the next byte
    if dl != 0:
        out[0] ^= 0x87
    return bytes(out)


def _aes_ecb(key: bytes):
    return Cipher(algorithms.AES(key), modes.ECB())


def transform_data_unit(seed: bytes, data_key: bytes, tweak_key: bytes,
                        data: bytes, encrypt: bool) -> bytes:
    """Port of AesXtsTransform.TransformDataUnit for one data unit.

    `seed` is the 16-byte tweak seed (xvdtool's _tweakBytes after the caller has
    written the data-unit number into bytes 0..3). `data` length must be a
    multiple of 16 (XVD always transforms whole 0x1000 pages = 256 blocks).
    """
    if len(seed) != 16 or len(data_key) != 16 or len(tweak_key) != 16:
        raise ValueError("seed, data_key and tweak_key must each be 16 bytes")
    if len(data) % 16 != 0:
        raise ValueError("data length must be a multiple of 16 (no ciphertext stealing)")
    # Encrypt the tweak seed with the tweak key (ECB, no padding).
    enc_tweak0 = _aes_ecb(tweak_key).encryptor().update(seed)
    blocks = len(data) // 16
    out = bytearray(data)

    # Pass 1: XOR running tweak into each block.
    t = enc_tweak0
    for i in range(blocks):
        base = i * 16
        for y in range(16):
            out[base + y] ^= t[y]
        t = multiply_tweak(t)

    # AES the whole buffer at once (ECB, encryptor or decryptor).
    ecb = _aes_ecb(data_key)
    xf = ecb.encryptor() if encrypt else ecb.decryptor()
    out = bytearray(xf.update(bytes(out)) + xf.finalize())

    # Pass 2: reset tweak to the original and XOR again.
    t = enc_tweak0
    for i in range(blocks):
        base = i * 16
        for y in range(16):
            out[base + y] ^= t[y]
        t = multiply_tweak(t)
    return bytes(out)


def seed_with_unit(seed_base: bytes, data_unit: int) -> bytes:
    """Mirror xvdtool: overwrite bytes 0..3 of the seed with the LE data unit."""
    s = bytearray(seed_base)
    s[0:4] = struct.pack("<I", data_unit & 0xFFFFFFFF)
    return bytes(s)


# ----- Independent oracle: OpenSSL XTS via `cryptography` -------------------------

def openssl_xts(data_key: bytes, tweak_key: bytes, seed: bytes,
                data: bytes, encrypt: bool) -> bytes:
    cipher = Cipher(algorithms.AES(data_key + tweak_key), modes.XTS(seed))
    ctx = cipher.encryptor() if encrypt else cipher.decryptor()
    return ctx.update(data) + ctx.finalize()


# ----- Known-answer vectors (IEEE P1619/D16, XTS-AES-128) ------------------------
# V2 and V3 are confirmed byte-for-byte against OpenSSL (distinct keys). V1 uses
# key1==key2, which OpenSSL refuses as a weak key, so it is checked against the
# published constant using the port only.
def _seq_le(n: int) -> bytes:
    return n.to_bytes(16, "little")

KNOWN_VECTORS = [
    {"name": "IEEE-1619 XTS-AES-128 #1 (zero key, seq 0)",
     "key1": bytes(16), "key2": bytes(16), "seed": _seq_le(0),
     "ptx": bytes(32),
     "ctx": "917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e",
     "oracle": False},
    {"name": "IEEE-1619 XTS-AES-128 #2",
     "key1": bytes([0x11]*16), "key2": bytes([0x22]*16), "seed": _seq_le(0x3333333333),
     "ptx": bytes([0x44]*32),
     "ctx": "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0",
     "oracle": True},
    {"name": "IEEE-1619 XTS-AES-128 #3",
     "key1": bytes.fromhex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0"), "key2": bytes([0x22]*16),
     "seed": _seq_le(0x3333333333), "ptx": bytes([0x44]*32),
     "ctx": "af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89",
     "oracle": True},
]


def run_known_vectors() -> list[dict]:
    results = []
    for v in KNOWN_VECTORS:
        port_ct = transform_data_unit(v["seed"], v["key1"], v["key2"], v["ptx"], True).hex()
        port_rt = transform_data_unit(v["seed"], v["key1"], v["key2"],
                                      bytes.fromhex(port_ct), False).hex() == v["ptx"].hex()
        row = {"name": v["name"], "expected": v["ctx"],
               "port_encrypt_matches_kat": port_ct == v["ctx"],
               "port_roundtrip_ok": port_rt,
               "oracle_runnable": v["oracle"] and _HAVE_CRYPTO}
        if v["oracle"] and _HAVE_CRYPTO:
            o_ct = openssl_xts(v["key1"], v["key2"], v["seed"], v["ptx"], True).hex()
            row["openssl_matches_kat"] = o_ct == v["ctx"]
            row["port_matches_openssl"] = o_ct == port_ct
        results.append(row)
    return results


def run_cross_check(trials: int, lengths: tuple[int, ...]) -> dict:
    """Bit-for-bit port vs OpenSSL over random distinct keys/seeds/lengths."""
    if not _HAVE_CRYPTO:
        return {"performed": False, "reason": "cryptography not installed"}
    mismatches = []
    checked = 0
    for _ in range(trials):
        for length in lengths:
            data_key = os.urandom(16)
            tweak_key = os.urandom(16)
            while tweak_key == data_key:            # OpenSSL rejects duplicated keys
                tweak_key = os.urandom(16)
            seed = os.urandom(16)
            pt = os.urandom(length)
            port_ct = transform_data_unit(seed, data_key, tweak_key, pt, True)
            o_ct = openssl_xts(data_key, tweak_key, seed, pt, True)
            port_pt = transform_data_unit(seed, data_key, tweak_key, o_ct, False)
            checked += 1
            if port_ct != o_ct:
                mismatches.append({"length": length, "stage": "encrypt",
                                   "data_key": data_key.hex(), "tweak_key": tweak_key.hex(),
                                   "seed": seed.hex()})
            elif port_pt != pt:
                mismatches.append({"length": length, "stage": "decrypt",
                                   "data_key": data_key.hex(), "tweak_key": tweak_key.hex(),
                                   "seed": seed.hex()})
    return {"performed": True, "trials": trials, "lengths": list(lengths),
            "cases_checked": checked, "mismatches": len(mismatches),
            "examples": mismatches[:5], "all_match": not mismatches}


def run_unit_fold_check() -> dict:
    """Exercise xvdtool's data-unit folding (overwrite low 4 bytes) vs OpenSSL."""
    if not _HAVE_CRYPTO:
        return {"performed": False, "reason": "cryptography not installed"}
    data_key = os.urandom(16)
    tweak_key = os.urandom(16)
    while tweak_key == data_key:
        tweak_key = os.urandom(16)
    base = os.urandom(16)
    pt = os.urandom(0x1000)   # one XVD page
    ok = True
    for unit in (0, 1, 2, 255, 0xAA, 0x12345678):
        seed = seed_with_unit(base, unit)
        port_ct = transform_data_unit(seed, data_key, tweak_key, pt, True)
        o_ct = openssl_xts(data_key, tweak_key, seed, pt, True)
        if port_ct != o_ct:
            ok = False
            break
    return {"performed": True, "page_size": 0x1000,
            "units_tested": [0, 1, 2, 255, 0xAA, 0x12345678],
            "all_match": ok}


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="Validate the XVD AES-XTS port against IEEE vectors and OpenSSL.")
    ap.add_argument("--trials", type=int, default=100, help="random cross-check iterations per length (default 100)")
    ap.add_argument("--report", type=Path, help="write JSON report to this path")
    args = ap.parse_args()

    kats = run_known_vectors()
    cross = run_cross_check(args.trials, (16, 32, 64, 256, 0x1000))
    fold = run_unit_fold_check()

    kat_ok = all(k["port_encrypt_matches_kat"] and k["port_roundtrip_ok"]
                 and (not k.get("oracle_runnable") or
                      (k.get("openssl_matches_kat") and k.get("port_matches_openssl")))
                 for k in kats)
    cross_ok = cross.get("all_match", False) if cross.get("performed") else None
    fold_ok = fold.get("all_match", False) if fold.get("performed") else None
    overall = bool(kat_ok) and cross_ok is not False and fold_ok is not False

    report = {
        "tool": TOOL,
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cryptography_available": _HAVE_CRYPTO,
        "scope": "cipher-primitive validation only; does NOT validate the XVD tweak-seed semantics "
                 "(that needs a real decryption round-trip with a legitimate key)",
        "known_answer_vectors": kats,
        "cross_check_vs_openssl": cross,
        "data_unit_fold_check": fold,
        "summary": {"known_vectors_pass": bool(kat_ok),
                    "cross_check_pass": cross_ok,
                    "unit_fold_pass": fold_ok,
                    "overall_pass": overall},
    }
    text = json.dumps(report, indent=2, ensure_ascii=False)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text, encoding="utf-8")
        print(f"report: {args.report.resolve()}")

    print(f"{TOOL}: cryptography={_HAVE_CRYPTO}")
    for k in kats:
        extra = ""
        if k.get("oracle_runnable"):
            extra = f" openssl==kat={k['openssl_matches_kat']} port==openssl={k['port_matches_openssl']}"
        else:
            extra = " (oracle cannot run equal-key XTS; port vs published constant only)"
        print(f"  KAT {k['name']}: port==kat={k['port_encrypt_matches_kat']} rt={k['port_roundtrip_ok']}{extra}")
    if cross.get("performed"):
        print(f"  cross-check vs OpenSSL: {cross['cases_checked']} cases, "
              f"mismatches={cross['mismatches']}, all_match={cross['all_match']}")
    else:
        print(f"  cross-check skipped: {cross.get('reason')}")
    if fold.get("performed"):
        print(f"  data-unit fold (4096B page): all_match={fold['all_match']}")
    print(f"OVERALL: {'PASS' if overall else 'FAIL'}")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
