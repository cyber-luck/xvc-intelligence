# PROJECT_ALPHA — Blind lab A/B/C + technical caveats absorbed

> English version of `RELATORIO_TECNICO.md`.

**Date:** 2026-11-22 · **Regression:** 188 tests passed (4 new lab tests) · **Real target:** `BLOCKED_MISSING_AUTHORIZED_CIK` (kept, correct).

> **ERRATUM (2026-11-22).** `reports/blind_lab/` was regenerated with the same command below after the CIK order fix (see the erratum in `reports/xts_real/`). The synthetic key and plaintext are unchanged (deterministic seed); the ciphertext changed and can now be decrypted by `recovery/crypto_lab/lab_xts.py`, which follows xvdtool. The `xts-tests` matrix gained the `xvdtool_official_vector` case (13/13).

## The two caveats — absorbed and demonstrated

**Caveat 1 — sampling does not prove numbering.**
- The pipeline **always** read each leaf's `data_unit` per page (`_xvc_units`); nothing changed at runtime;
- Added a **full audit** (`audit_data_units`): run on the real XVC over **all 29,342 leaves** of region 0x3E9 → **consecutive, zero jumps** (base `0xE5046EA2`). Linearity is now a proven fact across the whole region — and even so it is **never used**: each leaf is read individually;
- Test with an **injected discontinuity** (a 0x1000 jump at page 3): decryption stays **byte-for-byte correct** (reads leaf by leaf) while the audit reports the jump — proving nothing is extrapolated.

**Caveat 2 — the round-trip does not authenticate the CIK.**
- `encrypt_verify` labeled with explicit semantics: it proves **model consistency** (tweak/data_unit/region/VDUID/transform), it does **not** authenticate the key — XTS is perfectly reversible with any key;
- Demonstrated in the matrix: `roundtrip_with_wrong_cik_still_equal = True` (12/12 in the CLI), and rejection of the wrong key comes **only** from: structurally incoherent plaintext (no MZ) + byte-for-byte comparison with the reference + **zero catalog hits**;
- In the real flow, authentication lives in `validate_plaintext` (valid PE + exact size + catalog hash + custody) — never in the round-trip.

## Blind lab — three independent states (`crypto/synth_lab.py`, CLI `blind-lab`)

**A. Independent generator** (`reports\blind_lab\`): a known PE32+ of 35,840 B (9 pages + a partial page), **synthetic ODK/CIK** (deterministic LCG, unrelated to any real volume), region 0x3E9, VDUID, leaves with data_unit (jump injected at page 3), page slack 0xC00, synthetic catalog with the PE's hashes. Keys and reference **sealed** out of the analyzer's reach.

**B. Reverse engineering without keys:** the analyzer received only the container + public metadata. It correctly declared: `BLOCKED_MISSING_AUTHORIZED_CIK`; **0 MZ/PE candidates in the ciphertext** (an observed fact, not inference); recoverable structure (9 pages, partial 0x400, slack 0xC00, 9 leaves audited with the detected jump); plaintext `UNKNOWN — no CIK`; **no byte presented as recovered**.

**C. Key reveal:** streaming decryption (leaf-by-leaf data_unit, including the jump) → **byte-for-byte equality with the sealed reference** + identical SHA-256 + valid PE32+ x64 + **catalog hash hits in the synthetic catalog** + target name → `TARGET_IDENTITY_VERIFIED` → **`COMPLETE_VERIFIED`**. Embedded demonstrations: wrong CIK → round-trip still equal (caveat 2) but **rejected by the evidence** (divergent reference, no MZ, zero catalog hits).

**Success criteria: all OK** (`lab_report.json`, SHA-256 `76949d8ec0b2d462fd02849644875e6c13d46e0d6cfb00134cff145a71163025`).

## Artifacts and hashes

| File | Content | SHA-256 |
|---|---|---|
| `reports\xts_real_v2\xvc_crypto_key_mapping.json` | real diagnostics + **full audit of 29,342 leaves (consecutive, 0 jumps)** | `b631265af27ccbfe2ccb75c0996115578b5b3c70900d7acadf90dfb0c15ad626` |
| `reports\xts_real_v2\xvc_decryption_report.json` | real: `BLOCKED_MISSING_AUTHORIZED_CIK` | `ca254b1e434d73cde957a6495a92975de8965dfe9743d3bc37c5d91bc8e7341a` |
| `reports\xts_tests\xvc_xts_test_results.json` | matrix 12/12 (includes the two caveats) | `aedcf952c65c7cc3a7150f8a89089e9a730d03722018184b7da0939d0dc971f1` |
| `reports\blind_lab\lab_report.json` | full A/B/C lab | `76949d8ec0b2d462fd02849644875e6c13d46e0d6cfb00134cff145a71163025` |

**Commands:**
```powershell
python recovery\project_alpha\shadow_pe_reconstructor.py blind-lab --out reports\blind_lab --jump-at 3
python recovery\project_alpha\shadow_pe_reconstructor.py xts-tests --out reports\xts_tests\xvc_xts_test_results.json
python recovery\project_alpha\shadow_pe_reconstructor.py decrypt --xvc <XVC> --target game_scarlett_master.exe --out reports\xts_real_v2
python -I -m pytest -q   # 188 passed
```

## Final state

The engine is validated with independent tests; the blind lab demonstrated all three states end to end — including that the analyzer **refuses** to present plaintext without a key and that key authentication comes from **independent evidence**, never from the round-trip. On the real XVC: `data_unit` numbering proven across the whole region (29,342 leaves, zero anomalies), hash of the encrypted data recomputed and equal to prior evidence, originals intact — and real decryption remains correctly **blocked until a compatible authorized CIK exists** (`--cik-file` + `--cik-sha256` + `--provenance`), at which point the same state-C flow will run automatically.
