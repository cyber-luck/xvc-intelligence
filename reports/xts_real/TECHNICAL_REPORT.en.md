# PROJECT_ALPHA — XTS decryption pipeline (read-only; external CIK)

> English version of `RELATORIO_TECNICO.md`.

**Date:** 2026-11-22 · **Target:** `game_scarlett_master.exe` (XVC segment 12, region 0x3E9)
**Real-target status: `BLOCKED_MISSING_AUTHORIZED_CIK`** — full diagnostics, no CIK supplied, nothing simulated, no byte decrypted.
**Regression:** 184 tests passed (13 new XTS tests) + CLI matrix 10/10.

> **ERRATUM (2026-11-22, after integrating `crypto_lab`).** The CIK split originally described (`data_key=CIK[0:16]`, `tweak_key=CIK[16:32]`) was **inverted** relative to xvdtool. The correct layout is `CIK = tweak_key(16) ‖ data_key(16)` (`XVDFile.cs` `CryptSectionXts`), checked against xvdtool's official `xts_cipher.bin` vector. The real-target status is unchanged (no CIK was applied), but a legitimate CIK would have produced garbage **without any error**. Fixed in `cik_halves`; the engine is now named `xts_primitive_kat.py`. The JSON files in this folder are outputs of the original run and were kept as-is; their `derivation_model.step2` field reflects the error.

## Phase 1 — Regional key identification (real results)

| Item | Value | Source |
|---|---|---|
| Target region | `0x3E9`, segment 12, offset `0x64917000`, logical file **120,181,760 B** (region allocation: +0xC00 of page slack) | SegmentMetadata + XvcInfo |
| **Real KeyId** | **index 0** → keyslot GUID **`d4b2880b-884d-cf1b-eea5-bef5a2a7d4f6`** | XvcInfo keyslot array |
| **KeyMaterial@0x34C of the XVC** | **all zero** (fingerprint = SHA-256 of 32 null bytes) — the title carries **not even the wrapped CIK**; the regional key is provisioned externally (console/licensing) | read-only header read |
| xvdtool association | KeyId (index into the keyslot array) → GUID naming the key; the corresponding CIK enters via `--cik-file` (32 B) when legitimately supplied | documented model |
| **StandardOdk vs regional key** | `gameos.xvd` (EraOS): a system volume with KeyMaterial filled, unwrapped via StandardOdk — a header×ODK relationship for that XVD. **Title XVC: KeyMaterial zero; the title key is a different relationship (external keyslot)** — a gameos CIK/ODK does **not** serve the XVC and vice versa | `xvc_crypto_key_mapping.json` |
| Keyless mode | pipeline operational in **diagnostics**; no simulation | `xvc_decryption_report.json` |

## Phase 2 — AES-XTS engine (`crypto/xvc_xts_pipeline.py`)

- Reuses **`xts_primitive_kat.py`** (formerly `validate_xts.py`; port of `AesXtsTransform.cs`; validated against IEEE P1619/D16 and OpenSSL) — nothing re-implemented;
- AES-128-XTS with a 32 B composite CIK (`tweak_key=CIK[0:16]`, `data_key=CIK[16:32]` — fixed, see erratum); **0x1000 B** unit;
- 16 B seed = `[data_unit:4 | region_id:4 | VDUID:8]` — **real region_id (0x3E9)**, never a fixed section_id;
- `data_unit` read **from the corresponding hash entry** (bytes 0x14..0x18 of the leaf);
- per-page streaming, checkpoints every 1024 pages with **prefix verification on resume** (a divergent checkpoint restarts, never mixes);
- the secret is never printed (only the CIK's SHA-256 fingerprint); XVC opened only in `rb`; outputs to new files;
- **model vs effective validation**: the seed layout is derived from public source code and labeled as such; EFFECTIVE validation against real data only occurs with a legitimate CIK, via `encrypt_verify` (re-encryption compared byte for byte with the stored bytes).

**New real evidence (diagnostic):** the leaf `data_unit`s of region 0x3E9 form a **linear sequence with base `0xE5046EA2`** (delta between pages == delta between data_units, confirmed by real sampling at 5 points) — at runtime the value **always** comes from the leaf, never extrapolated.

## Phase 3 — Mandatory synthetic matrix (10/10 + 13 pytest)

With a known PE32+ and a CIK generated exclusively for testing:

1. decryption **byte-for-byte equal to the known original plaintext** (required beyond the round-trip); 2. re-encryption == ciphertext; 3. wrong CIK → no MZ; 4. wrong region_id; 5. wrong VDUID; 6. wrong data_unit (+1); 7. altered page detected by the leaf **before** decryption; 8. truncation detected; 9. **page slack excluded** from the plaintext; 10-13. interruption/resume with a valid checkpoint and a corrupted checkpoint (restarts from zero).
→ `xvc_xts_test_results.json` (SHA-256 `4c5883734bfc466434c90f52843ac1ef6fd095521bc69fffacaa2107e212cbd4`)

## Phase 4 — Real XVC: diagnostics performed (read-only)

Before any processing: offsets validated against SegmentMetadata; KeyId 0 confirmed; **hash of the encrypted data recomputed live = `79fe1510…dba89a`** (equal to prior evidence F-EXE-02); original intact. No CIK → `BLOCKED_MISSING_AUTHORIZED_CIK`.
→ `xvc_decryption_report.json` (SHA-256 `247262bd76b324a1dfb3d838edb8b72de36e3a4a4756d8afde61789fb9c8bebf`)

## Phase 5 — Plaintext validation (ready; not performed — no CIK)

Implemented and triggered automatically after a real decryption: MZ/PE\0\0, PE32+ x64 (0x8664/0x20B), exact logical size, sections/imports/exports/relocations/Debug via xvcintel, **RSDS GUID/age**, SHA-1/SHA-256/Authenticode, semantic comparison with `Catalog000.bin` (extracted from the XVC's own readable region), and the `SOURCE_RECOVERED ≠ TARGET_IDENTITY_VERIFIED` ladder with `COMPLETE_VERIFIED` only via the full chain (valid PE + exact size + catalog hash + custody) — **a valid PE is never promoted automatically**.

## Phase 6 — Deliverables

| File | State | SHA-256 |
|---|---|---|
| `xvc_crypto_key_mapping.json` | **generated (real)** — KeyId/keyslot, KeyMaterial zero, model, ODK vs regional, linear data_unit | `1d42bb97332e53afeb047e4e4132505eea0820c4ddc26eb974b467f19913d124` |
| `xvc_xts_test_results.json` | **generated** — matrix 10/10 | `4c5883734bfc466434c90f52843ac1ef6fd095521bc69fffacaa2107e212cbd4` |
| `xvc_decryption_report.json` | **generated (real)** — `BLOCKED_MISSING_AUTHORIZED_CIK` + diagnostics | `247262bd76b324a1dfb3d838edb8b72de36e3a4a4756d8afde61789fb9c8bebf` |
| `xvc_plaintext_validation.json` | N/A — requires a real decryption | — |
| `catalog_identity_verification.json` | N/A — same | — |
| `recovery_provenance.json` | N/A — same (generated automatically during a real decryption) | — |

**Commands (PowerShell):**

```powershell
# mandatory synthetic matrix
python recovery\project_alpha\shadow_pe_reconstructor.py xts-tests --out reports\xts_tests\xvc_xts_test_results.json

# read-only diagnostics (no CIK)
python recovery\project_alpha\shadow_pe_reconstructor.py decrypt `
  --xvc "G:\MyGame_v1\28872443D20A7_1.0.2.1_neutral__k2ss7vbb13xte_xs.xvc" `
  --target game_scarlett_master.exe --out reports\xts_real

# with an authorized CIK (when one exists): add
#   --cik-file <CIK.bin> [--cik-sha256 <hex>] --provenance "custody"
# the flow runs: storage validation -> streaming decryption with
# checkpoints -> round-trip (re-encryption == stored bytes) -> full Phase 5.
```

## Success criteria — verification

✔ XTS engine validated with independent tests (IEEE P1619 + OpenSSL + synthetic matrix 10/10 + 13 pytest);
✔ functional integration with the real XVC (SegmentMetadata, hash tree, leaves, region, segment);
✔ **correct KeyId identification** (index 0 → GUID `d4b2880b-…`, KeyMaterial zero → external provisioning);
✔ complete reports evidenced; **real decryption will only run with authorized, compatible key material** — today: `BLOCKED_MISSING_AUTHORIZED_CIK`, with no fabricated bytes, no ciphertext substitution, and no recovery claim without evidence.
