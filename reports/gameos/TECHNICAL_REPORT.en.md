# PROJECT_ALPHA — Analysis of `gameos.xvd` (EraOS system volume)

> English version of `RELATORIO_TECNICO.md`.

**Date:** 2026-11-22 · **File:** `G:\MyGame_v1\PROJECT_ALPHA\gameos.xvd` (348,069,888 bytes / ~332 MiB)
**Methods:** `xvcintel` parsers (read-only) + `inspect_xvd_v3` with `--verify-hashes full` and `--crypto-audit` + targeted hypothesis tests. **Original intact; nothing decrypted.**
File SHA-256: `d02ff50ae9164e540ce55b60b2f128b5c78bab6b…` (full value in `gameos_analysis.json`).

## 1. Identity and header (CONFIRMED against bytes)

| Field | Value |
|---|---|
| Format | XVD v3, magic `msft-xvd` @0x200 |
| Type / content | **Dynamic** (1) / **EraOS** (3) |
| VolumeFlags | `0x1` (ReadOnly) — **EncryptionDisabled NOT set** → content encrypted |
| VDUID / PDUID | `a31ea8e8-2999-4f3a-8f22-658edd493b6b` / `b78ddf1f2d874e4abf8b9b507a3f322e` |
| Version | **32778.0.26100.7901** (EraOS build derived from Windows 26100.7901) |
| ODK keyslot | **0 = StandardOdk** |
| **KeyMaterial@0x34C** | **present, non-zero** (entropy 4.875; SHA-256 fingerprint `0a95c5a3…`; raw bytes not exported) |
| DriveSize | 0x20000000 (**512 MB virtual drive**, sparse — 332 MB physical file) |
| UserDataLength / UserDataHash | 0x1F93000 (~33 MB) / `272894d4…` |
| PECatalogHash / PECatalogs | `3f4dce53…` / 128 non-zero bytes |
| Product correlations | **none** (ProductId/ContentID zeroed — a system volume with no link to the title package) |

## 2. Layout (CONFIRMED, closes against the file size)

```
0x0000000  header        0x3000     (cleartext)
0x0003000  hash_tree     0x339000   (~824 pages; 3 levels; 139,156 hashed pages)
0x0033C000  user_data     0x1F93000 (~33 MB — encrypted)
0x022CF000  dynamic_header(BAT) 0x1000 (encrypted — virtual→physical map of the sparse drive)
0x022D0000  drive_data    ~311 MB physical (512 MB drive pages allocated by the BAT)
```

## 3. Integrity (recomputed live, read-only)

| Check | Result |
|---|---|
| **Root hash** (TopHashBlockHash) | **VERIFIED** — `b9b8b758…` recomputed == stored, byte for byte |
| Tree links (level by level) | **824/824 verified, 0 divergences** |
| Leaves × physical data pages | **84,150 pages checked, 0 divergences** |
| Coverage | partial **by nature**: the volume is Dynamic — 139,156 *hashed* pages count the *virtual* pages of the 512 MB drive; the physical file stores ~84,150 allocated pages (sparse); the rest do not physically exist |

This re-confirms live the state declared before the project: *Hash Tree Valid = True; Data Hash Tree Valid = True* — now with numbers and hashes recorded.

## 4. Cryptographic audit (model; without decrypting)

- Cipher: **AES-128-XTS**, 0x1000 data unit; `data_unit` from the hash entry (samples: `data_unit == block`, model seed `[data_unit | section_id=1 | VDUID[0:8]]` — xvdtool reference model, not confirmed by a round-trip);
- **KeyMaterial present** → CIK wrapped via ODK: `CIK = AES-256-ECB-decrypt(StandardOdk, KeyMaterial@0x34C)` — a model applicable to THIS volume (unlike the title XVC, whose KeyMaterial is zero);
- `can_decrypt_now = False`: the **StandardOdk is not available**; `user_data`, the **BAT**, and the drive pages remain encrypted (the encrypted BAT prevents even the virtual→physical filesystem mapping);
- RSA signature: **not verified** (no public key supplied) — recorded as not-performed, not as a failure.

## 5. PECatalogHash hypothesis — NEGATIVE RECORDED

`PECatalogHash == SHA-256(PECatalogs)` plus 6 more candidate serializations (`caps+catalogs`, `catalogs+caps`, `hash+catalogs`, header windows): **all refuted**. The exact serialization covered by `PECatalogHash` remains **UNKNOWN** — the same stance the project takes toward the shared XVC-HD/MD hash: hypotheses tested, refuted, and documented, with no guess.

## 6. gameos.xvd × title XVC (definitive distinction)

| | gameos.xvd (EraOS) | Title XVC |
|---|---|---|
| Role | console **system** volume | **game** content |
| KeyMaterial@0x34C | **present** (CIK wrapped by the ODK) | **zero** (external regional key, keyslot GUID `d4b2880b-…`) |
| Unwrapping | `StandardOdk → CIK` (xvdtool model) | outside the ODK model — external CIK via `--cik-file` |
| Content | operating system (unrelated to the game executable) | the target `game_scarlett_master.exe` (region 0x3E9) |

**Consequence:** a gameos ODK/CIK would **not** decrypt the title XVC and vice versa. The gameos.xvd contains no game-executable material, decryptable or not — it is OS infrastructure, and its content remains encrypted for want of the StandardOdk.

## Artifacts

| File | Content |
|---|---|
| `gameos_analysis.json` | full analysis (header, layout, full integrity, crypto audit, limitations) |
| `RELATORIO_TECNICO.md` | this document (Portuguese) |
| `TECHNICAL_REPORT.en.md` | this document (English) |
