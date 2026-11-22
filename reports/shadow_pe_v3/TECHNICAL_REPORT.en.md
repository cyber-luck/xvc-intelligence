# PROJECT_ALPHA — Technical report v3 (final Shadow PE Reconstructor improvements)

> English version of `RELATORIO_TECNICO.md`.

**Date:** 2026-11-22 · **Target:** `game_scarlett_master.exe` · **Real-target classification: `METADATA_ONLY`** (unchanged and correct)
**Regression:** 166 tests passed (29 in the recovery package, including the 10 new catalog/identity tests) + selftest 21/21.
**Prior artifacts:** `reports/shadow_pe_final` (v2); this report describes what v3 adds.

## 1. Catalog — semantic validation (`catalog_semantic.json`, `catalog` subcommand)

The real `Catalog000.bin` (PE32+ x64, subsystem 17 XBOX_CODE_CATALOG, 13/13 checks passed):

| Aspect | Result | Level |
|---|---|---|
| Section structure | page 0 = 64 B header + 197 dense pages (~4,070/4,096 non-zero bytes); consistent with a code hash table | INFERRED |
| Field-by-field decode of the internal format | not publicly documented | UNKNOWN (honest) |
| **Raw** hash vs **Authenticode** hash | both computed for any candidate (Authenticode digest = image without the certificate table, streamed, larger than memory); searched in 5 forms: raw, lower/upper hex-ascii, base64, base64 without padding | implemented |
| Association with the executable | the target name does **not** appear in cleartext in the catalog; with no plaintext candidate, association is | UNKNOWN |
| Signature | **no embedded signature** (security directory absent, no PKCS#7); nothing to verify; cryptographic verification explicitly marked NOT PERFORMED | CONFIRMED |

## 2. Identity — `SOURCE_RECOVERED` ≠ `TARGET_IDENTITY_VERIFIED`

The new `assess_identity` function evaluates separately: `size_exact` (required), `machine_compatible` (supporting),
`catalog_hash_hit` (strong), `catalog_name_association` (supporting), `custody_documented` (required).

**Rule:** `TARGET_IDENTITY_VERIFIED` requires **all** of them; missing any → `TARGET_IDENTITY_UNVERIFIED`.
Demonstration on real data (msvcp140.dll as target, readable disk copy, exact size, declared custody):
`SOURCE_RECOVERED` = 565,232 bytes with a valid PE, yet `TARGET_IDENTITY_UNVERIFIED` (no catalog hash hit)
→ classification **`COMPLETE_UNVERIFIED`** (previously it would have been COMPLETE_VERIFIED; the earlier version conflated the concepts).

## 3. Provenance — `source_provenance.json`

Source facts (path, size, mtime, SHA-1/SHA-256, Authenticode digests) + custody claim
recorded **as a claim** (`custody_claim_is_not_proof: true`); identity proof lives in a separate section.
In the real case: claim = null (custody undocumented); provenance of the stored bytes = E1 (100% of blocks
identical to the XVC).

## 4. Size — `size_reconciliation.json` (3,072-byte divergence RESOLVED)

| Field | Value |
|---|---|
| Expected (XVC SegmentMetadata) | 120,181,760 B — ends at 0x400 within the 4 KiB page |
| Actual (disk copy) | 120,184,832 B — delta **+3,072 B** |
| Hypothesis | `page_slack_included_by_extraction`: extraction included the slack up to the page boundary |
| Test | disk tail compared byte for byte with the continuation of the XVC region (`0x6BBB4400..0x6BBB5000`) |
| Result | **100% identical → CONFIRMED**; no truncation applied; original file intact |

## 5. Classification — new ladder

`COMPLETE_VERIFIED` **only** with: 100% of bytes proven + valid PE + exact size + **verified identity**
(candidate's Authenticode/raw hash present in the readable catalog + documented custody).
Otherwise, a complete file → **`COMPLETE_UNVERIFIED`** (new). The other classes are unchanged:
PARTIAL_RECOVERED / STRUCTURE_ONLY / METADATA_ONLY / NO_RECOVERABLE_PE.

## 6. New tests (`tests/test_catalog_identity.py`, 10 cases)

1. PE with **same version/size but different hash** (1-byte forgery): no catalog hit → identity UNVERIFIED → `COMPLETE_UNVERIFIED`;
2. **Catalog with no proven association**: no hash and no name → UNVERIFIED even with size/machine/custody ok;
3. **Unverified provenance** (`--provenance` absent): UNVERIFIED; with hash + custody → VERIFIED → `COMPLETE_VERIFIED`;
4. **Authenticode** digest excludes the certificate table (with/without security directory);
5. Size reconciliation: page slack (real case 120,181,760 → 0xC00), truncated, exact — always without automatic truncation;
6. `source_provenance` records the claim as a claim.

## 7. Compatibility and rules

Prior CLI preserved (`run-all/inventory/locate/carve/experiments/reconstruct/validate/selftest`;
`--provenance` remains optional); new: `catalog` subcommand, outputs `catalog_semantic.json`,
`source_provenance.json`, `size_reconciliation.json`. Originals intact (rb); XVC/XVD not modified;
no fabricated bytes; no decryption.

## 8. Conclusion on the real target

Unchanged: **0 bytes of plaintext**; map `[0, 0x729D400)` = `ENCRYPTED_UNKNOWN`; identity/metadata CONFIRMED;
disk copy = stored XVC bytes + page slack (now **proven**, no longer `UNVERIFIED`).
`COMPLETE_VERIFIED` of the executable remains conditional on: a copy decrypted through an authorized process +
exact size + a hash present in `Catalog000.bin` + documented custody — a chain that is ready and tested.
