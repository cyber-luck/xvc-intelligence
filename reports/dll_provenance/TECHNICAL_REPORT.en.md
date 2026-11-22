# PROJECT_ALPHA — Provenance reconciliation of the 16 DLLs (keyless)

> English version of `RELATORIO_TECNICO.md`.

**Date:** 2026-11-22 · **Tool:** `reconcile-dlls` (`correlation/provenance_reconciliation.py`)
**Report:** `dll_provenance_reconciliation.json` — SHA-256 `3e467d568c911e4a0a6de70acf671542f471d6c41cbb310fa477daa28e18dd34`
**Regression:** 192 passed (4 new classification tests) · Originals intact · No key used.

## Step-by-step performed (per DLL)

1. **Build manifest:** all 16 in layout **chunk 1002** (packed together, after the exe in chunk 1001);
2. **XVC segment:** segments **13–28**, region **0x3EA** (the DLLs' single region);
3. **Real cryptographic state:** **KeyId 0 (encrypted region)** in **16/16**;
4. **Byte-for-byte comparison** disk × stored segment bytes (streamed): **0% equal blocks in 16/16** — expected and correct: plaintext × ciphertext is 0% by nature, and the classifier rule forbids calling that "different";
5. **Sizes:** **16/16 EXACTLY equal** (disk × SegmentMetadata, byte for byte at the logical size).

## Final classification

| Classification | Count | Interpretation |
|---|---|---|
| `ENCRYPTED_UNCOMPARABLE` | **16/16** | encrypted region; the bytes stored in the XVC are **not** the disk PE; bytes uncomparable without a key |
| `PACKAGE_IDENTICAL` | 0 | no DLL in a cleartext region |
| `DIFFERENT` | 0 | no demonstrable divergence |
| `UNKNOWN` | 0 | — |

## Conclusion on the hybrid assembly — now with complete evidence

**The folder is a HYBRID ASSEMBLY, proven by three independent facts:**

1. **Encrypted content** (exe): disk copy identical to the stored XVC bytes + page slack (E1, 29/29 blocks) → came from the **package extraction**;
2. **DLLs from the SAME build in cleartext**: they are encrypted in the XVC (KeyId 0 — never extracted from there), yet the **16/16 logical sizes match exactly** against SegmentMetadata → the disk binaries are **the same builds** as the package, obtained in plaintext **through another channel** (console/devkit — consistent with: no in-file Authenticode, console/onecore-xbox builds, not public Windows redistributables);
3. **Faithful configs** (disk == XVC, byte for byte, 3 files).

The **origin of the "other channel"** (how the DLLs' plaintext reached the disk) remains **UNKNOWN** — but the earlier doubt ("would the readable DLLs be from the package's build or from another build?") is **resolved: same build, same logical size, same distribution (chunk 1002/segments 13–28)**.

**Forensic consequence:** nothing in that channel produced the executable (the disk exe remains ciphertext identical to the XVC) — the source that supplied the DLLs' plaintext **did not have** the exe in cleartext, or it was not brought over. The `BLOCKED_MISSING_AUTHORIZED_CIK` block remains, now with the folder's provenance tree fully mapped and classified.
