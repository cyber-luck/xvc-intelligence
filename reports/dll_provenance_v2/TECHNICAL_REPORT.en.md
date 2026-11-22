# PROJECT_ALPHA — DLL provenance v2: corrected classifications + build identity via RSDS

> English version of `RELATORIO_TECNICO.md`.

**Date:** 2026-11-22 · **Correction absorbed:** size equality is **metadata correspondence, not build identity** — the v1 over-claim was removed.
**Report:** `dll_provenance_reconciliation.json` (schema /2) — SHA-256 `1b978f1e8f0752b9d7c25778416166a32290ac94a166c040b972a98744006e50`
**Regression:** 55 package tests passed.

## Canonical state table (implemented in the report)

| Object | Classification | Basis |
|---|---|---|
| On-disk executable | **`CIPHERTEXT_PACKAGE_IDENTICAL`** | E1: 29/29 blocks identical to the XVC + proven page slack |
| 16 readable DLLs | **`ENCRYPTED_UNCOMPARABLE`** | region 0x3EA KeyId 0; plaintext×ciphertext = 0% by nature |
| Compared configs | **`PACKAGE_IDENTICAL`** | byte-for-byte diff 3/3 identical to the XVC user data |
| DLL origin | **`PROVENANCE_UNKNOWN`** | exact sizes 16/16 = metadata (necessary, never sufficient) |
| EXE recovery | **`BLOCKED_MISSING_AUTHORIZED_CIK`** | CIK 0x3E9 absent; lab ready |

## Build identity via RSDS (the advance performed)

**Authoritative byte-level extraction** from each disk DLL (SHA-256, TimeDateStamp, linker, RSDS GUID+age+pdb path):

- **14/16 DLLs with a CodeView RSDS record** (2 without: `amd_fidelityfx_upscaler_xbox.dll` and `XboxBvhBuilder.dll` — POGO/REPRO only, consistent with the earlier records "16 of 19 images with RSDS");
- Each GUID+age **uniquely identifies the link** that produced that DLL — it is the build reference now recorded;
- **Cross-check against the previous session's records** (`pe_debug_records.json`, 2026-11-21): **16/16 `CONSISTENT`** (size, timestamp, and RSDS GUID/age match) → the disk files are **the same** ones analyzed by the previous session, unchanged — **the environment's internal custody is closed**.

## What this establishes — and what it deliberately does NOT establish

**Establishes:** (a) *what* is on disk — unique builds identified by RSDS, fully recorded; (b) that nothing has changed since the previous analysis; (c) that byte-for-byte equivalence with the package's protected copies is **UNPROVABLE without a key** (encrypted region) — stated, not worked around.

**Does not establish:** that the disk DLLs are byte-for-byte the same as segments 13–28. Size + RSDS are metadata/link-identity correspondences; final proof requires: (i) the holder's **corresponding PDBs** → GUID/age validation (validator ready and demonstrated); or (ii) an **authorized CIK** → decryption of the segments and byte-for-byte comparison (flow ready, lab state C).

## Triggers that close the chain (already implemented)

```powershell
# with the holder's PDBs: GUID/age per DLL
python recovery\project_alpha\shadow_pe_reconstructor.py identity --xvc <XVC> --disk <DIR> `
  --target game_scarlett_master.exe --out reports\pdb_check --pdb-pair "<dll>=<pdb>"

# with an authorized CIK: segments 13-28 bytes in cleartext + byte-for-byte comparison
python recovery\project_alpha\shadow_pe_reconstructor.py decrypt --xvc <XVC> `
  --target <dll> --cik-file <cik.bin> --cik-sha256 <hex> --provenance "custody" --out reports\seg_dll
```

**Final state:** the package's structure and cryptographic state are documented precisely; the hybrid is proven **as to state**; DLL origin is `PROVENANCE_UNKNOWN`; exe recovery unchanged: `BLOCKED_MISSING_AUTHORIZED_CIK`.
