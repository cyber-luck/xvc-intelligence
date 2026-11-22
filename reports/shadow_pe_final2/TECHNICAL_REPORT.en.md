# PROJECT_ALPHA: Shadow PE Reconstruction technical report (run 2)

**Language / Idioma:** English · [Português](RELATORIO_TECNICO.md)

**Target:** `game_scarlett_master.exe` (Xbox Series X|S / Scarlett, package 1.0.2.1)
**Run date:** 2026-11-22 · **Final classification: `METADATA_ONLY`**
**Tool:** `recovery/project_alpha/shadow_pe_reconstructor.py run-all` (commit `7be3f47`; the fixes are described in
section 9). Read-only; full log in `reports/shadow_pe_final2.log`.

This report supersedes `reports/shadow_pe_final/TECHNICAL_REPORT.en.md`. The conclusions did not change; the
origin of the numbers did: every value below was **measured in this run** and can be checked against the JSON files
in this folder. Anything not measured here is marked as such in section 10.

---

## 1. Direct answer

> *How much of the original executable can be recovered?*

| Class | Bytes | % of target (120,181,760) | Measured basis |
|---|---:|---:|---|
| `EXACT_RECOVERED` (plaintext with proof) | **0** | 0.000000 | no valid PE in any byte of the target (E3) |
| `MATCHED_COPY` of plaintext | **0** | 0.000000 | same |
| `STRUCTURAL_INFERENCE` (bytes) | 0 | 0.000000 | no observable PE structure |
| `ENCRYPTED_UNKNOWN` | 120,181,760 | 100.000000 | KeyId 0; entropy **7.999998** bits/byte; 0 valid PEs among 1,874 `MZ` occurrences |
| `MISSING` / `CONFLICTING_EVIDENCE` | 0 | 0 | — |

**No byte of the executable's code or data was recovered.** `shadow_pe_partial.bin` and `reconstructed.exe` were
not generated because there are no proven plaintext bytes. Artificial padding does not count as recovery.

**Provenance of the stored bytes (ciphertext), kept separate and never counted as recovery:** the on-disk copy
(`PROJECT_ALPHA\game_scarlett_master.exe`, 120,184,832 bytes) is **byte-for-byte identical** to the target's region
in the XVC across the 120,181,760 overlapping bytes (E1: 29/29 blocks of 4 MiB). The on-disk copy's 3,072 extra
bytes have no proven origin in the XVC (entropy 7.94; not zeros) and are recorded as `UNVERIFIED`.

> Disk and XVC are **the same evidence**, not two independent witnesses: one is a copy of the other.

## 2. Encryption state: what was measured and what is inferred

| Evidence | Value | Level |
|---|---|---|
| KeyId of the target's region in the XVC (segment 12, offset `0x64917000`) | 0 | CONFIRMED (XVC metadata) |
| Entropy of the whole region (120,181,760 bytes, 256 distinct values) | 7.999998 bits/byte | MEASURED |
| Valid PEs in the whole file / `MZ` occurrences | 0 / 1,874 | MEASURED |
| Detector proven on a known real PE (Catalog000.bin) | 1 PE detected | MEASURED (positive control) |
| Readable DLL on disk vs. its region in the XVC (KeyId 0) | 0% equal blocks | MEASURED (E6) |
| Content encrypted with AES-XTS | — | **INFERRED** |

The tool **does not verify** encryption: it has no key and does not attempt decryption. The conclusion that the
content is encrypted is an inference supported by the four measurements above. AES-XTS is the scheme expected for
encrypted XVD/XVC regions, not something observed in the bytes.

## 3. Inventory (Phase 1): `binary_inventory.json`

- 369 files, 449.7 GB. Roots: `G:\MyGame_v1\PROJECT_ALPHA` and the XVC (225.3 GB).
- All 369 records came from the cache keyed by (path, size, mtime), copied from the previous run
  (`fresh_scans: 0`). Hashes were **not** recomputed in this run.
- Hashing: 364 files with full SHA-256 (≤ 8 GiB). 5 above that with a **partial** 16 MiB head+tail hash, labeled
  as partial: the XVC, `audio.rpf`, `levels.rpf`, `movies.rpf`, `story000.rpf`.
- Formats: 305 `unknown_bin`, 33 `MZ`, 25 PNG, 3 XML, 2 MSFT-XVD (the XVC and `gameos.xvd`), 1 REGF.
- Per-file entropy in the inventory is **sampled** (up to 12 windows of 64 KB). The target entropy quoted in this
  report comes from E3, which measures the whole region.

## 4. Identity and location (Phase 2): `executable_candidates.json`

**Target metadata, by evidence level:**

| Field | Value | Level | Basis |
|---|---|---|---|
| Name | `game_scarlett_master.exe` | CONFIRMED | `MicrosoftGame.Config`, `appxmanifest.xml`, `microsoft_gameconfig.bin` hive, XVC segment metadata (layout XML as an additional source, INFERRED) |
| Location | segment 12, offset `0x64917000`, 120,181,760 bytes, KeyId 0 | CONFIRMED | XVC SegmentMetadata + XvcInfo |
| SHA-256 of the stored bytes | `79fe15101c861d0e6e3353d24ebba158ae7e0ed61ea79ece199ca91763dba89a` | MEASURED | identifies the ciphertext, not the PE |
| Version | 1.0.2.1 | INFERRED | **package** version (XVC header = `Identity@Version`); the PE's internal version is unknown |
| Architecture | x64 / PE32+ expected | INFERRED | Scarlett platform; the package DLLs are PE32+ AMD64; the target's header was never observed |
| Subsystem, sections, imports, entry point, PDB | — | UNKNOWN | no header byte observed |

Note: `metrics.json → metadata_coverage` lists the 8 fields **evaluated**, not the ones recovered. Only the name
and the location are confirmed.

**27 candidates:**

| Group | Count | State | Note |
|---|---:|---|---|
| Target | 1 | `ENCRYPTED_UNKNOWN`, on-disk copy also opaque | — |
| Package DLLs (KeyId 0 in the XVC) | 16 | `PLAINTEXT_AVAILABLE_EM_DISCO` | on-disk copies are readable PEs; recoverable dependencies, **not** evidence of the target's imports |
| DLLs outside the package | 3 | `PLAINTEXT_AVAILABLE_EM_DISCO` | 2 from the FidelityFX SDK (`port\third_party`), `sample_module.dll` |
| Executables from earlier sessions | 6 | `PLAINTEXT_AVAILABLE_EM_DISCO` | `platform_master.exe`, `alpha_*.exe` (4), `CMakeCXXCompilerId.exe`; **not** the original executable |
| Text reference | 1 | UNKNOWN | string `run GamingRepair.exe`, no file |

## 5. Experiments (Phase 6): `experiments.json`

| ID | Result | Control | Conclusion |
|---|---|---|---|
| **E1** disk vs. XVC (target) | 29/29 equal blocks (100%) | non-overlapping XVC region at `0x164917000`: 0% | the on-disk copy came from the XVC; plaintext remains unknown |
| **E1b** Catalog000.bin vs. XVC (KeyId 0xFFFF) | 1/1 equal block (100%) | non-overlapping region at `0x16484D000`: 0% | the on-disk catalog is a faithful copy of the readable region |
| **E6** `amd_fidelityfx_loader_xbox.dll` (valid PE on disk) vs. its XVC region (KeyId 0, 13,312 bytes) | 0/1 equal block (0%) | file against itself: 100% | the bytes in the XVC are transformed, consistent with encryption; no cryptographic weakness claimed |
| **E3** structural signatures in the target | 0 valid PEs / 1,874 `MZ`, whole file, no limit reached; entropy 7.999998 | **positive control executed:** the same detector finds 1 PE in Catalog000.bin | measured negative; covers the XVC region through byte identity (E1) |

The negative controls use an offset verified to lie inside the XVC and not to overlap the tested region.

Not executed in this run: build-to-build comparison (E2), since no other version of the package exists in the set.

## 6. Shadow PE map (Phase 4): `shadow_pe_map.json`, `recovery_provenance.json`

- Single interval `[0x0, 0x729D400)` = 120,181,760 bytes, class `ENCRYPTED_UNKNOWN`. Zero conflicts.
- Evidence recorded on the interval: segment 12, KeyId 0, measured entropy, 0 PEs / 1,874 `MZ`, "encryption
  INFERRED, not verified".
- Provenance: 1 `MATCHED_COPY` record of **ciphertext** (120,181,760 bytes, disk ↔ XVC) and 1 `UNVERIFIED` record
  (the 3,072-byte tail).

## 7. Recovered fragments (Phase 3): `recovered_fragments/`, `carve_fragment_manifest.json`

33 `EXACT_RECOVERED` fragments, extracted with exclusive writes and provenance (source, offset, SHA-256):

- 17 from the package root: the 16 DLLs and `Catalog000.bin` (`XBOX_CODE_CATALOG` PE, x64);
- 16 from `port\` (tools and builds from earlier sessions, FidelityFX SDK, CMake probes).

**None of the fragments belongs to the target.** In `metrics.json`: `fragments_recovered: 0` (target) and
`carve_fragments_total: 33`.

## 8. Validation (Phase 7)

- `Catalog000.bin`: valid, 13/13 checks (`catalog_pe_validation.json`), including the cross-check with `pefile`.
- Repository test suite after the fixes: **156 passed, 6 skipped** (integration tests that require `XVC_PATH`).
  CLI selftest: **21/21**.
- No binary was executed.

## 9. Fixes relative to `shadow_pe_final`

| Item | Previous run | This run |
|---|---|---|
| `MZ` occurrences in the target (E3) | 64: the search cap, with no warning | 1,874, whole file |
| Valid PEs in the target (E3) | `0` hardcoded, no validation | 0 measured by `pe_carver` |
| E3 control | text describing the synthetic tests | positive control executed on a real PE |
| Target entropy | "~7.997" hardcoded | 7.999998 measured over the whole region |
| E6 | arbitrary DLL; KeyId not checked | DLL with a valid PE on disk; KeyId 0 checked |
| Negative controls | +4 GiB without bounds checking | verified offset (inside the XVC, no overlap) |
| AES-XTS | stated as fact | marked as INFERRED |
| Disk + XVC | "two independent witnesses" | the same evidence |
| Version 1.0.2.1 | "CONFIRMED" | INFERRED (package version; PE version unknown) |
| `metadata_recovered` | hardcoded `True` | computed from the CONFIRMED candidate |
| `metrics.json` | `fragments_recovered: 0` seemed to contradict the 33 | separate counters, target and total |
| `run-all` | experiments ran 2× (E1 3×) | once, reused by `reconstruct` |
| Output files | 3 regenerated after the pipeline | all produced by the pipeline, none edited afterwards |

## 10. Limitations and what was not verified in this run

- **Encryption:** inferred (section 2), not verified.
- **Inventory hashes:** came from the previous run's cache; not recomputed.
- **3,072-byte tail:** unknown origin.
- **Absence of a PDB/MAP/OBJ/ILK for the target:** comes from an audit in earlier sessions, not from a search in
  this run.
- **Search for the catalog hashes** (F-EXE-04 in the previous report): not repeated.
- **Compressed streams:** `run-all` does **not** attempt to decode compressed streams (`compression_scanner` only
  runs in the selftest). An independent check made on the same date with
  `recovery/shadow_pe_standalone/shadow_pe_reconstructor.py` found 12 gzip/bzip2 signatures in the target, none
  decodable. That result is not part of the JSON files in this folder.
- `gameos.xvd`: out of scope; not analyzed beyond the inventory.

## 11. Impediments and next steps

1. **Content key unavailable.** If the inference in section 2 is correct, no byte of the target is recoverable
   without it. This is a cryptographic impediment, not a tool limitation. No decryption, key derivation, brute
   force or bypass was attempted.
2. **Legitimate paths:** a development build from the rights holder, a matching PDB, or a copy decrypted through an
   authorized process, with documented provenance (`docs/pt/pe-requisitos.md`). The pipeline automatically
   validates any candidate that appears.
3. **Without the key:** if a PDB for the target turns up, cross-check its sections and functions against the
   confirmed size of 120,181,760 bytes; if another version of the package turns up, compare the structure of the
   stored bytes.

## 12. Reproduction (PowerShell)

```powershell
# synthetic tests (do not touch the real artifacts)
python -I -m pytest -q
python recovery\project_alpha\shadow_pe_reconstructor.py selftest

# full pipeline (read-only; the output directory must be new)
python recovery\project_alpha\shadow_pe_reconstructor.py run-all `
    --xvc  "G:\MyGame_v1\28872443D20A7_1.0.2.1_neutral__k2ss7vbb13xte_xs.xvc" `
    --disk "G:\MyGame_v1\PROJECT_ALPHA" `
    --target game_scarlett_master.exe `
    --out  "reports\shadow_pe_final3"
```

To reuse the inventory hashes, copy `reports\shadow_pe_final2\.cache\` to `<out>\.cache\` before running.
Without the cache, the inventory recomputes the hashes of 449.7 GB.

## 13. Files in this folder

| File | Contents |
|---|---|
| `binary_inventory.json`, `artifact_index.json` | inventory of the 369 files; exact duplicates by SHA-256 |
| `executable_candidates.json` | 27 candidates with sources, levels and states |
| `carve_fragment_manifest.json`, `carve_provenance.json`, `recovered_fragments/` | the 33 fragments and their provenance |
| `experiments.json` | E1, E1b, E6, E3 with results, controls and conclusions |
| `shadow_pe_map.json` | interval map of the target |
| `recovery_provenance.json`, `fragment_manifest.json` | map provenance (ciphertext and tail) |
| `metrics.json` | per-class metrics, measured entropy and counts |
| `shadow_pe_report.html`, `shadow_pe_report_data.json` | visual report and full data |
| `catalog_pe_validation.json` | validation of Catalog000.bin |
