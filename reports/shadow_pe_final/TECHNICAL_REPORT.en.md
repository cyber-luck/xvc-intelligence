# PROJECT_ALPHA: final technical report of the Shadow PE Reconstruction

**Language / Idioma:** English · [Português](RELATORIO_TECNICO.md)

**Target:** `game_scarlett_master.exe` (Xbox Series X|S / Scarlett, package 1.0.2.1)
**Analysis date:** 2026-11-22 · **Final classification: `METADATA_ONLY`**
**Tool:** `recovery/project_alpha/shadow_pe_reconstructor.py` (+ the scanners/correlation/reconstruction/validation modules), built on `xvcintel` and `bin_pe_recovery`, read-only.

---

## 1. Direct answer to the central question

> *How much of the original executable can be recovered?*

| Class | Bytes | % of target (120,181,760) | Basis |
|---|---:|---:|---|
| `EXACT_RECOVERED` (plaintext with proof) | **0** | 0.000000 | no readable byte exists in any copy |
| `MATCHED_COPY` of **plaintext** | **0** | 0.000000 | same |
| `STRUCTURAL_INFERENCE` (bytes) | 0 | 0.000000 | no observable PE structure from which to infer a byte-level layout |
| `ENCRYPTED_UNKNOWN` | 120,181,760 | 100.000000 | KeyId 0 region in the XVC; no MZ; entropy ~7.997; two independent witnesses |
| `MISSING` / `CONFLICTING` | 0 | 0 | — |

**Provenance of the STORED bytes (ciphertext), kept separate and never counted as recovery:** the on-disk copy
(`PROJECT_ALPHA\game_scarlett_master.exe`, 120,184,832 bytes) is **100% identical** to the bytes stored in the XVC
(29/29 blocks of 4 MiB): experiment E1, with a negative control of 0/29. The 3,072 extra tail bytes have no
proven origin (entropy 7.94; non-zero) and are recorded as `UNVERIFIED` in the provenance.

**What was fully recovered (metadata, CONFIRMED):**
- Name, application ID, platform (`MicrosoftGame.Config` + `appxmanifest.xml` + hive + XVC layout, 4 consistent sources);
- Package version 1.0.2.1 (XVC header 0x3BC == `Identity@Version`);
- Exact location in the container: XVC segment 12, region 0x3E9, offset `0x64917000`, 120,181,760 bytes, 29,342 pages, KeyId 0;
- Hash of the stored bytes: SHA-256 `79fe1510…dba89a` (identifies the ciphertext, not the PE);
- Expected architecture: x64/PE32+, **INFERRED** (Scarlett platform + the 16 shipped DLLs are PE32+ AMD64, CONFIRMED in the on-disk bytes); the target's header was never observed;
- Subsystem, sections, imports, entry point, PDB: **UNKNOWN** (not observable; no PDB/MAP/OBJ/ILK exists in the surviving set).

**Real barrier:** the content is protected by AES-XTS (KeyId 0 region) and the content key is not
available. Without it, **no code or data byte of the executable can be recovered**: a cryptographic block,
not a limitation of the tool. No decryption, key derivation, brute force or integrity bypass was attempted
(the mission's absolute rules, all followed). `reconstructed.exe` **was not generated** because there are not
enough proven bytes; `shadow_pe_partial.bin` **was not generated** because there is no plaintext byte to
record (artificial padding is not recovery).

## 2. Inventory (Stage 1): `binary_inventory.json`

369 files / 449.7 GB scanned (roots: `G:\MyGame_v1\PROJECT_ALPHA` + the 225 GB XVC), with a cache keyed on
(path, size, mtime), so it can resume. Policy: full SHA-256 up to 8 GiB; above that, a 16 MiB head+tail hash
**labelled as partial** (never presented as a full hash). Formats: 33 MZ (valid PEs on disk: the package's 16
DLLs, the catalog, tools from earlier sessions), 2 MSFT-XVD (the XVC and `gameos.xvd`), 1 REGF (the gameconfig
hive), 3 XML, 25 PNG, 305 `unknown_bin` (RPFs and encrypted/opaque blobs).

## 3. Locating the executable (Stage 2): `executable_candidates.json`

27 candidates, each with source, evidence, **known** size (never an estimate presented as confirmed) and state:

- `game_scarlett_master.exe`: **CONFIRMED, target**. `ENCRYPTED_UNKNOWN` in the XVC **and** the on-disk copy is opaque;
- 16 shipped DLLs: CONFIRMED in the XVC as opaque (KeyId 0); **the on-disk copies are readable PEs** (`PLAINTEXT_AVAILABLE_EM_DISCO`). They are recoverable dependencies, **not** evidence that the target imports them;
- `platform_master.exe`, `alpha_*.exe`, CMake probes, `sample_module.dll`: **reconstruction tools from earlier sessions**, plaintext on disk, explicitly **not the original executable** (`platform_master` describes itself as a port runtime, with its own RSDS/GUID; see `G:\MyGame_v1\PROJECT_ALPHA_INTEGRATION\exe_reconstruction`);
- Raw strings (`.ExE`, `run GamingRepair.exe`, …): UNKNOWN, text references only.

*Recorded correction:* v1 of this JSON labelled the plaintext copies as UNKNOWN. It was regenerated with the
correct states; the earlier version is kept in `executable_candidates.v1.json`.

## 4. Recovered fragments (Stage 3): `recovered_fragments/` + `carve_fragment_manifest.json`

33 fragments extracted with exclusive writes and full provenance (source, offset, SHA-256, transformation):
16 readable DLLs, `Catalog000.bin` (an `XBOX_CODE_CATALOG` PE, machine 0x8664, **independently validated**:
`catalog_pe_validation.json` reports `valid=True`) and the tools from earlier sessions. Strict carving: a lone
`MZ` is never accepted (checks of `e_lfanew`, `PE\0\0`, COFF, Optional Header and Section Table against
physical bounds). **No fragment of the target.** Compressed streams: no legitimate decode in the target's
artifacts (magics without a successful decode are not compression).

## 5. Experiments (Stage 6): `experiments.json` (with hypothesis, basis, data, result, negative control, limitations and conclusion)

| ID | Result | Negative control |
|---|---|---|
| **E1** redundancy between containers | disk == XVC: **100%** (29/29 blocks of 4 MiB; 3,072 B opaque tail with no proven origin) | XVC region shifted by +4 GiB: **0%** (0/29) |
| **E1b** readable catalog | disk == readable XVC region (KeyId 0xFFFF): **100%** | shifted region: ~0% |
| **E6** DLL differential | plaintext on disk × XVC region (KeyId 0): **0%**, so the XVC content is ciphertext; **no** claim of a cryptographic weakness | the file against itself: 100% (comparator sanity check) |
| **E3** structural signatures | **negative confirmed**: no valid PE in any copy of the target | synthetic s01 (1 PE) / s04 (fake MZ → 0) |

Comparison between builds (E2): unavailable. The rar files in `original/` contain no usable earlier build, and
no other version of the package exists in the set. Negative result recorded.

## 6. Shadow PE map (Stage 4): `shadow_pe_map.json` / `shadow_pe_report.html` / `recovery_provenance.json`

A single range `[0x0, 0x729D400)` = 120,181,760 bytes, class `ENCRYPTED_UNKNOWN`, evidence: segment 12 /
region 0x3E9 / KeyId 0 / F-EXE-01..04 + the E1 equality of stored bytes. Zero conflicts. The provenance also
records the 29 `MATCHED_COPY` blocks of **ciphertext** (labelled as such) and the `UNVERIFIED` tail.

## 7. Independent validation (Stage 7)

- `Catalog000.bin`: valid (MZ, PE\0\0, consistent COFF/Optional headers, section inside the file, `xvcintel deep-parse` with no problems);
- Synthetic suite (14 mandatory scenarios): **156 tests passing** in the repo (19 for the shadow PE: PE at the
  start, embedded, truncated, fake MZ, random, compressed, multi-container, partial duplication, conflicting
  evidence resolved correctly, high entropy with no PE, file larger than memory via streaming, overwrite
  refusal, interrupt + resume via cache, round trip against a known synthetic original with classification
  `COMPLETE_VERIFIED`);
- CLI selftest: **21/21**.
- No binary was executed.

## 8. PowerShell commands (reproduction)

```powershell
# full test suite (synthetic; does not touch the real artifacts)
python -I -m pytest -q
python recovery\project_alpha\shadow_pe_reconstructor.py selftest

# full pipeline against the real artifacts (read-only; a new output folder is required)
python recovery\project_alpha\shadow_pe_reconstructor.py run-all `
    --xvc  "G:\MyGame_v1\28872443D20A7_1.0.2.1_neutral__k2ss7vbb13xte_xs.xvc" `
    --disk "G:\MyGame_v1\PROJECT_ALPHA" `
    --target game_scarlett_master.exe `
    --out  "reports\shadow_pe_final2"

# individual stages
python recovery\project_alpha\shadow_pe_reconstructor.py inventory "G:\MyGame_v1\PROJECT_ALPHA" --out reports\inv
python recovery\project_alpha\shadow_pe_reconstructor.py locate --xvc <XVC> --disk <DIR> --out reports\inv
python recovery\project_alpha\shadow_pe_reconstructor.py carve <DIR_OR_FILE> --out reports\carve
python recovery\project_alpha\shadow_pe_reconstructor.py experiments --xvc <XVC> --disk <DIR> --out reports\exp
python recovery\project_alpha\shadow_pe_reconstructor.py reconstruct --xvc <XVC> --disk <DIR> --out reports\map
python recovery\project_alpha\shadow_pe_reconstructor.py validate <PE> --machine 0x8664
```

Note: `--out` can never be inside the folder of an original artifact (safety guard); re-runs into the same
folder are refused (exclusive outputs, no overwriting). Use a new folder, or delete **only** outputs you
generated yourself.

## 9. Files in this report

| File | Content |
|---|---|
| `binary_inventory.json` | inventory of the 369 files (hash, entropy, signatures, policy) |
| `artifact_index.json` | exact duplicates by SHA-256 |
| `executable_candidates.json` (+ `.v1.json`) | 27 candidates with sources and states (v1 kept) |
| `carve_report.json` … `carve_provenance.json`, `carve_fragment_manifest.json` | carving + provenance of the 33 fragments |
| `experiments.json` | E1/E1b/E6/E3 with negative controls |
| `shadow_pe_map.json` | range map of the target with evidence |
| `shadow_pe_report.html`, `shadow_pe_report_data.json` | visual report + full data |
| `metrics.json` | metrics split by class (never adding proof and inference together) |
| `recovery_provenance.json`, `fragment_manifest.json` | provenance of the map (ciphertext MATCHED_COPY labelled, UNVERIFIED tail) |
| `catalog_pe_validation.json` | independent validation of the readable catalog |

## 10. Real barriers and justifiable next steps

1. **AES-XTS content key unavailable**: it blocks all of the target's plaintext. Recovering the code is only
   possible with a legitimate artifact: a development build from the rights holder, a matching PDB, or a copy
   decrypted through an authorized process (with documented provenance; see `docs/en/pe-requirements.md`).
2. The 3,072-byte tail of the on-disk copy: origin UNKNOWN; nothing can be claimed beyond what is recorded.
3. `gameos.xvd` (EraOS, StandardOdk): encrypted, outside the executable's scope; untouched.
4. Future experiments that are justifiable **without a key**: (a) if a PDB of the target turns up, extract the
   section/function layout and cross-check it with the CONFIRMED size of 120,181,760 bytes; (b) compare with
   another version of the package if one ever becomes available (structural analysis of data-unit reuse,
   without revealing plaintext); (c) keep the readable catalog as a verification reference in case a candidate
   PE appears (today the search for the stored bytes' hashes in it is negative, F-EXE-04, which is expected
   because the catalog describes the decrypted content).

**Absolute rules followed:** originals untouched (everything `rb`); XVD/XVC not modified; nothing decrypted;
no byte fabricated; negative results recorded with the same weight as positive ones; hypotheses never
presented as facts.
