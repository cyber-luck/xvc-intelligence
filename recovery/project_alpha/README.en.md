# PROJECT_ALPHA: Shadow PE Reconstructor

**Language / Idioma:** English · [Português](README.md)

A forensic pipeline that looks for every recoverable trace of a target executable
(default: `game_scarlett_master.exe`) across an XVC/XVD package and the files on disk.
For each byte range of the target it records **where the evidence came from and how
strong it is**. It runs alongside `xvcintel` and reuses its parsers, as well as the
scanner in `recovery/bin_pe_recovery/scripts/bin_pe_recovery.py`.

> **Status:** work in progress, not yet committed. `reports/shadow_pe/` exists but is
> empty, so no results against the real package have been recorded yet.

## Rules enforced in the code

- Original artifacts are opened **read-only** (`rb`). The XVD/XVC is never modified, and no flag is flipped.
- **No decryption**, key guessing or brute force.
- **No made-up bytes**: artificial padding is not counted as recovery.
- Outputs go only to **new files** (`xb` mode). Nothing is overwritten, no path traversal is allowed, and outputs are refused inside an original artifact's folder.
- Recovered bytes and inferred bytes are **never added together** in the same rate.
- **Negative results** are recorded with the same weight as positive ones.
- Recovered binaries are **never executed**.

## Requirements

- Python 3.10+, run from inside this repository. `_bootstrap.py` adds `src/` (xvcintel) and
  `scripts/` to the path and loads `recovery/bin_pe_recovery/scripts/bin_pe_recovery.py`.
- Optional: `zstandard` and `lz4` for those stream formats.

## Commands

```powershell
python -I recovery\project_alpha\shadow_pe_reconstructor.py <command> [options]
```

| Command | Stage | What it does |
|---|---|---|
| `inventory ROOTS... --out DIR [--stop-after N]` | 1 | Deep binary inventory: format by content, size, SHA-256 (full, or head+tail labelled partial), entropy by window, signatures, compression magics. Per-file cache, so it can resume |
| `locate [--xvc F] [--disk D] --out DIR` | 2 | Executable candidates from declared metadata (configs, manifest, hive, layout) and strings, combined in an evidence graph |
| `carve ROOTS... --out DIR [--extract-partial] [--max-scan N]` | 3 | Strict PE carving: MZ + valid e_lfanew + `PE\0\0` + COFF + optional header + section table within physical bounds. A lone `MZ` is never a PE |
| `reconstruct --xvc F --disk D --out DIR [--target NAME]` | 4 | Builds the classified byte-range map of the target, the HTML report and metrics |
| `experiments --xvc F --disk D --out DIR [--target NAME]` | 6 | Recovery experiments, each with a negative control (see below) |
| `validate PATH [--machine 0x8664] [--magic 0x20B] [--out F]` | 7 | Independent validation of one PE. Exit code 0 if valid |
| `selftest [--keep]` | — | Fast synthetic suite (14 scenarios) |
| `run-all --xvc F --disk D --out DIR [--target NAME]` | all | Full pipeline: inventory → locate → carve → experiments → reconstruct → validate `Catalog000.bin` |

Example:

```powershell
python -I recovery\project_alpha\shadow_pe_reconstructor.py selftest
python -I recovery\project_alpha\shadow_pe_reconstructor.py run-all `
    --xvc PACKAGE.xvc --disk DIR_WITH_EXTRACTED_FILES `
    --target game_scarlett_master.exe --out reports\shadow_pe
```

> Run `--disk` only against a folder whose origin is documented and legitimate. The folder
> in the script's built-in example (`G:\MyGame_v1\PROJECT_ALPHA`) was previously recorded as
> being of **unestablished origin** (see [docs/en/pe-requirements.md](../../docs/en/pe-requirements.md)).

## Byte-range classifications

Every byte of the target is in exactly one class. Proven bytes are never replaced by an inference.

| Class | Meaning |
|---|---|
| `EXACT_RECOVERED` | Plaintext bytes recovered and proven |
| `MATCHED_COPY` | Stored bytes proven identical to another copy (says nothing about plaintext) |
| `STRUCTURAL_INFERENCE` | Inferred from structure, with the basis recorded |
| `ENCRYPTED_UNKNOWN` | Stored bytes present but unreadable without the key |
| `MISSING` | No evidence |
| `CONFLICTING_EVIDENCE` | Sources with proven bytes disagree |
| `UNVERIFIED` | Not yet checked |

## Experiments (stage 6)

Each experiment records the hypothesis, method, inputs, result, a negative control,
limitations and a conclusion. Examples:

- **E1, redundancy between containers:** is the on-disk copy of the executable the same stored
  byte sequence as in the XVC? Compares 4 MiB blocks by SHA-256. Control: the same file against
  an XVC region shifted by `+0x100000000` (expects about 0% matches).
- **E1b, readable catalog:** `Catalog000.bin` on disk vs. its XVC region (KeyId 0xFFFF).
- **E3, structural signatures:** whether any valid PE header exists in any copy of the target.
  Control: synthetic scenarios s01 (real PE, 1 recovered) and s04 (fake MZ, 0 recovered).
- **E6, DLL differential:** a readable DLL on disk vs. its encrypted XVC region. Control: the file
  against itself (expects 100%). No key derivation is attempted.

## Outputs

`binary_inventory.json`, `artifact_index.json`, `executable_candidates.json`,
`carve_report.json`, `experiments.json`, `shadow_pe_map.json`, `shadow_pe_report_data.json`,
`shadow_pe_report.html`, `metrics.json`, `recovery_provenance.json`, `fragment_manifest.json`,
`carve_provenance.json`, `carve_fragment_manifest.json`, `catalog_pe_validation.json`,
`pe_validation.json` (from `validate`) and `recovered_fragments/`.

`shadow_pe_partial.bin` is written **only** if there are `EXACT_RECOVERED` ranges starting at
offset 0. It contains only proven bytes, never padding.

## Tests

- `selftest`: 14 synthetic scenarios with known expected bytes, including a real PE, an embedded
  PE, a truncated PE, a fake MZ, random data, a compressed PE, several PEs in one container,
  partial duplication, conflicting sources, high entropy, larger than memory, overwrite guard,
  interrupt and resume, and a round trip.
- `recovery/project_alpha/tests/test_shadow_pe.py`: the pytest version of these scenarios. It is
  included in the repository's `pytest` run through `pyproject.toml`.

## Limits

- The target's content is encrypted in the package (region KeyId 0). Without a legitimate key,
  no code or data byte of it can be recovered. That is a real cryptographic barrier, not a
  limitation of the tool.
- A parseable PE is not proof that it is the original executable, nor that it works.
- Matching ciphertext proves only that the stored bytes are identical.
