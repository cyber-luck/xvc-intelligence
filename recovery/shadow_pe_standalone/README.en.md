# Shadow PE Reconstructor (standalone): PROJECT_ALPHA

**Language / Idioma:** English · [Português](README.md)

A **read-only** forensic tool that looks for recoverable PE candidates in `.bin`, `.xvc` and `.xvd` files, catalogs and other artifacts. It also produces an inventory, references to executables, identical binary blocks and maps of annotated regions.

**It does not decrypt AES-XTS, does not recover keys, does not invent an `.exe` and does not automatically identify a candidate as the original executable.** Carved candidates are structurally recognized PEs; they may be Xbox catalogs, DLLs or other binaries.

This is a single-file tool that does not depend on `xvcintel`. For the modular pipeline integrated with this repository, see [`recovery/project_alpha/`](../project_alpha/README.en.md).

## Requirements

Python 3.10+, standard library only. Optional for streams: `python -m pip install zstandard lz4`.

## Minimal usage (PowerShell)

Copy `shadow_pe_reconstructor.py` to the project root, or run it from wherever it is.

```powershell
# A single BIN file, with PE carving and opt-in extraction
python -I .\shadow_pe_reconstructor.py "G:\PATH\PACKAGE\file.bin" `
  --out ".\analysis\shadow_pe_001" --max-scan 0 --compressed `
  --extract --hash-full --target-exe "game_scarlett_master.exe"

# Analyse every file in a folder (scan is limited by default)
python -I .\shadow_pe_reconstructor.py "G:\PATH\PACKAGE" `
  --out ".\analysis\shadow_pe_002" --compressed --match-blocks

# Full coverage (may take a long time over 200+ GiB of data)
python -I .\shadow_pe_reconstructor.py "G:\PATH\PACKAGE" `
  --out ".\analysis\shadow_pe_full" --max-scan 0 --max-total-scan 0 `
  --hash-full --compressed --extract
```

**Important:** `--max-scan 0` only means a full scan per file; `--max-total-scan 0` also removes the global limit. `--hash-full` computes the full SHA-256 of each file; without it, the tool records `prefix_sha256_not_full_file` with the exact number of bytes used. Any negative conclusion from a partial scan must stay partial.

By default the program reads up to 64 MiB of each file when looking for candidates, capped at 2 GiB in total. It can examine a folder of very large files without loading each one into RAM. `--compressed` searches for known streams; `--deep-zlib` widens the search heuristically, with possible false positives and extra cost. ZIP files are processed only with a limited decompressed size, and member paths are never reproduced on disk.

## Annotating encrypted regions identified by your reports

`--regions` takes a list of **external annotations**. The ranges are not inferred from entropy and are not automatically checked against the package. Use absolute physical offsets in the *corresponding file* (not RVAs). Example file `regions.example.json`:

```json
{
  "sources": [
    {
      "path": "G:\\PATH\\PACKAGE\\container.xvc",
      "regions": [
        {"offset": 1048576, "length": 4096, "state": "ENCRYPTED_UNKNOWN", "label": "segment 12, region 0x3E9; verify actual physical offset"}
      ]
    }
  ]
}
```

**Do not use the example offset as a real one.** Give the physical range that your `xvc_probe` actually reports. The scanner does not carve inside ranges annotated as encrypted; other regions of the same file remain eligible for inspection.

## Main options

| Option | Default | Purpose |
|---|---|---|
| `--out` | required | New or **empty** output folder |
| `--target-exe` | — | Name hint only; it **does not** validate identity |
| `--regions` | — | JSON manifest of user-supplied encrypted/known ranges |
| `--extract` | off | Carve validated plaintext candidates to new files |
| `--compressed` / `--deep-zlib` | off | Look for known compressed streams / also generic zlib |
| `--match-blocks` | off | Find identical stored blocks across inputs |
| `--hash-full` | off | Full-file SHA-256 (otherwise a prefix of `--hash-bytes`, 64 MiB) |
| `--max-scan` / `--max-total-scan` | 64 MiB / 2 GiB | PE scan bytes per input / across inputs (0 = unlimited) |
| `--max-files` | 10000 | Input file limit |

Further limits (candidates, streams, decompressed size, ZIP members, references, block matching) are listed by `--help`.

## Output files

- `binary_inventory.json`: sources, type, length, hash (full, or partial and labelled), sampled entropy and coverage.
- `executable_candidates.json`: PE candidates with headers, sections, imports and CodeView PDB when readable; name references are only clues.
- `shadow_pe_map.json`: `EXACT_RECOVERED`, `MISSING` and `ENCRYPTED_UNKNOWN` regions based on evidence or explicit annotations.
- `recovery_provenance.json`: source, offset or member, transformation and SHA-256 of each identified fragment.
- `summary.json`: final classification, counts, limits and warnings.
- `shadow_pe_report.html`: static dashboard that opens in any browser.
- `block_matches.json`: with `--match-blocks`, equal block hashes between different files. **It does not prove they belong to the target executable.**
- `recovered_fragments/`: only with `--extract`; copies of plaintext bytes, binaries are never executed.

The tool **does not automatically generate** `reconstructed.exe` or `shadow_pe_partial.bin` with made-up padding. When a valid PE exists, it keeps exactly the recoverable bytes and annotates any missing ranges.

## Result states

- `PLAINTEXT_PE_CANDIDATES_FOUND`: at least one structurally plausible PE; the identity of the original `.exe` is **not established**.
- `METADATA_ONLY`: clues to executables and/or annotated regions, with no PE recovered.
- `NO_RECOVERABLE_PE_OBSERVED`: no candidates were found in the bytes examined. **This does not prove that no PE exists outside the coverage.**

The run in [`example_real_inputs/`](example_real_inputs/) analysed 3 sample files (4 KB, 12 KB and 33 MB, all fully scanned) and ended with `NO_RECOVERABLE_PE_OBSERVED`: 0 candidates, 0 fragments, nothing decrypted.

## Tests

```powershell
python -m unittest discover -s tests -v
```

These are synthetic tests (18): valid/embedded/truncated PE, catalogs, MZ false positive, gzip/zlib/ZIP, metadata references, encrypted annotations, explicit partial SHA, block comparison, overwrite protection, partial scan, no promise of decryption, and output created inside the analysed folder.

## Integrity and safety

Inputs are always opened read-only. The tool refuses a non-empty output folder, creates reports and fragments only as new files (`x`, `xb`) and never executes code it finds. No change is made to `gameos.xvd`, `gameos.encdisabled.xvd` or the files examined. Without a legitimate key, AES-XTS-encrypted blocks remain `ENCRYPTED_UNKNOWN`.
