# PE recovery in BIN / XVC / XVD files: non-destructive analysis

**Language / Idioma:** English · [Português](README.md)

Compatible with Python 3.10+ on Windows. This package **does not include or replace** `src/xvcintel`.

> **In this repository:** the package lives in `recovery/bin_pe_recovery/`. The scanner is
> `recovery/bin_pe_recovery/scripts/bin_pe_recovery.py` (also used by `recovery/project_alpha`).
> The upgraded wrappers (`pe_check.py --scan-bin`, `xvc_probe.py --pe-scan`, `regf_dump.py --find-exe`)
> are in `recovery/bin_pe_recovery/scripts/` and **have not yet been installed** into the root `scripts/`.
> The commands below assume the installation described in "Installing into the project".

## Files

- `scripts/bin_pe_recovery.py`: a new standalone scanner for PE32/PE32+ at any offset in `.bin`, `.dat`, `.xvc` or `.xvd` files. It extracts valid plaintext candidates and writes JSON reports. It can optionally try to decompress gzip, XZ, bzip2, ZIP, LZ4, Zstandard and, on request, zlib streams.
- `scripts/pe_check.py`: keeps the existing call to `xvcintel` and adds `--scan-bin`. If `xvcintel` is not available, it can still check a PE directly at offset zero.
- `scripts/xvc_probe.py`: keeps the original XVC mode and adds `--pe-scan`, handled before the internal library is imported.
- `scripts/regf_dump.py`: keeps the hive reader via `xvcintel` and adds `--find-exe` to look for ASCII/UTF-16LE references to `.exe`, `.dll` and `.sys`. These are clues, NOT a full registry parser.
- `scripts/test_summary.py`: runs the existing tests, including the new suite `tests/test_bin_pe_recovery.py`.
- `samples/sample_ex_userdata_scan.json`, `samples/sample_ex_userdata_deep_scan.json`, `samples/sample_bat_scan.json`: reports from analysing the two samples provided earlier; `samples/test_results_13.json`: result of the 13 tests.

## Installing into the project

Copy the files from `scripts/` into the project's `scripts/`, and `tests/` into `tests/`, **backing up the files you replace**. The standalone scanner can sit in any folder next to the wrappers.

For Zstandard and LZ4 support:

```powershell
py -m pip install zstandard lz4 pytest
```

Without those dependencies, plain PE, gzip, zlib, XZ and bzip2 still work. Everything can be run with `python -I`.

## PowerShell examples

From the repository root, adjusting the input path to your real BIN:

```powershell
# 1) Report only: plaintext PE, up to 1 GiB of the file (default)
python -I .\scripts\pe_check.py --scan-bin "G:\PATH\file.bin" --json .\pe_report.json

# 2) Examine the whole file, extract recognized PEs and try known compression
python -I .\scripts\bin_pe_recovery.py scan "G:\PATH\file.bin" `
  --max-scan 0 --compressed `
  --extract-dir .\recovered_pe `
  --json .\full_report.json

# 3) Optional: look for possible zlib streams; false positives, high cost
python -I .\scripts\bin_pe_recovery.py scan "G:\PATH\file.bin" `
  --compressed --deep-zlib --max-streams 200 `
  --json .\zlib_report.json

# 4) The same scan through the XVC wrapper
python -I .\scripts\xvc_probe.py --pe-scan "G:\PATH\file.bin" --compressed --json .\xvc_pe.json

# 5) References to executables in a hive or metadata BIN (clues only)
python -I .\scripts\regf_dump.py --find-exe "G:\PATH\metadata.bin" --json .\exe_refs.json

# 6) Run the tests (pip install pytest)
python -I .\scripts\test_summary.py .\test_results.json
```

**Output names are exclusive**: the scanner does not replace existing JSON files or PEs. Choose new names or folders when you repeat a command.

## Scope and accuracy

| Data type | Support | Limitations |
|---|---|---|
| BIN file that is already a PE32/PE32+ | Yes | Detects a PE even without an `.exe` extension |
| PE concatenated or embedded in a BIN | Yes | Extracts the minimum extent from the headers and sections; the overlay may be missing |
| PE in gzip/XZ/bzip2/ZIP | Yes | Explicit input and output limits |
| PE in ZSTD/LZ4 | Yes, with optional libs | Requires `zstandard`/`lz4` |
| PE in zlib | Yes, with `--deep-zlib` | Header-based heuristic, false positives possible |
| PE in an **encrypted** XVD/XVC | No, not without a valid key | AES-XTS is not undone by an MZ search, a flag change or entropy |
| Signature, imports, PE working on Windows | Not validated | The PE may be a catalog, a DLL or a binary that depends on Xbox APIs |
| REGF hive | Classic `regf_dump` via xvcintel | `--find-exe` only searches for unvalidated strings |
| `Catalog000.bin` (if PE) | Special identification | Subsystem `0x11` marks it as an Xbox catalog candidate, not the game executable |

### Where a legitimate key is needed

For data that is already encrypted, the safe route is to obtain a decrypted copy **with valid credentials/keys from your own environment**. Once decrypted, the scan can be repeated on the image or on the extracted files. The scanner **does not generate, guess, extract or get around keys**, and it does not modify `gameos.xvd` or any input file.

Microsoft documents console package encryption; `xvdtool` states that it does not distribute production keys. See `https://github.com/emoose/xvdtool` and the Microsoft GDK packaging documentation.

## Evidence from the samples provided

- `ex_userdata.bin`: 33,107,968 bytes, full scan; 504 raw `MZ` hits, **0 valid PE structures**; three entropy samples of about 7.997 bits/byte. A deep zlib pass tried 128 streams (the limit was reached) and also found 0 PE files.
- `bat.bin`: 4,096 bytes, full scan; **0 valid PE structures**; entropy about 7.962 bits/byte.

These values show that **no plaintext PE executable can be carved from the sampled regions**. High entropy is compatible with encrypted or compressed data and **does not prove** encryption on its own.

## Note on `--max-scan`

The default 1 GiB limit protects against accidentally long runs over sets of hundreds of GiB. Use `--max-scan 0` to examine the whole file; the report includes `entire_file_scanned` and `coverage` so that conclusions are not drawn from partially examined files. Optional extraction never runs the binaries it produces.

## Tests

13 tests, all passing (`samples/test_results_13.json`).
