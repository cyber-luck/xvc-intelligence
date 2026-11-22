# PE recovery tools

**Language / Idioma:** English · [Português](README.md)

Three tools that look for recoverable PE executables in BIN/XVC/XVD files. They all follow
the project's rules: read-only input, no decryption or key handling, no made-up bytes, new
output files only, and recovered binaries are never executed. **None of them can recover
data from encrypted regions.**

| Folder | What it is | Dependencies | Tests |
|---|---|---|---|
| [`bin_pe_recovery/`](bin_pe_recovery/README.en.md) | PE32/PE32+ scanner at any offset, including inside compressed streams. Also ships upgraded versions of the wrappers (`--scan-bin`, `--pe-scan`, `--find-exe`), not yet installed into `scripts/` | Standard library (+ optional `zstandard`/`lz4`) | 13, pytest |
| [`project_alpha/`](project_alpha/README.en.md) | Modular pipeline built on `xvcintel`: inventory, locate, carve, experiments with negative controls, byte-range provenance map, validation | `src/xvcintel` + `bin_pe_recovery` | 14 scenarios (`selftest`) + pytest, included in the root `pytest` run |
| [`shadow_pe_standalone/`](shadow_pe_standalone/README.en.md) | Single-file standalone version | Standard library | 18, unittest |

## Running the tests

```powershell
# project_alpha (together with the xvcintel suite)
python -I -m pytest -q

# bin_pe_recovery
python -I -m pytest -q recovery\bin_pe_recovery\tests

# shadow_pe_standalone
python -I -m unittest discover -s recovery\shadow_pe_standalone\tests -v
```

Only run these tools on artifacts whose origin is documented and legitimate. `project_alpha`
output from real data goes to `reports/shadow_pe/`. Recovered binary fragments
(`recovered_fragments/`) are not committed.
