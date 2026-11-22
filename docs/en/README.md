# XVC Intelligence Engine: usage and architecture

**Language / Idioma:** English · [Português](../pt/README.md)

A **read-only** structural research tool for an Xbox XVD/XVC package.

What the tool does not do:

- write to the package;
- use, look for or derive keys;
- decrypt content or get around access protection;
- treat high entropy as proof of encryption.

Every conclusion carries one of these labels:

- **CONFIRMED**: checked against this package's bytes by a check that has an id;
- **INFERRED**: consistent but not proven, or taken from a public source (xvdtool) without local verification;
- **UNKNOWN**: not determined.

## Usage

```
python -I xvcintel.py analyze PACKAGE.xvc --out reports [--full-leaf] [--full-pages] [--cap-mb 160] \
       [--baseline tests/fixtures/xvc_files_report_baseline.json] [--tests-json reports/tests_summary.json]
python -I xvcintel.py header|layout|xvcinfo|files [--list]|integrity|pages|userdata PACKAGE.xvc
python -I xvcintel.py fingerprint PACKAGE.xvc --name game_scarlett_master.exe [--json profile.json]
python -I xvcintel.py graph PACKAGE.xvc --out graph.json
python -I xvcintel.py query --graph reports/graph.json --node game_scarlett_master.exe [--relation IMPORTS]
python -I xvcintel.py pe PE_FILE [--json out.json]
python -I xvcintel.py regf HIVE
python -I xvcintel.py regress old.json new.json
python -I scripts/xvc_probe.py PACKAGE.xvc --skip-scan --json-report files.json   # compatible wrapper
python -I scripts/test_summary.py reports/tests_summary.json                      # pytest + JSON summary
```

Tests: `python -m pytest -q`. 137 tests run without the package. With `XVC_PATH=<package>`, the 6 integration tests against the real package also run. `XVC_FULL=1` turns on the full scans in those tests, about 1.3 GB.

## Architecture

```
src/xvcintel/
  core/       result.py (Ok/Err + typed ParseError), reader.py (read-only FileSource, streaming, 256 MB limit), util.py
  formats/    xvd_header, layout, hashtree, xvcinfo, userdata (user data + PFX), filemap, regf, pe
              -> pure parsers: they take bytes and return a Result
  engines/    package (loads everything), treeio (hash-tree access), integrity, pages, profiler, configs,
              fingerprint, graph
  evidence/   model (Evidence/CheckResult/Finding), findings, reports (JSON, schema 1 and regression), html_report
  cli.py
scripts/      xvc_probe.py, pe_check.py, regf_dump.py (compatible wrappers), test_summary.py
tests/        synthxvc.py (generator for a complete synthetic XVC package, ~1 MB), fixtures/ (small extracts), test_*.py
legacy/       untouched copies of the original scripts (used by a compatibility test)
reports/      output of the last run against the real package
recovery/    PE recovery tools (see recovery/README.en.md)
docs/en/      this file, audit, format, pe-requirements, full-hash-verification
docs/pt/      the same pages in Portuguese
```

Dependencies: `formats` does not know about `engines`; `engines` reads the package only through `ByteSource`; `evidence` only consumes results.

## Cost limits (defaults)

| Check | Default | Option |
|---|---|---|
| Region or segment hash | full hash up to 160 MB per item; larger items are skipped and reported | `--cap-mb` |
| L0→L1 link | 64 sampled pages (seed 1234) | `--full-leaf` (all 321,211 pages, about 1.3 GB) |
| Leaf vs. data page | start, middle and end of each region, plus 32 random pages | `--samples` |
| Page-table RLE model | start, middle and end of each of the 76,469 runs | `--full-pages` (all 54,605,307 drive pages, reading only the leaves) |

By default, the project hashes in full only the regions and segments up to 160 MB; larger ones are skipped and reported. Running with `--cap-mb` above the package size (full hash, about 440 GB read) **verified** the 15 regions and 59 segments above 160 MB: 28/28 regions and 108/108 segments match. The region and segment hash rules are therefore CONFIRMED at full coverage. See [full-hash-verification.md](full-hash-verification.md) and `reports/full_hashes_result.json`.

## Other documents

- [format.md](format.md): the XVD/XVC format as decoded here.
- [pe-requirements.md](pe-requirements.md): what is needed to analyse the internal PE.
- [audit.md](audit.md): audit of the original scripts.
- [full-hash-verification.md](full-hash-verification.md): the full integrity check.
