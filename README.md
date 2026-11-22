# XVC Intelligence Engine

**Language / Idioma:** English · [Português](README.md)

A **read-only** structural research tool for Xbox **XVD/XVC** packages.

It decodes the container: XVD header, layout, hash tree, XvcInfo, regions, segments,
page table, user data and PE/COFF catalogs. It then checks the package's **integrity**
against the stored bytes, without decrypting anything and without modifying the file.

> **What this tool does NOT do:** write to the package, use or look for keys, decrypt
> content, or get around access protection. Every file is opened `rb`. High entropy is
> **never** treated as proof of encryption.

## Confidence labels

Every conclusion carries one of three labels:

- **CONFIRMED**: checked against this package's bytes by a check that has an `id`.
- **INFERRED**: consistent but not proven, or taken from a public source (xvdtool) without local verification.
- **UNKNOWN**: not determined.

## Quick start

Requires Python 3.10+. Run from the repository root.

```bash
# test suite (runs without the real package)
python -I -m pytest -q

# with the real package, also runs the integration tests
XVC_PATH='G:\path\package.xvc' python -I -m pytest -q
# XVC_FULL=1 additionally enables the full ~1.3 GB scans in those tests

# full analysis -> reports in reports/
python -I xvcintel.py analyze PACKAGE.xvc --out reports

# profile of the main executable
python -I xvcintel.py fingerprint PACKAGE.xvc --name game_scarlett_master.exe --json profile.json

# targeted inspections
python -I xvcintel.py header|layout|xvcinfo|files|integrity|pages|userdata PACKAGE.xvc

# other tools
python -I xvcintel.py graph PACKAGE.xvc --out graph.json
python -I xvcintel.py query --graph reports/graph.json --node game_scarlett_master.exe [--relation IMPORTS]
python -I xvcintel.py pe PE_FILE [--json out.json]
python -I xvcintel.py regf HIVE
python -I xvcintel.py regress old.json new.json
```

For a **full** hash of regions and segments above 160 MB, use `--cap-mb` with a high value
(for example, larger than the package). Every subcommand, option and default cost limit is
described in [`docs/README.en.md`](docs/README.en.md).

## Layout

```
src/xvcintel/            library (core, formats, engines, evidence, cli)
scripts/                 compatible wrappers for the original scripts + test_summary.py
                         + bin_pe_recovery.py (PE scanner, work in progress)
legacy/                  untouched copies of the original scripts (compatibility test)
tests/                   pytest suite, synthetic XVC generator (~1 MB), small fixtures
reports/                 output of the last run against the real package
docs/                    detailed documentation (Portuguese and English)
PROJECT_ALPHA_RECOVERY/  shadow PE reconstructor integrated with xvcintel (work in progress)
shadow_pe_reconstructor/ standalone shadow PE reconstructor (work in progress)
```

Dependencies only point inward: `formats` (pure parsers) → `engines` (read the package
only through `ByteSource`) → `evidence` (only consumes results).

## Verification status

Results against the reference package (225,336,647,680 bytes, version 1.0.2.1):

| Check | Coverage | Status |
|---|---|---|
| Layout calculated from the header | Ends exactly at the file size | CONFIRMED |
| Hash tree: top hash and links between levels | All 4 levels verified in full (`--full-leaf`) | CONFIRMED |
| **Region hash** (`SHA-256(region)[:8]`) | **28/28, full coverage** | CONFIRMED |
| **Segment hash** (`SHA-256(segment)[:8]`) | **108/108, full coverage** | CONFIRMED |
| Page table: RLE of data units | All 54,601,906 pages with a KeyId follow the rule | CONFIRMED |
| File mapping | 108/108 files, no overlaps | CONFIRMED |
| Regression against the original JSON report | 108/108 files identical in every field | PASS |

The full hash run read about 440 GB in about 7.4 minutes. The package was left
unchanged, including its modification time.

Report totals: 38 findings (27 CONFIRMED, 3 INFERRED, 8 UNKNOWN) and 35 checks
(29 PASS, 1 PARTIAL, 5 INFO). Tests: **143/143 passing** for the xvcintel suite. 137 run
without the package and 6 are integration tests against the real package.

### Main executable (`game_scarlett_master.exe`)

- **Storage (CONFIRMED):** segment 12, region `0x3E9` (holds only this file), offset
  `0x64917000`, 120,181,760 bytes, KeyId 0. Its region and segment hashes match.
- **Content (not readable):** the stored bytes have no `MZ` header, and entropy is about
  7.997 bits/byte across 16 windows. This is *consistent with* encryption but is not proof
  of it. No internal PE structure can be recovered without the content keys.
- **DLLs in the same package:** 16 DLLs are recorded as present. That alone does
  **not** show that the executable imports them.
- **Code catalog:** `Catalog000.bin` is a readable Xbox code catalog. None of the
  executable's stored hashes appear in it, which is expected if the catalog describes the
  decrypted content.

The PE parser (`formats/pe.py`) is ready and was tested against `pefile`. If a readable
copy of the executable is obtained through a legitimate route, run
`python -I xvcintel.py pe FILE` on it. See [`docs/pe-requisitos.en.md`](docs/pe-requisitos.en.md).

### Still open

- The hash shared by the **XVC-HD / XVC-MD** metadata regions, and the header's
  `OriginalXvcDataHash`, are **UNKNOWN**. Nine candidate ways of computing them were ruled
  out, including xvdtool's `VerifyXvcHash`.
- In segments 78, 90 and 107, the per-segment value does not match the data unit of the
  segment's first page. The cause is UNKNOWN.
- Data units repeat within the same region: 44.2M pages share a value with another page.
  The reason is UNKNOWN.
- The dynamic header (BAT) of the embedded EraOS XVD has not been decoded, so its layout
  does not fully close.

## Audit of the original scripts

The four original scripts were audited. Untouched copies are kept in [`legacy/`](legacy/).
The fixes:

- **Wrong mutable-data offset.** `xvc_probe.py` read MutableDataPageCount at `0x5E0`,
  which holds 0. The correct offset is `0x470`. A silent layout adjustment had been
  hiding the error; a mismatch now reports a FAIL instead.
- **Hard-coded drive offset.** `pfx_locate.py` used a fixed drive offset. Every offset is
  now calculated from the header.
- **Unsafe hive parsing.** `regf_dump.py` had no bounds checks and its recursion had no
  depth limit. Both are fixed.
- **Missing hash checks.** Region, segment and hash-tree checks did not exist before and
  have been added.
- **No tests.** There were no automated tests before; there are now 143.

The compatibility wrappers in `scripts/` keep the original command-line options, exit codes
and JSON report keys (schema 1). Details: [`docs/auditoria.en.md`](docs/auditoria.en.md).

## PE recovery tooling (work in progress, not yet committed)

All three tools follow the same rules as the rest of the project: read-only input, no
decryption or key handling, no made-up bytes, new output files only, and recovered binaries
are never executed. None of them can recover data from encrypted regions.

| Tool | What it is | Results so far |
|---|---|---|
| [`scripts/bin_pe_recovery.py`](scripts/xvc_pe_recovery_upgrade/README.en.md) | Scanner that finds PE32/PE32+ at any offset, including inside gzip, XZ, bzip2, ZIP, LZ4, Zstandard and (opt-in) zlib streams. 13 tests pass | `ex_userdata.bin` (33 MB): 504 raw `MZ` hits, **0 valid PE**; `bat.bin` (4 KB): **0 valid PE**; deep zlib pass: 128 streams, 0 PE |
| [`PROJECT_ALPHA_RECOVERY/`](PROJECT_ALPHA_RECOVERY/README.en.md) | Modular pipeline built on xvcintel: inventory, locate, carve, experiments with negative controls, byte-range provenance map, validation | Not yet run on real data (`reports/shadow_pe/` is empty) |
| [`shadow_pe_reconstructor/`](shadow_pe_reconstructor/README.en.md) | Single-file standalone version (standard library only). 18 synthetic tests | Example run on 3 sample files (all fully scanned): `NO_RECOVERABLE_PE_OBSERVED` |

Only run these tools on artifacts whose origin is documented and legitimate.

## Documentation

Each document exists in Portuguese (`.md`) and English (`.en.md`).

| Topic | Português | English |
|---|---|---|
| Detailed usage, architecture and cost limits | [docs/README.md](docs/README.md) | [docs/README.en.md](docs/README.en.md) |
| The XVD/XVC format as decoded here | [docs/formato.md](docs/formato.md) | [docs/formato.en.md](docs/formato.en.md) |
| What is needed to analyse the internal PE | [docs/pe-requisitos.md](docs/pe-requisitos.md) | [docs/pe-requisitos.en.md](docs/pe-requisitos.en.md) |
| Audit of the original scripts | [docs/auditoria.md](docs/auditoria.md) | [docs/auditoria.en.md](docs/auditoria.en.md) |
| Full integrity check | [docs/resumo-hashes-completos.md](docs/resumo-hashes-completos.md) | [docs/resumo-hashes-completos.en.md](docs/resumo-hashes-completos.en.md) |
| PE scanner (`bin_pe_recovery.py`) | [README.md](scripts/xvc_pe_recovery_upgrade/README.md) | [README.en.md](scripts/xvc_pe_recovery_upgrade/README.en.md) |
| Shadow PE reconstructor (modular) | [README.md](PROJECT_ALPHA_RECOVERY/README.md) | [README.en.md](PROJECT_ALPHA_RECOVERY/README.en.md) |
| Shadow PE reconstructor (standalone) | [README.md](shadow_pe_reconstructor/README.md) | [README.en.md](shadow_pe_reconstructor/README.en.md) |

## License and use

This is a local research project. The fixtures in `tests/fixtures/` are small extracts of
the analysed package and are included only for the test suite. Review them before
redistributing anything.
