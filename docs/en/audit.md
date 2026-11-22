# Audit of the existing scripts (Stage 1)

**Language / Idioma:** English · [Português](../pt/auditoria.md)

Scripts audited (untouched copies in `legacy/`): `xvc_probe.py` (940 lines), `pe_check.py` (192), `regf_dump.py` (81), `pfx_locate.py` (75).

## Feature matrix

| Script | Feature | State at audit | Problems found | Existing tests | Improvement made (where) |
|---|---|---|---|---|---|
| xvc_probe.py | XVD header reading | Worked for the basic fields | Read the MDU at **0x5E0** (value 0). The correct offset is **0x470** (MutableDataPageCount, xvdtool +0x270). With MDU = 0 the calculated XvcInfo landed one page early and was found only by the anchor search | None | `formats/xvd_header.py`: full header up to 0x1000, with a field table and absolute offsets. The MDU comes from 0x470 and is checked against XVC-MDU (`layout.mdu_vs_region`) |
| xvc_probe.py | Layout (xvdtool) | Correct after the adjustment using the XVC-MD region | The after-the-fact adjustment (`extra_ht_pages`) masked the MDU error | None | `formats/layout.py`: layout calculated only from the header; a mismatch now becomes a FAIL instead of a silent adjustment |
| xvc_probe.py | XvcInfo anchor (ContentID == VDUID) | Worked | It was the primary source of the offset; now it is only a check | None | `engines/package.py`: checks the anchor at the calculated offset. The ±radius search runs only as a fallback and is marked FAIL |
| xvc_probe.py | Regions, segments, per-segment array, (PageNum, Value) table | Worked | `UnknownD50` is `RegionSpecifierCount` in xvdtool. The position of the array and the table depends on there being no specifiers, and that was not checked | None | `formats/xvcinfo.py`: dataclasses, `Result`, and refuses to decode what follows the segments if `RegionSpecifierCount > 0` |
| xvc_probe.py | User data, SegmentMetadata, file map | Worked (108/108) | `decode_*` returned (dict, error) tuples, untyped | None | `formats/userdata.py`, `formats/filemap.py` (same check names, to keep the JSON compatible) |
| xvc_probe.py | JSON report (schema 1) | Worked | None | None | `evidence/reports.py::files_report`. Regression: 108/108 files identical in every field (`reports/regression.json`) |
| xvc_probe.py | Classification by signature and entropy | Worked | None. The rules were kept unchanged | None | `engines/profiler.py` |
| xvc_probe.py | String scan and entropy map | Worked | Duplicated "phase 4" header; `f.seek` scattered through the code | None | `scripts/xvc_probe.py` (wrapper with the same options) |
| xvc_probe.py | Region/segment hash | **Missing** (it only compared the region hash with the segment hash) | None | None | `engines/integrity.py`: SHA-256 of the stored bytes, with a configurable limit |
| xvc_probe.py | Hash tree | **Missing** (it only calculated the size) | None | None | `formats/hashtree.py` and `engines/integrity.py`: top, links between levels, leaves |
| pe_check.py | MZ, e_lfanew, COFF, optional header, Machine×magic, sections, alignment | Worked. 30 synthetic fixtures in `pe_tests/` | Module-level script (no functions), reads the whole file, stops at the first error, no data directories, imports, exports, resources, debug or security | Fixtures without automated assertions | `formats/pe.py`: full parser with `Result`; the 30 fixtures were ported to `tests/test_pe.py` with the original's expected result; compared with `pefile` on 5 Windows PEs |
| regf_dump.py | regf hive reading | Worked | No bounds checks (asserts, `IndexError` on a corrupt hive), unbounded recursion in `ri` | None | `formats/regf.py`: every cell checked, depth limited, errors become `Err` |
| pfx_locate.py | Locate a file in the PFX | Worked for this package | **Fixed DRIVE_OFFSET (0x63BCB000)**, fixed relative path, only checks `HeaderSize == 0x64` | None | Replaced by `fingerprint` / `files --list`, with the offset calculated from the header |

## Cross-cutting problems and fixes

1. **Fixed offsets** (rule 3): `pfx_locate.py` used a fixed `DRIVE_OFFSET`. Now every offset comes from the header. The test `test_layout_reproduces_real_offsets_from_header_values` recalculates all real offsets from the field values alone.
2. **Reading**: the package was always opened `rb`. This is now enforced by `core/reader.FileSource`, which has no write method and refuses single reads above 256 MB (`ReadLimitError`). Large hashes are streamed in 16 MB blocks.
3. **Errors**: malformed inputs become `Err(ParseError)` with a type (`truncated`, `bad_magic`, `out_of_bounds`, `inconsistent`, `invalid_value`, `unsupported`).
4. **Outputs**: `guard_output` refuses to write inside the package's folder.
5. **Tests**: there were no automated tests before. There are now 143 pytest tests: 137 without the package and 6 integration tests against the real package, enabled by the XVC_PATH variable.

## Compatibility

- `scripts/xvc_probe.py` accepts the same options (`--mdu-pages`, `--anchor-radius`, `--skip-scan`, `--scan-end`, `--window`, `--stride`, `--threshold`, `--max-gap`, `--dump`, `--list-files`, `--extract-userdata`, `--json-report`). The text output was reorganized but keeps the same blocks.
- `--json-report` has the same keys (schema 1). The only value difference: `source.drive_data_offset_source` now describes the correct source (0x470). With `keep_legacy_source_note=True`, the report is byte-for-byte identical in its fields (test `test_all_108_files_and_regression`).
- `scripts/pe_check.py` and `scripts/regf_dump.py` keep their exit codes: 0 when the PE is consistent, 1 when it is inconsistent or not a PE.
