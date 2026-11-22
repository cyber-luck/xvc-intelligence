# Full verification of region and segment hashes

**Language / Idioma:** English · [Português](../pt/resumo-hashes-completos.md)

**Date:** 2026-11-22 · **Mode:** read-only · **Package untouched** (225,336,647,680 bytes, mtime unchanged)

## What was done

The hashes of **all** regions and segments were recalculated **from scratch** from the bytes stored in the package. This includes the ones previously labelled **INFERRED** because they were above the 160 MB sampling limit. About 440 GB were streamed (≈218 GB of regions + ≈218 GB of segments) in about 7.4 minutes. Nothing was decrypted: only `SHA-256` of the bytes as stored.

- **Region rule:** the 8-byte hash at `+0x60` of the region header == `SHA-256(stored bytes of the region)[:8]`
- **Segment rule:** the 8-byte hash of the *update segment* (`+4`) == `SHA-256(segment pages up to the next segment / end of the region)[:8]`

## Result

| | Tested | Match | Skipped | Status |
|---|---:|---:|---:|---|
| **Regions** | 28 | 28 | 0 | PASS |
| **Segments** | 108 | 108 | 0 | PASS |

**Zero failures.** The rule, previously confirmed only by sample (13 regions / 49 segments), is now proven at **100% coverage**.

### Large items that were INFERRED (now CONFIRMED)

15 regions and 59 segments above 160 MB. A sample of the largest (all `stored == computed`):

| Region | Size | Hash | | Segment | Size | Hash |
|---|---:|---|---|---|---:|---|
| 0x3F1 | 70.92 GB | `417534028103e399` | | seg 80 | 70.92 GB | `417534028103e399` |
| 0x3EB | 56.82 GB | `1627e371f340c8d0` | | seg 84 | 26.58 GB | `766ce6474daae458` |
| 0x3F5 | 26.58 GB | `766ce6474daae458` | | seg 89 | 18.65 GB | `bd4924ed70abd014` |
| 0xBB8 | 19.58 GB | `d013dedbfc0713a2` | | seg 76 | 8.23 GB | `6fb1b7d6afa17742` |
| 0x3ED | 8.23 GB | `6fb1b7d6afa17742` | | seg 98 | 7.73 GB | `380d660d1d91f5d6` |

Full table of all 28 regions and 108 segments (with `stored`/`computed`/`match`): `reports/full_hashes_result.json`.

## Still UNKNOWN (because of the rule, not the size)

Three metadata regions do **not** use `SHA-256` of their own bytes, so they are outside this method:

- `0x40000005` **XVC-HD**, `0x40000001` **XVC-MD**, `0x40000006` **XVC-MDU**

The hash shared by XVC-HD/XVC-MD remains **UNKNOWN**. The 9 candidate serializations (including xvdtool's `VerifyXvcHash`) are still ruled out. It is the only open item of structural integrity.

## Effect on the reports

- `reports/findings.json`: `integrity.region_hash` and `integrity.segment_hash` went `PARTIAL → PASS` with "full" coverage. Findings **F-RG-01** and **F-SG-01** now read 28/28 and 108/108, 0 skipped (check summary: PASS 27→29, PARTIAL 3→1).
- `reports/executable_profile.json`: new `integrity.rule_coverage_whole_package` (CONFIRMED), recording that the executable's hash rule holds for 100% of the package, not only for items ≤ 160 MB.
- `reports/full_hashes_result.json`: raw evidence from the full run.

## Note

The executable `game_scarlett_master.exe` (segment 12, 120,181,760 bytes) was already below the limit, so its region/segment hash was always CONFIRMED. What this run adds is proof that the **whole** integrity structure of the package checks out: no item depends on size-based inference any more.
