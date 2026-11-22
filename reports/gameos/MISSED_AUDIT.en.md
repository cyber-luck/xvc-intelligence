# Retrospective audit — what went unnoticed and what was verified now

> English version of `AUDITORIA_DESPERCEBIDOS.md`.

**Date:** 2026-11-22 · All checks below were performed now, read-only.

## Overlooked items that were UNREPORTED FACTS (now verified)

| # | Item | Check performed now | Result |
|---|---|---|---|
| 1 | **`Summary.json` in the XVC user data (204 B) — never opened by any phase** | direct dump | **`GDKVersion: "10.0.26100.7822"`** + flags: IntelligentDelivery=false, InstallFeatures/Recipes=false, **SupportsDefaultEnableMods=true**. It is the first direct evidence of the **GDK version** used in packaging — pipeline metadata missing from the identity report. `Metadata.json` = `{}` empty. |
| 2 | **`gameos.xvd` provenance never linked to the XVC** | byte-for-byte comparison of the embedded `XVC-EXVD` region × the on-disk file | **RESOLVED: identical** — same size (0x14BF2000), same VDUID/build, **332/332 blocks of 1 MiB equal, zero divergence**. The on-disk gameos.xvd is the **extraction of the EraOS volume embedded in the XVC itself** (region 0x3000..0x14BF5000). We had analyzed the volume in isolation; the link to the package was unnoticed. |
| 3 | **XVC-MDU page (mutable data, 1 page) never examined** | dump | 31 non-zero bytes, all `0x03`, the rest zeros — trivial mutable-data content, now documented. |
| 4 | **On-disk configs × configs INSIDE the XVC never differentiated** | byte-for-byte diff (3 files) | **Identical** (MicrosoftGame.Config, appxmanifest.xml, microsoft_gameconfig.bin) — the disk copies are faithful to the embedded ones; the concern about "post-factory edits" does not apply to the current state. |
| 5 | **Page 0 of `Catalog000.bin` (64 B) never decoded** | dump + 3 hash hypotheses | 64 apparently random bytes; **not** the SHA-256 of the section, of the whole catalog, nor of the exe's stored bytes → function **UNKNOWN** (hypotheses refuted and documented). |
| 6 | **Signature state of the 16 DLLs never checked** | security directory parse | **None** of the 16 has an embedded security dir (no in-file Authenticode) — consistent with console packaging: code integrity lives in the hash tree + package catalog, not per file. |

## Conceptual oversight (partially characterized now)

**The provenance of the plaintext DLLs.** The game folder is **hybrid**: readable DLLs + encrypted exe — so it is **neither** a pure XVC extraction (everything would come encrypted) nor a pure console install (everything would come decrypted). New checks: the CRTs are **not** the public Windows desktop copies (distinct hashes — console/onecore-xbox builds) and no DLL carries an embedded signature. Reinforced conclusion: the plaintext material came from a **console/devkit environment**, assembled from ≥2 sources — the exact origin remains **UNKNOWN** and is the only provenance gap in the on-disk set.

## Already covered (nothing new, confirmed)

3,072 B tail (page slack, proven), `data_unit` (full audit of 29,342 leaves), hash of the stored bytes, the XVC's zero KeyMaterial × the gameos non-zero one, StandardOdk × regional-key differentiation — all already documented in earlier phases.

## Open items that remain UNKNOWN (no guess)

1. Function of the 64 B of catalog page 0;
2. Shared XVC-HD/XVC-MD hash (unknown serialization; earlier hypotheses refuted);
3. Exact origin of the console DLLs' plaintext copies;
4. `PECatalogHash` (gameos and title): candidate serializations refuted.

## Practical consequence

Item 1 (GDK 10.0.26100.7822) should enter the `identity_report` as pipeline evidence; item 2 closes the provenance of gameos.xvd (it is not an orphan artifact — it is part of the XVC); none of this changes the central block (CIK absent; no authorized build artifact exists in the environment).
