# PROJECT_ALPHA — Hunt for authorized original-build artifacts (exe + PDB)

> English version of `RELATORIO_TECNICO.md`.

**Date:** 2026-11-22 · **Tool:** `hunt-artifacts` (`correlation/artifact_hunt.py`) · **Regression:** 188 passed
**Report:** `artifact_hunt_report.json` — SHA-256 `1294fb3058be7cf7d734e55cf0b0112f368dd341037824ebf36925283bf4e8ff`

## Scan

287,860 files across the project's authorized roots (`PROJECT_ALPHA`, `PROJECT_ALPHA_INTEGRATION`, `PROJECT_RECOVERY`, `recovery`, `original`, `estudos`, `Leonida_work`, `XboxBvhBuilder_estudo`, `anonymization`, the xvc-intelligence repository). Third-party tool repositories (AnyPS5, radeon_gpu_analyzer, WinDurango, wt-imhex, wt-trace) excluded by documented decision — they are tools, not project artifacts.

## Systematic result — DEFINITIVELY NEGATIVE (with proof)

| Front | Finding | Evidence |
|---|---|---|
| **PDB of the original executable** | **NONEXISTENT in the authorized environment** | 184 PDBs recorded with real GUID/age from the info stream; **none** with a name tied to the target; **zero** RSDS in 570 PEs pointing to any `game_scarlett_master.pdb` — an authentic build PE would carry that reference |
| **Plaintext executable** | **NONEXISTENT** | the only candidate with the target name = the encrypted copy (120,184,832 B, no MZ, provenance proven = stored XVC bytes + page slack) |
| Proven PE↔PDB pairs | **289 pairs by GUID+age** — all from **prior sessions' reconstructions or tools** (platform_master, alpha_bootstrap, build_script, CMake probes, study DLLs) | pairwise `GUID_AGE_MATCH` verification |
| References to the target | 170 — **all reports/configs/fixtures**, plus: the `.cpp/.obj` of the `reconstructed_engine` prototype (an explicit prior reconstruction), a dashboard `.ts` test, and our own synthetic fixtures | none is original build material |

**Proven conclusion:** nowhere in the authorized environment is there a plaintext executable or PDB/symbols of the original build. What existed as a "reconstructed executable" is a product of prior sessions and is correctly labeled as such. Recovery remains blocked on **both** sides, now both systematically demonstrated:

1. **CIK for region 0x3E9** — absent (reproducible lab ready; `BLOCKED_MISSING_AUTHORIZED_CIK`);
2. **A legitimate external artifact** — nonexistent in the environment (this hunt).

## Next actionable step (external, the only path left)

Obtain from the holder/authorized channel **any one** of: (a) a decrypted copy of the executable; (b) a development build 1.0.2.1; (c) the corresponding PDB; (d) a CIK through an authorized channel. The intake chain is ready and tested end to end (blind lab state C):

```powershell
# when an authorized executable candidate arrives:
python recovery\project_alpha\shadow_pe_reconstructor.py reconstruct `
  --xvc "G:\MyGame_v1\28872443D20A7_1.0.2.1_neutral__k2ss7vbb13xte_xs.xvc" `
  --disk "<artifact_folder>" --target game_scarlett_master.exe `
  --out reports\intake_exe --provenance "documented custody"

# when a PDB candidate arrives: validate GUID/age against the executable's RSDS:
python recovery\project_alpha\shadow_pe_reconstructor.py identity --xvc <XVC> --disk <folder> `
  --target game_scarlett_master.exe --out reports\intake_pdb `
  --pdb-pair "<exe>=<pdb>"

# when an authorized CIK arrives:
python recovery\project_alpha\shadow_pe_reconstructor.py decrypt --xvc <XVC> `
  --target game_scarlett_master.exe --out reports\intake_cik `
  --cik-file <cik.bin> --cik-sha256 <hex> --provenance "custody"

# re-validate the environment at any time:
python recovery\project_alpha\shadow_pe_reconstructor.py hunt-artifacts <roots> --out reports\artifact_hunt
```

**Criteria unchanged:** `COMPLETE_VERIFIED` requires an exact size of 120,181,760 B + a valid PE32+ x64 + a hash (Authenticode/raw) in `Catalog000.bin` + GUID/age consistent with a PDB (if any) + documented custody. Name/size/version coincidences remain insufficient; no byte is fabricated; originals intact.
