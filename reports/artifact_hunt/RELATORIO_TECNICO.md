# PROJECT_ALPHA — Caça a artefatos autorizados da build original (exe + PDB)

**Data:** 2026-11-22 · **Ferramenta:** `hunt-artifacts` (`correlation/artifact_hunt.py`) · **Regressão:** 188 aprovados
**Relatório:** `artifact_hunt_report.json` — SHA-256 `1294fb3058be7cf7d734e55cf0b0112f368dd341037824ebf36925283bf4e8ff`

## Escaneamento

287.860 arquivos nas raízes autorizadas do projeto (`PROJECT_ALPHA`, `PROJECT_ALPHA_INTEGRATION`, `PROJECT_RECOVERY`, `recovery`, `original`, `estudos`, `Leonida_work`, `XboxBvhBuilder_estudo`, `anonymization`, repositório xvc-intelligence). Repositórios de ferramentas de terceiros (AnyPS5, radeon_gpu_analyzer, WinDurango, wt-imhex, wt-trace) excluídos por decisão documentada — são ferramentas, não artefatos do projeto.

## Resultado sistemático — DEFINITIVO NEGATIVO (com prova)

| Frente | Achado | Evidência |
|---|---|---|
| **PDB do executável original** | **INEXISTENTE no ambiente autorizado** | 184 PDBs registrados com GUID/age reais do info stream; **nenhum** com nome ligado ao alvo; **zero** RSDS em 570 PEs apontando para qualquer `game_scarlett_master.pdb` — um PE autêntico da build carregaria essa referência |
| **Executável em plaintext** | **INEXISTENTE** | único candidato com nome do alvo = a cópia cifrada (120.184.832 B, sem MZ, proveniência provada = bytes gravados do XVC + page slack) |
| Pares PE↔PDB comprovados | **289 pares por GUID+age** — todos de **reconstruções de sessões anteriores ou ferramentas** (platform_master, alpha_bootstrap, build_script, probes CMake, DLLs de estudo) | verificação `GUID_AGE_MATCH` par a par |
| Referências ao alvo | 170 — **todas relatórios/configs/fixtures**, mais: o `.cpp/.obj` do protótipo `reconstructed_engine` (reconstrução anterior explícita), um teste `.ts` do dashboard, e fixtures sintéticas nossas | nenhuma é material de build original |

**Conclusão comprovada:** não há, em lugar nenhum do ambiente autorizado, executável em plaintext nem PDB/símbolos da build original. O que existia de "executável reconstruído" é produto de sessões anteriores e está corretamente rotulado como tal. A recuperação permanece bloqueada pelos **dois** lados, agora ambos sistematicamente demonstrados:

1. **CIK da região 0x3E9** — ausente (laboratório reproduzível pronto; `BLOCKED_MISSING_AUTHORIZED_CIK`);
2. **Artefato legítimo externo** — inexistente no ambiente (esta caça).

## Próximo passo acionável (externo, único caminho restante)

Obter do detentor/canal autorizado **qualquer um** de: (a) cópia decifrada do executável; (b) build de desenvolvimento 1.0.2.1; (c) PDB correspondente; (d) CIK por canal autorizado. A cadeia de intake está pronta e testada end-to-end (laboratório cego estado C):

```powershell
# ao receber um candidato a executavel autorizado:
python recovery\project_alpha\shadow_pe_reconstructor.py reconstruct `
  --xvc "G:\MyGame_v1\28872443D20A7_1.0.2.1_neutral__k2ss7vbb13xte_xs.xvc" `
  --disk "<pasta_do_artefato>" --target game_scarlett_master.exe `
  --out reports\intake_exe --provenance "custodia documentada"

# ao receber um PDB candidato: validar GUID/age contra o RSDS do executavel:
python recovery\project_alpha\shadow_pe_reconstructor.py identity --xvc <XVC> --disk <pasta> `
  --target game_scarlett_master.exe --out reports\intake_pdb `
  --pdb-pair "<exe>=<pdb>"

# ao receber uma CIK autorizada:
python recovery\project_alpha\shadow_pe_reconstructor.py decrypt --xvc <XVC> `
  --target game_scarlett_master.exe --out reports\intake_cik `
  --cik-file <cik.bin> --cik-sha256 <hex> --provenance "custodia"

# revalidar o ambiente a qualquer momento:
python recovery\project_alpha\shadow_pe_reconstructor.py hunt-artifacts <raizes> --out reports\artifact_hunt
```

**Critérios inalterados:** `COMPLETE_VERIFIED` exige tamanho exato 120.181.760 B + PE32+ x64 válido + hash (Authenticode/bruto) no `Catalog000.bin` + GUID/age coerentes com PDB (se houver) + custódia documentada. Coincidências de nome/tamanho/versão continuam insuficientes; nenhum byte é fabricado; originais intactos.
