# PROJECT_ALPHA — Relatório técnico final da Shadow PE Reconstruction

**Idioma / Language:** Português · [English](TECHNICAL_REPORT.en.md)

**Alvo:** `game_scarlett_master.exe` (Xbox Series X|S / Scarlett, pacote 1.0.2.1)
**Data da análise:** 2026-11-22 · **Classificação final: `METADATA_ONLY`**
**Ferramenta:** `recovery/project_alpha/shadow_pe_reconstructor.py` (+ módulos scanners/correlation/reconstruction/validation), construída sobre `xvcintel` e `bin_pe_recovery`, somente leitura.

---

## 1. Resposta direta à pergunta central

> *Quanto do executável original pode ser recuperado?*

| Classe | Bytes | % do alvo (120.181.760) | Base |
|---|---:|---:|---|
| `EXACT_RECOVERED` (plaintext com prova) | **0** | 0,000000 | nenhum byte legível existe em nenhuma cópia |
| `MATCHED_COPY` de **plaintext** | **0** | 0,000000 | idem |
| `STRUCTURAL_INFERENCE` (bytes) | 0 | 0,000000 | nenhuma estrutura PE observável para inferir layout byte a byte |
| `ENCRYPTED_UNKNOWN` | 120.181.760 | 100,000000 | região KeyId 0 no XVC; sem MZ; entropia ~7,997; dois testemunhos independentes |
| `MISSING` / `CONFLICTING` | 0 | 0 | — |

**Proveniência dos bytes GRAVADOS (ciphertext), separada e nunca somada como recuperação:** a cópia em disco
(`PROJECT_ALPHA\game_scarlett_master.exe`, 120.184.832 bytes) é **100% idêntica** aos bytes gravados no XVC
(29/29 blocos de 4 MiB) — experimento E1, com controle negativo 0/29. Os 3.072 bytes de cauda excedentes
não têm origem comprovada (entropia 7,94; não-zeros) e ficam registrados como `UNVERIFIED` na proveniência.

**O que foi plenamente recuperado (metadados, CONFIRMADO):**
- Nome, ID de aplicação, plataforma (`MicrosoftGame.Config` + `appxmanifest.xml` + hive + layout XVC, 4 fontes consistentes);
- Versão do pacote 1.0.2.1 (cabeçalho XVC 0x3BC == `Identity@Version`);
- Localização exata no contêiner: XVC segmento 12, região 0x3E9, offset `0x64917000`, 120.181.760 bytes, 29.342 páginas, KeyId 0;
- Hash dos bytes gravados: SHA-256 `79fe1510…dba89a` (identifica o ciphertext, não o PE);
- Arquitetura esperada: x64/PE32+ — **INFERIDO** (plataforma Scarlett + as 16 DLLs distribuídas são PE32+ AMD64 CONFIRMADAS nos bytes em disco); cabeçalho do alvo nunca observado;
- Subsistema, seções, imports, entry point, PDB: **UNKNOWN** (não observáveis; PDB/MAP/OBJ/ILK inexistentes no conjunto sobrevivente).

**Impedimento real:** o conteúdo está protegido por AES-XTS (região KeyId 0) e a chave de conteúdo não está
disponível. Sem ela, **nenhum byte de código ou dado do executável é recuperável** — bloqueio criptográfico,
não limitação de ferramenta. Não houve tentativa de descriptografia, derivação de chave, força bruta ou bypass
de integridade (regras absolutas da missão, cumpridas). `reconstructed.exe` **não foi gerado** porque não há
bytes suficientes comprovados; `shadow_pe_partial.bin` **não foi gerado** porque não há nenhum byte de
plaintext para registrar (preenchimento artificial não é recuperação).

## 2. Inventário (Fase 1) — `binary_inventory.json`

369 arquivos / 449,7 GB varridos (raízes: `G:\MyGame_v1\PROJECT_ALPHA` + o XVC de 225 GB), com cache por
(caminho, tamanho, mtime) — retomável. Política: SHA-256 completo ≤ 8 GiB; acima disso, hash head+tail de
16 MiB **rotulado como parcial** (nunca apresentado como hash completo). Formatos: 33 MZ (PEs válidos em
disco: 16 DLLs do pacote, catálogo, ferramentas de sessões anteriores), 2 MSFT-XVD (o XVC e `gameos.xvd`),
1 REGF (hive do gameconfig), 3 XML, 25 PNG, 305 `unknown_bin` (RPFs e blobs cifrados/opacos).

## 3. Localização do executável (Fase 2) — `executable_candidates.json`

27 candidatos com fonte, evidência, tamanho **conhecido** (nunca estimado como confirmado) e estado:

- `game_scarlett_master.exe` — **CONFIRMADO, alvo** — `ENCRYPTED_UNKNOWN` no XVC **e** cópia em disco opaca;
- 16 DLLs distribuídas — CONFIRMADAS no XVC como opacas (KeyId 0); **cópias em disco são PEs legíveis** (`PLAINTEXT_AVAILABLE_EM_DISCO`) — dependências recuperáveis, **não** evidência de import do alvo;
- `platform_master.exe`, `alpha_*.exe`, CMake probes, `sample_module.dll` — **ferramentas de reconstrução de sessões anteriores**, plaintext em disco, explicitamente **não são o executável original** (o `platform_master` se autodescreve como runtime de porta, RSDS/GUID próprios, ver `G:\MyGame_v1\PROJECT_ALPHA_INTEGRATION\exe_reconstruction`);
- Strings brutas (`.ExE`, `run GamingRepair.exe`, …) — UNKNOWN, só referências de texto.

*Correção registrada:* a v1 deste JSON rotulava as cópias plaintext como UNKNOWN; regenerada com estados
corretos, versão anterior preservada em `executable_candidates.v1.json`.

## 4. Fragmentos recuperados (Fase 3) — `recovered_fragments/` + `carve_fragment_manifest.json`

33 fragmentos extraídos com gravacao exclusiva e proveniência completa (origem, offset, SHA-256,
transformação): 16 DLLs legíveis, `Catalog000.bin` (PE `XBOX_CODE_CATALOG`, máquina 0x8664, **validado
independentemente** — `catalog_pe_validation.json`: `valid=True`) e as ferramentas de sessões anteriores.
Carving estrito: `MZ` sozinho nunca aceito (validação de `e_lfanew`, `PE\0\0`, COFF, Optional Header,
Section Table contra limites físicos). **Nenhum fragmento do alvo.** Fluxos comprimidos: nenhum decode
legítimo nos artefatos do alvo (magics sem decodificação bem-sucedida não são compressão).

## 5. Experimentos (Fase 6) — `experiments.json` (com hipótese, base, dados, resultado, controle negativo, limitações e conclusão)

| ID | Resultado | Controle negativo |
|---|---|---|
| **E1** redundância entre contêineres | disco == XVC: **100%** (29/29 blocos de 4 MiB; cauda 3.072 B opaca sem origem) | região deslocada +4 GiB no XVC: **0%** (0/29) |
| **E1b** catálogo legível | disco == região legível do XVC (KeyId 0xFFFF): **100%** | região deslocada: ~0% |
| **E6** diferencial DLL | plaintext em disco × região XVC (KeyId 0): **0%** — conteúdo XVC é ciphertext; **nenhuma** alegação de falha criptográfica | arquivo contra ele mesmo: 100% (sanidade do comparador) |
| **E3** assinaturas estruturais | **negativo confirmado**: nenhum PE válido em nenhuma cópia do alvo | sintéticos s01 (1 PE) / s04 (MZ falso → 0) |

Comparação entre builds (E2): indisponível — os rar de `original/` não contêm build anterior utilizável;
nenhuma outra versão do pacote existe no conjunto. Resultado negativo registrado.

## 6. Mapa shadow PE (Fase 4) — `shadow_pe_map.json` / `shadow_pe_report.html` / `recovery_provenance.json`

Intervalo único `[0x0, 0x729D400)` = 120.181.760 bytes, classe `ENCRYPTED_UNKNOWN`, evidência: segmento 12 /
região 0x3E9 / KeyId 0 / F-EXE-01..04 + igualdade de bytes gravados E1. Zero conflitos. Proveniência
registra também os 29 blocos `MATCHED_COPY` de **ciphertext** (rotulados como tal) e a cauda `UNVERIFIED`.

## 7. Validação independente (Fase 7)

- `Catalog000.bin`: válido (MZ, PE\0\0, COFF/Optional coerentes, seção dentro do arquivo, `xvcintel deep-parse` sem problemas);
- Suíte sintética (14 cenários obrigatórios): **156 testes aprovados** no repo (19 do shadow PE: PE no início,
  embutido, truncado, MZ falso, aleatório, comprimido, multi-contêiner, duplicação parcial, conflito de
  evidência com resolução correta, entropia alta sem PE, arquivo maior que a memória via streaming, recusa de
  sobrescrita, interrupção+retomada via cache, round-trip contra original sintético conhecido com
  classificação `COMPLETE_VERIFIED`);
- Selftest CLI: **21/21**.
- Nenhum binário foi executado.

## 8. Comandos PowerShell (reprodução)

```powershell
# suite de testes completa (sinteticos; nao toca nos artefatos reais)
python -I -m pytest -q
python recovery\project_alpha\shadow_pe_reconstructor.py selftest

# pipeline completo contra os artefatos reais (somente leitura; saida nova obrigatoria)
python recovery\project_alpha\shadow_pe_reconstructor.py run-all `
    --xvc  "G:\MyGame_v1\28872443D20A7_1.0.2.1_neutral__k2ss7vbb13xte_xs.xvc" `
    --disk "G:\MyGame_v1\PROJECT_ALPHA" `
    --target game_scarlett_master.exe `
    --out  "reports\shadow_pe_final2"

# passos individuais
python recovery\project_alpha\shadow_pe_reconstructor.py inventory "G:\MyGame_v1\PROJECT_ALPHA" --out reports\inv
python recovery\project_alpha\shadow_pe_reconstructor.py locate --xvc <XVC> --disk <DIR> --out reports\inv
python recovery\project_alpha\shadow_pe_reconstructor.py carve <DIR_OU_ARQUIVO> --out reports\carve
python recovery\project_alpha\shadow_pe_reconstructor.py experiments --xvc <XVC> --disk <DIR> --out reports\exp
python recovery\project_alpha\shadow_pe_reconstructor.py reconstruct --xvc <XVC> --disk <DIR> --out reports\mapa
python recovery\project_alpha\shadow_pe_reconstructor.py validate <PE> --machine 0x8664
```

Observação: `--out` nunca pode ficar dentro da pasta de um artefato original (guarda de segurança);
reexecuções no mesmo diretório são recusadas (saídas exclusivas, sem sobrescrita) — use um diretório novo
ou apague **somente** saídas geradas por você.

## 9. Arquivos deste relatório

| Arquivo | Conteúdo |
|---|---|
| `binary_inventory.json` | inventário dos 369 arquivos (hash, entropia, assinaturas, política) |
| `artifact_index.json` | duplicações exatas por SHA-256 |
| `executable_candidates.json` (+ `.v1.json`) | 27 candidatos com fontes e estados (v1 preservada) |
| `carve_report.json` … `carve_provenance.json`, `carve_fragment_manifest.json` | carving + proveniência dos 33 fragmentos |
| `experiments.json` | E1/E1b/E6/E3 com controles negativos |
| `shadow_pe_map.json` | mapa de intervalos do alvo com evidências |
| `shadow_pe_report.html`, `shadow_pe_report_data.json` | relatório visual + dados completos |
| `metrics.json` | métricas separadas por classe (nunca somando prova com inferência) |
| `recovery_provenance.json`, `fragment_manifest.json` | proveniência do mapa (MATCHED_COPY de ciphertext rotulado, cauda UNVERIFIED) |
| `catalog_pe_validation.json` | validação independente do catálogo legível |

## 10. Impedimentos reais e próximos passos justificáveis

1. **Chave de conteúdo AES-XTS indisponível** — bloqueia todo o plaintext do alvo. A recuperação do código
   só é possível com um artefato legítimo: build de desenvolvimento do detentor, PDB correspondente, ou cópia
   decifrada por processo autorizado (com proveniência documentada — ver `docs/pt/pe-requisitos.md`).
2. Cauda de 3.072 bytes da cópia em disco: origem UNKNOWN; nada pode ser afirmado além do registrado.
3. `gameos.xvd` (EraOS, StandardOdk): cifrado, fora do escopo do executável; intocado.
4. Experimentos futuros justificáveis **sem chave**: (a) se um PDB do alvo aparecer, extrair layout de
   seções/funções e cruzar com o tamanho CONFIRMADO de 120.181.760 bytes; (b) comparar com outra versão do
   pacote se algum dia disponível (análise estrutural de reuso de unidades de dados, sem revelar plaintext);
   (c) manter o catálogo legível como referência de verificação caso um PE candidato surja (hoje a busca pelos
   hashes dos bytes gravados nele é negativa — F-EXE-04 — o que é esperado, pois o catálogo descreve o
   conteúdo decifrado).

**Regras absolutas cumpridas:** originais intactos (tudo `rb`); XVD/XVC não modificados; nada descriptografado;
nenhum byte fabricado; resultados negativos registrados com a mesma força dos positivos; hipóteses nunca
apresentadas como fatos.
