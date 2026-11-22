# PROJECT_ALPHA: relatório técnico da Shadow PE Reconstruction (execução 2)

**Alvo:** `game_scarlett_master.exe` (Xbox Series X|S / Scarlett, pacote 1.0.2.1)
**Data da execução:** 2026-11-22 · **Classificação final: `METADATA_ONLY`**
**Ferramenta:** `recovery/project_alpha/shadow_pe_reconstructor.py run-all` (commit `30515f0` + correções não commitadas
nesse arquivo, descritas na seção 9). Somente leitura; log completo em `reports/shadow_pe_final2.log`.

Este relatório substitui `reports/shadow_pe_final/RELATORIO_TECNICO.md`. As conclusões não mudaram; mudou a
origem dos números: todos os valores abaixo foram **medidos nesta execução** e podem ser conferidos nos JSON
desta pasta. O que não foi medido aqui está marcado como tal na seção 10.

---

## 1. Resposta direta

> *Quanto do executável original pode ser recuperado?*

| Classe | Bytes | % do alvo (120.181.760) | Base medida |
|---|---:|---:|---|
| `EXACT_RECOVERED` (plaintext com prova) | **0** | 0,000000 | nenhum PE válido em nenhum byte do alvo (E3) |
| `MATCHED_COPY` de plaintext | **0** | 0,000000 | idem |
| `STRUCTURAL_INFERENCE` (bytes) | 0 | 0,000000 | nenhuma estrutura PE observável |
| `ENCRYPTED_UNKNOWN` | 120.181.760 | 100,000000 | KeyId 0; entropia **7,999998** bits/byte; 0 PE válidos em 1.874 ocorrências de `MZ` |
| `MISSING` / `CONFLICTING_EVIDENCE` | 0 | 0 | — |

**Nenhum byte de código ou dado do executável foi recuperado.** `shadow_pe_partial.bin` e `reconstructed.exe`
não foram gerados porque não há bytes de plaintext comprovados. Preenchimento artificial não conta como recuperação.

**Proveniência dos bytes gravados (ciphertext), separada e nunca somada como recuperação:** a cópia em disco
(`PROJECT_ALPHA\game_scarlett_master.exe`, 120.184.832 bytes) é **byte a byte idêntica** à região do alvo no XVC
nos 120.181.760 bytes de sobreposição (E1: 29/29 blocos de 4 MiB). Os 3.072 bytes excedentes da cópia em disco
não têm origem comprovada no XVC (entropia 7,94; não são zeros) e ficam como `UNVERIFIED`.

> Disco e XVC são **a mesma evidência**, não dois testemunhos independentes: um é cópia do outro.

## 2. Estado de cifragem: o que foi medido e o que é inferido

| Evidência | Valor | Nível |
|---|---|---|
| KeyId da região do alvo no XVC (segmento 12, offset `0x64917000`) | 0 | CONFIRMADO (metadados XVC) |
| Entropia da região inteira (120.181.760 bytes, 256 valores distintos) | 7,999998 bits/byte | MEDIDO |
| PE válidos no arquivo inteiro / ocorrências de `MZ` | 0 / 1.874 | MEDIDO |
| Detector comprovado com PE real conhecido (Catalog000.bin) | 1 PE detectado | MEDIDO (controle positivo) |
| DLL legível em disco × sua região no XVC (KeyId 0) | 0% de blocos iguais | MEDIDO (E6) |
| Conteúdo cifrado com AES-XTS | — | **INFERIDO** |

A ferramenta **não verifica** a cifragem: ela não tem a chave e não tenta descriptografar. A conclusão de que o
conteúdo está cifrado é uma inferência sustentada pelas quatro medições acima. AES-XTS é o esquema esperado para
regiões cifradas de XVD/XVC, não algo observado nos bytes.

## 3. Inventário (Fase 1): `binary_inventory.json`

- 369 arquivos, 449,7 GB. Raízes: `G:\MyGame_v1\PROJECT_ALPHA` e o XVC (225,3 GB).
- Todos os 369 registros vieram do cache por (caminho, tamanho, mtime), copiado da execução anterior
  (`fresh_scans: 0`). Os hashes **não** foram recalculados nesta execução.
- Hash: 364 arquivos com SHA-256 completo (≤ 8 GiB). 5 acima disso com hash **parcial** head+tail de 16 MiB,
  rotulado como parcial: o XVC, `audio.rpf`, `levels.rpf`, `movies.rpf`, `story000.rpf`.
- Formatos: 305 `unknown_bin`, 33 `MZ`, 25 PNG, 3 XML, 2 MSFT-XVD (o XVC e `gameos.xvd`), 1 REGF.
- A entropia por arquivo no inventário é **amostrada** (até 12 janelas de 64 KB). A entropia do alvo citada
  neste relatório vem do E3, que mede a região inteira.

## 4. Identidade e localização (Fase 2): `executable_candidates.json`

**Metadados do alvo, por nível de evidência:**

| Campo | Valor | Nível | Base |
|---|---|---|---|
| Nome | `game_scarlett_master.exe` | CONFIRMADO | `MicrosoftGame.Config`, `appxmanifest.xml`, hive `microsoft_gameconfig.bin`, metadados de segmento do XVC (layout XML como fonte adicional, INFERIDO) |
| Localização | segmento 12, offset `0x64917000`, 120.181.760 bytes, KeyId 0 | CONFIRMADO | XVC SegmentMetadata + XvcInfo |
| SHA-256 dos bytes gravados | `79fe15101c861d0e6e3353d24ebba158ae7e0ed61ea79ece199ca91763dba89a` | MEDIDO | identifica o ciphertext, não o PE |
| Versão | 1.0.2.1 | INFERIDO | versão do **pacote** (cabeçalho XVC = `Identity@Version`); a versão interna do PE é desconhecida |
| Arquitetura | x64 / PE32+ esperado | INFERIDO | plataforma Scarlett; as DLLs do pacote são PE32+ AMD64; o cabeçalho do alvo nunca foi observado |
| Subsistema, seções, imports, entry point, PDB | — | UNKNOWN | nenhum byte do cabeçalho observado |

Atenção: `metrics.json → metadata_coverage` lista os 8 campos **avaliados**, não os recuperados. Só o nome e a
localização estão confirmados.

**27 candidatos:**

| Grupo | Qtd | Estado | Observação |
|---|---:|---|---|
| Alvo | 1 | `ENCRYPTED_UNKNOWN`, cópia em disco também opaca | — |
| DLLs do pacote (KeyId 0 no XVC) | 16 | `PLAINTEXT_AVAILABLE_EM_DISCO` | cópias em disco são PEs legíveis; dependências recuperáveis, **não** evidência de import do alvo |
| DLLs fora do pacote | 3 | `PLAINTEXT_AVAILABLE_EM_DISCO` | 2 do FidelityFX SDK (`port\third_party`), `sample_module.dll` |
| Executáveis de sessões anteriores | 6 | `PLAINTEXT_AVAILABLE_EM_DISCO` | `platform_master.exe`, `alpha_*.exe` (4), `CMakeCXXCompilerId.exe`; **não** são o executável original |
| Referência textual | 1 | UNKNOWN | string `run GamingRepair.exe`, sem arquivo |

## 5. Experimentos (Fase 6): `experiments.json`

| ID | Resultado | Controle | Conclusão |
|---|---|---|---|
| **E1** disco × XVC (alvo) | 29/29 blocos iguais (100%) | região não sobreposta do XVC em `0x164917000`: 0% | a cópia em disco veio do XVC; plaintext continua desconhecido |
| **E1b** Catalog000.bin × XVC (KeyId 0xFFFF) | 1/1 bloco igual (100%) | região não sobreposta em `0x16484D000`: 0% | o catálogo em disco é cópia fiel da região legível |
| **E6** `amd_fidelityfx_loader_xbox.dll` (PE válido em disco) × sua região XVC (KeyId 0, 13.312 bytes) | 0/1 bloco igual (0%) | arquivo contra ele mesmo: 100% | bytes no XVC são transformados, consistente com cifragem; nenhuma falha criptográfica alegada |
| **E3** assinaturas estruturais no alvo | 0 PE válidos / 1.874 `MZ`, arquivo inteiro, sem limite atingido; entropia 7,999998 | **controle positivo executado:** o mesmo detector acha 1 PE em Catalog000.bin | negativo medido; cobre a região XVC por identidade de bytes (E1) |

Os controles negativos usam um offset verificado dentro do XVC e sem sobreposição com a região testada.

Não executados nesta execução: comparação entre builds (E2), por não haver outra versão do pacote no conjunto.

## 6. Mapa shadow PE (Fase 4): `shadow_pe_map.json`, `recovery_provenance.json`

- Intervalo único `[0x0, 0x729D400)` = 120.181.760 bytes, classe `ENCRYPTED_UNKNOWN`. Zero conflitos.
- Evidência registrada no intervalo: segmento 12, KeyId 0, entropia medida, 0 PE / 1.874 `MZ`, "cifragem
  INFERIDA, não verificada".
- Proveniência: 1 registro `MATCHED_COPY` de **ciphertext** (120.181.760 bytes, disco ↔ XVC) e 1 registro
  `UNVERIFIED` (cauda de 3.072 bytes).

## 7. Fragmentos recuperados (Fase 3): `recovered_fragments/`, `carve_fragment_manifest.json`

33 fragmentos `EXACT_RECOVERED`, extraídos com gravação exclusiva e proveniência (origem, offset, SHA-256):

- 17 da raiz do pacote: as 16 DLLs e `Catalog000.bin` (PE `XBOX_CODE_CATALOG`, x64);
- 16 de `port\` (ferramentas e builds de sessões anteriores, FidelityFX SDK, probes do CMake).

**Nenhum fragmento é do alvo.** Em `metrics.json`: `fragments_recovered: 0` (do alvo) e `carve_fragments_total: 33`.

## 8. Validação (Fase 7)

- `Catalog000.bin`: válido, 13/13 checagens (`catalog_pe_validation.json`), inclusive a comparação com `pefile`.
- Suíte do repositório, depois das correções: **156 aprovados, 6 pulados** (testes de integração que exigem
  `XVC_PATH`). Selftest CLI: **21/21**.
- Nenhum binário foi executado.

## 9. Correções em relação a `shadow_pe_final`

| Ponto | Execução anterior | Esta execução |
|---|---|---|
| Ocorrências de `MZ` no alvo (E3) | 64: era o limite da busca, sem aviso | 1.874, arquivo inteiro |
| PE válidos no alvo (E3) | `0` escrito fixo no código, sem validação | 0 medido pelo `pe_carver` |
| Controle do E3 | descrição textual dos testes sintéticos | controle positivo executado com PE real |
| Entropia do alvo | "~7,997" fixo no código | 7,999998 medido na região inteira |
| E6 | DLL arbitrária; KeyId não conferido | DLL com PE válido em disco; KeyId 0 conferido |
| Controles negativos | +4 GiB sem checar limites | offset verificado (cabe no XVC, sem sobreposição) |
| AES-XTS | afirmado como fato | marcado como INFERIDO |
| Disco + XVC | "dois testemunhos independentes" | a mesma evidência |
| Versão 1.0.2.1 | "CONFIRMADA" | INFERIDO (versão do pacote; versão do PE desconhecida) |
| `metadata_recovered` | `True` fixo | calculado a partir do candidato CONFIRMED |
| `metrics.json` | `fragments_recovered: 0` parecia contradizer os 33 | contadores separados, alvo e total |
| `run-all` | experimentos executados 2× (E1 3×) | uma vez, reaproveitados pelo `reconstruct` |
| Arquivos de saída | 3 regenerados depois do pipeline | todos gerados pelo pipeline, nenhum editado depois |

## 10. Limitações e o que não foi verificado nesta execução

- **Cifragem:** inferida (seção 2), não verificada.
- **Hashes do inventário:** vieram do cache da execução anterior; não foram recalculados.
- **Cauda de 3.072 bytes:** origem desconhecida.
- **Ausência de PDB/MAP/OBJ/ILK do alvo:** vem de auditoria de sessões anteriores, não de uma busca desta execução.
- **Busca dos hashes do catálogo** (F-EXE-04 no relatório anterior): não repetida.
- **Fluxos comprimidos:** o `run-all` **não** tenta decodificar fluxos comprimidos (o `compression_scanner` só
  roda no selftest). Uma verificação independente feita na mesma data com
  `recovery/shadow_pe_standalone/shadow_pe_reconstructor.py` achou no alvo 12 assinaturas gzip/bzip2, nenhuma
  decodificável. Esse resultado não faz parte dos JSON desta pasta.
- `gameos.xvd`: fora do escopo; não analisado além do inventário.

## 11. Impedimentos e próximos passos

1. **Chave de conteúdo indisponível.** Se a inferência da seção 2 estiver correta, nenhum byte do alvo é
   recuperável sem ela. É um impedimento criptográfico, não uma limitação da ferramenta. Não houve tentativa de
   descriptografia, derivação de chave, força bruta ou bypass.
2. **Caminhos legítimos:** build de desenvolvimento do detentor dos direitos, PDB correspondente, ou cópia
   decifrada por processo autorizado, com proveniência documentada (`docs/pt/pe-requisitos.md`). O pipeline valida
   automaticamente qualquer candidato que aparecer.
3. **Sem chave:** se surgir um PDB do alvo, cruzar seções e funções com o tamanho confirmado de 120.181.760
   bytes; se surgir outra versão do pacote, comparar a estrutura dos bytes gravados.

## 12. Reprodução (PowerShell)

```powershell
# testes sintéticos (não tocam nos artefatos reais)
python -I -m pytest -q
python recovery\project_alpha\shadow_pe_reconstructor.py selftest

# pipeline completo (somente leitura; o diretório de saída precisa ser novo)
python recovery\project_alpha\shadow_pe_reconstructor.py run-all `
    --xvc  "G:\MyGame_v1\28872443D20A7_1.0.2.1_neutral__k2ss7vbb13xte_xs.xvc" `
    --disk "G:\MyGame_v1\PROJECT_ALPHA" `
    --target game_scarlett_master.exe `
    --out  "reports\shadow_pe_final3"
```

Para reaproveitar os hashes do inventário, copie `reports\shadow_pe_final2\.cache\` para `<out>\.cache\` antes
de rodar. Sem o cache, o inventário recalcula os hashes de 449,7 GB.

## 13. Arquivos desta pasta

| Arquivo | Conteúdo |
|---|---|
| `binary_inventory.json`, `artifact_index.json` | inventário dos 369 arquivos; duplicações exatas por SHA-256 |
| `executable_candidates.json` | 27 candidatos com fontes, níveis e estados |
| `carve_fragment_manifest.json`, `carve_provenance.json`, `recovered_fragments/` | os 33 fragmentos e sua proveniência |
| `experiments.json` | E1, E1b, E6, E3 com resultados, controles e conclusões |
| `shadow_pe_map.json` | mapa de intervalos do alvo |
| `recovery_provenance.json`, `fragment_manifest.json` | proveniência do mapa (ciphertext e cauda) |
| `metrics.json` | métricas por classe, entropia e contagens medidas |
| `shadow_pe_report.html`, `shadow_pe_report_data.json` | relatório visual e dados completos |
| `catalog_pe_validation.json` | validação do Catalog000.bin |
