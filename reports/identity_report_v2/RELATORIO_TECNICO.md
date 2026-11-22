# PROJECT_ALPHA — Relatório final: validação cruzada de identidade

**Data:** 2026-11-22 · **Alvo:** `game_scarlett_master.exe` (pacote 1.0.2.1, XVC 225 GB)
**Escopo desta fase:** evidências do pipeline de compilação, GUID/age de PDB, correspondência com o manifesto de build e relatório independente de identidade. **Nenhum experimento criptográfico novo** — os resultados de v3 (E1/E1b/E6/E3, catálogo semântico, reconciliação de tamanho) foram reaproveitados por citação, não re-executados.

## 1. Resultados principais

| Verificação | Resultado | Nível |
|---|---|---|
| Identidade declarada (config × cabeçalho XVC) | `game_scarlett_master.exe`, versão **1.0.2.1 consistente** | CONFIRMED |
| **Manifesto de build × pacote** | **104/104 arquivos confirmados** no SegmentMetadata; **nenhum faltando** | CONFIRMED |
| Executável alvo | layout chunk **1001** → XVC **segmento 12** (KeyId 0, 120.181.760 B) | CONFIRMED |
| Ordem dos chunks × segmentos | **monotônica** (segmentos 1..107 na ordem do layout; `Marker="Launch"` no chunk 3009 fecha a sequência) | CONFIRMED |
| Arquivos de subdiretório (`data/ttdb/*.ttpf`, `pack/*`) | casados por **caminho completo normalizado**; nomes duplicados entre packs desambiguados (ex.: `ttdb_maps.ttpf` → segmentos 86 e 94 distintos) | CONFIRMED |
| **PDB GUID/age (validador)** | par real `platform_master.exe` × `platform_master.pdb` → **`GUID_AGE_MATCH`** (GUID `c9822067-6fea-4aa9-9daa-84a94ef73d08`, age 19) | CONFIRMED |
| PDB do alvo | **ABSENT** (nenhum PDB/MAP do executável existe; validador pronto para uso futuro) | CONFIRMED (ausência) |
| RSDS das 16 DLLs | 16 registros extraídos — evidência do **ambiente de build dos fornecedores**, nunca do alvo | CONFIRMED (com rótulo correto) |

## 2. Divergências restantes — investigadas individualmente, nenhuma forçada

4 arquivos do XVC **ausentes do layout** (nenhum arquivo de conteúdo):

| Arquivo | Investigação |
|---|---|
| `microsoft_gameconfig.bin` | hive regf do GameConfig — gerado pelo empacotador, não listado como conteúdo |
| `appxmanifest.xml` | manifesto do pacote — metadado do empacotador |
| `Catalog000.bin` | catálogo de código Xbox (PE subsystem 17, já caracterizado em v3) |
| `layout_3202719e-…xs.xml` | **o próprio manifesto de build**, incluído no pacote como metadado |

Conclusão: divergência esperada entre "conteúdo declarado no layout" e "metadados de sistema do empacotador". Nenhuma correspondência foi forçada; nenhuma divergência ocultada.

## 3. Correção validada em dados reais (não só sintético)

O matching v1 usava nome base e marcava 37/104 (arquivos em subdiretórios não casavam). A correção normaliza
`DestinationPath + Include` (ex.: `\pack\story000\data\ttdb\maps\` + `ttdb_maps.ttpf`) e compara com o caminho
completo do SegmentMetadata; fallback por nome base **apenas quando único**. Resultado real recalculado:
**104/104**. Regressão: **171 testes aprovados** (34 do pacote de recuperação; 5 novos: PDB sintético MSF 7.00,
GUID/age com match e mismatch, manifesto com faltante, violação de ordem, par não-validado).

## 4. Escada de verificação para a cópia autorizada (quando existir)

Coincidências de tamanho/versão/hash isolado **não bastam**. Cadeia exigida, toda já implementada e testada:

1. PE válido x64/PE32+ com tamanho **exatamente 120.181.760 B** (SegmentMetadata) — `reconstruct`;
2. hash (**Authenticode ou bruto**) presente no `Catalog000.bin` legível — `catalog`;
3. GUID/age de RSDS coerentes com PDB correspondente, quando existir — `cross_validate_rsds_pdb`;
4. custodia documentada (`--provenance`, registrada como claim) — `source_provenance.json`.

Sem o item 2 (ou melhor evidência equivalente), arquivo completo → `COMPLETE_UNVERIFIED`, nunca `COMPLETE_VERIFIED`.

## 5. Hashes dos relatórios desta fase

| Arquivo | SHA-256 |
|---|---|
| `identity_report.json` | `ede3f7b480bb1baf196dc75a3c4eb2f0b45afde853ae2662b6a50532da5f6481` |
| `pdb_cross_validation.json` | `42f38ccdb7a2822cbbadaa0ace615be2618c8410934cf48a672c913d6e67430b` |

Evidência prévia reaproveitada (v3, não re-executada): `reports/shadow_pe_v3/catalog_semantic.json`,
`experiments.json` (E1/E1b/E6/E3), `size_reconciliation.json` (cauda de 3.072 B = page slack, CONFIRMED).

## 6. Conclusão

Identidade **declarada**, **armazenamento** e **manifesto de build** estão cruzados e confirmados de forma
independente, com rastreabilidade completa (layout chunk 1001 → segmento 12 → região cifrada → cópia em disco
com proveniência de bytes gravados provada). O próximo avanço significativo permanece condicionado a obter a
cópia autorizada em texto claro e demonstrar correspondência pela cadeia acima — sem depender de coincidências
de tamanho, versão ou hashes isolados. Originais intactos; nenhum byte fabricado; nenhum bypass tentado.
