# PROJECT_ALPHA — Relatório técnico v3 (melhorias finais do Shadow PE Reconstructor)

**Data:** 2026-11-22 · **Alvo:** `game_scarlett_master.exe` · **Classificação do alvo real: `METADATA_ONLY`** (inalterada e correta)
**Regressão:** 166 testes aprovados (29 do pacote de recuperação, incluindo os 10 novos de catálogo/identidade) + selftest 21/21.
**Artefatos anteriores:** `reports/shadow_pe_final` (v2); este relatório descreve o que v3 acrescenta.

## 1. Catalogo — validacao semantica (`catalog_semantic.json`, subcomando `catalog`)

O `Catalog000.bin` real (PE32+ x64, subsystem 17 XBOX_CODE_CATALOG, validado 13/13 checagens):

| Aspecto | Resultado | Nível |
|---|---|---|
| Estrutura da seção | página 0 = cabeçalho de 64 B + 197 páginas densas (~4.070/4.096 bytes não-nulos); consistente com tabela de hashes de código | INFERIDO |
| Decodificação campo a campo do formato interno | não documentada publicamente | UNKNOWN (honesto) |
| Hash **bruto** x hash **Authenticode** | ambos calculados para qualquer candidato (digest Authenticode = imagem sem a tabela de certificados, streaming, > memória); buscados em 5 formas: raw, hex-ascii minúsculo/maiúsculo, base64, base64 sem padding | implementado |
| Associação ao executável | nome do alvo **não** ocorre em texto claro no catálogo; sem candidato plaintext, associação | UNKNOWN |
| Assinatura | **nenhuma assinatura embutida** (security directory ausente, sem PKCS#7); nada a verificar; verificação criptográfica explicitamente marcada como NÃO EXECUTADA | CONFIRMADO |

## 2. Identidade — `SOURCE_RECOVERED` ≠ `TARGET_IDENTITY_VERIFIED`

Nova função `assess_identity` avalia separadamente: `size_exact` (necessário), `machine_compatible` (apoio),
`catalog_hash_hit` (forte), `catalog_name_association` (apoio), `custody_documented` (necessário).

**Regra:** `TARGET_IDENTITY_VERIFIED` exige **todos**; sem qualquer um → `TARGET_IDENTITY_UNVERIFIED`.
Demonstração em dados reais (msvcp140.dll como alvo, cópia legível em disco, tamanho exato, custodia declarada):
`SOURCE_RECOVERED` = 565.232 bytes com PE válido, porém `TARGET_IDENTITY_UNVERIFIED` (sem hash no catálogo)
→ classificação **`COMPLETE_UNVERIFIED`** (antes seria COMPLETE_VERIFIED; a versão anterior con flundia os conceitos).

## 3. Proveniência — `source_provenance.json`

Fatos da fonte (caminho, tamanho, mtime, SHA-1/SHA-256, digests Authenticode) + claim de custodia
registrado **como claim** (`custody_claim_is_not_proof: true`); a prova de identidade vive em seção separada.
No caso real: claim = null (custodia não documentada); proveniência dos bytes gravados = E1 (100% dos blocos
idênticos ao XVC).

## 4. Tamanho — `size_reconciliation.json` (divergência de 3.072 bytes RESOLVIDA)

| Campo | Valor |
|---|---|
| Esperado (XVC SegmentMetadata) | 120.181.760 B — termina em 0x400 dentro da página de 4 KiB |
| Real (cópia em disco) | 120.184.832 B — delta **+3.072 B** |
| Hipótese | `page_slack_included_by_extraction`: a extração incluiu a folga até o limite da página |
| Teste | cauda do disco comparada byte a byte com a continuação da região no XVC (`0x6BBB4400..0x6BBB5000`) |
| Resultado | **100% idêntica → CONFIRMADO**; nenhum truncamento aplicado; arquivo original intacto |

## 5. Classificação — nova escada

`COMPLETE_VERIFIED` **somente** com: bytes 100% com prova + PE válido + tamanho exato + **identidade verificada**
(hash Authenticode/bruto do candidato presente no catálogo legível + custodia documentada).
Caso contrário, arquivo completo → **`COMPLETE_UNVERIFIED`** (novo). As demais classes不变:
PARTIAL_RECOVERED / STRUCTURE_ONLY / METADATA_ONLY / NO_RECOVERABLE_PE.

## 6. Testes novos (`tests/test_catalog_identity.py`, 10 casos)

1. PE **mesma versão/tamanho com hash diferente** (falsificação de 1 byte): sem hit no catálogo → identidade UNVERIFIED → `COMPLETE_UNVERIFIED`;
2. **Catálogo sem associação comprovada**: sem hash e sem nome → UNVERIFIED mesmo com tamanho/máquina/custodia ok;
3. **Procedência não verificada** (`--provenance` ausente): UNVERIFIED; com hash + custodia → VERIFIED → `COMPLETE_VERIFIED`;
4. Digest **Authenticode** exclui a tabela de certificados (com/sem security directory);
5. Reconciliação de tamanho: page slack (caso real 120.181.760 → 0xC00), truncado, exato — sempre sem truncamento automático;
6. `source_provenance` registra claim como claim.

## 7. Compatibilidade e regras

CLI anterior preservada (`run-all/inventory/locate/carve/experiments/reconstruct/validate/selftest`;
`--provenance` continua opcional); novos: subcomando `catalog`, saídas `catalog_semantic.json`,
`source_provenance.json`, `size_reconciliation.json`. Originais intactos (rb); XVC/XVD não modificados;
nenhum byte fabricado; sem descriptografia.

## 8. Conclusão sobre o alvo real

Mantida: **0 bytes de plaintext**; mapa `[0, 0x729D400)` = `ENCRYPTED_UNKNOWN`; identidade/metadados CONFIRMADOS;
cópia em disco = bytes gravados do XVC + page slack (agora **provado**, não mais `UNVERIFIED`).
`COMPLETE_VERIFIED` do executável continua condicionado a: copia decifrada por processo autorizado +
tamanho exato + hash presente no `Catalog000.bin` + custodia documentada — cadeia pronta e testada.
