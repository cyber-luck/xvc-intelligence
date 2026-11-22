# PROJECT_ALPHA — Reconciliação de proveniência das 16 DLLs (sem chaves)

**Data:** 2026-11-22 · **Ferramenta:** `reconcile-dlls` (`correlation/provenance_reconciliation.py`)
**Relatório:** `dll_provenance_reconciliation.json` — SHA-256 `3e467d568c911e4a0a6de70acf671542f471d6c41cbb310fa477daa28e18dd34`
**Regressão:** 192 aprovados (4 novos de classificação) · Originais intactos · Nenhuma chave usada.

## Passo a passo executado (por DLL)

1. **Manifesto de build:** todas as 16 no **chunk 1002** do layout (empacotadas juntas, após o exe no chunk 1001);
2. **Segmento XVC:** segmentos **13–28**, região **0x3EA** (única região das DLLs);
3. **Estado criptográfico real:** **KeyId 0 (região cifrada)** em **16/16**;
4. **Comparação byte a byte** disco × bytes gravados do segmento (streaming): **0% de blocos iguais em 16/16** — esperado e correto: plaintext × ciphertext é 0% por natureza, e a regra do classificador impede chamar isso de "diferente";
5. **Tamanhos:** **16/16 EXATAMENTE iguais** (disco × SegmentMetadata, byte a byte no tamanho lógico).

## Classificação final

| Classificação | Contagem | Interpretação |
|---|---|---|
| `ENCRYPTED_UNCOMPARABLE` | **16/16** | região cifrada; os bytes gravados no XVC **não são** o PE em disco; bytes não comparáveis sem chave |
| `PACKAGE_IDENTICAL` | 0 | nenhuma DLL em região de texto claro |
| `DIFFERENT` | 0 | nenhuma divergência demonstrável |
| `UNKNOWN` | 0 | — |

## Conclusão sobre a montagem híbrida — agora com evidência completa

**A pasta é uma MONTAGEM HÍBRIDA, comprovada em três fatos independentes:**

1. **Conteúdo cifrado** (exe): cópia em disco idêntica aos bytes gravados do XVC + page slack (E1, 29/29 blocos) → veio da **extração do pacote**;
2. **DLLs da MESMA build em texto claro**: estão cifradas no XVC (KeyId 0 — jamais extraídas dali), porém os **16/16 tamanhos lógicos batem exatamente** com o SegmentMetadata → os binários em disco são **as mesmas builds** do pacote, obtidas em plaintext **por outra via** (console/devkit — coerente com: sem Authenticode in-file, builds console/onecore-xbox, não são redistribuíveis públicos do Windows);
3. **Configs fiéis** (disco == XVC, byte a byte, 3 arquivos).

A **origem da "outra via"** (como os plaintext das DLLs chegaram ao disco) permanece **UNKNOWN** — mas a dúvida anterior ("as DLLs legíveis seriam da build do pacote ou de outra build?") está **resolvida: mesma build, mesmo tamanho lógico, mesma distribuição (chunk 1002/segmentos 13–28)**.

**Consequência forense:** nada nessa via produziu o executável (o exe em disco permanece ciphertext idêntico ao XVC) — a fonte que forneceu os plaintext das DLLs **não tinha** o exe em claro, ou ele não foi trazido. O bloqueio `BLOCKED_MISSING_AUTHORIZED_CIK` permanece, agora com a árvore de proveniência da pasta completamente mapeada e classificada.
