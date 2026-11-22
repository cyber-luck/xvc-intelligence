# Verificação completa de hashes de região e segmento

**Data:** 2026-11-22 · **Modo:** somente leitura · **Pacote intocado** (225.336.647.680 bytes, mtime inalterado)

## O que foi feito

Recalculados **do zero**, a partir dos bytes gravados no pacote, os hashes de **todas** as
regiões e segmentos — inclusive os que antes ficaram marcados como **INFERRED** por estarem
acima do limite de amostragem de 160 MB. Leitura em streaming de ~440 GB (≈218 GB de regiões +
≈218 GB de segmentos), em ~7,4 min. Nada foi decifrado: apenas `SHA-256` dos bytes como gravados.

- **Regra de região:** hash de 8 bytes em `+0x60` do cabeçalho da região == `SHA-256(bytes gravados da região)[:8]`
- **Regra de segmento:** hash de 8 bytes do *update segment* (`+4`) == `SHA-256(páginas do segmento até o próximo segmento / fim da região)[:8]`

## Resultado

| | Testadas | Conferem | Puladas | Status |
|---|---:|---:|---:|---|
| **Regiões** | 28 | 28 | 0 | PASS |
| **Segmentos** | 108 | 108 | 0 | PASS |

**Zero falhas.** A regra, que antes era confirmada só por amostra (13 regiões / 49 segmentos),
está agora comprovada em **100% da cobertura**.

### Itens grandes que estavam INFERRED (agora CONFIRMED)

15 regiões e 59 segmentos acima de 160 MB. Amostra dos maiores (todos `stored == computed`):

| Região | Tamanho | Hash | | Segmento | Tamanho | Hash |
|---|---:|---|---|---|---:|---|
| 0x3F1 | 70,92 GB | `417534028103e399` | | seg 80 | 70,92 GB | `417534028103e399` |
| 0x3EB | 56,82 GB | `1627e371f340c8d0` | | seg 84 | 26,58 GB | `766ce6474daae458` |
| 0x3F5 | 26,58 GB | `766ce6474daae458` | | seg 89 | 18,65 GB | `bd4924ed70abd014` |
| 0xBB8 | 19,58 GB | `d013dedbfc0713a2` | | seg 76 | 8,23 GB | `6fb1b7d6afa17742` |
| 0x3ED | 8,23 GB | `6fb1b7d6afa17742` | | seg 98 | 7,73 GB | `380d660d1d91f5d6` |

Tabela completa de todas as 28 regiões e 108 segmentos (com `stored`/`computed`/`match`):
`reports/full_hashes_result.json`.

## Continua UNKNOWN (por regra, não por tamanho)

Três regiões de metadados **não** usam `SHA-256` dos próprios bytes, então ficam fora deste método:

- `0x40000005` **XVC-HD**, `0x40000001` **XVC-MD**, `0x40000006` **XVC-MDU**

O hash compartilhado de XVC-HD/XVC-MD segue **UNKNOWN** — as 9 serializações candidatas (incluindo a
do `VerifyXvcHash` do xvdtool) continuam refutadas. É o único item de integridade estrutural em aberto.

## Impacto nos relatórios

- `reports/findings.json` — `integrity.region_hash` e `integrity.segment_hash`: `PARTIAL → PASS`,
  cobertura "completa"; findings **F-RG-01** e **F-SG-01** com texto de 28/28 e 108/108, 0 pulados
  (resumo de checks: PASS 27→29, PARTIAL 3→1).
- `reports/executable_profile.json` — novo `integrity.rule_coverage_whole_package` (CONFIRMED):
  documenta que a regra de hash do executável vale em 100% do pacote, não só nos itens ≤ 160 MB.
- `reports/full_hashes_result.json` — evidência bruta da corrida completa.

## Observação

O executável `game_scarlett_master.exe` (segmento 12, 120.181.760 bytes) já estava abaixo do limite,
então seu hash de região/segmento sempre foi CONFIRMED. O que esta corrida acrescenta é a prova de
que **toda** a estrutura de integridade do pacote fecha — nenhum item depende mais de inferência por tamanho.
