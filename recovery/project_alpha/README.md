# PROJECT_ALPHA: Shadow PE Reconstructor

**Idioma / Language:** Português · [English](README.en.md)

Pipeline forense que procura todo vestígio recuperável de um executável alvo
(padrão: `game_scarlett_master.exe`) em um pacote XVC/XVD e nos arquivos em disco.
Para cada faixa de bytes do alvo, registra **de onde veio a evidência e qual a sua
força**. Trabalha junto com o `xvcintel` e reutiliza os parsers dele, além do
scanner de `recovery/bin_pe_recovery/scripts/bin_pe_recovery.py`.

> **Estado:** em desenvolvimento, ainda não versionado no git. `reports/shadow_pe/` existe,
> mas está vazio; nenhum resultado contra o pacote real foi registrado até agora.

## Regras impostas no código

- Artefatos originais abertos **somente para leitura** (`rb`). O XVD/XVC nunca é modificado e nenhuma flag é alterada.
- **Nenhuma descriptografia**, adivinhação de chave ou força bruta.
- **Nenhum byte inventado**: preenchimento artificial não conta como recuperação.
- Saídas só em **arquivos novos** (modo `xb`). Nada é sobrescrito, não há path traversal, e a gravação é recusada dentro da pasta de um artefato original.
- Bytes recuperados e bytes inferidos **nunca são somados** na mesma taxa.
- **Resultados negativos** são registrados com o mesmo peso dos positivos.
- Binários recuperados **nunca são executados**.

## Requisitos

- Python 3.10+, executado dentro deste repositório. O `_bootstrap.py` coloca `src/` (xvcintel)
  e `scripts/` no path e carrega `recovery/bin_pe_recovery/scripts/bin_pe_recovery.py`.
- Opcional: `zstandard` e `lz4` para esses formatos de fluxo.

## Comandos

```powershell
python -I recovery\project_alpha\shadow_pe_reconstructor.py <comando> [opções]
```

| Comando | Fase | O que faz |
|---|---|---|
| `inventory RAÍZES... --out DIR [--stop-after N]` | 1 | Inventário binário profundo: formato pelo conteúdo, tamanho, SHA-256 (completo, ou início+fim rotulado como parcial), entropia por janela, assinaturas, magics de compressão. Cache por arquivo, permite retomar |
| `locate [--xvc F] [--disk D] --out DIR` | 2 | Candidatos a executável a partir dos metadados declarados (configs, manifest, hive, layout) e de strings, reunidos num grafo de evidência |
| `carve RAÍZES... --out DIR [--extract-partial] [--max-scan N]` | 3 | PE carving estrito: MZ + e_lfanew válido + `PE\0\0` + COFF + optional header + tabela de seções dentro dos limites físicos. `MZ` sozinho nunca é PE |
| `reconstruct --xvc F --disk D --out DIR [--target NOME]` | 4 | Monta o mapa classificado de faixas de bytes do alvo, o relatório HTML e as métricas |
| `experiments --xvc F --disk D --out DIR [--target NOME]` | 6 | Experimentos de recuperação, cada um com controle negativo (ver abaixo) |
| `validate CAMINHO [--machine 0x8664] [--magic 0x20B] [--out F]` | 7 | Validação independente de um PE. Código de saída 0 se válido |
| `selftest [--keep]` | — | Suíte sintética rápida (14 cenários) |
| `run-all --xvc F --disk D --out DIR [--target NOME]` | todas | Pipeline completo: inventário → localização → carving → experimentos → reconstrução → validação do `Catalog000.bin` |

Exemplo:

```powershell
python -I recovery\project_alpha\shadow_pe_reconstructor.py selftest
python -I recovery\project_alpha\shadow_pe_reconstructor.py run-all `
    --xvc PACOTE.xvc --disk PASTA_COM_ARQUIVOS_EXTRAIDOS `
    --target game_scarlett_master.exe --out reports\shadow_pe
```

> Use `--disk` apenas numa pasta de origem documentada e legítima. A pasta do exemplo embutido
> no script (`G:\MyGame_v1\PROJECT_ALPHA`) foi registrada antes como de **origem não
> estabelecida** (ver [docs/pt/pe-requisitos.md](../../docs/pt/pe-requisitos.md)).

## Classificação das faixas de bytes

Cada byte do alvo fica em exatamente uma classe. Bytes comprovados nunca são substituídos por inferência.

| Classe | Significado |
|---|---|
| `EXACT_RECOVERED` | Bytes em claro recuperados e comprovados |
| `MATCHED_COPY` | Bytes gravados comprovadamente iguais a outra cópia (nada diz sobre o conteúdo em claro) |
| `STRUCTURAL_INFERENCE` | Inferido pela estrutura, com a base registrada |
| `ENCRYPTED_UNKNOWN` | Bytes gravados presentes, mas ilegíveis sem a chave |
| `MISSING` | Sem evidência |
| `CONFLICTING_EVIDENCE` | Fontes com bytes comprovados divergem |
| `UNVERIFIED` | Ainda não verificado |

## Experimentos (fase 6)

Cada experimento registra hipótese, método, entradas, resultado, controle negativo,
limitações e conclusão. Exemplos:

- **E1, redundância entre contêineres:** a cópia em disco do executável é a mesma sequência de
  bytes gravados no XVC? Compara blocos de 4 MiB por SHA-256. Controle: o mesmo arquivo contra uma
  região do XVC deslocada em `+0x100000000` (espera cerca de 0% de blocos iguais).
- **E1b, catálogo legível:** `Catalog000.bin` em disco contra sua região no XVC (KeyId 0xFFFF).
- **E3, assinaturas estruturais:** se existe algum cabeçalho PE válido em alguma cópia do alvo.
  Controle: cenários sintéticos s01 (PE verdadeiro, 1 recuperado) e s04 (MZ falso, 0 recuperados).
- **E6, análise diferencial de DLL:** uma DLL legível em disco contra sua região cifrada no XVC.
  Controle: o arquivo contra ele mesmo (espera 100%). Nenhuma derivação de chave é tentada.

## Saídas

`binary_inventory.json`, `artifact_index.json`, `executable_candidates.json`,
`carve_report.json`, `experiments.json`, `shadow_pe_map.json`, `shadow_pe_report_data.json`,
`shadow_pe_report.html`, `metrics.json`, `recovery_provenance.json`, `fragment_manifest.json`,
`carve_provenance.json`, `carve_fragment_manifest.json`, `catalog_pe_validation.json`,
`pe_validation.json` (do `validate`) e `recovered_fragments/`.

`shadow_pe_partial.bin` só é gravado se houver faixas `EXACT_RECOVERED` começando no offset 0.
Contém apenas bytes comprovados, nunca preenchimento.

## Testes

- `selftest`: 14 cenários sintéticos com bytes esperados conhecidos: PE verdadeiro, PE embutido,
  PE truncado, MZ falso, dados aleatórios, PE comprimido, vários PEs num contêiner, duplicação
  parcial, fontes conflitantes, entropia alta, maior que a memória, proteção contra sobrescrita,
  interrupção e retomada, e ida e volta.
- `recovery/project_alpha/tests/test_shadow_pe.py`: versão pytest desses cenários. Entra no
  `pytest` do repositório via `pyproject.toml`.

## Limites

- O conteúdo do alvo está cifrado no pacote (região KeyId 0). Sem uma chave legítima, nenhum
  byte de código ou dado dele pode ser recuperado. É uma barreira criptográfica real, não uma
  limitação da ferramenta.
- Um PE parseável não prova que é o executável original, nem que funciona.
- Igualdade de texto cifrado só prova que os bytes gravados são idênticos.
