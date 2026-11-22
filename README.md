# XVC Intelligence Engine

**Idioma / Language:** Português · [English](README.en.md)

Ferramenta de pesquisa estrutural **somente leitura** para pacotes Xbox **XVD/XVC**.

Decodifica a estrutura do contêiner: cabeçalho XVD, layout, árvore de hashes, XvcInfo,
regiões, segmentos, tabela de páginas, user data e catálogos PE/COFF. Em seguida verifica a
**integridade** do pacote contra os bytes gravados, sem decifrar nada e sem modificar o arquivo.

> **O que esta ferramenta NÃO faz:** não escreve no pacote, não usa nem procura chaves, não
> decifra conteúdo, não contorna proteção de acesso. Toda abertura é `rb` (leitura). Entropia
> alta **nunca** é tratada como prova de criptografia.

## Rótulos de confiança

Cada conclusão leva um destes rótulos:

- **CONFIRMED**: verificado contra os bytes deste pacote por uma checagem com `id`.
- **INFERRED**: consistente, mas não provado, ou vindo de fonte pública (xvdtool) sem verificação local.
- **UNKNOWN**: não determinado.

## Início rápido

Requer Python 3.10+. Execute na raiz do repositório.

```bash
# suíte de testes (roda sem o pacote real)
python -I -m pytest -q

# com o pacote real, inclui os testes de integração
XVC_PATH='G:\caminho\pacote.xvc' python -I -m pytest -q
# XVC_FULL=1 liga também as varreduras completas de ~1,3 GB nesses testes

# análise completa -> relatórios em reports/
python -I xvcintel.py analyze PACOTE.xvc --out reports

# perfil do executável principal
python -I xvcintel.py fingerprint PACOTE.xvc --name game_scarlett_master.exe --json perfil.json

# inspeções pontuais
python -I xvcintel.py header|layout|xvcinfo|files|integrity|pages|userdata PACOTE.xvc

# outras ferramentas
python -I xvcintel.py graph PACOTE.xvc --out graph.json
python -I xvcintel.py query --graph reports/graph.json --node game_scarlett_master.exe [--relation IMPORTS]
python -I xvcintel.py pe ARQUIVO_PE [--json saida.json]
python -I xvcintel.py regf HIVE
python -I xvcintel.py regress antigo.json novo.json
```

Para hash **completo** de regiões e segmentos acima de 160 MB, use `--cap-mb` com um valor alto
(por exemplo, maior que o pacote). Todos os subcomandos, opções e limites de custo padrão estão
descritos em [`docs/pt/README.md`](docs/pt/README.md).

## Estrutura

```
xvc-intelligence/
├── README.md · README.en.md     visão geral (português · inglês)
├── xvcintel.py                  lançador da CLI (python -I xvcintel.py ...)
├── pyproject.toml
├── src/xvcintel/                biblioteca: core, formats, engines, evidence, cli
├── tests/                       suíte pytest, gerador de XVC sintético (~1 MB), fixtures pequenas
├── scripts/                     wrappers compatíveis com os scripts originais + test_summary.py
├── legacy/                      cópias intactas dos scripts originais (teste de compatibilidade)
├── docs/
│   ├── pt/                      documentação detalhada em português
│   └── en/                      documentação detalhada em inglês
├── recovery/                    ferramentas de recuperação de PE (em desenvolvimento)
│   ├── bin_pe_recovery/         scanner de PE em BIN/XVC/XVD (+ wrappers atualizados e amostras)
│   ├── project_alpha/           reconstrutor shadow PE integrado ao xvcintel
│   └── shadow_pe_standalone/    reconstrutor shadow PE autônomo (arquivo único)
├── reports/                     saídas da última execução contra o pacote real
│   └── shadow_pe/               saídas do reconstrutor shadow PE
└── dist/                        pacotes .zip das ferramentas (ignorado pelo git)
```

Dependências fluem para dentro: `formats` (parsers puros) → `engines` (lê o pacote só por
`ByteSource`) → `evidence` (só consome resultados).

## Estado da verificação

Resultados contra o pacote de referência (225.336.647.680 bytes, versão 1.0.2.1):

| Verificação | Cobertura | Status |
|---|---|---|
| Layout a partir do cabeçalho | fecha no tamanho exato do arquivo | CONFIRMED |
| Árvore de hashes: topo e ligações entre níveis | os 4 níveis verificados por completo (`--full-leaf`) | CONFIRMED |
| **Hash de região** (`SHA-256(região)[:8]`) | **28/28, cobertura completa** | CONFIRMED |
| **Hash de segmento** (`SHA-256(segmento)[:8]`) | **108/108, cobertura completa** | CONFIRMED |
| Tabela de páginas: RLE das unidades de dados | todas as 54.601.906 páginas com KeyId seguem a regra | CONFIRMED |
| Mapeamento de arquivos | 108/108 arquivos, sem sobreposição | CONFIRMED |
| Regressão contra o relatório JSON original | 108/108 arquivos idênticos em todos os campos | PASS |

A corrida de hash completo leu cerca de 440 GB em cerca de 7,4 minutos. O pacote ficou
intocado, inclusive a data de modificação.

Totais do relatório: 38 findings (27 CONFIRMED, 3 INFERRED, 8 UNKNOWN) e 35 checagens
(29 PASS, 1 PARTIAL, 5 INFO). Testes: **143/143 passando** na suíte do xvcintel. 137 rodam
sem o pacote e 6 são testes de integração com o pacote real.

### Executável principal (`game_scarlett_master.exe`)

- **Armazenamento (CONFIRMED):** segmento 12, região `0x3E9` (só contém este arquivo), offset
  `0x64917000`, 120.181.760 bytes, KeyId 0. Os hashes de região e de segmento conferem.
- **Conteúdo (ilegível):** os bytes gravados não têm cabeçalho `MZ`, e a entropia é de cerca
  de 7,997 bits/byte em 16 janelas. Isso é *consistente com* criptografia, mas não a prova.
  Nenhuma estrutura PE interna pode ser recuperada sem as chaves de conteúdo.
- **DLLs no mesmo pacote:** 16 DLLs aparecem como presentes. Isso, sozinho, **não** mostra
  que o executável as importa.
- **Catálogo de código:** `Catalog000.bin` é um catálogo de código Xbox legível. Nenhum dos
  hashes dos bytes gravados do executável aparece nele, o que é esperado se o catálogo
  descreve o conteúdo decifrado.

O parser de PE (`formats/pe.py`) está pronto e foi testado contra o `pefile`. Se uma cópia
legível do executável for obtida por via legítima, rode `python -I xvcintel.py pe ARQUIVO`
nela. Ver [`docs/pt/pe-requisitos.md`](docs/pt/pe-requisitos.md).

### Em aberto

- O hash compartilhado das regiões de metadados **XVC-HD / XVC-MD**, e o
  `OriginalXvcDataHash` do cabeçalho, seguem **UNKNOWN**. Nove formas candidatas de
  calculá-los foram refutadas, incluindo o `VerifyXvcHash` do xvdtool.
- Nos segmentos 78, 90 e 107, o valor por segmento não bate com a unidade de dados da primeira
  página do segmento. A causa é UNKNOWN.
- Unidades de dados se repetem dentro da mesma região: 44,2 milhões de páginas compartilham o
  valor com outra página. O motivo é UNKNOWN.
- O dynamic header (BAT) do XVD EraOS embutido não foi decodificado, então o layout dele não
  fecha por completo.

## Auditoria dos scripts originais

Os quatro scripts originais foram auditados. Cópias intactas ficam em [`legacy/`](legacy/).
As correções:

- **Offset errado do mutable data.** O `xvc_probe.py` lia MutableDataPageCount em `0x5E0`,
  que vale 0. O offset correto é `0x470`. Um ajuste silencioso de layout escondia o erro;
  agora uma divergência vira FAIL.
- **Offset de drive fixo.** O `pfx_locate.py` usava um offset de drive fixo. Agora todo
  offset é calculado a partir do cabeçalho.
- **Leitura insegura de hive.** O `regf_dump.py` não verificava limites e sua recursão não
  tinha limite de profundidade. Ambos corrigidos.
- **Checagens de hash ausentes.** As checagens de região, segmento e árvore de hashes não
  existiam e foram adicionadas.
- **Sem testes.** Não havia nenhum teste automatizado; agora são 143.

Os wrappers compatíveis em `scripts/` mantêm as opções de linha de comando, os códigos de saída
e as chaves do relatório JSON (schema 1). Detalhes: [`docs/pt/auditoria.md`](docs/pt/auditoria.md).

## Ferramentas de recuperação de PE (em desenvolvimento, ainda não versionadas)

As três ferramentas seguem as mesmas regras do resto do projeto: entrada somente leitura,
nenhuma descriptografia nem uso de chaves, nenhum byte inventado, saídas só em arquivos novos,
e binários recuperados nunca são executados. Nenhuma delas recupera dados de regiões cifradas.

| Ferramenta | O que é | Resultados até agora |
|---|---|---|
| [`recovery/bin_pe_recovery/`](recovery/bin_pe_recovery/README.md) | Scanner que encontra PE32/PE32+ em qualquer offset, inclusive dentro de fluxos gzip, XZ, bzip2, ZIP, LZ4, Zstandard e (opcional) zlib. 13 testes passando | `ex_userdata.bin` (33 MB): 504 ocorrências brutas de `MZ`, **0 PE válido**; `bat.bin` (4 KB): **0 PE válido**; varredura zlib profunda: 128 fluxos, 0 PE |
| [`recovery/project_alpha/`](recovery/project_alpha/README.md) | Pipeline modular sobre o xvcintel: inventário, localização, carving, experimentos com controle negativo, mapa de proveniência por faixa de bytes, validação | Ainda não executado em dados reais (`reports/shadow_pe/` está vazio) |
| [`recovery/shadow_pe_standalone/`](recovery/shadow_pe_standalone/README.md) | Versão autônoma em arquivo único (só biblioteca padrão). 18 testes sintéticos | Execução de exemplo em 3 arquivos de amostra (todos varridos por inteiro): `NO_RECOVERABLE_PE_OBSERVED` |

Use essas ferramentas apenas em artefatos de origem documentada e legítima.

## Documentação

Cada documento existe em português (`.md`) e em inglês (`.en.md`).

| Assunto | Português | English |
|---|---|---|
| Uso detalhado, arquitetura e limites de custo | [docs/pt/README.md](docs/pt/README.md) | [docs/en/README.md](docs/en/README.md) |
| O formato XVD/XVC como decodificado aqui | [docs/pt/formato.md](docs/pt/formato.md) | [docs/en/format.md](docs/en/format.md) |
| O que falta para analisar o PE interno | [docs/pt/pe-requisitos.md](docs/pt/pe-requisitos.md) | [docs/en/pe-requirements.md](docs/en/pe-requirements.md) |
| Auditoria dos scripts originais | [docs/pt/auditoria.md](docs/pt/auditoria.md) | [docs/en/audit.md](docs/en/audit.md) |
| Verificação completa de integridade | [docs/pt/resumo-hashes-completos.md](docs/pt/resumo-hashes-completos.md) | [docs/en/full-hash-verification.md](docs/en/full-hash-verification.md) |
| Scanner de PE (`bin_pe_recovery.py`) | [README.md](recovery/bin_pe_recovery/README.md) | [README.en.md](recovery/bin_pe_recovery/README.en.md) |
| Reconstrutor shadow PE (modular) | [README.md](recovery/project_alpha/README.md) | [README.en.md](recovery/project_alpha/README.en.md) |
| Reconstrutor shadow PE (autônomo) | [README.md](recovery/shadow_pe_standalone/README.md) | [README.en.md](recovery/shadow_pe_standalone/README.en.md) |

## Licença e uso

Projeto local de pesquisa. As fixtures em `tests/fixtures/` são extratos pequenos do pacote
analisado, incluídos apenas para a suíte de testes. Revise-as antes de qualquer redistribuição.
