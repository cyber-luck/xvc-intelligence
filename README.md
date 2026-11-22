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
│   └── shadow_pe_final/         resultado final do reconstrutor shadow PE (+ execuções anteriores)
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
sem o pacote e 6 são testes de integração com o pacote real. Com o `project_alpha`, o
`pytest` da raiz roda 156 testes sem o pacote.

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

## Ferramentas de recuperação de PE

As três ferramentas seguem as mesmas regras do resto do projeto: entrada somente leitura,
nenhuma descriptografia nem uso de chaves, nenhum byte inventado, saídas só em arquivos novos,
e binários recuperados nunca são executados. Nenhuma delas recupera dados de regiões cifradas.

### Resultado contra os artefatos reais

O pipeline completo do [`recovery/project_alpha/`](recovery/project_alpha/README.md) foi executado
em 2026-11-22, somente leitura, contra o pacote real e a pasta de arquivos extraídos: 369 arquivos,
449,7 GB varridos. **Classificação final: `METADATA_ONLY`.** Relatório completo:
[`reports/shadow_pe_final/RELATORIO_TECNICO.md`](reports/shadow_pe_final/RELATORIO_TECNICO.md)
([English](reports/shadow_pe_final/TECHNICAL_REPORT.en.md)).

| Classe | Bytes do alvo (120.181.760) | % |
|---|---:|---:|
| `EXACT_RECOVERED` (conteúdo em claro comprovado) | 0 | 0% |
| `STRUCTURAL_INFERENCE` | 0 | 0% |
| `ENCRYPTED_UNKNOWN` | 120.181.760 | 100% |
| `MISSING` / `CONFLICTING_EVIDENCE` | 0 | 0% |

- **Nenhum byte do conteúdo em claro do executável é recuperável.** O alvo inteiro está numa
  região KeyId 0, sem `MZ`, com entropia de cerca de 7,997. Sem a chave de conteúdo AES-XTS, isso é
  uma barreira criptográfica real, não uma limitação da ferramenta.
- **Identidade e localização CONFIRMED** por 4 fontes concordantes: nome, versão 1.0.2.1,
  plataforma Scarlett, segmento 12, offset `0x64917000`, SHA-256 dos bytes gravados `79fe1510…`.
- **33 fragmentos recuperados, com proveniência, nenhum deles do alvo:** as 16 DLLs distribuídas
  (legíveis na cópia em disco), `Catalog000.bin` (PE `XBOX_CODE_CATALOG`, validado de forma
  independente) e ferramentas de sessões anteriores. Esses binários não são versionados.
- `reconstructed.exe` e `shadow_pe_partial.bin` **não foram gerados, de propósito**: não há bytes
  comprovados, e preenchimento artificial não é recuperação.

| Experimento | Resultado | Controle negativo |
|---|---|---|
| **E1**, redundância entre contêineres | A cópia em disco é idêntica aos bytes gravados no XVC em 100% (29/29 blocos de 4 MiB). Isso é texto cifrado, não conteúdo em claro. A cauda extra de 3.072 bytes fica `UNVERIFIED` | Região do XVC deslocada em +4 GiB: 0/29 |
| **E1b**, catálogo legível | `Catalog000.bin` em disco é idêntico à região legível do XVC (KeyId 0xFFFF): 100% | Região deslocada: ~0% |
| **E6**, diferencial de DLL | DLL legível em disco contra sua região no XVC (KeyId 0): 0% de blocos iguais, ou seja, a região do XVC é cifrada. Nenhuma falha criptográfica é alegada | O arquivo contra ele mesmo: 100% |
| **E3**, assinaturas estruturais | Negativo confirmado: nenhum PE válido em nenhuma cópia do alvo | Sintéticos s01 (1 PE) e s04 (MZ falso, 0 PE) |
| **E2**, comparação entre builds | Não executado: nenhuma outra versão do pacote está disponível | — |

**Próximo passo com potencial real:** obter um artefato legítimo do detentor dos direitos (build
de desenvolvimento ou PDB correspondente) e cruzá-lo com o tamanho confirmado de 120.181.760 bytes.
O pipeline valida automaticamente qualquer candidato que aparecer.

`reports/shadow_pe/` e `reports/shadow_pe_run/` guardam execuções anteriores incompletas; o
resultado válido é `reports/shadow_pe_final/`.

### As ferramentas

| Ferramenta | O que é | Resultados |
|---|---|---|
| [`recovery/bin_pe_recovery/`](recovery/bin_pe_recovery/README.md) | Scanner que encontra PE32/PE32+ em qualquer offset, inclusive dentro de fluxos gzip, XZ, bzip2, ZIP, LZ4, Zstandard e (opcional) zlib. 13 testes passando | `ex_userdata.bin` (33 MB): 504 ocorrências brutas de `MZ`, **0 PE válido**; `bat.bin` (4 KB): **0 PE válido**; varredura zlib profunda: 128 fluxos, 0 PE |
| [`recovery/project_alpha/`](recovery/project_alpha/README.md) | Pipeline modular sobre o xvcintel: inventário, localização, carving, experimentos com controle negativo, mapa de proveniência por faixa de bytes, validação. 19 testes pytest + `selftest` 21/21 | Executado contra os artefatos reais: `METADATA_ONLY`, 0 bytes do alvo recuperados (ver acima) |
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
| Relatório técnico da reconstrução shadow PE | [RELATORIO_TECNICO.md](reports/shadow_pe_final/RELATORIO_TECNICO.md) | [TECHNICAL_REPORT.en.md](reports/shadow_pe_final/TECHNICAL_REPORT.en.md) |
| Reconstrutor shadow PE (autônomo) | [README.md](recovery/shadow_pe_standalone/README.md) | [README.en.md](recovery/shadow_pe_standalone/README.en.md) |

## Licença e uso

Projeto local de pesquisa. As fixtures em `tests/fixtures/` são extratos pequenos do pacote
analisado, incluídos apenas para a suíte de testes. Revise-as antes de qualquer redistribuição.
