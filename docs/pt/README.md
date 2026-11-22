# XVC Intelligence Engine: uso e arquitetura

**Idioma / Language:** Português · [English](../en/README.md)

Ferramenta de pesquisa estrutural, **somente leitura**, para um pacote Xbox XVD/XVC.

O que a ferramenta não faz:

- não escreve no pacote;
- não usa, não procura e não deriva chaves;
- não decifra conteúdo nem contorna proteção de acesso;
- não trata entropia alta como prova de criptografia.

Cada conclusão leva um destes rótulos:

- **CONFIRMED**: verificado contra os bytes deste pacote por uma checagem com id;
- **INFERRED**: consistente, mas não provado, ou vindo de fonte pública (xvdtool) sem verificação local;
- **UNKNOWN**: não determinado.

## Uso

```
python -I xvcintel.py analyze PACOTE.xvc --out reports [--full-leaf] [--full-pages] [--cap-mb 160] \
       [--baseline tests/fixtures/xvc_files_report_baseline.json] [--tests-json reports/tests_summary.json]
python -I xvcintel.py header|layout|xvcinfo|files [--list]|integrity|pages|userdata PACOTE.xvc
python -I xvcintel.py fingerprint PACOTE.xvc --name game_scarlett_master.exe [--json perfil.json]
python -I xvcintel.py graph PACOTE.xvc --out graph.json
python -I xvcintel.py query --graph reports/graph.json --node game_scarlett_master.exe [--relation IMPORTS]
python -I xvcintel.py pe ARQUIVO_PE [--json saida.json]
python -I xvcintel.py regf HIVE
python -I xvcintel.py regress antigo.json novo.json
python -I scripts/xvc_probe.py PACOTE.xvc --skip-scan --json-report arquivos.json   # wrapper compatível
python -I scripts/test_summary.py reports/tests_summary.json                       # pytest + resumo JSON
```

Testes: `python -m pytest -q`. São 137 testes que rodam sem o pacote. Com `XVC_PATH=<pacote>` rodam também os 6 de integração com o pacote real. `XVC_FULL=1` liga nesses testes as varreduras completas de cerca de 1,3 GB.

## Arquitetura

```
src/xvcintel/
  core/       result.py (Ok/Err + ParseError tipado), reader.py (FileSource "rb", streaming, limite 256 MB), util.py
  formats/    xvd_header, layout, hashtree, xvcinfo, userdata (user data + PFX), filemap, regf, pe
              -> parsers puros: recebem bytes e devolvem Result
  engines/    package (carrega tudo), treeio (acesso à árvore), integrity, pages, profiler, configs,
              fingerprint, graph
  evidence/   model (Evidence/CheckResult/Finding), findings, reports (JSON, schema 1 e regressão), html_report
  cli.py
scripts/      xvc_probe.py, pe_check.py, regf_dump.py (wrappers compatíveis), test_summary.py
tests/        synthxvc.py (gerador de pacote XVC sintético completo, ~1 MB), fixtures/ (extratos pequenos), test_*.py
legacy/       cópias intactas dos scripts originais (usadas em teste de compatibilidade)
reports/      saídas da última execução contra o pacote real
recovery/    ferramentas de recuperação de PE (ver recovery/README.md)
docs/pt/      este arquivo, auditoria, formato, pe-requisitos, resumo-hashes-completos
docs/en/      as mesmas páginas em inglês
```

Dependências: `formats` não conhece `engines`; `engines` lê o pacote só por `ByteSource`; `evidence` só consome resultados.

## Limites de custo (padrões)

| Verificação | Padrão | Opção |
|---|---|---|
| Hash de região ou segmento | completo até 160 MB por item; acima disso é pulado e relatado | `--cap-mb` |
| Ligação L0→L1 | 64 páginas amostradas (semente 1234) | `--full-leaf` (todas as 321.211 páginas, cerca de 1,3 GB) |
| Folha × página de dados | início, meio e fim de cada região, mais 32 páginas aleatórias | `--samples` |
| Modelo RLE da tabela | início, meio e fim de cada uma das 76.469 sequências | `--full-pages` (todas as 54.605.307 páginas de drive, lendo só as folhas) |

Por padrão, o projeto calcula o hash completo apenas das regiões e segmentos até 160 MB; acima disso é pulado e relatado. Rodando com `--cap-mb` acima do tamanho do pacote (hash completo, ~440 GB lidos), as 15 regiões e 59 segmentos acima de 160 MB **foram verificados**: 28/28 regiões e 108/108 segmentos conferem. As regras de hash de região e segmento estão, portanto, CONFIRMED em cobertura completa — ver [resumo-hashes-completos.md](resumo-hashes-completos.md) e `reports/full_hashes_result.json`.

## Outros documentos

- [formato.md](formato.md): o formato XVD/XVC como decodificado aqui.
- [pe-requisitos.md](pe-requisitos.md): o que falta para analisar o PE interno.
- [auditoria.md](auditoria.md): auditoria dos scripts originais.
- [resumo-hashes-completos.md](resumo-hashes-completos.md): verificação completa de integridade.
