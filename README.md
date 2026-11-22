# XVC Intelligence Engine

Ferramenta de pesquisa estrutural **somente leitura** para pacotes Xbox **XVD/XVC**.
Decodifica a estrutura do contêiner — cabeçalho XVD, layout, árvore de hashes, XvcInfo,
regiões, segmentos, tabela de páginas, user data e catálogos PE/COFF — e verifica a
**integridade** contra os bytes gravados, sem decifrar nada e sem tocar no arquivo.

> **O que esta ferramenta NÃO faz:** não escreve no pacote, não usa chaves, não decifra
> conteúdo, não contorna proteção de acesso. Toda abertura é `rb` (leitura). Entropia alta
> **não** é tratada como prova de criptografia.

## Rótulos de confiança

Cada conclusão leva um rótulo:

- **CONFIRMED** — verificado contra os bytes deste pacote por uma checagem com `id`.
- **INFERRED** — consistente, mas não provado, ou vindo de fonte pública (xvdtool) sem verificação local.
- **UNKNOWN** — não determinado.

## Início rápido

```bash
# suite de testes (roda sem o pacote real)
python -I -m pytest -q
# com o pacote real, inclui os testes de integração:
XVC_PATH='G:\caminho\pacote.xvc' python -I -m pytest -q

# análise completa -> relatórios em reports/
python -I xvcintel.py analyze PACOTE.xvc --out reports

# perfil do executável principal
python -I xvcintel.py fingerprint PACOTE.xvc --name game_scarlett_master.exe --json perfil.json

# inspeções pontuais
python -I xvcintel.py header|layout|xvcinfo|files|integrity|pages|userdata PACOTE.xvc
```

Para hash **completo** de regiões/segmentos acima de 160 MB, use `--cap-mb` com um valor alto
(ex.: maior que o pacote). A lista completa de subcomandos e opções está em
[`docs/README.md`](docs/README.md).

## Estrutura

```
src/xvcintel/     biblioteca (core, formats, engines, evidence, cli)
scripts/          wrappers compatíveis com os scripts originais + test_summary.py
legacy/           cópias intactas dos scripts originais (teste de compatibilidade)
tests/            suíte pytest + gerador de pacote sintético + fixtures pequenas
reports/          saídas da última execução contra o pacote real
docs/             documentação detalhada
```

Dependências fluem para dentro: `formats` (parsers puros) → `engines` (lê o pacote só por
`ByteSource`) → `evidence` (consome resultados). Detalhes em [`docs/README.md`](docs/README.md).

## Estado da verificação

Contra o pacote de referência (225 GB), a estrutura fecha byte a byte:

| Verificação | Cobertura | Status |
|---|---|---|
| Layout a partir do cabeçalho | fecha no tamanho exato do arquivo | CONFIRMED |
| Topo da árvore de hashes e ligações entre níveis | topo completo; L0→L1 por amostra (ou `--full-leaf`) | CONFIRMED |
| **Hash de região** (`SHA-256(região)[:8]`) | **28/28, cobertura completa (~218 GB lidos)** | CONFIRMED |
| **Hash de segmento** (`SHA-256(segmento)[:8]`) | **108/108, cobertura completa (~218 GB lidos)** | CONFIRMED |
| Mapeamento de arquivos | 108/108 arquivos, sem sobreposição | CONFIRMED |

Em aberto: o hash compartilhado das regiões de metadados **XVC-HD/XVC-MD** segue **UNKNOWN**
(as serializações candidatas, incluindo a do `VerifyXvcHash` do xvdtool, continuam refutadas),
e o interior dos arquivos cifrados não é acessível sem chave. Ver
[`docs/resumo-hashes-completos.md`](docs/resumo-hashes-completos.md).

## Documentação

- [`docs/README.md`](docs/README.md) — uso detalhado, arquitetura e limites de custo.
- [`docs/formato.md`](docs/formato.md) — o formato XVD/XVC como decodificado aqui.
- [`docs/pe-requisitos.md`](docs/pe-requisitos.md) — o que falta para analisar o PE interno.
- [`docs/auditoria.md`](docs/auditoria.md) — auditoria do projeto original.
- [`docs/resumo-hashes-completos.md`](docs/resumo-hashes-completos.md) — verificação completa de integridade.

## Licença e uso

Projeto local de pesquisa. As fixtures em `tests/fixtures/` são extratos pequenos do pacote
analisado, incluídos apenas para a suíte de testes — revise antes de qualquer redistribuição.
