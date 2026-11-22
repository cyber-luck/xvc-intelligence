# Ferramentas de recuperação de PE

**Idioma / Language:** Português · [English](README.en.md)

Três ferramentas para procurar executáveis PE recuperáveis em arquivos BIN/XVC/XVD. Todas
seguem as regras do projeto: entrada somente leitura, nenhuma descriptografia nem uso de
chaves, nenhum byte inventado, saídas só em arquivos novos, e binários recuperados nunca são
executados. **Nenhuma delas recupera dados de regiões cifradas.**

| Pasta | O que é | Dependências | Testes |
|---|---|---|---|
| [`bin_pe_recovery/`](bin_pe_recovery/README.md) | Scanner de PE32/PE32+ em qualquer offset, inclusive em fluxos comprimidos. Traz também versões atualizadas dos wrappers (`--scan-bin`, `--pe-scan`, `--find-exe`), ainda não instaladas em `scripts/` | Biblioteca padrão (+ `zstandard`/`lz4` opcionais) | 13, pytest |
| [`project_alpha/`](project_alpha/README.md) | Pipeline modular sobre o `xvcintel`: inventário, localização, carving, experimentos com controle negativo, mapa de proveniência por faixa de bytes, validação | `src/xvcintel` + `bin_pe_recovery` | 14 cenários (`selftest`) + pytest, incluído no `pytest` da raiz |
| [`shadow_pe_standalone/`](shadow_pe_standalone/README.md) | Versão autônoma em arquivo único | Biblioteca padrão | 18, unittest |
| [`crypto_lab/`](crypto_lab/README.md) | Laboratório **sintético**: reproduz o AES-XTS do xvdtool sobre contêineres e PEs gerados localmente (`LAB_SYNTHETIC`), mede o que as ferramentas acima veem sem chave e confirma a recuperação com a chave sintética. Nunca toca o pacote real | `cryptography` (extra `lab`) | 61 (pytest/unittest), incluído no `pytest` da raiz |

O `crypto_lab` é a única pasta que usa chaves, e só chaves sintéticas geradas por ele mesmo.

## Rodar os testes

```powershell
# project_alpha (junto com a suíte do xvcintel)
python -I -m pytest -q

# bin_pe_recovery
python -I -m pytest -q recovery\bin_pe_recovery\tests

# shadow_pe_standalone
python -I -m unittest discover -s recovery\shadow_pe_standalone\tests -v
```

Use essas ferramentas apenas em artefatos de origem documentada e legítima. O resultado do
`project_alpha` contra os dados reais (`METADATA_ONLY`, 0 bytes do alvo recuperados) está em
`reports/shadow_pe_final2/`, com o [relatório técnico](../reports/shadow_pe_final2/RELATORIO_TECNICO.md). Os fragmentos binários
recuperados (`recovered_fragments/`) não são versionados.
