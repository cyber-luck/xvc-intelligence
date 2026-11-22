# Recuperação de PE em arquivos BIN / XVC / XVD — análise não destrutiva

**Idioma / Language:** Português · [English](README.en.md)

Compatível com Python 3.10+ no Windows. Este pacote **não inclui nem substitui** `src/xvcintel`.

> **Neste repositório:** o pacote fica em `recovery/bin_pe_recovery/`. O scanner é
> `recovery/bin_pe_recovery/scripts/bin_pe_recovery.py` (usado também pelo `recovery/project_alpha`).
> Os wrappers atualizados (`pe_check.py --scan-bin`, `xvc_probe.py --pe-scan`, `regf_dump.py --find-exe`)
> ficam em `recovery/bin_pe_recovery/scripts/` e **ainda não foram instalados** em `scripts/` na raiz.
> Os comandos abaixo assumem a instalação descrita em "Instalação no projeto".

## Arquivos

- `scripts/bin_pe_recovery.py`: novo scanner autônomo de PE32/PE32+ em qualquer offset de arquivos `.bin`, `.dat`, `.xvc` ou `.xvd`. Extrai candidatos válidos de conteúdo em claro, com relatórios JSON. Opcionalmente tenta descompactar gzip, XZ, bzip2, ZIP, LZ4, Zstandard e, sob solicitação, fluxos zlib.
- `scripts/pe_check.py`: preserva a chamada existente a `xvcintel`; adiciona `--scan-bin`. Se `xvcintel` não existir, ainda consegue verificar um PE direto no offset zero.
- `scripts/xvc_probe.py`: preserva o modo XVC original, adiciona `--pe-scan` antes das importações da biblioteca interna.
- `scripts/regf_dump.py`: preserva o leitor de hives via `xvcintel`; adiciona `--find-exe` para procurar referências ASCII/UTF-16LE a `.exe`, `.dll` e `.sys`. São pistas, NÃO parser de registro completo.
- `scripts/test_summary.py`: execução dos testes existentes, incluindo a nova suíte `tests/test_bin_pe_recovery.py`.
- `samples/sample_ex_userdata_scan.json`, `samples/sample_ex_userdata_deep_scan.json`, `samples/sample_bat_scan.json`: relatórios da análise das duas amostras previamente fornecidas; `samples/test_results_13.json`: resultado dos 13 testes.

## Instalação no projeto

Copie os arquivos de `scripts/` para `scripts/` no seu projeto, e `tests/` para `tests/`, **fazendo backup dos arquivos substituídos**. O scanner independente pode ser colocado em qualquer diretório ao lado dos wrappers.

Para suportar Zstandard e LZ4:

```powershell
py -m pip install zstandard lz4 pytest
```

Sem essas dependências, PE puro, gzip, zlib, XZ e bzip2 continuam funcionando. É possível executar tudo com `python -I`.

## Exemplos PowerShell

Na raiz do repositório, ajustar caminho de entrada para o seu BIN real:

```powershell
# 1) Somente relatório: PE em texto claro, até 1 GiB do arquivo (padrão)
python -I .\scripts\pe_check.py --scan-bin "G:\CAMINHO\arquivo.bin" --json .\relatorio_pe.json

# 2) Examinar arquivo completo, extrair PE reconhecidos e testar compressão conhecida
python -I .\scripts\bin_pe_recovery.py scan "G:\CAMINHO\arquivo.bin" `
  --max-scan 0 --compressed `
  --extract-dir .\pe_recuperados `
  --json .\relatorio_completo.json

# 3) Opcional: buscar possíveis streams zlib; há falsos positivos, custo elevado
python -I .\scripts\bin_pe_recovery.py scan "G:\CAMINHO\arquivo.bin" `
  --compressed --deep-zlib --max-streams 200 `
  --json .\relatorio_zlib.json

# 4) A mesma varredura pelo wrapper XVC
python -I .\scripts\xvc_probe.py --pe-scan "G:\CAMINHO\arquivo.bin" --compressed --json .\xvc_pe.json

# 5) Referências a executáveis em hive ou BIN de metadados (somente pistas)
python -I .\scripts\regf_dump.py --find-exe "G:\CAMINHO\metadata.bin" --json .\refs_exe.json

# 6) Executar testes (pip install pytest)
python -I .\scripts\test_summary.py .\resultado_testes.json
```

**Os nomes de saída são exclusivos**: o scanner não substitui arquivos JSON ou PEs existentes. Escolha nomes ou diretórios novos ao repetir os comandos.

## Escopo e precisão

| Tipo de dado | Suporte | Limitações |
|---|---|---|
| Arquivo BIN que já é PE32/PE32+ | Sim | Detecta PE mesmo sem extensão `.exe` |
| PE concatenado ou embutido em BIN | Sim | Extrai extensão mínima dos cabeçalhos e seções; overlay pode faltar |
| PE em gzip/XZ/bzip2/ZIP | Sim | Limites explícitos de entrada e saída |
| PE em ZSTD/LZ4 | Sim, com libs opcionais | Necessário instalar `zstandard`/`lz4` |
| PE em zlib | Sim, com `--deep-zlib` | Heurística baseada em cabeçalho, falsos positivos possíveis |
| PE em XVD/XVC **criptografado** | Não, sem chave válida | AES-XTS não é revertido por uma busca MZ, alteração de flag ou entropia |
| Assinatura, imports, PE funcional no Windows | Não validado | O PE pode ser catalog, DLL ou binário dependente de APIs Xbox |
| REGF hive | `regf_dump` tradicional via xvcintel | `--find-exe` apenas busca strings não validadas |
| `Catalog000.bin` (se PE) | Identificação especial | Subsystem `0x11` sinaliza candidato a catálogo Xbox, não executável do jogo |

### Onde é preciso uma chave legítima

Para dados já cifrados, o caminho seguro é obter uma cópia descriptografada **com credenciais/chaves válidas do seu ambiente**. Uma vez descriptografados, a busca pode ser repetida na imagem ou nos arquivos extraídos. O scanner **não gera, adivinha, extrai nem contorna chaves** e não modifica `gameos.xvd` nem qualquer arquivo de entrada.

A Microsoft documenta criptografia de pacotes de console; o `xvdtool` declara não distribuir as chaves de produção. Confira: `https://github.com/emoose/xvdtool` e a documentação Microsoft GDK de packaging.

## Evidências obtidas nas amostras fornecidas

- `ex_userdata.bin`: 33.107.968 bytes, varredura integral; 504 ocorrências brutas de `MZ`, **0 estruturas PE válidas**; três amostras de entropia ~7,997 bits/byte.
- `bat.bin`: 4.096 bytes, varredura integral; **0 estruturas PE válidas**; entropia ~7,962 bits/byte.

Esses valores indicam que **as regiões amostradas não permitem carvar executáveis PE em texto claro**. Alta entropia é compatível com dados cifrados ou comprimidos e **não prova** criptografia isoladamente.

## Nota de uso sobre `--max-scan`

O limite padrão de 1 GiB protege contra operações inadvertidamente longas em conjuntos de centenas de GiB. Use `--max-scan 0` quando quiser examinar o arquivo inteiro; o relatório inclui `entire_file_scanned` e `coverage`, para impedir conclusões indevidas sobre arquivos examinados parcialmente. A extração opcional jamais executa os binários produzidos.
