# Shadow PE Reconstructor — PROJECT_ALPHA

**Idioma / Language:** Português · [English](README.en.md)

Ferramenta forense **somente-leitura** para localizar candidatos PE recuperáveis em arquivos `.bin`, `.xvc`, `.xvd`, catálogos e outros artefatos. Também produz inventário, referências a executáveis, blocos binários idênticos e mapas de regiões anotadas.

**Não descriptografa AES-XTS, não recupera chaves, não inventa `.exe` e não identifica automaticamente um candidato como o executável original.** Candidatos car­vados são PE estruturalmente reconhecidos; podem ser catálogos Xbox, DLLs ou outros binários.

## Requisitos

Python 3.10+; bibliotecas padrão. Opcional para streams: `python -m pip install zstandard lz4`.

## Uso mínimo (PowerShell)

Copie `shadow_pe_reconstructor.py` para a raiz do projeto ou execute-o pelo caminho onde estiver.

```powershell
cd "G:\MyGame_v1\PROJECT_RECOVERY\analysis\xvd\inspect_xvd_v3\inspect_xvd_v3"

# Um arquivo BIN específico, com PE carving e extração opt-in
python -I .\shadow_pe_reconstructor.py "G:\CAMINHO\PACOTE\arquivo.bin" `
  --out ".\analysis\shadow_pe_001" --max-scan 0 --compressed `
  --extract --hash-full --target-exe "game_scarlett_master.exe"

# Analisar todos os arquivos de um diretório (varredura limitada por padrão)
python -I .\shadow_pe_reconstructor.py "G:\CAMINHO\PACOTE" `
  --out ".\analysis\shadow_pe_002" --compressed --match-blocks

# Cobertura integral (pode levar bastante tempo nos 200+ GiB de dados)
python -I .\shadow_pe_reconstructor.py "G:\CAMINHO\PACOTE" `
  --out ".\analysis\shadow_pe_full" --max-scan 0 --max-total-scan 0 `
  --hash-full --compressed --extract
```

**Importante:** `--max-scan 0` só significa varredura completa por arquivo; `--max-total-scan 0` remove também o limite global. `--hash-full` calcula o SHA-256 completo dos arquivos; sem ele, registra `prefix_sha256_not_full_file` com o número exato de bytes usados. Qualquer conclusão negativa de varredura parcial deve permanecer parcial.

Por padrão o programa lê até 64 MiB de cada arquivo para procurar candidatos, limitado a 2 GiB no total; ele pode examinar um diretório de arquivos muito grandes sem carregar cada arquivo inteiro na RAM. `--compressed` pesquisa streams conhecidos; `--deep-zlib` amplia a busca com heurística, sujeita a falsos positivos e custo adicional. ZIP é processado apenas com tamanho descomprimido limitado, sem reproduzir caminhos de membros do arquivo.

## Anotar regiões criptografadas identificadas pelos seus relatórios

O parâmetro `--regions` aceita uma lista **de anotações externas**. Os intervalos não são inferidos por entropia e não são automaticamente verificados contra o pacote. Use offsets físicos absolutos do *arquivo correspondente* (não RVA). Arquivo de exemplo `regions.example.json`:

```json
{
  "sources": [
    {
      "path": "G:\\CAMINHO\\PACOTE\\container.xvc",
      "regions": [
        {"offset": 1048576, "length": 4096, "state": "ENCRYPTED_UNKNOWN", "label": "segment 12, region 0x3E9; verify actual physical offset"}
      ]
    }
  ]
}
```

**Não use o offset do exemplo como real.** Informe o intervalo físico que o seu `xvc_probe` efetivamente reporta. O scanner não faz carving dentro de intervalos anotados como criptografados; outras regiões do mesmo arquivo continuam elegíveis para inspeção.

## Arquivos produzidos

- `binary_inventory.json` — fontes, tipo, comprimento, hash (integral ou parcial rotulado), entropia amostral e cobertura.
- `executable_candidates.json` — candidatos PE com cabeçalhos, seções, imports e PDB CodeView quando legíveis; referências de nomes são apenas pistas.
- `shadow_pe_map.json` — regiões `EXACT_RECOVERED`, `MISSING` e `ENCRYPTED_UNKNOWN` baseadas em evidência ou anotações explícitas.
- `recovery_provenance.json` — fonte, offset ou membro, transformação e SHA-256 de cada fragmento identificado.
- `summary.json` — classificação final, contagem, limites e advertências.
- `shadow_pe_report.html` — painel estático, abre em qualquer navegador.
- `block_matches.json` — se usar `--match-blocks`, hashes iguais de blocos entre arquivos distintos. **Não prova que correspondem ao executável alvo.**
- `recovered_fragments/` — somente com `--extract`; cópias de bytes em claro, sem executar os binários.

A ferramenta **não gera automaticamente** `reconstructed.exe` nem `shadow_pe_partial.bin` com preenchimentos fictícios. Quando um PE válido existir, preserva exatamente os bytes recuperáveis e anota eventuais intervalos ausentes.

## Estados do resultado

- `PLAINTEXT_PE_CANDIDATES_FOUND`: pelo menos um PE estruturalmente plausível; identidade do `.exe` original **não estabelecida**.
- `METADATA_ONLY`: pistas de executáveis e/ou regiões anotadas, sem PE recuperado.
- `NO_RECOVERABLE_PE_OBSERVED`: não foram encontrados candidatos nos bytes examinados. **Não equivale a provar que não existe PE fora da cobertura.**

## Testes

```powershell
python -m unittest discover -s tests -v
```

São testes sintéticos: PE válido/embutido/truncado, catálogos, falso positivo MZ, gzip/zlib/ZIP, referências de metadados, anotações criptografadas, SHA parcial explícito, comparação de blocos, proteções de sobrescrita, varredura parcial, ausência de promessa de descriptografia e criação de saída dentro da pasta analisada.

## Integridade e segurança

Entradas sempre são abertas em modo de leitura. A ferramenta recusa uma pasta de saída não vazia, cria relatórios e fragmentos apenas em arquivos novos (`x`, `xb`) e não executa código encontrado. Nenhuma modificação é feita em `gameos.xvd`, `gameos.encdisabled.xvd` ou nos arquivos examinados. Sem uma chave legítima, blocos cifrados por AES-XTS permanecem `ENCRYPTED_UNKNOWN`.
