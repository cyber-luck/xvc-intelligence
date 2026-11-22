# Auditoria dos scripts existentes (Etapa 1)

**Idioma / Language:** Português · [English](../en/audit.md)

Scripts auditados (cópias intactas em `legacy/`): `xvc_probe.py` (940 linhas), `pe_check.py` (192), `regf_dump.py` (81), `pfx_locate.py` (75).

## Matriz de funcionalidades

| Script | Funcionalidade | Estado na auditoria | Problemas encontrados | Testes existentes | Melhoria aplicada (onde) |
|---|---|---|---|---|---|
| xvc_probe.py | Leitura do cabeçalho XVD | Funcionava para os campos básicos | Lia o MDU em **0x5E0** (vale 0). O offset certo é **0x470** (MutableDataPageCount, xvdtool +0x270). Com MDU = 0 o XvcInfo calculado caía uma página antes e só era achado pela busca de âncora | Nenhum | `formats/xvd_header.py`: cabeçalho completo até 0x1000, com tabela de campos e offsets absolutos. O MDU vem de 0x470 e é conferido com XVC-MDU (`layout.mdu_vs_region`) |
| xvc_probe.py | Layout (xvdtool) | Correto depois do ajuste pela região XVC-MD | Ajuste *a posteriori* (`extra_ht_pages`) mascarava o erro do MDU | Nenhum | `formats/layout.py`: layout calculado só do cabeçalho; a divergência agora vira FAIL em vez de ajuste silencioso |
| xvc_probe.py | Âncora do XvcInfo (ContentID == VDUID) | Funcionava | Era a fonte primária do offset; agora é só verificação | Nenhum | `engines/package.py`: confere a âncora no offset calculado. A busca em ±raio só roda como fallback e marca FAIL |
| xvc_probe.py | Regiões, segmentos, array por segmento, tabela (PageNum, Value) | Funcionava | `UnknownD50` é `RegionSpecifierCount` no xvdtool. A posição do array e da tabela depende de não haver especificadores, e isso não era verificado | Nenhum | `formats/xvcinfo.py`: dataclasses, `Result`, e recusa decodificar o que vem depois dos segmentos se `RegionSpecifierCount > 0` |
| xvc_probe.py | User data, SegmentMetadata, mapa de arquivos | Funcionava (108/108) | `decode_*` devolviam tuplas (dict, erro), sem tipos | Nenhum | `formats/userdata.py`, `formats/filemap.py` (mesmos nomes de checagem, para manter o JSON compatível) |
| xvc_probe.py | Relatório JSON (schema 1) | Funcionava | Nenhum | Nenhum | `evidence/reports.py::files_report`. Regressão: 108/108 arquivos idênticos em todos os campos (`reports/regression.json`) |
| xvc_probe.py | Classificação por assinatura e entropia | Funcionava | Nenhum. As regras foram mantidas sem alteração | Nenhum | `engines/profiler.py` |
| xvc_probe.py | Varredura de strings e mapa de entropia | Funcionava | Cabeçalho duplicado "fase 4"; `f.seek` espalhado pelo código | Nenhum | `scripts/xvc_probe.py` (wrapper com as mesmas opções) |
| xvc_probe.py | Hash de região/segmento | **Ausente** (só comparava hash de região com hash de segmento) | Nenhum | Nenhum | `engines/integrity.py`: SHA-256 dos bytes gravados, com limite configurável |
| xvc_probe.py | Hash tree | **Ausente** (só calculava o tamanho) | Nenhum | Nenhum | `formats/hashtree.py` e `engines/integrity.py`: topo, ligações entre níveis, folhas |
| pe_check.py | MZ, e_lfanew, COFF, optional header, Machine×magic, seções, alinhamento | Funcionava. 30 fixtures sintéticas em `pe_tests/` | Script de nível de módulo (sem funções), lê o arquivo inteiro, para no primeiro erro, sem data directories, imports, exports, recursos, debug ou security | Fixtures sem asserções automatizadas | `formats/pe.py`: parser completo com `Result`; as 30 fixtures foram portadas para `tests/test_pe.py` com o resultado esperado do original; comparação com `pefile` em 5 PEs do Windows |
| regf_dump.py | Leitura de hive regf | Funcionava | Sem verificação de limites (asserts, `IndexError` em hive corrompido), recursão sem limite em `ri` | Nenhum | `formats/regf.py`: toda célula conferida, profundidade limitada, erros viram `Err` |
| pfx_locate.py | Localizar um arquivo no PFX | Funcionava para este pacote | **DRIVE_OFFSET fixo (0x63BCB000)**, caminho relativo fixo, confere só `HeaderSize == 0x64` | Nenhum | Substituído por `fingerprint` / `files --list`, com offset calculado do cabeçalho |

## Problemas transversais e correções

1. **Offsets fixos** (regra 3): `pfx_locate.py` usava `DRIVE_OFFSET` fixo. Agora todo offset vem do cabeçalho. O teste `test_layout_reproduces_real_offsets_from_header_values` recalcula todos os offsets reais só a partir dos valores de campo.
2. **Leitura**: o pacote sempre foi aberto com `rb`. Agora isso é imposto por `core/reader.FileSource`, que não tem método de escrita e recusa leituras únicas acima de 256 MB (`ReadLimitError`). Hashes grandes usam streaming em blocos de 16 MB.
3. **Erros**: entradas malformadas viram `Err(ParseError)` com tipo (`truncated`, `bad_magic`, `out_of_bounds`, `inconsistent`, `invalid_value`, `unsupported`).
4. **Saídas**: `guard_output` recusa gravar dentro da pasta do pacote.
5. **Testes**: antes não havia nenhum teste automatizado. Agora são 143 testes pytest: 137 sem o pacote e 6 de integração com o pacote real, condicionados à variável XVC_PATH.

## Compatibilidade

- `scripts/xvc_probe.py` aceita as mesmas opções (`--mdu-pages`, `--anchor-radius`, `--skip-scan`, `--scan-end`, `--window`, `--stride`, `--threshold`, `--max-gap`, `--dump`, `--list-files`, `--extract-userdata`, `--json-report`). A saída de texto foi reorganizada, mas mantém os mesmos blocos.
- O `--json-report` tem as mesmas chaves (schema 1). Única diferença de valor: `source.drive_data_offset_source` agora descreve a fonte correta (0x470). Com `keep_legacy_source_note=True`, o relatório fica byte a byte igual nos campos (teste `test_all_108_files_and_regression`).
- `scripts/pe_check.py` e `scripts/regf_dump.py` mantêm os códigos de saída: 0 quando o PE é consistente, 1 quando é inconsistente ou não é PE.
