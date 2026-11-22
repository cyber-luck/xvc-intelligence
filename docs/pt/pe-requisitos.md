# O que falta para analisar as estruturas PE internas de `game_scarlett_master.exe`

**Idioma / Language:** Português · [English](../en/pe-requirements.md)

## Situação

Todo o armazenamento do executável está verificado contra os bytes do pacote (CONFIRMED):

- segmento 12, região 0x3E9 (região com um único arquivo), KeyId 0;
- offset 0x64917000, 120.181.760 bytes, 29.342 páginas;
- hash de segmento e de região conferem (3b221181d8be52ba);
- 16 folhas da hash tree amostradas conferem;
- uma única entrada na tabela de páginas.

O **conteúdo** do executável não é legível:

- os bytes gravados não começam com `MZ`, e `parse_pe` devolve `bad_magic`;
- a entropia é de cerca de 7,997 bits/byte em 16 janelas de 64 KB espalhadas pelo arquivo;
- a região tem KeyId 0, enquanto as regiões de conteúdo legível têm KeyId 0xFFFF;
- o cabeçalho não tem o bit `EncryptionDisabled`.

Isso é **consistente** com conteúdo cifrado, mas não é prova: entropia alta não demonstra criptografia (regra 8).

**Conclusão:** nenhuma estrutura PE interna (cabeçalhos, seções, imports, exports, recursos, debug/PDB, TLS, load config, funções, strings) pode ser obtida deste pacote sem as chaves de conteúdo. Este projeto não tem essas chaves, não as procura, não deriva chaves e não tenta contornar a proteção (regras 5 e 6). Os nomes das 16 DLLs distribuídas **não** são evidência de import.

## O que é necessário

Um **PE legível de `game_scarlett_master.exe`, obtido de forma legítima**. Exemplos:

- um build de desenvolvimento fornecido pelo detentor dos direitos;
- um arquivo de símbolos (PDB) correspondente, quando disponível;
- uma cópia decifrada obtida por um processo autorizado pelo detentor dos direitos.

A proveniência tem de ser documentada. Cópias de origem não estabelecida (por exemplo, as que estão em `G:\MyGame_v1\PROJECT_ALPHA`) **não** foram abertas. Cabe ao usuário decidir sobre elas.

## Como verificar que o PE corresponde a este pacote (sem chave)

Com um PE legível em mãos, a correspondência só é demonstrável indiretamente:

1. O tamanho tem de ser exatamente 120.181.760 bytes (CONFIRMED pelo SegmentMetadata). Isso é necessário, mas não suficiente.
2. O SHA-256 dos bytes **gravados** (79fe1510…) e o hash de segmento referem-se ao texto cifrado. Por isso **não** servem para comparar com um PE decifrado.
3. Comparação útil: procurar os hashes do PE (SHA-1, SHA-256 e Authenticode) dentro de `Catalog000.bin`, que é um catálogo de código Xbox legível. Hoje a busca pelos hashes dos bytes gravados dá negativo (F-EXE-04), o que é esperado se o catálogo descreve o conteúdo decifrado.
4. Versão: o PE ou o PDB deve corresponder à versão 1.0.2.1 do pacote (PackageVersion do cabeçalho, já CONFIRMED contra o MicrosoftGame.config).

## O que passa a ser possível com o PE legível

O `formats/pe.py` já está pronto e foi testado em PEs do Windows contra o `pefile`:

| Estrutura | Comando | Já implementado |
|---|---|---|
| Cabeçalhos DOS, COFF e optional (PE32+ AMD64 esperado), alinhamentos, subsystem | `python -I xvcintel.py pe ARQUIVO --json out.json` | Sim |
| Tabela de seções, mapeamento RVA → offset, sobreposições | idem | Sim |
| Imports por DLL e por função (por nome ou ordinal), delay imports | idem | Sim |
| Exports, incluindo forwarders | idem | Sim |
| Árvore de recursos (contagem por tipo) | idem | Sim |
| Debug directory, CodeView RSDS (GUID, age, caminho do PDB, chave do symbol server) | idem | Sim |
| Security directory (WIN_CERTIFICATE, presença de PKCS#7) | idem | Sim |
| Tabela de símbolos COFF (ponteiro, contagem, string table) | idem | Sim |
| Cruzar imports com as 16 DLLs do pacote (CONFIRMED em vez de UNKNOWN) | a fazer: alimentar `graph.py` com `pe.imports` | Parcial (as arestas IMPORTS existem como UNKNOWN) |
| Desmontagem e funções | ferramentas externas (Ghidra/IDA) sobre o PE legível | Fora do escopo |

## Próxima etapa recomendada

A etapa com maior chance de produzir informação nova sobre o executável é conseguir o artefato legítimo descrito acima e rodar `xvcintel pe` nele. Sem o artefato, o que ainda pode ser investigado é estrutural, como a origem da reutilização de unidades de dados e as exceções dos segmentos 78 e 90. Para isso é preciso comparar com outra versão do mesmo pacote. Isso não revela nada do código.
