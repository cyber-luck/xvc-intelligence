# Notas de formato XVD/XVC (com rótulos de confiança)

Os offsets são absolutos no arquivo, salvo indicação. A coluna "Teste" aponta para o id da checagem (em `reports/findings.json`) ou para o teste pytest correspondente.

## Cabeçalho (xvdtool `XvdHeader`; comentário do xvdtool + 0x200 = offset absoluto)

| Offset | Campo | Neste pacote | Confiança | Teste |
|---|---|---|---|---|
| 0x208 | VolumeFlags | 0x41 = ReadOnly \| RegionIdInXts | valor CONFIRMED; nomes INFERRED (xvdtool) | F-HDR-05 |
| 0x240 | TopHashBlockHash | = SHA-256(página 0 da árvore) | CONFIRMED | integrity.top_hash |
| 0x260 | OriginalXvcDataHash | não reproduzido por 9 serializações (incl. VerifyXvcHash do xvdtool) | UNKNOWN | hypothesis.metadata_hash |
| 0x30C | PECatalogHash | ≠ SHA-256(Catalog000.bin) | UNKNOWN (relação) | F-EXE-04 |
| 0x32C | EmbeddedXVD_PDUID | = PDUID do XVD embutido = hash da região XVC-EXVD | CONFIRMED | embedded.pduid_link, F-RG-02 |
| 0x39C | ProductId | contém os 12 caracteres ASCII do StoreId (posições 0–6 e 9–13) | CONFIRMED (bytes); codificação INFERRED | F-HDR-08 |
| 0x3BC | PackageVersion 4×u16 | (1,2,0,1), que lido ao contrário dá 1.0.2.1 = manifest | CONFIRMED | F-HDR-03 |
| 0x46C | PersistentLocalStorageSize | 0x800 = SizeMB 2048 | CONFIRMED | F-HDR-04 |
| 0x470 | MutableDataPageCount | 1 = comprimento de XVC-MDU (o probe antigo lia 0x5E0) | CONFIRMED | layout.mdu_vs_region |
| 0x471 | Unknown471 | 0x04 | valor CONFIRMED; significado UNKNOWN | F-HDR-07 |
| 0x494 | MinSysVersion 4×u16 | (0x25AF, 0x65F4, 0, 0x800A) | valor CONFIRMED; leitura 10.0.26100.9647 + bit 0x8000 INFERRED | F-HDR-06 |

## Layout

O layout é cabeçalho 0x3000 | XVD embutido | MDU | hash tree | user data | XvcInfo | dynamic header | drive data. Ele é calculado só a partir do cabeçalho e fecha com o tamanho do arquivo. CONFIRMED (layout.*).

## Hash tree

- Entradas de 0x18 bytes, com 170 entradas por página e o nível mais alto gravado primeiro.
- Páginas hasheadas: drive + user data + XvcInfo + dynamic header = 54.605.734. A página hasheada 0 é o início do user data.
- Páginas por nível: L0..L3 = 321211, 1890, 12, 1. O início de cada nível, em páginas da árvore, é 1903, 13, 1 e 0.
- Os links foram verificados por completo em todos os níveis (--full-leaf). CONFIRMED (F-HT-01..03).
- Folhas:
  - em regiões com KeyId ≠ 0xFFFF, `entry[:0x14] = SHA-256(página gravada)[:0x14]` e `entry[0x14:0x18]` é um u32 ("unidade de dados");
  - em regiões 0xFFFF e nos metadados, `entry = SHA-256[:0x18]`;
  - verificado por amostragem de 116 páginas. CONFIRMED (F-HT-04).
- O u32 é o tweak XTS segundo o xvdtool. Isso fica INFERRED e documentado **só como estrutura**: nenhum experimento criptográfico foi feito.

## XvcInfo

- 0xD10..0xDA8: campos do xvdtool. Valores: RegionSpecifierCount (0xD50) = 0; PageTableCount (0xD54, "ReservedD54" no xvdtool) = 76.469.
- 0xDA8: 31 cabeçalhos de região de 0x80 bytes cada. Depois deles vêm 108 update segments de 12 bytes, a partir de +0x1D28.
- +0x2238: um u32 por segmento. Ele é igual à unidade de dados da primeira página do segmento em 105/108 (CONFIRMED). Exceções:

  | Segmento | Arquivo | Diferença |
  |---|---|---|
  | 78 | anim.rpf | −1 |
  | 90 | story000_script.rpf | −37 |
  | 107 | Update.alignmentchunk | sem relação |

  Nenhum dos três valores é a unidade de dados de qualquer página (nem numa janela de ±2000 páginas, nem dentro de qualquer sequência da tabela). A causa é UNKNOWN (F-PT-07-*).
- +0x23E8: tabela (u32 PageNum, u32 Value), estritamente crescente. É uma **codificação RLE das unidades de dados**: unidade(p) = Value + (p − PageNum) da entrada que governa a página.
  - Todas as 54.601.906 páginas com KeyId seguem a regra; entre as 3.401 páginas sem KeyId, as exceções são 3.390.
  - Não há entradas redundantes.
  - CONFIRMED (F-PT-01..03), com varredura completa.
- Unidades de dados **repetem** dentro da mesma região: 44.179.883 páginas compartilham o valor com outra página, para 13.233.733 valores distintos. Em 400 pares amostrados (mesma unidade, mesma região) o hash gravado nunca é igual. CONFIRMED (F-PT-04); motivo UNKNOWN.
- Hash de região (+0x60, 8 bytes) = SHA-256(bytes gravados da região)[:8]. CONFIRMED para 13 regiões ≤ 160 MB; a região XVC-EXVD usa o PDUID; XVC-HD e XVC-MD compartilham 5c2b65ad36990544 (UNKNOWN).
- Hash do update segment = SHA-256(páginas do segmento)[:8]. CONFIRMED para 49/49 segmentos ≤ 160 MB; os 59 maiores não foram testados (a regra fica INFERRED para eles).
- Flags de região: 0x1 nas regiões de metadados, 0x0 nas de conteúdo e 0x4 na região InitialPlay. Os nomes do enum do xvdtool não batem com esse uso. UNKNOWN (F-RG-04).
- InitialPlayOffset = fim da região InitialPlay = tamanho do arquivo. CONFIRMED (F-RG-05).

## User data e SegmentMetadata (" PFX")

- Formatos descritos em `formats/userdata.py`: 6 arquivos e 108 entradas.
- As 108 páginas relativas são iguais a PageNum do segmento menos a página inicial do drive. CONFIRMED (F-FM-01).
- O GUID b364c736-… não aparece no cabeçalho, no XvcInfo nem nos outros arquivos do user data. CONFIRMED (F-FM-02); significado UNKNOWN.

## XVD embutido (região XVC-EXVD)

- O parser de cabeçalho e de layout funciona nele: é EraOS, Dynamic, DriveSize 512 MB.
- Top hash, link L0→L1 e folha 0 do user data conferem. Na folha, `entry[:0x14]` é o hash e `entry[0x14:0x18]` vale 0.
- O fim do layout calculado não fecha com EmbeddedXVDLength. É esperado num XVD dinâmico, mas a BAT não foi decodificada. UNKNOWN.
