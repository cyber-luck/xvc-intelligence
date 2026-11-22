# PROJECT_ALPHA — Análise de `gameos.xvd` (volume de sistema EraOS)

**Data:** 2026-11-22 · **Arquivo:** `G:\MyGame_v1\PROJECT_ALPHA\gameos.xvd` (348.069.888 bytes / ~332 MiB)
**Métodos:** parsers `xvcintel` (somente leitura) + `inspect_xvd_v3` com `--verify-hashes full` e `--crypto-audit` + testes de hipótese pontuais. **Original intacto; nada descriptografado.**
SHA-256 do arquivo: `d02ff50ae9164e540ce55b60b2f128b5c78bab6b…` (completo em `gameos_analysis.json`).

## 1. Identidade e cabeçalho (CONFIRMADO contra bytes)

| Campo | Valor |
|---|---|
| Formato | XVD v3, magic `msft-xvd` @0x200 |
| Tipo / conteúdo | **Dynamic** (1) / **EraOS** (3) |
| VolumeFlags | `0x1` (ReadOnly) — **EncryptionDisabled NÃO setado** → conteúdo cifrado |
| VDUID / PDUID | `a31ea8e8-2999-4f3a-8f22-658edd493b6b` / `b78ddf1f2d874e4abf8b9b507a3f322e` |
| Versão | **32778.0.26100.7901** (build EraOS derivada de Windows 26100.7901) |
| ODK keyslot | **0 = StandardOdk** |
| **KeyMaterial@0x34C** | **presente, não-zero** (entropia 4,875; fingerprint SHA-256 `0a95c5a3…`; bytes brutos não exportados) |
| DriveSize | 0x20000000 (**drive virtual de 512 MB**, esparso — arquivo físico de 332 MB) |
| UserDataLength / UserDataHash | 0x1F93000 (~33 MB) / `272894d4…` |
| PECatalogHash / PECatalogs | `3f4dce53…` / 128 bytes não-zero |
| Correlações de produto | **nenhuma** (ProductId/ContentID zerados — volume de sistema sem vínculo ao pacote do título) |

## 2. Layout (CONFIRMADO, fecha com o tamanho do arquivo)

```
0x0000000  header        0x3000     (texto claro)
0x0003000  hash_tree     0x339000   (~824 páginas; 3 níveis; 139.156 páginas hasheadas)
0x0033C000  user_data     0x1F93000 (~33 MB — cifrado)
0x022CF000  dynamic_header(BAT) 0x1000 (cifrado — mapa virtual→físico do drive esparso)
0x022D0000  drive_data    ~311 MB físicos (páginas do drive 512 MB alocadas pelo BAT)
```

## 3. Integridade (recomputada ao vivo, somente leitura)

| Verificação | Resultado |
|---|---|
| **Root hash** (TopHashBlockHash) | **VERIFICADO** — `b9b8b758…` recomputado == armazenado, byte a byte |
| Ligações da árvore (nível a nível) | **824/824 verificadas, 0 divergências** |
| Folhas × páginas físicas de dados | **84.150 páginas conferidas, 0 divergências** |
| Cobertura | parcial **por natureza**: o volume é Dynamic — 139.156 páginas *hasheadas* contam as páginas *virtuais* do drive de 512 MB; o arquivo físico armazena ~84.150 páginas alocadas (esparso); as demais não existem fisicamente |

Isso reconfirma ao vivo o estado declarado antes do projeto: *Hash Tree Valid = True; Data Hash Tree Valid = True* — agora com números e hashes registrados.

## 4. Auditoria criptográfica (modelo; sem decifrar)

- Cifra: **AES-128-XTS**, unidade de dados de 0x1000; `data_unit` da entrada de hash (amostras: `data_unit == bloco`, seed modelo `[data_unit | section_id=1 | VDUID[0:8]]` — modelo de referência xvdtool, não confirmado por round-trip);
- **KeyMaterial presente** → CIK embrulhada via ODK: `CIK = AES-256-ECB-decrypt(StandardOdk, KeyMaterial@0x34C)` — modelo aplicável a ESTE volume (ao contrário do XVC do título, cujo KeyMaterial é zero);
- `can_decrypt_now = False`: a **StandardOdk não está disponível**; `user_data`, **BAT** e páginas do drive permanecem cifrados (o BAT cifrado impede até o mapeamento virtual→físico do filesystem);
- Assinatura RSA: **não verificada** (nenhuma chave pública fornecida) — registrado como não-executado, não como falha.

## 5. Hipótese PECatalogHash — NEGATIVO REGISTRADO

`PECatalogHash == SHA-256(PECatalogs)` e mais 6 serializações candidatas (`caps+catalogs`, `catalogs+caps`, `hash+catalogs`, janelas do cabeçalho): **todas refutadas**. A serialização exata coberta pelo `PECatalogHash` permanece **UNKNOWN** — mesma postura do projeto diante do hash compartilhado XVC-HD/MD: hipóteses testadas, refutadas e documentadas, sem palpite.

## 6. gameos.xvd × XVC do título (distinção definitiva)

| | gameos.xvd (EraOS) | XVC do título |
|---|---|---|
| Papel | volume de **sistema** do console | conteúdo do **jogo** |
| KeyMaterial@0x34C | **presente** (CIK embrulhada pela ODK) | **zero** (chave regional externa, keyslot GUID `d4b2880b-…`) |
| Desembrulho | `StandardOdk → CIK` (modelo xvdtool) | fora do modelo ODK — CIK externa por `--cik-file` |
| Conteúdo | sistema operacional (sem relação com o executável do jogo) | o alvo `game_scarlett_master.exe` (região 0x3E9) |

**Consequência:** uma ODK/CIK do gameos **não** descriptografaria o XVC do título e vice-versa. O gameos.xvd não contém, decifrável ou não, qualquer material do executável do jogo — é infraestrutura de OS, e seu conteúdo permanece cifrado por ausência da StandardOdk.

## Artefatos

| Arquivo | Conteúdo |
|---|---|
| `gameos_analysis.json` | análise completa (cabeçalho, layout, integridade full, crypto audit, limitações) |
| `RELATORIO_TECNICO.md` | este documento |
