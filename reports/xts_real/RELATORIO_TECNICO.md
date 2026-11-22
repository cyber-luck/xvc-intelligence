# PROJECT_ALPHA — Pipeline XTS de descriptografia (somente-leitura; CIK externa)

**Data:** 2026-11-22 · **Alvo:** `game_scarlett_master.exe` (XVC segmento 12, região 0x3E9)
**Status do alvo real: `BLOCKED_MISSING_AUTHORIZED_CIK`** — diagnóstico completo, nenhuma CIK fornecida, nada simulado, nenhum byte decifrado.
**Regressão:** 184 testes aprovados (13 novos de XTS) + matriz CLI 10/10.

> **ERRATA (2026-11-22, após integração do `crypto_lab`).** A divisão da CIK descrita originalmente (`data_key=CIK[0:16]`, `tweak_key=CIK[16:32]`) estava **invertida** em relação ao xvdtool. O layout correto é `CIK = tweak_key(16) ‖ data_key(16)` (`XVDFile.cs` `CryptSectionXts`), conferido contra o vetor oficial `xts_cipher.bin` do xvdtool. O status do alvo real não muda (nenhuma CIK foi aplicada), mas uma CIK legítima teria gerado lixo **sem erro**. Corrigido em `cik_halves`; o motor passou a se chamar `xts_primitive_kat.py`. Os JSONs desta pasta são saídas da execução original e foram preservados; o campo `derivation_model.step2` deles reflete o erro.

## Fase 1 — Identificação da chave regional (resultados reais)

| Item | Valor | Fonte |
|---|---|---|
| Região do alvo | `0x3E9`, segmento 12, offset `0x64917000`, arquivo lógico **120.181.760 B** (alocação da região: +0xC00 de page slack) | SegmentMetadata + XvcInfo |
| **KeyId real** | **index 0** → keyslot GUID **`d4b2880b-884d-cf1b-eea5-bef5a2a7d4f6`** | array de keyslots do XvcInfo |
| **KeyMaterial@0x34C do XVC** | **todo zero** (fingerprint = SHA-256 de 32 bytes nulos) — o título **não carrega nem a CIK embrulhada**; a chave regional é provisionada externamente (console/licenciamento) | leitura somente-leitura do cabeçalho |
| Associação xvdtool | KeyId (índice no array de keyslots) → GUID que nomeia a chave; a CIK correspondente entra por `--cik-file` (32 B) quando legitimamente fornecida | modelo documentado |
| **StandardOdk × chave regional** | `gameos.xvd` (EraOS): volume de sistema com KeyMaterial preenchido, desembrulhado via ODK StandardOdk — relação header×ODK daquele XVD. **XVC do título: KeyMaterial zero; a chave do título é outra relação (keyslot externo)** — uma CIK/ODK do gameos **não** serve para o XVC e vice-versa | `xvc_crypto_key_mapping.json` |
| Modo sem chave | pipeline operacional em **diagnóstico**; nenhuma simulação | `xvc_decryption_report.json` |

## Fase 2 — Motor AES-XTS (`crypto/xvc_xts_pipeline.py`)

- Reutiliza **`xts_primitive_kat.py`** (antes `validate_xts.py`; port do `AesXtsTransform.cs`; validado contra IEEE P1619/D16 e OpenSSL) — nada re-implementado;
- AES-128-XTS com CIK composta de 32 B (`tweak_key=CIK[0:16]`, `data_key=CIK[16:32]` — corrigido, ver errata); unidade de **0x1000 B**;
- seed de 16 B = `[data_unit:4 | region_id:4 | VDUID:8]` — **region_id real (0x3E9)**, nunca section_id fixo;
- `data_unit` lido **da entrada de hash correspondente** (bytes 0x14..0x18 da folha);
- streaming por página, checkpoints a cada 1024 páginas com **verificação do prefixo na retomada** (checkpoint divergente reinicia, nunca mistura);
- segredo jamais impresso (apenas fingerprint SHA-256 da CIK); XVC aberto só em `rb`; saídas em arquivos novos;
- **modelo × validação efetiva**: o layout do seed é derivado de código-fonte público e rotulado como tal; validação EFETIVA contra dados reais só ocorre com CIK legítima, via `encrypt_verify` (re-cifragem comparada byte a byte com o gravado).

**Evidência real nova (diagnóstico):** os `data_unit` da folha da região 0x3E9 formam **sequência linear com base `0xE5046EA2`** (delta entre páginas == delta entre data_units, confirmado por amostragem real em 5 pontos) — em execução o valor **sempre** vem da folha, nunca extrapolado.

## Fase 3 — Matriz sintética obrigatória (10/10 + 13 pytest)

Com PE32+ conhecido e CIK gerada exclusivamente para teste:

1. descriptografia **igual byte a byte ao plaintext original conhecido** (exigida além do round-trip); 2. re-cifragem == ciphertext; 3. CIK errada → sem MZ; 4. region_id errado; 5. VDUID errado; 6. data_unit errado (+1); 7. página alterada detectada pela folha **antes** da descriptografia; 8. truncamento detectado; 9. **page slack excluído** do plaintext; 10-13. interrupção/retomada com checkpoint válido e checkpoint corrompido (reinicia do zero).
→ `xvc_xts_test_results.json` (SHA-256 `4c5883734bfc466434c90f52843ac1ef6fd095521bc69fffacaa2107e212cbd4`)

## Fase 4 — XVC real: diagnóstico executado (somente leitura)

Antes de qualquer processamento: offsets validados contra SegmentMetadata; KeyId 0 conferido; **hash dos dados cifrados recomputado ao vivo = `79fe1510…dba89a`** (igual à evidência anterior F-EXE-02); original intacto. Sem CIK → `BLOCKED_MISSING_AUTHORIZED_CIK`.
→ `xvc_decryption_report.json` (SHA-256 `247262bd76b324a1dfb3d838edb8b72de36e3a4a4756d8afde61789fb9c8bebf`)

## Fase 5 — Validação do plaintext (pronta; não executada — sem CIK)

Implementada e acionada automaticamente após descriptografia real: MZ/PE\0\0, PE32+ x64 (0x8664/0x20B), tamanho lógico exato, seções/imports/exports/relocations/Debug via xvcintel, **RSDS GUID/age**, SHA-1/SHA-256/Authenticode, comparação semântica com `Catalog000.bin` (extraído da própria região legível do XVC), e a escada `SOURCE_RECOVERED ≠ TARGET_IDENTITY_VERIFIED` com `COMPLETE_VERIFIED` somente pela cadeia completa (PE válido + tamanho exato + hash no catálogo + custódia) — **PE válido nunca é promovido automaticamente**.

## Fase 6 — Entregas

| Arquivo | Estado | SHA-256 |
|---|---|---|
| `xvc_crypto_key_mapping.json` | **gerado (real)** — KeyId/keyslot, KeyMaterial zero, modelo, ODK×regional, data_unit linear | `1d42bb97332e53afeb047e4e4132505eea0820c4ddc26eb974b467f19913d124` |
| `xvc_xts_test_results.json` | **gerado** — matriz 10/10 | `4c5883734bfc466434c90f52843ac1ef6fd095521bc69fffacaa2107e212cbd4` |
| `xvc_decryption_report.json` | **gerado (real)** — `BLOCKED_MISSING_AUTHORIZED_CIK` + diagnóstico | `247262bd76b324a1dfb3d838edb8b72de36e3a4a4756d8afde61789fb9c8bebf` |
| `xvc_plaintext_validation.json` | N/A — exige descriptografia real | — |
| `catalog_identity_verification.json` | N/A — idem | — |
| `recovery_provenance.json` | N/A — idem (gerado automaticamente na descriptografia real) | — |

**Comandos (PowerShell):**

```powershell
# matriz sintetica obrigatoria
python recovery\project_alpha\shadow_pe_reconstructor.py xts-tests --out reports\xts_tests\xvc_xts_test_results.json

# diagnostico somente-leitura (sem CIK)
python recovery\project_alpha\shadow_pe_reconstructor.py decrypt `
  --xvc "G:\MyGame_v1\28872443D20A7_1.0.2.1_neutral__k2ss7vbb13xte_xs.xvc" `
  --target game_scarlett_master.exe --out reports\xts_real

# com CIK autorizada (quando existir): acrescente
#   --cik-file <CIK.bin> [--cik-sha256 <hex>] --provenance "custodia"
# o fluxo executa: validacao de armazenamento -> descriptografia streaming com
# checkpoints -> round-trip (re-cifracao == bytes gravados) -> Fase 5 completa.
```

## Critério de sucesso — verificação

✔ motor XTS validado com testes independentes (IEEE P1619 + OpenSSL + matriz sintética 10/10 + 13 pytest);
✔ integração funcional com o XVC real (SegmentMetadata, hash tree, folhas, região, segmento);
✔ **identificação correta do KeyId** (index 0 → GUID `d4b2880b-…`, KeyMaterial zero → provisionamento externo);
✔ relatórios completos comprovados; **descriptografia real somente será executada com material de chave autorizado e compatível** — hoje: `BLOCKED_MISSING_AUTHORIZED_CIK`, sem bytes fabricados, sem substituição de ciphertext, sem declaração de recuperação sem evidência.
