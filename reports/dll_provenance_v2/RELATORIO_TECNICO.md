# PROJECT_ALPHA — Proveniência das DLLs v2: classificações corrigidas + identidade de build por RSDS

**Data:** 2026-11-22 · **Correção absorvida:** igualdade de tamanho é **correspondência de metadados, não identidade de build** — o excesso de afirmação da v1 foi retirado.
**Relatório:** `dll_provenance_reconciliation.json` (schema /2) — SHA-256 `1b978f1e8f0752b9d7c25778416166a32290ac94a166c040b972a98744006e50`
**Regressão:** 55 testes do pacote aprovados.

## Tabela-canonical de estado (implementada no relatório)

| Objeto | Classificação | Base |
|---|---|---|
| Executável em disco | **`CIPHERTEXT_PACKAGE_IDENTICAL`** | E1: 29/29 blocos idênticos ao XVC + page slack provado |
| 16 DLLs legíveis | **`ENCRYPTED_UNCOMPARABLE`** | região 0x3EA KeyId 0; plaintext×ciphertext = 0% por natureza |
| Configurações comparadas | **`PACKAGE_IDENTICAL`** | diff byte a byte 3/3 idêntico ao user data do XVC |
| Origem das DLLs | **`PROVENANCE_UNKNOWN`** | tamanhos exatos 16/16 = metadados (necessário, jamais suficiente) |
| Recuperação do EXE | **`BLOCKED_MISSING_AUTHORIZED_CIK`** | CIK 0x3E9 ausente; laboratório pronto |

## Identidade de build por RSDS (o avanço executado)

Extração **autoritativa dos bytes** de cada DLL em disco (SHA-256, TimeDateStamp, linker, RSDS GUID+age+pdb path):

- **14/16 DLLs com registro CodeView RSDS** (2 sem: `amd_fidelityfx_upscaler_xbox.dll` e `XboxBvhBuilder.dll` — apenas POGO/REPRO, coerente com os registros anteriores "16 de 19 imagens com RSDS");
- Cada GUID+age **identifica unicamente o link** que gerou aquela DLL — é a referência de build agora registrada;
- **Cross-check contra os registros da sessão anterior** (`pe_debug_records.json`, 2026-11-21): **16/16 `CONSISTENT`** (tamanho, timestamp e RSDS GUID/age conferem) → os arquivos em disco são **os mesmos** analisados pela sessão anterior, inalterados — **custódia interna do ambiente fechada**.

## O que isso estabelece — e o que deliberadamente NÃO estabelece

**Estabelece:** (a) o *quê* está em disco — builds únicas identificadas por RSDS, com registro completo; (b) que nada mudou desde a análise anterior; (c) que a equivalência byte a byte com as cópias protegidas do pacote é **INDEMONSTRÁVEL sem chave** (região cifrada) — declarado, não contornado.

**Não estabelece:** que as DLLs em disco sejam byte a byte as mesmas dos segmentos 13–28. Tamanho + RSDS são correspondências de metadados/identidade de link; a prova final exige: (i) **PDBs correspondentes** do detentor → validação GUID/age (validador pronto e demonstrado); ou (ii) **CIK autorizada** → descriptografia dos segmentos e comparação byte a byte (fluxo pronto, estado C do laboratório).

## Gatilhos que fecham a cadeia (já implementados)

```powershell
# com PDBs do detentor: GUID/age por DLL
python recovery\project_alpha\shadow_pe_reconstructor.py identity --xvc <XVC> --disk <DIR> `
  --target game_scarlett_master.exe --out reports\pdb_check --pdb-pair "<dll>=<pdb>"

# com CIK autorizada: bytes dos segmentos 13-28 em claro + comparação byte a byte
python recovery\project_alpha\shadow_pe_reconstructor.py decrypt --xvc <XVC> `
  --target <dll> --cik-file <cik.bin> --cik-sha256 <hex> --provenance "custodia" --out reports\seg_dll
```

**Estado final:** estrutura e estado criptográfico do pacote documentados com precisão; híbrido comprovado **quanto ao estado**; origem das DLLs `PROVENANCE_UNKNOWN`; recuperação do exe inalterada: `BLOCKED_MISSING_AUTHORIZED_CIK`.
