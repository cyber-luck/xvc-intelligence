# PROJECT_ALPHA — Laboratório as cegas A/B/C + ressalvas técnicas absorvidas

**Data:** 2026-11-22 · **Regressão:** 188 testes aprovados (4 novos do laboratório) · **Alvo real:** `BLOCKED_MISSING_AUTHORIZED_CIK` (mantido, correto).

## As duas ressalvas — absorvidas e demonstradas

**Ressalva 1 — amostragem não prova numeração.**
- O pipeline **sempre** leu o `data_unit` de cada folha por página (`_xvc_units`); nada mudou na execução;
- Adicionada **auditoria integral** (`audit_data_units`): executada no XVC real sobre **todas as 29.342 folhas** da região 0x3E9 → **consecutivas, zero saltos** (base `0xE5046EA2`). A linearidade agora é fato comprovado na região inteira — e ainda assim **nunca é usada**: cada folha é lida individualmente;
- Teste com **descontinuidade injetada** (salto de 0x1000 na página 3): a descriptografia continua **byte a byte correta** (lê folha a folha) enquanto a auditoria reporta o salto — provando que nada é extrapolado.

**Ressalva 2 — round-trip não autentica a CIK.**
- `encrypt_verify` rotulado com semântica explícita: prova **consistência do modelo** (tweak/data_unit/region/VDUID/transform), **não** autentica chave — XTS é perfeitamente reversível com qualquer chave;
- Demonstrado na matriz: `roundtrip_with_wrong_cik_still_equal = True` (12/12 na CLI), e a rejeição da chave errada vem **somente** de: plaintext estruturalmente incoerente (sem MZ) + comparação byte a byte com a referência + **zero hits no catálogo**;
- No fluxo real, a autenticação vive em `validate_plaintext` (PE válido + tamanho exato + hash no catálogo + custódia) — jamais no round-trip.

## Laboratório as cegas — três estados independentes (`crypto/synth_lab.py`, CLI `blind-lab`)

**A. Gerador independente** (`reports\blind_lab\`): PE32+ conhecido de 35.840 B (9 páginas + página parcial), **ODK/CIK sintéticas** (LCG determinístico, sem relação com volumes reais), região 0x3E9, VDUID, folhas com data_unit (salto injetado na página 3), page slack 0xC00, catálogo sintético com os hashes do PE. Chaves e referência **seladas** fora do alcance do analisador.

**B. Engenharia reversa sem chaves:** o analisador recebeu apenas o contêiner + metadados públicos. Declarou corretamente: `BLOCKED_MISSING_AUTHORIZED_CIK`; **0 candidatos MZ/PE no ciphertext** (fato observado, não inferência); estrutura recuperável (9 páginas, parcial 0x400, slack 0xC00, 9 folhas auditadas com o salto detectado); plaintext `UNKNOWN — sem CIK`; **nenhum byte apresentado como recuperado**.

**C. Revelação das chaves:** descriptografia streaming (data_unit folha a folha, com o salto) → **igualdade byte a byte com a referência selada** + SHA-256 idêntico + PE32+ x64 válido + **hits de hash no catálogo sintético** + nome do alvo → `TARGET_IDENTITY_VERIFIED` → **`COMPLETE_VERIFIED`**. Demonstrações embutidas: CIK errada → round-trip igual (ressalva 2) mas **rejeitada pela evidência** (referência divergente, sem MZ, zero hits no catálogo).

**Critérios de sucesso: todos OK** (`lab_report.json`, SHA-256 `76949d8ec0b2d462fd02849644875e6c13d46e0d6cfb00134cff145a71163025`).

## Artefatos e hashes

| Arquivo | Conteúdo | SHA-256 |
|---|---|---|
| `reports\xts_real_v2\xvc_crypto_key_mapping.json` | diagnóstico real + **auditoria integral 29.342 folhas (consecutivas, 0 saltos)** | `b631265af27ccbfe2ccb75c0996115578b5b3c70900d7acadf90dfb0c15ad626` |
| `reports\xts_real_v2\xvc_decryption_report.json` | real: `BLOCKED_MISSING_AUTHORIZED_CIK` | `ca254b1e434d73cde957a6495a92975de8965dfe9743d3bc37c5d91bc8e7341a` |
| `reports\xts_tests\xvc_xts_test_results.json` | matriz 12/12 (inclui as duas ressalvas) | `aedcf952c65c7cc3a7150f8a89089e9a730d03722018184b7da0939d0dc971f1` |
| `reports\blind_lab\lab_report.json` | laboratório A/B/C completo | `76949d8ec0b2d462fd02849644875e6c13d46e0d6cfb00134cff145a71163025` |

**Comandos:**
```powershell
python recovery\project_alpha\shadow_pe_reconstructor.py blind-lab --out reports\blind_lab --jump-at 3
python recovery\project_alpha\shadow_pe_reconstructor.py xts-tests --out reports\xts_tests\xvc_xts_test_results.json
python recovery\project_alpha\shadow_pe_reconstructor.py decrypt --xvc <XVC> --target game_scarlett_master.exe --out reports\xts_real_v2
python -I -m pytest -q   # 188 aprovados
```

## Estado final

O motor está validado com testes independentes; o laboratório cego demonstrou de ponta a ponta os três estados — inclusive que o analisador **recusa** apresentar plaintext sem chave e que a autenticação de chave vem da **evidência independente**, nunca do round-trip. No XVC real: numeração de `data_unit` comprovada em toda a região (29.342 folhas, zero anomalias), hash dos dados cifrados recomputado e igual à evidência anterior, originais intactos — e a descriptografia real permanece corretamente **bloqueada até existir CIK autorizada compatível** (`--cik-file` + `--cik-sha256` + `--provenance`), quando o mesmo fluxo do estado C executará automaticamente.
