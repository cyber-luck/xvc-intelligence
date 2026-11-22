# crypto_lab — laboratório criptográfico XVD/XVC (sintético)

Reproduz as regras criptográficas **documentadas no código** do
[xvdtool](https://github.com/emoose/xvdtool) (commit `6fc2886`) sobre contêineres e executáveis
**gerados aqui**, marcados `LAB_SYNTHETIC`. Depois mede o que as ferramentas do projeto conseguem
observar sem chave e confirma que a chave sintética correta recupera o PE byte a byte.

Três domínios que nunca se misturam:

| Domínio | O que é | O que este laboratório afirma |
|---|---|---|
| **Laboratório sintético** | PEs, chaves e contêineres gerados por `lab_encryptor.py` | todas as medições dos relatórios |
| **Modelo documentado** | o que o código do xvdtool/XanaduXVD faz (`lab_reference.py`) | "confirmado" = é assim que a *ferramenta* faz; compatibilidade com o console **não** foi testada |
| **Pacote real** | o `.xvc` analisado em `reports/shadow_pe_final2/` | nada: o laboratório não o abre, não o decifra e não aplica chaves sintéticas a ele |

## Início rápido

Requer Python 3.11+ e `cryptography` (`pip install cryptography`, ou o extra `lab` do
`pyproject.toml`). Sem `cryptography`, os testes do laboratório são pulados.

```powershell
# pipeline completo (seed de TESTE => determinístico) + regressão da raiz
python -I recovery\crypto_lab\crypto_lab.py run-all --seed 20261122 --run-tests

# padrão (sem --seed): chaves aleatórias seguras (secrets.token_bytes)
python -I recovery\crypto_lab\crypto_lab.py run-all

# etapas isoladas
python -I recovery\crypto_lab\crypto_lab.py vectors | generate --seed N | blind | reveal | compare | report

# ferramentas sem chave
python -I recovery\crypto_lab\tools\inspect_xvd.py  ARQUIVO [--json SAIDA]
python -I recovery\crypto_lab\tools\validate_xts.py ARQUIVO [--json SAIDA]

# testes
python -I -m pytest -q recovery\crypto_lab\tests
python -I -m unittest discover -s recovery\crypto_lab\tests -p "test_lab_*.py"
```

## Estrutura

```
recovery/crypto_lab/
├── crypto_lab.py               orquestrador (run-all), critérios de aceitação, reprodutibilidade, integração
├── lab_reference.py            FASE 1: regras CONFIRMED / HYPOTHESIS / NOT_IMPLEMENTED com arquivo:linha
├── lab_xts.py                  FASE 3: AesXtsTransform (porte rápido + porte literal do C#) e verificação OpenSSL
├── lab_xvd_profile.py          FASE 2, perfil A: ODK -> AES-256-ECB -> KeyMaterial -> CIK -> XTS (headerId 1)
├── lab_xvc_profile.py          FASE 2, perfil B: KeyId -> GUID -> CIK -> XTS (headerId = RegionId), sem ODK
├── lab_hash_tree.py            entradas [SHA256(ct)[:20]][LE32(data_unit)], níveis, índice do XvdMath
├── lab_container.py            cabeçalho XVD, user data, SegmentMetadata (offsets do xvcintel)
├── lab_pe_generator.py         FASE 4: PE32+ x64 próprio (+ build B com diferenças localizadas)
├── lab_encryptor.py            FASES 4-5: ENCRYPTOR -> public/ (contêineres) e sealed/ (verdade, chaves)
├── blind_forensic_analysis.py  FASE 6: FORENSIC ANALYZER às cegas, com auditoria de acesso
├── lab_decryptor.py            FASE 7: revelação autorizada, round-trip, 9 controles negativos
├── compare_results.py          FASE 8: comparação, falsos positivos, distinção de builds, vazamento do XTS
├── lab_vectors.py              vetores conhecidos (IEEE 1619, xvdtool, FIPS-197)
├── lab_report.py               gera crypto_lab_final_report.html
├── lab_common.py               caminhos, gerador determinístico rotulado, guardas de escrita
├── tools/inspect_xvd.py        inspeção sem chave (não existia no repositório; criado aqui)
├── tools/validate_xts.py       validação estrutural XTS sem chave (idem)
├── tests/                      61 testes (pytest e unittest)
├── fixtures/known_vectors.json vetores públicos; fixtures/generated/ é regenerável (ignorado pelo git)
└── reports/                    crypto_lab_report.json, blind_analysis.json, key_reveal_analysis.json,
                                xts_roundtrip_results.json, pe_recovery_comparison.json,
                                crypto_lab_final_report.html  (reports/work/ é regenerável)
```

## Modelo reproduzido (resumo da Fase 1)

- **Perfil A (XVD não-XVC):** `KeyMaterial` (abs. `0x34C`) = AES-256-ECB(ODK, CIK), sem padding;
  ODK escolhida por `ODKKeyslotID` (abs. `0x49C`). XTS de `UserDataOffset` até o fim, `headerId = 1`.
- **Perfil B (XVC):** `Region.KeyId` indexa `XvcInfo.EncryptionKeyIds[]` (GUID); a CIK vem de um
  armazenamento por GUID. A ODK **não** participa (`CryptHeaderCik` retorna cedo para XVC).
  `headerId = RegionHeader.Id`; `KeyId 0xFFFF` = região sem cifra.
- **XTS:** `CIK[0:16]` = chave do tweak, `CIK[16:32]` = chave dos dados; seed =
  `LE32(data_unit) ‖ LE32(section_id) ‖ VDUID[0:8]`; multiplicação em GF(2¹²⁸) little-endian com
  redução `0x87`; uma página `0x1000` = um data unit; sem ciphertext stealing. Equivale ao XTS-AES-128
  do IEEE 1619 com Key1 = dados e Key2 = tweak, e reproduz o `xts_cipher.bin` do próprio xvdtool.
- **Data unit:** lido dos 4 últimos bytes da entrada de hash de nível 0 (`entry+0x14`).
- **Hipóteses não implementadas:** flag `RegionIdInXts` (0x40) e bit `DiffusiveDisabled` (XanaduXVD);
  nenhuma etapa difusiva foi implementada por falta de evidência.

## Separação ENCRYPTOR × FORENSIC ANALYZER

`lab_encryptor.py` grava `fixtures/generated/public/` (dois contêineres + `lab_manifest.json`) e
`fixtures/generated/sealed/` (os dois PEs, `lab_ground_truth.json`, `lab_keystore.json`). O analisador
só recebe `public/`, recusa a pasta selada e recusa uma pasta pública contaminada. Todas as ferramentas
rodam no mesmo processo sob `sys.addaudithook`; o relatório lista cada arquivo aberto e falha se algum
for material selado.

## Resultados (execução `--seed 20261122`)

Ver `reports/crypto_lab_final_report.html`. Em resumo:

- **Às cegas:** 0 bytes de plaintext dos executáveis; `shadow_pe_reconstructor` = `METADATA_ONLY`;
  0 candidatos PE entre as ocorrências aleatórias de `MZ` no ciphertext; isca MZ/PE rejeitada.
  Observável: cabeçalho, GUIDs de CIK, regiões cifradas, nomes/tamanhos/offsets (XVC), integridade
  da árvore e todas as entradas do tweak. Desconhecido: qualquer byte de código, seções, imports,
  strings; no XVD, até o nome e o tamanho do PE.
- **Com a chave sintética:** 100% dos bytes, SHA-256 idênticos, PE válido (4 seções, 5 imports,
  7/7 strings), round-trip exato. Os 9 controles negativos batem com a matriz esperada.
- **Achados úteis:** (1) round-trip exato **não** prova a chave: XTS é permutação para qualquer chave;
  (2) "data unit = índice da página" passa quando a numeração é sequencial a partir de 0 — só a
  numeração não sequencial expõe o erro; (3) ODK errada desembrulha uma CIK errada **sem erro**;
  (4) entropia não prova cifra: ~97% das páginas do PE *em claro* passam de 7,9 bits/byte;
  (5) com chave **e** tweak repetidos, o XTS revela sem chave quais páginas mudaram entre builds.

### Achados nas ferramentas do projeto

- `xvcintel integrity.leaf_vs_data` comparava 0x18 bytes em XVD não-XVC cifrado e falhava; o xvdtool
  usa 0x14 (`DataHashEntryLength`). Corrigido em `src/xvcintel/engines/integrity.py`, com teste em
  `tests/test_xvd_noxvc_integrity.py`. O resultado no pacote real (XVC) não muda.
- O resumo do cabeçalho rotulava o `KeyMaterial` não-zero como "não usado" também em XVD não-XVC;
  rótulo corrigido em `src/xvcintel/formats/xvd_header.py`.
- `inspect_xvd.py` e `validate_xts.py` não existiam; foram criados em `tools/`.

## Limites

Contêineres sem assinatura RSA, sem XVD embutido e sem sistema de arquivos no drive do perfil A;
`OriginalXvcDataHash` não reproduzido. Nenhum console aceitaria estes arquivos, e nada aqui foi
testado contra hardware. O laboratório prova o comportamento do código de referência e das nossas
ferramentas, não que o executável real tenha sido decifrado.
