"""FASE 1 - modelo de referencia, extraido diretamente do codigo-fonte publico.

Fontes lidas (copias em diretorio temporario, nao versionadas aqui):
  * emoose/xvdtool          commit 6fc28862cc5fb711843c0e717101ce4034acf805
  * xboxoneresearch/XanaduXVD commit 50aa0dc89350de580b77f26ade1018b16b0bc1f8

Cada regra leva um status:
  CONFIRMED_BY_CODE   - lido no codigo da referencia (arquivo:linha) e reproduzido
                        pelo laboratorio com teste automatizado;
  CONFIRMED_BY_VECTOR - alem do codigo, o vetor de teste da propria referencia
                        (xts_plain.bin / xts_cipher.bin) foi reproduzido byte a byte;
  PROJECT_OBSERVATION - regra observada pelo xvcintel no pacote real, nao no xvdtool;
  HYPOTHESIS          - sugerida por nome de campo/comentario, sem codigo que a use;
  NOT_IMPLEMENTED     - funcionalidade ausente nas referencias.

"Confirmado pelo codigo" significa: e assim que a FERRAMENTA de referencia faz.
Nao significa que o console Xbox faz igual; isso nao e testado aqui.
"""
from __future__ import annotations

XVDTOOL = {"repo": "https://github.com/emoose/xvdtool", "commit": "6fc28862cc5fb711843c0e717101ce4034acf805"}
XANADU = {"repo": "https://github.com/xboxoneresearch/XanaduXVD", "commit": "50aa0dc89350de580b77f26ade1018b16b0bc1f8"}

X = "xvdtool"
XA = "XanaduXVD"

RULES: list[dict] = [
    # ------------------------------------------------------------ chaves
    {"id": "R01", "topic": "CIK do cabecalho XVD (nao-XVC)", "status": "CONFIRMED_BY_CODE",
     "rule": "Header.KeyMaterial (32 bytes, offset relativo 0x14C = absoluto 0x34C) e a CIK cifrada com a ODK "
             "por AES-ECB sem padding e IV nulo; CryptHeaderCik decifra in-place.",
     "source": [(X, "LibXboxOne/XVD/XVDFile.cs", "269-300 CryptHeaderCik"),
                (X, "LibXboxOne/XVD/XVDStructs.cs", "61 KeyMaterial @0x14C"),
                (XA, "src/XVDTypes.h", "247-250 key_material: 'encrypted or sealed CIK'")],
     "lab": "lab_xvd_profile.wrap_cik / unwrap_cik", "test": "test_keys.TestProfileA"},
    {"id": "R02", "topic": "Tamanho da ODK", "status": "CONFIRMED_BY_CODE",
     "rule": "A ODK e uma chave AES de 32 bytes (DurangoKeyEntry dataSize 0x20) -> AES-256-ECB.",
     "source": [(X, "LibXboxOne/Keys/DurangoKeys.cs", "20-22 OdkStorage (dataSize 0x20)")],
     "lab": "ODK sintetica de 32 bytes", "test": "test_keys.TestProfileA"},
    {"id": "R03", "topic": "Selecao da ODK", "status": "CONFIRMED_BY_CODE",
     "rule": "ODKKeyslotID (relativo 0x29C = absoluto 0x49C) escolhe a ODK, salvo OverrideOdk.",
     "source": [(X, "LibXboxOne/XVD/XVDFile.cs", "277"), (X, "LibXboxOne/XVD/XVDStructs.cs", "105"),
                (XA, "src/XVDTypes.h", "302-306 odk_id: zero => inferida pelo ContentType")],
     "lab": "slot sintetico 0x1AB5 (nao corresponde a nenhum slot real)", "test": "test_keys"},
    {"id": "R04", "topic": "XVC nao usa a ODK", "status": "CONFIRMED_BY_CODE",
     "rule": "CryptHeaderCik retorna sem fazer nada quando IsXvcFile; as CIKs das regioes XVC vem da tabela "
             "XvcInfo.EncryptionKeyIds (GUID) e de um armazenamento de chaves/licencas (GetXvcKeyByGuid).",
     "source": [(X, "LibXboxOne/XVD/XVDFile.cs", "271-275"), (X, "LibXboxOne/XVD/XVDFile.cs", "1008-1060 GetXvcKey/GetXvcKeyByGuid")],
     "lab": "lab_xvc_profile.get_xvc_key (sem ODK)", "test": "test_keys.TestProfileB"},
    {"id": "R05", "topic": "Selecao da CIK regional", "status": "CONFIRMED_BY_CODE",
     "rule": "Region.KeyId e indice em EncryptionKeyIds[]; KeyId 0xFFFF (XVC_KEY_NONE) = regiao sem cifra; "
             "regioes com KeyId+1 > KeyCount sao ignoradas.",
     "source": [(X, "LibXboxOne/XVD/XVDFile.cs", "302-320 CryptXvcRegion"), (X, "LibXboxOne/XVD/XvcConstants.cs", "5"),
                (X, "LibXboxOne/XVD/XVDStructs.cs", "467-495 XvcInfo (EncryptionKeyIds @0x10, KeyCount @0xD1E)")],
     "lab": "lab_xvc_profile", "test": "test_keys.TestProfileB"},
    # ------------------------------------------------------------ XTS
    {"id": "R06", "topic": "Divisao da CIK", "status": "CONFIRMED_BY_VECTOR",
     "rule": "CIK[0:16] = chave AES-128 do tweak; CIK[16:32] = chave AES-128 dos dados.",
     "source": [(X, "LibXboxOne/XVD/XVDFile.cs", "343-350"), (X, "LibXboxOne.Tests/AesXtsTests.cs", "7-17")],
     "lab": "lab_xts.split_cik", "test": "test_xts.test_xvdtool_vector"},
    {"id": "R07", "topic": "Seed do tweak", "status": "CONFIRMED_BY_VECTOR",
     "rule": "seed[0:4]=data_unit LE32, seed[4:8]=headerId LE32, seed[8:16]=VDUID[0:8].",
     "source": [(X, "LibXboxOne/XVD/XVDFile.cs", "352-355"), (X, "LibXboxOne/Crypto/AesXts.cs", "63-64")],
     "lab": "lab_xts.build_tweak_seed", "test": "test_xts"},
    {"id": "R08", "topic": "headerId para XVD nao-XVC", "status": "CONFIRMED_BY_CODE",
     "rule": "Decrypt/Encrypt de XVD nao-XVC chamam CryptSectionXts com headerId = 0x1, de UserDataOffset ate o "
             "fim do arquivo. O proprio codigo marca como 'todo: check ... any other headerId besides 0x1'.",
     "source": [(X, "LibXboxOne/XVD/XVDFile.cs", "427-430"), (X, "LibXboxOne/XVD/XVDFile.cs", "461-463")],
     "lab": "lab_xvd_profile.SECTION_ID_XVD = 1", "test": "test_containers"},
    {"id": "R09", "topic": "headerId para XVC", "status": "CONFIRMED_BY_CODE",
     "rule": "CryptXvcRegion passa (uint)RegionHeader.Id como headerId; o xvdtool nao consulta o flag RegionIdInXts.",
     "source": [(X, "LibXboxOne/XVD/XVDFile.cs", "319")],
     "lab": "lab_xvc_profile", "test": "test_decrypt.test_wrong_region_id"},
    {"id": "R10", "topic": "XTS = IEEE 1619", "status": "CONFIRMED_BY_VECTOR",
     "rule": "T0 = AES(tweak_key, seed); C_i = E(P_i ^ T_i) ^ T_i; T_{i+1} = T_i*x em GF(2^128) com reducao 0x87, "
             "little-endian. Equivale ao XTS-AES-128 do IEEE 1619 com Key1=dados, Key2=tweak.",
     "source": [(X, "LibXboxOne/Crypto/AesXts.cs", "38-97")],
     "lab": "lab_xts.AesXtsTransform (+ verificacao cruzada com OpenSSL)", "test": "test_xts"},
    {"id": "R11", "topic": "Sem ciphertext stealing", "status": "CONFIRMED_BY_CODE",
     "rule": "TransformDataUnit so processa inputCount/16 blocos; as paginas sao sempre 0x1000.",
     "source": [(X, "LibXboxOne/Crypto/AesXts.cs", "72")], "lab": "lab_xts (ValueError se nao multiplo de 16)",
     "test": "test_xts.test_partial_block_rejected"},
    {"id": "R12", "topic": "Unidade de dados", "status": "CONFIRMED_BY_CODE",
     "rule": "Uma pagina 0x1000 = um data unit. Com integridade ligada, o data unit vem dos 4 ultimos bytes da "
             "entrada de hash de nivel 0 da pagina (entry+0x14); sem integridade, e o indice da pagina dentro da secao.",
     "source": [(X, "LibXboxOne/XVD/XVDFile.cs", "327-340"), (X, "LibXboxOne/XVD/XVDFile.cs", "377")],
     "lab": "lab_hash_tree.data_unit_of_page", "test": "test_hash_tree / test_decrypt.test_wrong_data_unit"},
    # ------------------------------------------------------------ integridade
    {"id": "R13", "topic": "Entrada de hash de dados cifrados", "status": "CONFIRMED_BY_CODE",
     "rule": "HASH_ENTRY_LENGTH = 0x18; com cifra, so os primeiros 0x14 bytes sao SHA-256(pagina gravada) "
             "(DataHashEntryLength). Entrada = SHA256(ciphertext)[:20] || LE32(data_unit).",
     "source": [(X, "LibXboxOne/XVD/XVDFile.cs", "27-28, 128"), (X, "LibXboxOne/XVD/XVDFile.cs", "883-917 VerifyDataHashTree")],
     "lab": "lab_hash_tree.leaf_entry_encrypted", "test": "test_hash_tree"},
    {"id": "R14", "topic": "Niveis superiores", "status": "CONFIRMED_BY_CODE",
     "rule": "Nivel k+1 guarda SHA-256(pagina do nivel k)[:0x18]; 0xAA entradas por pagina; topo primeiro; "
             "TopHashBlockHash = SHA-256(primeira pagina da arvore).",
     "source": [(X, "LibXboxOne/XVD/XVDFile.cs", "921-1006"), (X, "LibXboxOne/XVD/XvdMath.cs", "91-187")],
     "lab": "xvcintel.formats.hashtree.build_tree (reaproveitado)", "test": "test_hash_tree"},
    {"id": "R15", "topic": "Hash cobre ciphertext", "status": "CONFIRMED_BY_CODE",
     "rule": "VerifyDataHashTree le os bytes gravados; a integridade pode ser verificada sem chave e nao diz "
             "nada sobre o plaintext.",
     "source": [(X, "LibXboxOne/XVD/XVDFile.cs", "897-903")], "lab": "tools/validate_xts.py", "test": "test_blind"},
    {"id": "R16", "topic": "Folha de pagina sem KeyId", "status": "PROJECT_OBSERVATION",
     "rule": "No pacote real (xvcintel), paginas sem KeyId guardam SHA-256[:0x18] completo; com KeyId, "
             "[:0x14] + data unit. O xvdtool so compara 0x14 bytes quando IsEncrypted.",
     "source": [("xvc-intelligence", "src/xvcintel/formats/hashtree.py", "leaf_matches")],
     "lab": "lab_hash_tree.leaf_entry_plain", "test": "test_containers (xvcintel integrity PASS)"},
    {"id": "R17", "topic": "Tabela de paginas RLE", "status": "PROJECT_OBSERVATION",
     "rule": "XvcInfo apos os segmentos: array por segmento e tabela (PageNum, Value) cujo Value governa o data "
             "unit por RLE. Nao lido pelo xvdtool.",
     "source": [("xvc-intelligence", "src/xvcintel/engines/pages.py", "modelo RLE")],
     "lab": "lab_xvc_profile (tabela gerada)", "test": "test_containers"},
    # ------------------------------------------------------------ hipoteses / nao implementado
    {"id": "H01", "topic": "Flag RegionIdInXts (0x40)", "status": "HYPOTHESIS",
     "rule": "O nome sugere que o console escolhe entre RegionId e 1 no tweak por este flag. O xvdtool nao "
             "le o flag; usa RegionId para XVC e 1 para XVD por tipo de conteudo.",
     "source": [(X, "LibXboxOne/XVD/XVDEnums.cs", "76"), (XA, "src/XVDTypes.h", "81")],
     "lab": "flag gravado (0x40 no XVC, ausente no XVD), mas a decisao segue o xvdtool", "test": "-"},
    {"id": "H02", "topic": "Etapa difusiva", "status": "HYPOTHESIS",
     "rule": "XanaduXVD nomeia o bit DiffusiveDisabled (0x400) em VolumeFlags. Nenhuma referencia implementa um "
             "difusor; o vetor do xvdtool e reproduzido por XTS puro. NAO implementado no laboratorio.",
     "source": [(XA, "src/XVDTypes.h", "85")], "lab": "nao implementado (por decisao)", "test": "-"},
    {"id": "H03", "topic": "ODK por ContentType", "status": "HYPOTHESIS",
     "rule": "Comentario do XanaduXVD: odk_id == 0 => ODK inferida pelo ContentType. Sem codigo.",
     "source": [(XA, "src/XVDTypes.h", "302-306")], "lab": "nao modelado", "test": "-"},
    {"id": "N01", "topic": "Criptografia no XanaduXVD", "status": "NOT_IMPLEMENTED",
     "rule": "README do XanaduXVD: 'Package decryption', 'XVC support' e 'Hash tree verification' nao marcados.",
     "source": [(XA, "README.md", "14-22 (checklist)")], "lab": "XanaduXVD usado so para nomes de campos", "test": "-"},
    {"id": "N02", "topic": "Hash do XvcInfo em pacotes retail", "status": "NOT_IMPLEMENTED",
     "rule": "VerifyXvcHash: 'todo: investigate why this gets the correct hash for dev XVCs but fails for retail'.",
     "source": [(X, "LibXboxOne/XVD/XVDFile.cs", "697")], "lab": "OriginalXvcDataHash nao reproduzido", "test": "-"},
    {"id": "N03", "topic": "Assinatura do cabecalho", "status": "NOT_IMPLEMENTED",
     "rule": "O laboratorio nao assina o cabecalho (0x200 bytes de assinatura RSA). A area guarda o marcador "
             "LAB_SYNTHETIC; nenhum console aceitaria estes arquivos.",
     "source": [], "lab": "marcador LAB_SYNTHETIC na area de assinatura", "test": "test_containers"},
    {"id": "N04", "topic": "Sistema de arquivos do drive XVD", "status": "NOT_IMPLEMENTED",
     "rule": "O drive do perfil A guarda o PE cru alinhado em pagina, sem NTFS/exFAT. Simplificacao do laboratorio.",
     "source": [], "lab": "descritor LAB no user data (cifrado) informa offset/tamanho", "test": "-"},
]


def rules_by_status() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for r in RULES:
        out.setdefault(r["status"], []).append(r["id"])
    return out


def as_json() -> dict:
    return {
        "sources": {"xvdtool": XVDTOOL, "XanaduXVD": XANADU},
        "rules": [{**r, "source": [{"repo": s[0], "file": s[1], "lines": s[2]} for s in r["source"]]} for r in RULES],
        "by_status": rules_by_status(),
        "disclaimer": ("Confirmado pelo codigo = comportamento da ferramenta de referencia. Compatibilidade com o "
                       "console Xbox NAO foi demonstrada por teste independente."),
    }
