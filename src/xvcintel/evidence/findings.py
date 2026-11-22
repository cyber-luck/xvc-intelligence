"""Constroi os achados (CONFIRMED/INFERRED/UNKNOWN) a partir dos resultados dos motores.

Regra: um achado so e CONFIRMED se o check citado passou contra bytes deste
pacote. Checks amostrados ficam CONFIRMED apenas para o que foi examinado, e o
texto diz a cobertura. Semantica vinda do xvdtool sem verificacao local e INFERRED.
"""
from __future__ import annotations

from ..engines.configs import Configs
from ..engines.package import Package
from ..formats.xvd_header import product_id_storeid_test
from .model import CONFIRMED, FAIL, INFERRED, PARTIAL, PASS, UNKNOWN, CheckResult, Evidence, Finding


def _by_id(checks: list[CheckResult]) -> dict[str, CheckResult]:
    return {c.id: c for c in checks}


def _lvl(c: CheckResult | None, ok_statuses=(PASS, PARTIAL)) -> str:
    if c is None:
        return UNKNOWN
    return CONFIRMED if c.status in ok_statuses else UNKNOWN


def build_findings(pkg: Package, checks: list[CheckResult], profile: dict | None, configs: Configs) -> list[Finding]:
    C = _by_id(checks + pkg.checks)
    h, xi, lay = pkg.header, pkg.xvcinfo, pkg.layout
    F: list[Finding] = []

    def add(fid, cat, stmt, level, ev=(), tests=(), how="", notes=""):
        F.append(Finding(fid, cat, stmt, level, list(ev), list(tests), how, notes))

    # ---------------- cabecalho / layout
    c = C.get("layout.mdu_vs_region")
    add("F-HDR-01", "cabecalho", "MutableDataPageCount fica no byte 0x470 (xvdtool +0x270); vale "
        f"{h.mutable_data_page_count} e coincide com o comprimento da regiao XVC-MDU. O probe antigo lia 0x5E0 (errado).",
        _lvl(c), [Evidence("xvc:cabecalho", "MutableDataPageCount", 0x470, str(h.mutable_data_page_count), "layout.mdu_vs_region")],
        ["layout.mdu_vs_region", "layout.xvcinfo_anchor"], "Refutado se XVC-MDU.Length != 0x470 * 0x1000 em outro pacote.")
    add("F-HDR-02", "cabecalho", f"Layout calculado do cabecalho fecha exatamente com o tamanho do arquivo "
        f"(fim 0x{lay.end:X}) e as regioes XVC-HD/EXVD/MDU/MD coincidem com ele.",
        CONFIRMED if C.get("layout.end_equals_size") and C["layout.end_equals_size"].passed and
        C.get("layout.regions_match") and C["layout.regions_match"].passed else UNKNOWN,
        tests=["layout.end_equals_size", "layout.regions_match", "layout.hash_tree_size"])
    add("F-HDR-03", "cabecalho", f"PackageVersion (0x3BC, 4 x u16 = {h.package_version}) lido em ordem inversa = "
        f"{h.package_version_str}, igual ao Identity@Version do MicrosoftGame.config.",
        CONFIRMED if (configs.game_config.get("Identity") or {}).get("Version") == h.package_version_str else UNKNOWN,
        [Evidence("xvc:cabecalho", "PackageVersion", 0x3BC, str(h.package_version))], ["fingerprint.package_version"])
    pls = configs.game_config.get("PersistentLocalStorageSizeMB")
    add("F-HDR-04", "cabecalho", f"PersistentLocalStorageSize (0x46C) = {h.persistent_local_storage_size} == SizeMB do "
        f"MicrosoftGame.config ({pls}).", CONFIRMED if pls == h.persistent_local_storage_size else UNKNOWN,
        [Evidence("xvc:cabecalho", "PersistentLocalStorageSize", 0x46C, str(h.persistent_local_storage_size))],
        ["fingerprint.pls"])
    add("F-HDR-05", "cabecalho", f"VolumeFlags 0x{h.volume_flags:X} = {'|'.join(h.flag_names)} (nomes do enum do "
        "xvdtool). O bit EncryptionDisabled nao esta setado.", INFERRED,
        [Evidence("xvc:cabecalho", "VolumeFlags", 0x208, f"0x{h.volume_flags:X}"), Evidence("xvdtool", "XvdVolumeFlags")],
        how="Confirmaria com um XVD de conteudo conhecido com EncryptionDisabled setado (bytes legiveis) e outro sem.",
        notes="valor do campo CONFIRMED; significado dos bits vem do xvdtool (INFERRED)")
    mv = h.min_sys_version
    add("F-HDR-06", "cabecalho", f"0x494..0x49B (xvdtool MinSysVersion) = {tuple(hex(x) for x in mv)}; lendo em ordem "
        f"inversa como o PackageVersion: 0x{mv[3]:X}.{mv[2]}.{mv[1]}.{mv[0]} (26100 = 0x65F4 coincide com a familia do "
        f"GDKVersion {(configs.summary.get('PackageFeatures') or {}).get('GDKVersion')}). O bit alto 0x8000 do primeiro "
        "componente e o valor 0x0A sem ele (=10) sugerem 10.0.26100.x, mas o significado do bit e desconhecido.",
        INFERRED, [Evidence("xvc:cabecalho", "MinSysVersion", 0x494)],
        how="Comparar com outro pacote/GDK conhecido; o XVD embutido tem o mesmo padrao em 0x3BC.")
    zero = {n: not any(v) for n, v in (("KeyMaterial", h.key_material), ("UserDataHash", h.user_data_hash),
                                         ("SandboxId", h.sandbox_id), ("PECatalogCaps", h.pe_catalog_caps),
                                         ("PECatalogs", h.pe_catalogs))}
    add("F-HDR-07", "cabecalho", f"Unknown471 (0x471) = 0x{h.unknown_471:X}; campos zerados: "
        + ", ".join(f"{k}={'zero' if v else 'nao-zero'}" for k, v in zero.items()) + ".", CONFIRMED,
        [Evidence("xvc:cabecalho", "Unknown471", 0x471, f"0x{h.unknown_471:X}")], ["test_headers.py"],
        how="Significado de 0x471 UNKNOWN: comparar com outros pacotes (o XVD embutido tem 0).",
        notes="significado de 0x471 UNKNOWN")
    if configs.game_config.get("StoreId"):
        t = product_id_storeid_test(h.product_id, configs.game_config["StoreId"])
        add("F-HDR-08", "cabecalho", f"ProductId (0x39C) {t['product_id']} contem os 12 caracteres ASCII do StoreId "
            f"{t['store_id']} em ordem: [0:7]='{t['store_id'][:7]}' e [9:14]='{t['store_id'][7:]}'; bytes 7-8 = "
            f"{t['bytes_7_8']} e 14-15 = {t['bytes_14_15']} nao sao ASCII.",
            CONFIRMED if t["contains_all_12_in_order_split_7_5"] else UNKNOWN,
            [Evidence("xvc:cabecalho", "ProductId", 0x39C, t["product_id"]), Evidence("userdata:MicrosoftGame.config", "StoreId")],
            ["test_headers.py::test_product_id_storeid"],
            "Hipotese de codificacao (GUID bytes_le com nibble de versao 3 em byte 7 e variante 0b110 em byte 8) "
            "fica INFERRED; confirmaria com outro pacote cujo StoreId seja conhecido.",
            notes=f"leitura como GUID: {t['as_guid']} (versao {t['guid_version_nibble']}, variante {t['guid_variant_bits']}) - INFERRED")

    # ---------------- arvore de hashes
    g = lay.geometry
    add("F-HT-01", "hash tree", f"Geometria do xvdtool confirmada: {lay.hashed_pages} paginas hasheadas "
        f"(drive + user data + XvcInfo + dynamic header), niveis L0..L{g.levels - 1} = {list(g.level_pages)}, "
        f"topo gravado primeiro (inicios {[g.level_start(i) for i in range(g.levels)]}).",
        CONFIRMED if C.get("layout.hash_tree_size", None) and C["layout.hash_tree_size"].passed else UNKNOWN,
        tests=["layout.hash_tree_size", "test_hashtree.py"])
    add("F-HT-02", "hash tree", "SHA-256(pagina 0 da arvore) == TopHashBlockHash (0x240).", _lvl(C.get("integrity.top_hash")),
        tests=["integrity.top_hash"])
    links = [cc for cid, cc in C.items() if cid.startswith("integrity.link_")]
    add("F-HT-03", "hash tree", "SHA-256(pagina filha)[:0x18] == entrada do pai em todos os niveis. Cobertura: "
        + "; ".join(f"{cc.id.split('.')[-1]} {cc.detail} ({cc.coverage})" for cc in links),
        CONFIRMED if links and all(cc.status in (PASS, PARTIAL) for cc in links) else UNKNOWN,
        tests=[cc.id for cc in links])
    c = C.get("integrity.leaf_vs_data")
    add("F-HT-04", "hash tree", "Folhas: em regioes com KeyId != 0xFFFF, entry[:0x14] == SHA-256(pagina gravada)[:0x14] "
        "e entry[0x14:0x18] e um u32 separado; em regioes 0xFFFF e metadados, entry == SHA-256[:0x18]. "
        + (c.detail + " - " + c.coverage if c else ""), _lvl(c), tests=["integrity.leaf_vs_data"],
        how="Amostrado; a varredura completa das folhas contra L1 e feita por --full-leaf.")
    add("F-HT-05", "hash tree", "O u32 em entry[0x14:0x18] e a 'unidade de dados' usada como tweak XTS (xvdtool). "
        "Nao verificado aqui (exigiria chave); documentado apenas como estrutura.", INFERRED,
        [Evidence("xvdtool", "XVDFile.CryptSectionXts")],
        how="Nao testavel sem chave (fora do escopo por regra). O que e testavel - a relacao com a tabela de "
            "paginas - esta em F-PT-02.")

    # ---------------- tabela de paginas
    c1, c2, c3 = C.get("pages.value_eq_leaf_du"), C.get("pages.rle_model"), C.get("pages.no_redundant_entries")
    add("F-PT-01", "tabela de paginas", "Tabela (u32 PageNum, u32 Value) em XvcInfo apos o array por segmento: "
        + (c1.detail if c1 else ""), _lvl(c1), tests=["pages.value_eq_leaf_du"])
    rle_level = UNKNOWN
    if c2 and c2.status == PASS:
        rle_level = CONFIRMED
    elif c2 and c2.status == PARTIAL:
        rle_level = CONFIRMED
    add("F-PT-02", "tabela de paginas", "A tabela e uma codificacao run-length das unidades de dados: para toda pagina "
        "de regiao com KeyId, unidade(p) = Value + (p - PageNum) da entrada que governa p. "
        + (f"{c2.detail}. Cobertura: {c2.coverage}" if c2 else ""), rle_level, tests=["pages.rle_model"],
        how="Refutado por qualquer pagina com KeyId que nao siga a regra (--full-pages varre todas).",
        notes="as unicas excecoes esperadas sao paginas de regioes 0xFFFF, onde entry[0x14:0x18] faz parte do hash")
    add("F-PT-03", "tabela de paginas", "Nenhuma entrada redundante (codificacao minima). " + (c3.detail if c3 else ""),
        _lvl(c3), tests=["pages.no_redundant_entries"])
    c = C.get("pages.data_unit_reuse")
    if c:
        add("F-PT-04", "tabela de paginas", "Unidades de dados NAO sao unicas por pagina dentro de uma regiao: " + c.detail,
            CONFIRMED if c.counts.get("pairs_same_du") else UNKNOWN, tests=["pages.data_unit_reuse"],
            how="Contagem derivada do modelo RLE (F-PT-02); pares conferidos diretamente nas folhas.",
            notes="o motivo e UNKNOWN; hipotese: valores herdados de versoes anteriores do pacote (atualizacao por "
                  "paginas) - testavel comparando com outra versao do mesmo titulo")
    c = C.get("pages.transitions")
    if c:
        add("F-PT-05", "tabela de paginas", "Entre entradas consecutivas da mesma regiao, Value volta para tras em "
            f"{c.counts['backward']} casos e salta para frente em {c.counts['forward']}.", CONFIRMED,
            tests=["pages.transitions"])
    c = C.get("pages.segment_values")
    if c:
        add("F-PT-06", "XvcInfo", "Array u32 por segmento (logo apos os update segments; xvdtool nao o le) == unidade de "
            "dados da 1a pagina do segmento em " + c.detail.split(";")[0], CONFIRMED, tests=["pages.segment_values"])
        for e in c.data.get("exceptions", []):
            add(f"F-PT-07-seg{e['segment']}", "XvcInfo",
                f"Excecao no segmento {e['segment']} ({e['file']}): valor {e['value']}, unidade da 1a pagina "
                f"{e['du_first_page']} (diferenca {e['value_minus_du']:+d}); nao e unidade+1 da pagina anterior "
                f"({e['du_previous_page']}); nao aparece como unidade em +/-janela ({e['window_pages_with_du_eq_value']}) "
                f"nem dentro de nenhuma sequencia da tabela ({e['value_in_any_run']}).",
                UNKNOWN, [Evidence("xvc:XvcInfo", f"segment value [{e['segment']}]",
                                   xi.base_offset + xi.segval_off + 4 * e["segment"], e["value"])],
                ["pages.segment_values"],
                "Proximo teste: comparar com o mesmo arquivo em outra versao do pacote; testar se o valor e uma "
                "unidade de dados 'virtual' anterior a uma pagina removida.",
                notes="fato da divergencia CONFIRMED; causa UNKNOWN")

    # ---------------- regioes / segmentos
    c = C.get("integrity.region_hash")
    if c:
        add("F-RG-01", "regioes", "Hash de regiao (8 bytes em +0x60, xvdtool 'aka RegionPDUID', nao calculado pelo "
            "xvdtool) == SHA-256(bytes gravados da regiao)[:8]: " + c.detail, _lvl(c), tests=["integrity.region_hash"],
            how="Regioes acima do limite nao foram calculadas; aumentar --cap-mb para testa-las.")
        add("F-RG-02", "regioes", "Hash da regiao XVC-EXVD == EmbeddedXVD_PDUID[:8] (e PDUID do XVD embutido).",
            CONFIRMED if any(r.get("desc") == "XVC-EXVD" and r.get("match") for r in c.data["regions"]) else UNKNOWN,
            tests=["integrity.region_hash", "embedded.pduid_link"])
    c = C.get("hypothesis.metadata_hash")
    if c:
        add("F-RG-03", "regioes", "XVC-HD e XVC-MD compartilham o mesmo hash de regiao; nenhuma das "
            f"{len(c.data.get('results', []))} serializacoes testadas (incl. VerifyXvcHash do xvdtool) reproduz esse "
            "valor nem o OriginalXvcDataHash.", UNKNOWN, tests=["hypothesis.metadata_hash"],
            how="Hipoteses refutadas listadas em hypothesis.metadata_hash; proximo candidato: hash sobre a versao "
                "'pre-hash-tree' do pacote inteiro de metadados (nao reproduzivel sem o empacotador).")
    c = C.get("integrity.segment_hash")
    if c:
        add("F-SG-01", "segmentos", "Hash do update segment (+4, 8 bytes) == SHA-256(paginas gravadas do segmento ate o "
            "proximo segmento ou fim da regiao)[:8]: " + c.detail, _lvl(c), tests=["integrity.segment_hash"],
            how="Segmentos acima do limite nao testados: a regra fica INFERRED para eles.")
    if xi:
        add("F-RG-04", "regioes", "Flags de regiao observadas: metadados 0x1, conteudo 0x0, regiao InitialPlay "
            f"(0x{xi.fields['InitialPlayRegionId']:X}) 0x"
            f"{(xi.region_by_id(xi.fields['InitialPlayRegionId']).flags if xi.region_by_id(xi.fields['InitialPlayRegionId']) else 0):X}"
            ". Pelo enum do xvdtool 0x4 seria Preview e InitialPlay seria 0x2: os nomes do enum nao batem com o uso aqui.",
            UNKNOWN, tests=["test_formats.py::test_xvcinfo_regions"],
            how="Comparar flags de regiao em pacotes com PreviewRegionId != 0 ou com mais regioes InitialPlay.",
            notes="valores CONFIRMED; significado UNKNOWN")
        ip = xi.fields["InitialPlayOffset"]
        rr = xi.region_by_id(xi.fields["InitialPlayRegionId"])
        add("F-RG-05", "XvcInfo", f"InitialPlayOffset (0xD28) = 0x{ip:X} == fim da regiao InitialPlay == tamanho do arquivo.",
            CONFIRMED if rr and ip == rr.end == pkg.size else UNKNOWN,
            [Evidence("xvc:XvcInfo", "InitialPlayOffset", xi.field_abs("InitialPlayOffset"), f"0x{ip:X}")],
            how="Pacote com regiao InitialPlay que nao seja a ultima diria se o campo e 'fim da regiao' ou 'fim do arquivo'.",
            notes="significado (fim da parte jogavel inicial?) INFERRED")
        add("F-XI-01", "XvcInfo", f"RegionSpecifierCount (0xD50) = {xi.fields['RegionSpecifierCount']}; PageTableCount "
            f"(0xD54, 'ReservedD54' no xvdtool) = {xi.fields['PageTableCount']}; a tabela fecha em +0x{xi.tail_off:X} e o "
            "resto do XvcInfo e zero.", CONFIRMED if xi.tail_nonzero == 0 else UNKNOWN, tests=["xvcinfo.struct.10"])

    # ---------------- user data / arquivos
    fm_ok = pkg.file_checks and all(ok for _, ok, _ in pkg.file_checks)
    add("F-FM-01", "arquivos", f"{len(pkg.rows)} arquivos do SegmentMetadata.bin mapeados 1:1 para segmentos e regioes; "
        "todas as checagens de intervalo passaram.", CONFIRMED if fm_ok else UNKNOWN,
        tests=["filemap"] + [n for n, _, _ in pkg.file_checks])
    if pkg.segmeta and pkg.userdata and xi:
        gid = pkg.segmeta.guid
        needles = (gid.bytes_le, gid.bytes)
        hdr = pkg.src.read_at(0, 0x3000)
        xraw = pkg.src.read_at(xi.base_offset, xi.length)
        others = b"".join(f.data for f in pkg.userdata.files if f.path != "SegmentMetadata.bin")
        hits = {name: any(n in blob for n in needles) for name, blob in
                (("cabecalho", hdr), ("XvcInfo", xraw), ("outros arquivos do user data (inclui hive)", others))}
        add("F-FM-02", "arquivos", f"GUID do SegmentMetadata ({gid}) procurado (bytes_le e big-endian): "
            + ", ".join(f"{k}={'encontrado' if v else 'ausente'}" for k, v in hits.items()) + ".",
            CONFIRMED, tests=["findings: busca de bytes"], notes="significado do GUID UNKNOWN")

    # ---------------- XVD embutido
    eh = pkg.embedded_header
    if eh:
        add("F-EX-01", "XVD embutido", f"A regiao XVC-EXVD contem um segundo XVD legivel pelo mesmo parser: ContentType "
            f"{eh.content_type} ({eh.content_type_name} no enum do xvdtool), Type {eh.type} ({eh.type_name}), DriveSize "
            f"0x{eh.drive_size:X}, VolumeFlags 0x{eh.volume_flags:X}.", CONFIRMED if C.get("embedded.top_hash") and
            C["embedded.top_hash"].passed else INFERRED, tests=["embedded.top_hash", "embedded.link_L0_L1"],
            how="Nomes de enum: so confirmaveis com documentacao oficial; layout: top hash/link/folha ja testados.",
            notes="nomes dos enums INFERRED; o layout calculado da arvore do embutido confere (top hash)")
        add("F-EX-02", "XVD embutido", "O fim do layout calculado do XVD embutido nao fecha com EmbeddedXVDLength "
            "(XVD dinamico: o drive data so ocupa os blocos alocados).", UNKNOWN,
            how="Decodificar a BAT do dynamic header (0xCCC bytes) e conferir os blocos alocados.")
        c = C.get("embedded.user_data_hash")
        if c:
            add("F-EX-03", "XVD embutido", "UserDataHash do XVD embutido nao e SHA-256 dos bytes gravados do seu user data.",
                UNKNOWN if c.status != PASS else CONFIRMED, tests=["embedded.user_data_hash"],
                how="Hipotese restante (hash do conteudo decifrado) nao e testavel sem chave.")

    # ---------------- executavel
    if profile and "error" not in profile:
        st, ig = profile["storage"], profile["integrity"]
        add("F-EXE-01", "executavel", f"game_scarlett_master.exe: segmento {st['segment_index']['value']}, regiao "
            f"{st['region_id']['value']} (regiao de um unico arquivo), KeyId {st['key_id_index']['value']}, offset "
            f"{st['absolute_offset']['value']}, {st['size']['value']} bytes, {st['page_table_entries_in_segment']['value']} "
            "entrada(s) na tabela de paginas (uma unica sequencia de unidades de dados).", CONFIRMED,
            tests=["filemap", "fingerprint"])
        seg = ig.get("segment_hash", {})
        add("F-EXE-02", "executavel", f"Bytes gravados do executavel: SHA-256 {ig.get('sha256_stored_bytes', {}).get('value')}; "
            f"hash de segmento e de regiao conferem ({seg.get('value')}). Isto identifica os bytes cifrados/gravados, "
            "nao o PE.", seg.get("level", UNKNOWN), tests=["integrity.segment_hash", "fingerprint"])
        add("F-EXE-03", "executavel", "Os bytes gravados nao tem MZ/PE; imports, exports, secoes, entry point e funcoes "
            "do executavel sao UNKNOWN. Os nomes das 16 DLLs do pacote nao sao evidencia de import.", UNKNOWN,
            tests=["fingerprint"], how="Requer um PE legivel obtido legitimamente (ver docs/pt/pe-requisitos.md).")
        cat = profile.get("code_catalog")
        if cat:
            add("F-EXE-04", "executavel", f"Catalog000.bin (PE {cat['pe_subsystem']}) nao contem o SHA-256/SHA-1 dos bytes "
                f"gravados do executavel, nem o hash de segmento; SHA-256 do catalogo == PECatalogHash: "
                f"{cat['sha256_catalog_equals_PECatalogHash']}.", CONFIRMED, tests=["fingerprint"],
                how="Com um PE legivel do executavel: procurar seus hashes (SHA-1/SHA-256/Authenticode) no catalogo.",
                notes="relacao entre o catalogo e o executavel UNKNOWN")
    return F
