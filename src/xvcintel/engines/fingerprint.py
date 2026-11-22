"""Perfil individual de um executavel do pacote (por padrao game_scarlett_master.exe).

Separa rigidamente:
  - metadados de armazenamento/identidade (verificaveis contra bytes do pacote);
  - conteudo do executavel (imports, exports, secoes, codigo): UNKNOWN enquanto os
    bytes gravados nao forem um PE legivel. Nomes de DLLs distribuidas NAO sao imports.
"""
from __future__ import annotations

import hashlib
import random

from ..core.result import Ok
from ..core.util import PAGE, entropy
from ..evidence.model import CONFIRMED, INFERRED, UNKNOWN
from ..formats.hashtree import sha256
from ..formats.layout import DRIVE
from ..formats.pe import parse_pe
from .configs import Configs, load_configs
from .package import Package
from .treeio import TreeReader

DEFAULT_TARGET = "game_scarlett_master.exe"


def _field(value, level: str, source: str, test: str | None = None) -> dict:
    return {"value": value, "level": level, "source": source, "test": test}


def fingerprint_executable(pkg: Package, name: str = DEFAULT_TARGET, cap_bytes: int = 160 * 1024 * 1024,
                           leaf_samples: int = 16, seed: int = 1234, configs: Configs | None = None) -> dict:
    row = pkg.row(name)
    if row is None:
        return {"target": name, "error": "arquivo nao encontrado no SegmentMetadata"}
    xi, h = pkg.xvcinfo, pkg.header
    cfg = configs or load_configs(pkg)
    reg = row.region
    seg = xi.segments[row.index]
    seg_end = xi.segment_end(row.index, pkg.size)
    prof: dict = {"target": name, "schema": "xvcintel.executable_profile/1"}

    # ---------------- identidade (configs do pacote)
    gc_ex = next((e for e in cfg.game_config.get("executables", []) if e.get("Name", "").casefold() == name.casefold()), None)
    man_app = next((a for a in cfg.manifest.get("applications", []) if a.get("Executable", "").casefold() == name.casefold()), None)
    hv_ex = next((e for e in cfg.hive.get("executables", []) if str(e.get("Name", "")).casefold() == name.casefold()), None)
    ident_consistent = bool(gc_ex and man_app and hv_ex) and len({gc_ex.get("Id"), man_app.get("Id"), hv_ex.get("Id")}) == 1
    pv_cfg = (cfg.game_config.get("Identity") or {}).get("Version")
    prof["identity"] = {
        "declared_in_MicrosoftGame.config": _field(gc_ex, CONFIRMED if gc_ex else UNKNOWN, "userdata:MicrosoftGame.config"),
        "declared_in_appxmanifest": _field(man_app, CONFIRMED if man_app else UNKNOWN, "userdata:appxmanifest.xml"),
        "declared_in_gameconfig_hive": _field(hv_ex, CONFIRMED if hv_ex else UNKNOWN, "userdata:microsoft_gameconfig.bin"),
        "application_id_consistent_across_3_configs": _field(ident_consistent, CONFIRMED if ident_consistent else UNKNOWN,
                                                              "3 configs", "fingerprint.identity"),
        "TitleId": _field(cfg.game_config.get("TitleId"), CONFIRMED, "userdata:MicrosoftGame.config"),
        "StoreId": _field(cfg.game_config.get("StoreId"), CONFIRMED, "userdata:MicrosoftGame.config"),
        "MSAAppId": _field(cfg.game_config.get("MSAAppId"), CONFIRMED, "userdata:MicrosoftGame.config"),
        "package_identity": _field(cfg.game_config.get("Identity"), CONFIRMED, "userdata:MicrosoftGame.config"),
        "package_version_header_vs_config": _field(
            {"header_0x3BC": h.package_version_str, "config": pv_cfg},
            CONFIRMED if pv_cfg == h.package_version_str else UNKNOWN, "xvc:cabecalho 0x3BC x MicrosoftGame.config",
            "fingerprint.package_version"),
    }

    # ---------------- armazenamento
    t_entries = [(p, v) for p, v in xi.page_table if seg.page <= p < seg_end // PAGE]
    prof["storage"] = {
        "segment_index": _field(row.index, CONFIRMED, "SegmentMetadata.bin + XvcInfo", "filemap"),
        "region_id": _field(f"0x{reg.id:X}" if reg else None, CONFIRMED, "XvcInfo regiao", "filemap"),
        "region_offset": _field(f"0x{reg.offset:X}", CONFIRMED, "XvcInfo regiao +0x50"),
        "region_length": _field(f"0x{reg.length:X}", CONFIRMED, "XvcInfo regiao +0x58"),
        "region_flags": _field(f"0x{reg.flags:X}", CONFIRMED, "XvcInfo regiao +0x8"),
        "region_is_single_file": _field(len(xi.region_segments(reg)) == 1, CONFIRMED, "XvcInfo"),
        "key_id_index": _field(reg.key_id, CONFIRMED, "XvcInfo regiao +0x4"),
        "key_id_guid": _field(str(xi.keys[reg.key_id]) if reg.keyed and reg.key_id < len(xi.keys) else None,
                              CONFIRMED, "XvcInfo +0x10 (identificador da chave; nenhuma chave usada)"),
        "absolute_offset": _field(f"0x{row.start:X}", CONFIRMED, "drive data (layout do cabecalho) + pagina do SegmentMetadata"),
        "end_offset_exclusive": _field(f"0x{row.end:X}", CONFIRMED, "offset + Size"),
        "size": _field(row.size, CONFIRMED, "SegmentMetadata.bin"),
        "pages": _field((row.size + PAGE - 1) // PAGE, CONFIRMED, "Size / 0x1000"),
        "relative_page": _field(f"0x{row.relative_page:X}", CONFIRMED, "SegmentMetadata.bin"),
        "segment_slack_bytes": _field(row.slack, CONFIRMED, "segmento x paginas do arquivo"),
        "page_table_entries_in_segment": _field(len(t_entries), CONFIRMED, "XvcInfo tabela de paginas"),
        "segment_value_u32": _field(f"0x{xi.segment_values[row.index]:08X}" if xi.segment_values else None,
                                    CONFIRMED, "XvcInfo array por segmento"),
    }

    # ---------------- integridade
    integ: dict = {}
    seg_len = seg_end - seg.offset
    if row.size <= cap_bytes:
        hs, h1 = hashlib.sha256(), hashlib.sha1()
        n = 0
        for blob in pkg.src.iter_chunks(row.start, row.size):
            hs.update(blob)
            h1.update(blob)
            n += len(blob)
        integ["sha256_stored_bytes"] = _field(hs.hexdigest(), CONFIRMED if n == row.size else UNKNOWN,
                                              f"SHA-256 dos {n} bytes gravados (nao e hash do PE decifrado)")
        integ["sha1_stored_bytes"] = _field(h1.hexdigest(), CONFIRMED if n == row.size else UNKNOWN, "SHA-1 dos bytes gravados")
    else:
        integ["sha256_stored_bytes"] = _field(None, UNKNOWN, f"pulado: tamanho {row.size} > limite {cap_bytes}")
    if seg_len <= cap_bytes:
        d, n = pkg.src.sha256_range(seg.offset, seg_len)
        ok = d[:8] == seg.hash and n == seg_len
        integ["segment_hash"] = _field({"stored": seg.hash.hex(), "computed": d[:8].hex(), "match": ok},
                                       CONFIRMED if ok else UNKNOWN, "XvcInfo update segment +4", "integrity.segment_hash")
        if reg and len(xi.region_segments(reg)) == 1 and reg.offset == seg.offset and reg.length == seg_len:
            okr = d[:8] == reg.hash
            integ["region_hash"] = _field({"stored": reg.hash.hex(), "match": okr}, CONFIRMED if okr else UNKNOWN,
                                          "XvcInfo regiao +0x60 (regiao = segmento)", "integrity.region_hash")
    else:
        integ["segment_hash"] = _field(None, UNKNOWN, f"pulado: segmento {seg_len} > limite {cap_bytes}")
    tr = TreeReader(pkg.src, pkg.layout)
    first_p, last_p = row.start // PAGE, (row.end - 1) // PAGE
    rnd = random.Random(seed)
    picks = sorted({first_p, last_p, (first_p + last_p) // 2} |
                   {rnd.randint(first_p, last_p) for _ in range(max(0, leaf_samples - 3))})
    leaf_ok = 0
    for p in picks:
        e = tr.leaf_for_page(p)
        if e[:0x14] == sha256(pkg.src.read_at(p * PAGE, PAGE))[:0x14]:
            leaf_ok += 1
    integ["leaf_hashes_sampled"] = _field(f"{leaf_ok}/{len(picks)}", CONFIRMED if leaf_ok == len(picks) else UNKNOWN,
                                          f"amostra de {len(picks)} paginas (semente {seed}); entry[:0x14]",
                                          "integrity.leaf_vs_data")
    integ["first_page_leaf_entry_offset"] = _field(f"0x{tr.leaf_offset(first_p):X}", CONFIRMED, "geometria da hash tree")
    integ["first_page_data_unit"] = _field(f"0x{tr.data_unit(first_p):08X}", CONFIRMED,
                                           "entry[0x14:0x18]; significado (unidade XTS) INFERRED do xvdtool")
    prof["integrity"] = integ

    # ---------------- conteudo (somente o que os bytes gravados mostram)
    head = pkg.src.read_at(row.start, min(0x10000, row.size))
    windows = []
    if row.size > 0x10000:
        for i in range(16):
            off = row.start + (row.size - 0x10000) * i // 15
            windows.append(round(entropy(pkg.src.read_at(off, 0x10000)), 4))
    pe_try = parse_pe(head, deep=False)
    prof["stored_content"] = {
        "first_16_bytes_hex": _field(head[:16].hex(" "), CONFIRMED, "bytes gravados"),
        "mz_signature_at_0": _field(head[:2] == b"MZ", CONFIRMED, "bytes gravados"),
        "pe_parse": _field("PE valido" if isinstance(pe_try, Ok) else str(pe_try.error), CONFIRMED, "formats.pe.parse_pe"),
        "entropy_first_64kb": _field(round(entropy(head), 4), CONFIRMED, "amostra"),
        "entropy_16_windows_64kb": _field(windows, CONFIRMED, "16 janelas de 64 KB espalhadas"),
        "encryption_inference": _field("regiao com KeyId != 0xFFFF e bytes sem estrutura reconhecivel; consistente com "
                                       "conteudo cifrado, mas entropia nao prova criptografia",
                                       INFERRED, "KeyId + entropia + flags do cabecalho (EncryptionDisabled ausente)"),
    }
    unknown = "UNKNOWN: os bytes gravados nao formam um PE legivel (sem MZ); nada pode ser afirmado"
    prof["pe_content"] = {k: _field(None, UNKNOWN, unknown) for k in
                          ("machine", "sections", "entry_point", "imports", "exports", "resources", "debug_pdb",
                           "tls", "load_config", "functions", "strings", "compiler_linker")}

    # ---------------- DLLs distribuidas (somente nomes)
    dlls = []
    for r in pkg.rows:
        if r.name.lower().endswith(".dll"):
            dlls.append({"name": r.name, "segment": r.index, "region": f"0x{r.region.id:X}" if r.region else None,
                         "size": r.size, "key_id": r.region.key_id if r.region else None})
    prof["co_packaged_dlls"] = {
        "level": CONFIRMED, "source": "SegmentMetadata.bin",
        "note": "apenas presenca no mesmo pacote; NAO prova que o executavel importa estas DLLs",
        "items": dlls}

    # ---------------- inicializacao
    prof["launch_config"] = {
        "appx_entry_point": _field(man_app.get("EntryPoint") if man_app else None, CONFIRMED if man_app else UNKNOWN,
                                   "appxmanifest.xml Application@EntryPoint"),
        "target_device_family": _field(gc_ex.get("TargetDeviceFamily") if gc_ex else None, CONFIRMED if gc_ex else UNKNOWN,
                                       "MicrosoftGame.config"),
        "is_dev_only": _field(gc_ex.get("IsDevOnly") if gc_ex else None, CONFIRMED if gc_ex else UNKNOWN, "MicrosoftGame.config"),
        "virtual_machine": _field(cfg.game_config.get("virtual_machine"), CONFIRMED, "MicrosoftGame.config"),
        "persistent_local_storage_MB": _field(
            {"config": cfg.game_config.get("PersistentLocalStorageSizeMB"), "header_0x46C": h.persistent_local_storage_size},
            CONFIRMED if cfg.game_config.get("PersistentLocalStorageSizeMB") == h.persistent_local_storage_size else UNKNOWN,
            "MicrosoftGame.config x cabecalho 0x46C", "fingerprint.pls"),
        "protocols": _field(cfg.manifest.get("protocols"), CONFIRMED, "appxmanifest.xml"),
        "dependencies": _field(cfg.manifest.get("dependencies"), CONFIRMED, "appxmanifest.xml"),
        "capabilities": _field(cfg.manifest.get("capabilities"), CONFIRMED, "appxmanifest.xml"),
        "gdk_version": _field((cfg.summary.get("PackageFeatures") or {}).get("GDKVersion"), CONFIRMED, "Summary.json"),
    }

    # ---------------- catalogo de codigo
    cat_row = next((r for r in pkg.rows if r.name.lower().startswith("catalog") and r.name.lower().endswith(".bin")), None)
    if cat_row:
        cat = pkg.src.read_at(cat_row.start, cat_row.size) if cat_row.size <= cap_bytes else b""
        probes = {}
        if "sha256_stored_bytes" in integ and integ["sha256_stored_bytes"]["value"]:
            probes["sha256_stored_exe"] = bytes.fromhex(integ["sha256_stored_bytes"]["value"])
            probes["sha1_stored_exe"] = bytes.fromhex(integ["sha1_stored_bytes"]["value"])
        probes["PECatalogHash_header"] = h.pe_catalog_hash
        probes["segment_hash_exe"] = seg.hash
        found = {k: (v in cat) for k, v in probes.items()}
        cat_pe = parse_pe(cat) if cat else None
        prof["code_catalog"] = {
            "file": cat_row.name, "segment": cat_row.index,
            "pe_subsystem": (cat_pe.value.subsystem_name if isinstance(cat_pe, Ok) else None),
            "sha256_catalog": hashlib.sha256(cat).hexdigest() if cat else None,
            "sha256_catalog_equals_PECatalogHash": hashlib.sha256(cat).digest() == h.pe_catalog_hash if cat else None,
            "byte_search_in_catalog": found,
            "level": CONFIRMED,
            "note": "busca de bytes exatos; ausencia nao exclui que o catalogo descreva o executavel (pode usar hash "
                    "do conteudo decifrado ou outro formato)",
        }
    return prof


def profile_lines(prof: dict) -> list[str]:
    out = [f"== perfil do executavel: {prof.get('target')}"]
    if "error" in prof:
        return out + [f"   ! {prof['error']}"]
    for section in ("identity", "storage", "integrity", "stored_content", "launch_config", "pe_content"):
        out.append(f"-- {section}")
        for k, f in prof[section].items():
            v = f["value"]
            if isinstance(v, (dict, list)):
                v = str(v)
                v = v if len(v) < 160 else v[:157] + "..."
            out.append(f"   [{f['level']:<9}] {k:<44} {v}")
    out.append(f"-- DLLs no mesmo pacote ({len(prof['co_packaged_dlls']['items'])}): "
               + ", ".join(d["name"] for d in prof["co_packaged_dlls"]["items"]))
    out.append(f"   nota: {prof['co_packaged_dlls']['note']}")
    if "code_catalog" in prof:
        c = prof["code_catalog"]
        out.append(f"-- catalogo {c['file']}: subsystem {c['pe_subsystem']}; SHA-256 == PECatalogHash: "
                   f"{c['sha256_catalog_equals_PECatalogHash']}; busca de bytes: {c['byte_search_in_catalog']}")
    return out
