"""Grafo de evidencia: quem declara qual executavel e onde ele esta.

Consolida: configs em disco, configs do user data do XVC, layout XML,
strings brutas, mapa de arquivos do XVC (SegmentMetadata) e inventario.
Cada candidato traz fontes, evidencia concreta, estado de recuperacao e
grau de confianca CONFIRMED / INFERRED / UNKNOWN.
"""
from __future__ import annotations

from pathlib import Path

CONFIRMED = "CONFIRMED"
INFERRED = "INFERRED"
UNKNOWN = "UNKNOWN"


def xvc_storage_facts(xvc_path: Path, *, target_names: list[str] | None = None) -> dict:
    """Carrega o XVC com o xvcintel (somente leitura) e devolve fatos de armazenamento."""
    from xvcintel.core.reader import FileSource
    from xvcintel.core.result import Ok
    from xvcintel.engines.package import load_package

    src = FileSource(str(xvc_path))
    r = load_package(src)
    from xvcintel.core.result import Ok as _Ok
    if not isinstance(r, _Ok):
        src.close()
        return {"error": str(r.error)}
    pkg = r.value
    rows = []
    for row in pkg.rows:
        rows.append({
            "filename": row.name,
            "segment_index": row.index,
            "absolute_offset": f"0x{row.start:X}",
            "end_offset_exclusive": f"0x{row.end:X}",
            "size": row.size,
            "key_id": row.region.key_id if row.region else None,
            "key_id_guid": str(pkg.xvcinfo.keys[row.region.key_id]) if (row.region and row.region.keyed and row.region.key_id < len(pkg.xvcinfo.keys)) else None,
        })
    facts = {
        "xvc_path": str(Path(xvc_path).resolve()),
        "xvc_size": pkg.size,
        "volume_flags": f"0x{pkg.header.volume_flags:X}" if hasattr(pkg.header, "volume_flags") else None,
        "encryption_disabled_bit": bool(getattr(pkg.header, "encryption_disabled", False)),
        "package_version": getattr(pkg.header, "package_version_str", None),
        "files": rows,
    }
    src.close()
    return facts


def build_candidates(meta_disk: dict, xvc_facts: dict | None, inventory: dict | None = None,
                     disk_dir: Path | None = None) -> dict:
    cands: dict[str, dict] = {}

    def _add(name: str, source: str, detail: str, level: str = CONFIRMED, **extra):
        c = cands.setdefault(name, {"name": name, "sources": [], "evidence": [], "extra": {}})
        c["sources"].append({"source": source, "detail": detail, "level": level})
        c["extra"].update(extra)

    cfgs = meta_disk.get("configs", {})
    gc = cfgs.get("MicrosoftGame.config", {})
    for ex in gc.get("executables", []):
        nm = ex.get("Name")
        if nm:
            _add(nm, "MicrosoftGame.Config (disco)", f"Executable Name={nm} Id={ex.get('Id')} TDF={ex.get('TargetDeviceFamily')} IsDevOnly={ex.get('IsDevOnly')}")
    man = cfgs.get("appxmanifest.xml", {})
    for app in man.get("applications", []):
        nm = app.get("Executable")
        if nm:
            _add(nm, "appxmanifest.xml (disco)", f"Application Executable={nm} Id={app.get('Id')}")
    hive = cfgs.get("microsoft_gameconfig.bin", {})
    for ex in hive.get("executables", []):
        nm = ex.get("Name") or ex.get("ExecutableName")
        if nm:
            _add(nm, "microsoft_gameconfig.bin (hive)", f"Executable key={nm}")
    for fname, parsed in cfgs.items():
        for fg in (parsed.get("file_groups") or []):
            inc = fg.get("Include", "")
            if inc.lower().endswith((".exe", ".dll")):
                _add(Path(inc).name, f"layout:{fname}", f"FileGroup Include={inc} Dest={fg.get('DestinationPath')}", INFERRED,
                     layout_source_path=fg.get("SourcePath"))
    for ref in meta_disk.get("references", [])[:400]:
        txt = ref.get("text", "")
        low = txt.lower()
        if low.endswith(".exe") and len(txt) < 200:
            base = Path(txt.replace("\\", "/")).name
            if base.lower().endswith(".exe") and len(cands.get(base, {}).get("sources", [])) == 0:
                _add(base, f"strings:{ref.get('file', '?')}@0x{ref.get('offset', 0):x}", f"string bruta: {txt[-120:]}", UNKNOWN)

    xvc_files = (xvc_facts or {}).get("files", [])
    for row in xvc_files:
        nm = row["filename"]
        if nm.lower().endswith((".exe", ".dll")):
            _add(nm, "XVC SegmentMetadata + XvcInfo",
                 f"segmento {row['segment_index']} offset {row['absolute_offset']} tamanho {row['size']} KeyId {row['key_id']}",
                 CONFIRMED, xvc_offset=row["absolute_offset"], xvc_size=row["size"], key_id=row["key_id"])

    if inventory:
        for r in inventory.get("files", []):
            nm = r["name"].lower()
            if nm.endswith((".exe", ".dll")):
                disk_copy = {"path": r["path"], "size": r["size"], "format": r["format"],
                             "format_kinds": r.get("format_kinds", [])}
                existing = cands.get(r["name"])
                if existing:
                    existing["extra"]["disk_copy"] = disk_copy
                else:
                    _add(r["name"], "inventario em disco", f"arquivo {r['name']} tamanho {r['size']} formato {r['format']}", CONFIRMED,
                         disk_copy=disk_copy)

    out = []
    for name, c in sorted(cands.items()):
        levels = [s["level"] for s in c["sources"]]
        conf = CONFIRMED if CONFIRMED in levels else (INFERRED if INFERRED in levels else UNKNOWN)
        size_known = None
        for s in c["sources"]:
            pass
        extra = c["extra"]
        xvc_size = extra.get("xvc_size")
        disk = extra.get("disk_copy")
        state = UNKNOWN
        if extra.get("key_id") == 0:
            state = "ENCRYPTED_UNKNOWN(opaco; KeyId 0; sem MZ)"
        if disk:
            kinds = disk.get("format_kinds") or []
            is_pe = any(k.startswith("PE(") for k in kinds)
            if is_pe:
                state = "PLAINTEXT_AVAILABLE_EM_DISCO"
            elif state.startswith("ENCRYPTED"):
                state += " | copia_em_disco_tambem_opaca"
        out.append({
            "name": name,
            "role": ("main_executable" if name.lower().endswith(".exe") else "dependency_dll"),
            "confidence": conf,
            "sources": c["sources"],
            "size_known": {"value": xvc_size or (disk or {}).get("size"), "basis": "XVC SegmentMetadata" if xvc_size else "arquivo em disco"},
            "size_estimated": None,
            "recovery_state": state,
            "details": extra,
        })
    return {
        "schema": "alpha_recovery.executable_candidates/1",
        "note": "tamanhos estimados nunca sao apresentados como confirmados",
        "candidates": out,
    }
