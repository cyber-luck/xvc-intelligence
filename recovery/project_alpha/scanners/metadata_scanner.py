"""Fase 2: metadados declarativos (configs, manifest, hive, layout) e strings.

Reutiliza os parsers do xvcintel (configs.py, regf.py) sobre arquivos em
disco. Nenhuma string bruta e tratada como caminho valido de registro.
"""
from __future__ import annotations

import re
from pathlib import Path

from _bootstrap import read_head, load_bin_pe_recovery

_bpr = load_bin_pe_recovery()


def scan_metadata_dir(d: Path) -> dict:
    d = Path(d)
    out: dict = {"dir": str(d.resolve()), "configs": {}, "references": [], "problems": []}
    gc = d / "MicrosoftGame.Config"
    if gc.is_file():
        from xvcintel.engines.configs import parse_game_config
        out["configs"]["MicrosoftGame.config"] = parse_game_config(read_head(gc, 1 << 20))
    man = d / "appxmanifest.xml"
    if man.is_file():
        from xvcintel.engines.configs import parse_manifest
        out["configs"]["appxmanifest.xml"] = parse_manifest(read_head(man, 4 << 20))
    hive = d / "microsoft_gameconfig.bin"
    if hive.is_file():
        from xvcintel.engines.configs import parse_hive_config
        out["configs"]["microsoft_gameconfig.bin"] = parse_hive_config(read_head(hive, 32 << 20))
    layout_files = sorted(d.glob("layout_*.xml")) + sorted(d.glob("*.layout.xml"))
    for lf in layout_files:
        out["configs"][lf.name] = parse_layout_xml(read_head(lf, 8 << 20))
    for f in sorted(d.iterdir()):
        if not f.is_file() or f.stat().st_size > 512 << 20:
            continue
        try:
            refs = strings_refs(f, max_results=200)
        except OSError as exc:
            out["problems"].append(f"{f.name}: {exc}")
            continue
        for r in refs:
            r["file"] = f.name
        out["references"].extend(refs)
    out["references"].sort(key=lambda r: (r["file"], r["offset"]))
    return out


def parse_layout_xml(data: bytes) -> dict:
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(data.decode("utf-8-sig", errors="replace"))
    except ET.ParseError:
        return {"error": "xml_invalido"}
    groups = []
    markers = []
    for el in root.iter():
        tag = el.tag.split("}", 1)[-1]
        if tag == "FileGroup":
            groups.append(dict(el.attrib))
        elif tag in ("ChunkMarker", "Marker"):
            markers.append(dict(el.attrib))
    return {"file_groups": groups, "markers": markers}


def strings_refs(path: Path, *, max_scan: int = 0, max_results: int = 1000) -> list[dict]:
    p = Path(path)
    size = p.stat().st_size
    cap = size if max_scan == 0 else min(size, max_scan)
    matches: list[dict] = []
    with open(p, "rb") as fh:
        pos, step, overlap = 0, 1 << 20, 1024
        while pos < cap:
            d = fh.read(min(step + overlap, cap - pos))
            if not d:
                break
            owned = min(step, cap - pos)
            for enc, rex in (("ascii", _bpr.ASCII_EXE_RE), ("utf16le", _bpr.WIDE_EXE_RE)):
                for m in rex.finditer(d):
                    if m.start() >= owned:
                        continue
                    txt = m.group().decode("utf-16-le" if enc == "utf16le" else "ascii", errors="replace").strip()
                    matches.append({"offset": pos + m.start(), "encoding": enc, "text": txt[-220:]})
                    if len(matches) >= max_results:
                        return matches
            pos += owned
            fh.seek(pos)
    return matches
