"""Caca e registro de artefatos autorizados da build original.

Foco: executavel em plaintext e simbolos PDB. A parte criptografica ja tem
laboratorio reproduzivel; o bloqueio real e a CIK da regiao 0x3E9 - por isso
o caminho acionavel e localizar artefatos legitimos onde existirem.

O que este modulo faz:
  - registra TODOS os PEs das raizes autorizadas com seus RSDS (PDB path,
    GUID, age);
  - registra TODOS os PDBs com GUID/age reais do info stream;
  - casa PE<->PDB por GUID+age (par comprovado, como platform_master);
  - lista subprodutos de build (.lib/.obj/.map/.ilk/.exp/.dmp/.tlog/.rsp);
  - lista archives com membros quando legivel (.zip) ou nomes em claro
    (.rar/.7z scan de strings);
  - busca referencias ao alvo por nome e por conteudo (com limite de tamanho);
  - NADA declara como 'o executavel original': candidatos apenas entram como
    candidates_for_intake, sujeitos a cadeia de validacao existente.
"""
from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from _bootstrap import utc_now
from correlation.catalog_semantics import file_digests
from correlation.identity_report import pdb_info_stream, rsds_records

PE_EXTS = {".exe", ".dll", ".sys", ".com", ".scr", ".ocx"}
PDB_EXTS = {".pdb"}
BYPRODUCT_EXTS = {".lib", ".obj", ".map", ".ilk", ".exp", ".dmp", ".tlog", ".rsp", ".idb", ".iobj", ".ipdb"}
ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".gz", ".xz"}
TARGET_TOKENS = ("game_scarlett_master", "scarlett_master")
CONTENT_SCAN_CAP = 64 << 20
EXCLUDE_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules", "vcpkg_installed"}

TARGET_HINT_NOTE = ("candidatos a intake: passam pela cadeia de validacao existente "
                    "(validate + catalogo + identity); nada aqui e declarado como o executavel original")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(4 << 20)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _machine_of(path: Path) -> str | None:
    try:
        with open(path, "rb") as fh:
            head = fh.read(0x400)
        if head[:2] != b"MZ" or len(head) < 0x40:
            return None
        lfanew = int.from_bytes(head[0x3C:0x40], "little")
        if lfanew + 6 > len(head):
            return None
        return f"0x{int.from_bytes(head[lfanew + 4:lfanew + 6], 'little'):04x}"
    except OSError:
        return None


def _archive_members(path: Path) -> dict:
    ext = path.suffix.lower()
    if ext == ".zip":
        try:
            with zipfile.ZipFile(path) as z:
                return {"readable": True, "members": [i.filename for i in z.infolist()][:200]}
        except (OSError, zipfile.BadZipFile) as exc:
            return {"readable": False, "error": type(exc).__name__}
    try:
        data = path.read_bytes() if path.stat().st_size <= (8 << 20) else b""
        if not data:
            return {"readable": False, "note": "archive grande: so inventario"}
        import re
        names = [m.group().decode("latin-1") for m in re.finditer(rb"[ -~]{6,160}", data)]
        return {"readable": True, "plaintext_names_sample": names[:60]}
    except OSError as exc:
        return {"readable": False, "error": type(exc).__name__}


def _content_references(path: Path) -> list[str]:
    if path.suffix.lower() in PE_EXTS | PDB_EXTS or path.stat().st_size > CONTENT_SCAN_CAP:
        return []
    try:
        data = path.read_bytes()
    except OSError:
        return []
    hits = []
    low = data.lower()
    for tok in TARGET_TOKENS:
        if tok.encode() in low:
            hits.append(tok)
    return hits


def hunt(roots, *, out_note: str = "") -> dict:
    pe_registry: list[dict] = []
    pdb_registry: list[dict] = []
    byproducts: list[dict] = []
    archives: list[dict] = []
    target_refs: list[dict] = []

    files: list[Path] = []
    for root in roots:
        root = Path(root)
        if root.is_file():
            files.append(root)
        elif root.is_dir():
            for dirpath, dirnames, filenames in __import__("os").walk(root):
                dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDE_DIRS)
                for fn in sorted(filenames):
                    files.append(Path(dirpath) / fn)
    files.sort(key=lambda p: str(p).lower())

    for f in files:
        ext = f.suffix.lower()
        name_l = f.name.lower()
        name_hit = [t for t in TARGET_TOKENS if t in name_l]
        try:
            size = f.stat().st_size
        except OSError:
            continue
        if any(t in name_l for t in TARGET_TOKENS):
            target_refs.append({"file": str(f), "size": size, "via": "filename", "tokens": name_hit})
        if ext in PE_EXTS:
            rec = {"path": str(f), "size": size, "machine": _machine_of(f), "sha256": _sha256(f)}
            if size <= (64 << 20):
                rec["rsds"] = [r for r in rsds_records(f) if "guid" in r]
            else:
                rec["rsds"] = "skipped_size"
            pe_registry.append(rec)
        elif ext in PDB_EXTS:
            info = pdb_info_stream(f)
            rec = {"path": str(f), "size": size, "guid": info.get("guid"), "age": info.get("age")}
            if "error" not in info:
                rec["info"] = info
            pdb_registry.append(rec)
        elif ext in BYPRODUCT_EXTS:
            byproducts.append({"path": str(f), "size": size})
        elif ext in ARCHIVE_EXTS:
            archives.append({"path": str(f), "size": size, **_archive_members(f)})
        if not name_hit:
            hits = _content_references(f)
            if hits:
                target_refs.append({"file": str(f), "size": size, "via": "content", "tokens": hits})

    pairs = []
    pdb_by_key = {}
    for p in pdb_registry:
        if p.get("guid"):
            pdb_by_key.setdefault((p["guid"].lower(), p.get("age")), []).append(p)
    for pe in pe_registry:
        for r in pe.get("rsds") or []:
            if isinstance(r, dict) and r.get("guid"):
                matches = pdb_by_key.get((r["guid"].lower(), r.get("age")), [])
                for m in matches:
                    pairs.append({"pe": pe["path"], "pdb": m["path"], "guid": r["guid"], "age": r["age"],
                                  "verdict": "GUID_AGE_MATCH (par comprovado)"})

    candidates = [pe for pe in pe_registry
                  if any(t in pe["path"].lower() for t in TARGET_TOKENS)]
    return {
        "schema": "alpha_recovery.artifact_hunt/1",
        "generated_utc": utc_now(),
        "roots": [str(Path(r)) for r in roots],
        "note": out_note or TARGET_HINT_NOTE,
        "summary": {
            "files_walked": len(files),
            "pe_artifacts": len(pe_registry),
            "pdb_artifacts": len(pdb_registry),
            "pdb_pe_pairs_matched": len(pairs),
            "build_byproducts": len(byproducts),
            "archives": len(archives),
            "target_references": len(target_refs),
        },
        "pe_registry": sorted(pe_registry, key=lambda r: r["path"].lower()),
        "pdb_registry": sorted(pdb_registry, key=lambda r: r["path"].lower()),
        "pdb_pe_pairs": pairs,
        "build_byproducts": sorted(byproducts, key=lambda r: r["path"].lower()),
        "archives": sorted(archives, key=lambda r: r["path"].lower()),
        "target_references": sorted(target_refs, key=lambda r: r["file"].lower()),
        "candidates_for_intake": {
            "executable_like": [c["path"] for c in candidates],
            "next_step": ("rodar a cadeia de validacao: validate -> catalog (hash Authenticode/bruto) -> "
                          "identity (tamanho 120.181.760 + custodia); nada e declarado original sem a cadeia inteira"),
        },
    }


def hunt_summary_lines(report: dict) -> list[str]:
    s = report["summary"]
    out = [f"arquivos varridos: {s['files_walked']:,}",
           f"PEs: {s['pe_artifacts']}  PDBs: {s['pdb_artifacts']}  pares PE<->PDB comprovados: {s['pdb_pe_pairs_matched']}",
           f"subprodutos: {s['build_byproducts']}  archives: {s['archives']}  referencias ao alvo: {s['target_references']}"]
    for p in report["pdb_pe_pairs"][:10]:
        out.append(f"  par: {Path(p['pe']).name} <-> {Path(p['pdb']).name} ({p['verdict']})")
    for c in report["candidates_for_intake"]["executable_like"][:10]:
        out.append(f"  candidato a intake: {c}")
    return out
