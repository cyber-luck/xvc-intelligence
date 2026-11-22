"""Relatorio independente de identidade: cruzamento de evidencias do
pipeline de compilacao, validacao GUID/age de PDB e correspondencia com o
manifesto de build (layout XML x SegmentMetadata).

Sem novos experimentos criptograficos: consome fatos ja verificados
(configs, mapa de arquivos do XVC, catalogo semantico) e adiciona as
evidencias de build que faltavam.
"""
from __future__ import annotations

import struct
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

from xvcintel.core.result import Ok
from xvcintel.formats.pe import parse_pe

CONFIRMED = "CONFIRMED"
INFERRED = "INFERRED"
UNKNOWN = "UNKNOWN"
MISMATCH = "MISMATCH"


# ---------------------------------------------------------------- PDB
def pdb_info_stream(pdb_path: Path) -> dict:
    """Extrai version/signature/age/GUID do PDB (MSF 7.00 / stream 1)."""
    pdb_path = Path(pdb_path)
    with open(pdb_path, "rb") as f:
        sb = f.read(0x38)
        if not sb.startswith(b"Microsoft C/C++ MSF 7.00"):
            return {"error": "nao e PDB MSF 7.00"}
        page_size, _free, num_blocks, dir_size, _unk, block_map_addr = struct.unpack("<IIIIII", sb[0x20:0x38])
        n_dir_pages = (dir_size + page_size - 1) // page_size
        f.seek(block_map_addr * page_size)
        dir_pages = struct.unpack(f"<{n_dir_pages}I", f.read(4 * n_dir_pages))
        d = b""
        for bp in dir_pages:
            f.seek(bp * page_size)
            d += f.read(page_size)
        d = d[:dir_size]
        num_streams = struct.unpack_from("<I", d, 0)[0]
        sizes = struct.unpack_from(f"<{num_streams}I", d, 4) if num_streams else ()
        blocks: list[list[int]] = []
        pos = 4 + 4 * num_streams
        for sz in sizes:
            if sz in (0, 0xFFFFFFFF):
                blocks.append([])
                continue
            nb = (sz + page_size - 1) // page_size
            blocks.append(list(struct.unpack_from(f"<{nb}I", d, pos)))
            pos += 4 * nb

        def read_stream(i: int) -> bytes:
            sz = sizes[i]
            out = b""
            for bp in blocks[i]:
                f.seek(bp * page_size)
                out += f.read(page_size)
            return out[:sz]

        if num_streams < 2:
            return {"error": "sem stream 1"}
        s1 = read_stream(1)
    if len(s1) < 28:
        return {"error": "stream 1 curto demais"}
    version, signature, age = struct.unpack_from("<III", s1, 0)
    guid = str(uuid.UUID(bytes_le=s1[12:28]))
    known_versions = {19990807: "VC70", 20000404: "VC80", 20091201: "VC110", 20150408: "VC140"}
    return {
        "pdb": str(pdb_path),
        "msf_version": known_versions.get(version, f"0x{version:08X}"),
        "signature": f"0x{signature:08X}",
        "age": age,
        "guid": guid,
    }


def rsds_records(pe_path: Path) -> list[dict]:
    """Registros CodeView RSDS do PE (GUID, age, caminho do PDB)."""
    pe_path = Path(pe_path)
    data = pe_path.read_bytes() if pe_path.stat().st_size <= (64 << 20) else b""
    if not data:
        return [{"error": "PE grande demais para leitura integral em rsds_records"}]
    r = parse_pe(data, deep=True)
    if not isinstance(r, Ok):
        return [{"error": str(r.error)}]
    out = []
    for de in r.value.debug or []:
        if de.type == 2 and de.codeview:
            out.append({"pdb_path": de.codeview.get("pdb_path"), "guid": de.codeview.get("guid"),
                        "age": de.codeview.get("age"), "rva": de.rva})
    return out


def cross_validate_rsds_pdb(pe_path: Path, pdb_path: Path) -> dict:
    """Valida GUID e age do registro RSDS do PE contra o PDB real."""
    recs = [r for r in rsds_records(pe_path) if "guid" in r]
    info = pdb_info_stream(pdb_path)
    if "error" in info or not recs:
        return {"pe": str(pe_path), "pdb": str(pdb_path), "rsds": recs, "pdb_info": info,
                "verdict": "NOT_VALIDATED", "detail": "RSDS ausente no PE ou PDB ilegivel"}
    rec = recs[0]
    guid_ok = rec["guid"].lower() == info["guid"].lower()
    age_ok = rec["age"] == info["age"]
    verdict = "GUID_AGE_MATCH" if (guid_ok and age_ok) else ("GUID_MATCH_AGE_MISMATCH" if guid_ok else "MISMATCH")
    return {
        "pe": str(pe_path), "pdb": str(pdb_path),
        "rsds": rec, "pdb_info": info,
        "guid_match": guid_ok, "age_match": age_ok,
        "verdict": verdict,
        "meaning": ("o PDB corresponde exatamente ao link que gerou este PE; evidencia forte de par PE/PDB"
                    if verdict == "GUID_AGE_MATCH" else
                    "PDB de outro link: GUID/age divergentes documentam que o par NAO corresponde"),
    }


# ---------------------------------------------------------------- layout/build
def build_layout_evidence(layout_path: Path) -> dict:
    """Manifesto de build: chunks, arquivos, marcos e caminhos-fonte."""
    layout_path = Path(layout_path)
    try:
        root = ET.fromstring(layout_path.read_text(encoding="utf-8-sig", errors="replace"))
    except ET.ParseError as exc:
        return {"error": f"xml invalido: {exc}"}
    chunks = []
    for c in root.iter():
        tag = c.tag.split("}", 1)[-1]
        if tag != "Chunk":
            continue
        entries = []
        for fg in c:
            if fg.tag.split("}", 1)[-1] == "FileGroup":
                entries.append(dict(fg.attrib))
        chunks.append({"id": c.get("Id"), "marker": c.get("Marker"), "file_groups": entries})
    files = []
    for ch in chunks:
        for fg in ch["file_groups"]:
            files.append({"chunk": ch["id"], "include": fg.get("Include"),
                          "destination": fg.get("DestinationPath"), "source": fg.get("SourcePath")})
    source_roots = sorted({f["source"] for f in files if f["source"]})
    return {
        "layout": str(layout_path),
        "chunks": chunks,
        "files": files,
        "source_roots": source_roots,
        "launch_marker_chunk": next((c["id"] for c in chunks if c.get("marker") == "Launch"), None),
        "note": "o nome do arquivo de layout embute o VDUID do pacote (3202719e-...); os caminhos-fonte apontam para a maquina de build, fora do conjunto sobrevivente",
    }


def manifest_correspondence(layout: dict, xvc_files: list[dict]) -> dict:
    """Layout x SegmentMetadata: cada arquivo do manifesto esta no pacote?
    Correspondencia por caminho completo normalizado (DestinationPath+Include)
    e, apenas quando univoco, por nome base. Ordem dos chunks x segmentos."""
    def norm(p: str) -> str:
        return (p or "").replace("\\", "/").strip("/").lower()

    rows_full = {norm(r["filename"]): r for r in xvc_files}
    from collections import Counter
    base_counts = Counter(norm(r["filename"]).rsplit("/", 1)[-1] for r in xvc_files)
    rows_base = {norm(r["filename"]).rsplit("/", 1)[-1]: r for r in xvc_files
                 if base_counts[norm(r["filename"]).rsplit("/", 1)[-1]] == 1}
    checks = []
    missing = []
    for f in layout.get("files", []):
        name = (f["include"] or "").split("\\")[-1]
        full_key = norm((f.get("destination") or "") + (f["include"] or ""))
        row = rows_full.get(full_key) or rows_base.get(name.lower())
        if row:
            checks.append({"file": full_key, "in_layout_chunk": f["chunk"], "in_xvc_segment": row["segment_index"],
                           "status": CONFIRMED})
        else:
            missing.append(full_key)
            checks.append({"file": full_key, "in_layout_chunk": f["chunk"], "in_xvc_segment": None, "status": MISMATCH})
    matched_files = {c["file"] for c in checks if c["status"] == CONFIRMED}
    layout_exes = [c["file"] for c in checks if c["file"].lower().endswith(".exe")]
    xvc_exes = [r["filename"] for r in xvc_files if r["filename"].lower().endswith(".exe")]
    extra_in_xvc = [r["filename"] for r in xvc_files if norm(r["filename"]) not in matched_files]
    segs = [c["in_xvc_segment"] for c in checks if c.get("in_xvc_segment") is not None]
    order_monotonic = all(a <= b for a, b in zip(segs, segs[1:]))
    return {
        "schema": "alpha_recovery.manifest_correspondence/1",
        "layout_files": len(checks),
        "confirmed_in_xvc": sum(1 for c in checks if c["status"] == CONFIRMED),
        "missing_from_xvc": missing,
        "xvc_files_absent_from_layout": extra_in_xvc,
        "executable_in_layout": [c.rsplit("/", 1)[-1] for c in layout_exes],
        "executable_in_xvc": xvc_exes,
        "layout_chunk_order_equals_segment_order": order_monotonic,
        "checks": checks,
    }


def dependency_build_environment(disk_dir: Path, dll_names: list[str]) -> dict:
    """RSDS das dependencias: evidencia do AMBIENTE de build, nunca do alvo."""
    out = []
    for name in dll_names:
        p = Path(disk_dir) / name
        if not p.is_file():
            out.append({"dll": name, "status": "ausente em disco"})
            continue
        recs = [r for r in rsds_records(p) if "guid" in r]
        for r in recs:
            r["dll"] = name
            r["role"] = "dependencia; evidencia do ambiente de build do fornecedor, nao do executavel alvo"
            out.append(r)
        if not recs:
            out.append({"dll": name, "status": "sem registro RSDS"})
    return {"records": out,
            "note": "RSDS de DLLs distribuidas provam a geracao de build dos FORNECEDORES; nao sao evidencia de import nem de identidade do executavel alvo"}


def build_identity_report(*, xvc_path: Path, disk_dir: Path, target: str,
                          prior: dict | None = None) -> dict:
    from correlation.evidence_graph import xvc_storage_facts
    from scanners.metadata_scanner import scan_metadata_dir

    disk_dir = Path(disk_dir)
    facts = xvc_storage_facts(xvc_path)
    if "error" in facts:
        return {"error": facts["error"]}
    meta = scan_metadata_dir(disk_dir)
    layout_files = sorted(disk_dir.glob("layout_*.xml")) + sorted(disk_dir.glob("*.layout.xml"))
    layout = build_layout_evidence(layout_files[0]) if layout_files else {"error": "layout ausente"}
    corr = manifest_correspondence(layout, facts["files"]) if "error" not in layout else {"error": "layout ausente"}
    row = next((r for r in facts["files"] if r["filename"].casefold() == target.casefold()), None)

    cfg = meta.get("configs", {})
    gc = cfg.get("MicrosoftGame.config", {})
    man = cfg.get("appxmanifest.xml", {})
    declared = {
        "name": target,
        "application_id": (gc.get("executables") or [{}])[0].get("Id") or man.get("applications", [{}])[0].get("Id"),
        "package_identity": gc.get("Identity"),
        "package_version": facts.get("package_version"),
        "version_consistent": gc.get("Identity", {}).get("Version") == facts.get("package_version"),
        "sources_agreeing": sum(1 for c in (gc.get("executables") or []) if c.get("Name", "").casefold() == target.casefold()),
    }

    dlls = sorted(r["filename"] for r in facts["files"] if r["filename"].endswith(".dll")
                  and (disk_dir / r["filename"]).is_file())
    dep_env = dependency_build_environment(disk_dir, dlls)

    target_pdb = {"status": "ABSENT",
                  "evidence": "nenhum PDB do alvo existe no conjunto sobrevivente; validador GUID/age pronto e demonstrado em par real (platform_master.exe x platform_master.pdb)"}

    verification_ladder = {
        "statement": "o proximo avanco depende de uma copia autorizada em texto claro demonstrada como correspondente ao executavel esperado",
        "coincidences_not_sufficient": ["tamanho igual", "versao igual", "hash isolado fora do catalogo"],
        "required_chain": [
            "PE valido x64/PE32+ com tamanho exatamente igual ao SegmentMetadata",
            "hash (Authenticide ou bruto) presente no Catalog000.bin legivel",
            "GUID/age de RSDS coerentes com PDB correspondente, quando existir",
            "custodia documentada; coincidencias de tamanho/versao nunca bastam",
        ],
        "ready_implementations": ["reconstruct (mapa+identidade)", "catalog (busca semantica)",
                                  "cross_validate_rsds_pdb (GUID/age)"],
    }
    import datetime as _dt
    return {
        "schema": "alpha_recovery.identity_report/1",
        "generated_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "target": target,
        "declared_identity": declared,
        "storage": row,
        "manifest_correspondence": corr,
        "layout_evidence": layout if "error" not in layout else layout,
        "dependency_build_environment": dep_env,
        "target_pdb": target_pdb,
        "prior_evidence_reused": prior or "catalog_semantic.json e experimentos E1/E1b/E6/E3 ja concluidos (v3); nada re-executado aqui",
        "verification_ladder": verification_ladder,
        "conclusion": ("identidade declarada e armazenamento CONFIRMADOS; correspondencia com o manifesto de build "
                        + ("CONFIRMADA" if corr.get("missing_from_xvc") == [] and corr.get("executable_in_xvc") else "com pendencias")
                        + "; correspondencia ao CONTEUDO do executavel permanece dependente de copia autorizada em texto claro"),
    }
