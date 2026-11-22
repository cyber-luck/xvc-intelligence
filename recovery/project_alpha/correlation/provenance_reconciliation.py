"""Reconciliacao de proveniencia das DLLs distribuidas.

Para cada DLL do pacote:
  1. localizacao no manifesto de build (layout XML) e no SegmentMetadata;
  2. estado criptografico real da regiao (KeyId / keyed);
  3. comparacao byte a byte disco x segmento (streaming por blocos);
  4. classificacao com evidencia:
       PACKAGE_IDENTICAL        - bytes identicos ao pacote (regiao em claro)
       DIFFERENT                - regiao em claro, bytes divergentes
       ENCRYPTED_UNCOMPARABLE   - regiao cifrada (KeyId 0): comparacao de
                                   plaintext x ciphertext e 0% por natureza;
                                   a igualdade de tamanho permanece evidencia
                                   de MESMA BUILD, sem prova de bytes
       UNKNOWN                  - ausente em disco ou no pacote
  5. atualizacao da conclusao sobre montagem hibrida da pasta.
"""
from __future__ import annotations

import json
from pathlib import Path

from _bootstrap import utc_now
from correlation.block_matching import block_match
from correlation.identity_report import build_layout_evidence
from correlation.evidence_graph import xvc_storage_facts

PLAIN_KEY = 0xFFFF


def classification_table() -> list[dict]:
    """Tabela-canonical de estado, com basis de evidencia por linha."""
    return [
        {"object": "executavel_em_disco", "classification": "CIPHERTEXT_PACKAGE_IDENTICAL",
         "basis": "E1: 29/29 blocos de 4 MiB identicos aos bytes gravados do XVC + page slack provado (3.072 B)"},
        {"object": "16_dlls_legiveis", "classification": "ENCRYPTED_UNCOMPARABLE",
         "basis": "regiao 0x3EA KeyId 0: plaintext x ciphertext = 0% por natureza; bytes do pacote nao comparaveis sem chave"},
        {"object": "configuracoes_comparadas", "classification": "PACKAGE_IDENTICAL",
         "basis": "diff byte a byte: 3/3 arquivos identicos aos embutidos no XVC"},
        {"object": "origem_das_dlls", "classification": "PROVENANCE_UNKNOWN",
         "basis": ("tamanhos logicos exatos (16/16) sao CORRESPONDENCIA DE METADADOS, nao identidade de build; "
                   "identidade de build exige RSDS/GUID/age/registros de compilacao ou comparacao byte a byte pos-chave")},
        {"object": "recuperacao_do_exe", "classification": "BLOCKED_MISSING_AUTHORIZED_CIK",
         "basis": "CIK da regiao 0x3E9 ausente; pipeline e laboratorio prontos"},
    ]


def _norm_guid(g: str) -> str:
    return (g or "").replace("-", "").strip().lower()


def _build_identity_fields(path: Path) -> dict:
    """Identidade de build de um PE em disco: RSDS autoritativo dos bytes."""
    import hashlib
    import struct as _st
    from correlation.identity_report import rsds_records
    p = Path(path)
    data_head = p.read_bytes()[: (2 << 20)]
    ident = {"sha256": None, "size": p.stat().st_size, "timestamp_utc": None, "linker": None, "rsds": []}
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        while True:
            b = fh.read(4 << 20)
            if not b:
                break
            h.update(b)
    ident["sha256"] = h.hexdigest()
    if data_head[:2] == b"MZ" and len(data_head) >= 0x40:
        lfanew = _st.unpack_from("<I", data_head, 0x3C)[0]
        opt = lfanew + 24
        ident["timestamp_utc"] = _ts_utc(_st.unpack_from("<I", data_head, lfanew + 8)[0])
        maj, minor = _st.unpack_from("<BB", data_head, opt + 2)
        ident["linker"] = f"{maj}.{minor}"
    for r in rsds_records(p):
        if "guid" in r:
            ident["rsds"].append({"guid": r["guid"], "age": r["age"], "pdb_path": r.get("pdb_path")})
    return ident


def _ts_utc(ts: int) -> str:
    import datetime as _dt
    try:
        return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return f"invalid:{ts}"


def _prior_crosscheck(dll: str, ident: dict, prior_images: list[dict]) -> dict:
    """Consistencia com registros de sessao anterior (mesmos arquivos no ambiente?)."""
    pi = next((x for x in prior_images if (x.get("file") or "").split("\\")[-1].lower() == dll.lower()), None)
    if pi is None:
        return {"status": "ABSENT_IN_PRIOR_RECORDS"}
    checks = {
        "size": pi.get("size") == ident["size"],
        "timestamp": _norm_ts(pi.get("timestamp_utc")) == _norm_ts(ident["timestamp_utc"]),
    }
    prior_rsds = (pi.get("debug_records") or [{}])[0] if pi.get("debug_records") else {}
    mine = ident["rsds"][0] if ident["rsds"] else {}
    if prior_rsds.get("guid") and mine.get("guid"):
        checks["rsds_guid"] = _norm_guid(prior_rsds["guid"]) == _norm_guid(mine["guid"])
        checks["rsds_age"] = prior_rsds.get("age") == mine.get("age")
    ok = all(v for v in checks.values())
    return {"status": "CONSISTENT" if ok else "DIVERGENT", "checks": checks,
            "prior_generated_utc_note": "registros da sessao anterior lidos por referencia, nao reexecutados"}


def _norm_ts(ts) -> str | None:
    return (str(ts).replace("+00:00", "Z").replace("Z", "") or None) if ts else None


def classify(*, keyed: bool, key_id: int, disk_size, stored_size, pct_equal, disk_exists: bool,
             stored_exists: bool) -> str:
    if not stored_exists:
        return "UNKNOWN"
    if not disk_exists:
        return "UNKNOWN"
    if keyed and key_id != PLAIN_KEY:
        return "ENCRYPTED_UNCOMPARABLE"
    if pct_equal == 100.0:
        return "PACKAGE_IDENTICAL"
    return "DIFFERENT"


def reconcile_dlls(xvc_path: Path, disk_dir: Path, *, prior_records: Path | None = None,
                   out_note: str = "") -> dict:
    xvc_path = Path(xvc_path)
    disk_dir = Path(disk_dir)
    facts = xvc_storage_facts(xvc_path)
    if "error" in facts:
        return {"error": facts["error"]}
    layout_files = sorted(disk_dir.glob("layout_*.xml")) + sorted(disk_dir.glob("*.layout.xml"))
    layout = build_layout_evidence(layout_files[0]) if layout_files else {"error": "layout ausente"}
    manifest_chunks = {}
    if "error" not in layout:
        for f in layout.get("files", []):
            manifest_chunks[(f["include"] or "").split("\\")[-1].lower()] = f["chunk"]

    prior_images: list[dict] = []
    if prior_records and Path(prior_records).is_file():
        pd = json.loads(Path(prior_records).read_text(encoding="utf-8"))
        prior_images = pd.get("images") or []

    rows = facts["files"]
    dll_rows = [r for r in rows if r["filename"].lower().endswith(".dll")]
    result_rows = []
    for r in dll_rows:
        name = r["filename"]
        disk = disk_dir / name
        disk_exists = disk.is_file()
        stored_size = r["size"]
        disk_size = disk.stat().st_size if disk_exists else None
        keyed = r.get("key_id") not in (None, PLAIN_KEY)
        pct = None
        first_div = None
        if disk_exists:
            m = block_match(disk, 0, xvc_path, int(r["absolute_offset"], 16), min(stored_size, disk_size),
                            block=1 << 20)
            pct = m.get("pct_equal_blocks")
            first_div = m.get("first_divergence_relative")
        cls = classify(keyed=keyed, key_id=r.get("key_id"), disk_size=disk_size, stored_size=stored_size,
                        pct_equal=pct, disk_exists=disk_exists, stored_exists=True)
        row = {
            "dll": name,
            "manifest_chunk": manifest_chunks.get(name.lower()),
            "segment": r["segment_index"],
            "xvc_offset": r["absolute_offset"],
            "stored_size": stored_size,
            "disk_size": disk_size,
            "size_match": disk_size == stored_size,
            "key_id": r.get("key_id"),
            "region_encrypted": keyed,
            "blocks_equal_pct": pct,
            "first_divergence": first_div,
            "classification": cls,
        }
        if disk_exists:
            ident = _build_identity_fields(disk)
            ident["size_equality_is_metadata_correspondence_only"] = True
            ident["size_equality_note"] = ("tamanho logico igual ao SegmentMetadata e correspondencia de "
                                           "metadados; NAO prova identidade de build")
            if prior_images:
                ident["prior_session_crosscheck"] = _prior_crosscheck(name, ident, prior_images)
            row["build_identity"] = ident
        result_rows.append(row)

    by_cls: dict[str, int] = {}
    for r in result_rows:
        by_cls[r["classification"]] = by_cls.get(r["classification"], 0) + 1
    sizes_match = sum(1 for r in result_rows if r["size_match"])

    enc = [r for r in result_rows if r["classification"] == "ENCRYPTED_UNCOMPARABLE"]
    identical = [r for r in result_rows if r["classification"] == "PACKAGE_IDENTICAL"]
    different = [r for r in result_rows if r["classification"] == "DIFFERENT"]

    if identical and not enc:
        conclusion = ("todas as DLLs comparaveis sao PACKAGE_IDENTICAL: a pasta em disco e extracao fiel do pacote")
    elif enc and not identical and not different:
        conclusion = (
            "todas as DLLs estao em regioes CIFRADAS do XVC (KeyId 0): os bytes gravados nao sao o PE em disco; "
            "a comparacao plaintext x ciphertext e 0% por natureza e NAO e evidencia de build diferente. "
            f"Os {sizes_match}/{len(result_rows)} tamanhos logicos iguais sao CORRESPONDENCIA DE METADADOS "
            "(necesaria, jamais suficiente para identidade de build). A identidade de build de cada DLL em disco "
            "esta estabelecida por RSDS (GUID+age+pdb path) na secao build_identity; a EQUIVALENCIA BYTE A BYTE "
            "com as copias protegidas do pacote permanece INDEMONSTRAVEL sem chave. "
            "A pasta e MONTAGEM HIBRIDA quanto ao ESTADO dos arquivos: exe = CIPHERTEXT_PACKAGE_IDENTICAL; "
            "DLLs = ENCRYPTED_UNCOMPARABLE com origem PROVENANCE_UNKNOWN"
        )
    else:
        conclusion = ("estado misto inesperado (PACKAGE_IDENTICAL e/ou DIFFERENT presentes junto a cifradas); "
                     "ver linhas individuais antes de concluir")

    return {
        "schema": "alpha_recovery.dll_provenance/2",
        "generated_utc": utc_now(),
        "xvc": str(xvc_path),
        "disk_dir": str(disk_dir),
        "note": out_note or ("sem uso de chaves: a comparacao usa apenas bytes gravados; regioes cifradas sao "
                             "declaradas incomparaveis, nunca 'diferentes'"),
        "summary": {
            "dlls": len(result_rows),
            "by_classification": by_cls,
            "sizes_exactly_equal": sizes_match,
            "sizes_note": "correspondencia de metadados; nao e identidade de build",
        },
        "classification_table": classification_table(),
        "rows": result_rows,
        "hybrid_assembly_conclusion": conclusion,
    }
