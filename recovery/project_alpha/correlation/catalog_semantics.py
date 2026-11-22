"""Validacao semantica do Catalog000.bin (PE XBOX_CODE_CATALOG) e avaliacao
de identidade de um candidato a copia autorizada.

Distincoes obrigatorias:
  - hash bruto do arquivo x hash Authenticode (digest excluindo a tabela de
    certificados) - ambos calculados e buscados em formas distintas;
  - SOURCE_RECOVERED (bytes recuperados de uma fonte) x TARGET_IDENTITY_VERIFIED
    (correspondencia comprovada ao alvo) - nunca con fundidos;
  - assinatura: presenca e verificacao sao coisas diferentes; sem dependencia
    criptografica, a presenca e detectada e a verificacao e registrada como
    NAO EXECUTADA.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from xvcintel.core.result import Ok
from xvcintel.formats.pe import parse_pe

CONFIRMED = "CONFIRMED"
INFERRED = "INFERRED"
UNKNOWN = "UNKNOWN"
PAGE = 0x1000


def authenticode_digests(path: Path) -> dict:
    """Digests Authenticode do PE: arquivo inteiro EXCETO a tabela de
    certificados (security directory, cujo RVA e um offset de arquivo).
    Streaming por blocos: funciona para arquivos maiores que a memoria."""
    path = Path(path)
    size = path.stat().st_size
    with open(path, "rb") as fh:
        head = fh.read(0x400)
        if len(head) < 0x40 or head[:2] != b"MZ":
            return {"error": "nao e PE"}
        lfanew = struct.unpack_from("<I", head, 0x3C)[0]
        opt = lfanew + 24
        need = opt + 4
        while len(head) < need:
            head += fh.read(need - len(head))
        magic = struct.unpack_from("<H", head, opt)[0]
        dd_off = opt + (112 if magic == 0x20B else 96)
        need = dd_off + 4 * 8 + 8
        while len(head) < need:
            head += fh.read(need - len(head))
        sec_off, sec_len = struct.unpack_from("<II", head, dd_off + 4 * 8)
    valid = bool(sec_off and sec_len and sec_off + sec_len <= size and sec_off >= need)
    h1, h256 = hashlib.sha1(), hashlib.sha256()
    excluded = {"file_offset": sec_off, "length": sec_len} if valid else None
    with open(path, "rb") as fh:
        pos = 0
        while pos < size:
            chunk = fh.read(min(4 << 20, size - pos))
            if not chunk:
                break
            if valid:
                cstart, cend = pos, pos + len(chunk)
                if cend <= sec_off or cstart >= sec_off + sec_len:
                    keep = chunk
                else:
                    parts = []
                    if cstart < sec_off:
                        parts.append(chunk[:sec_off - cstart])
                    if cend > sec_off + sec_len:
                        parts.append(chunk[sec_off + sec_len - cstart:])
                    keep = b"".join(parts)
                h1.update(keep)
                h256.update(keep)
            else:
                h1.update(chunk)
                h256.update(chunk)
            pos += len(chunk)
    return {
        "sha1": h1.hexdigest(),
        "sha256": h256.hexdigest(),
        "cert_table_excluded": excluded,
        "note": "digest sobre a imagem sem a tabela de certificados (regra Authenticode); checksum incluido",
    }


def file_digests(path: Path) -> dict:
    h1, h256 = hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(4 << 20)
            if not b:
                break
            h1.update(b)
            h256.update(b)
    return {"sha1": h1.hexdigest(), "sha256": h256.hexdigest()}


def _search_forms(blob: bytes, digest_hex: str) -> list[dict]:
    hits: list[dict] = []
    raw = bytes.fromhex(digest_hex)
    off = blob.find(raw)
    if off >= 0:
        hits.append({"form": "raw_bytes", "offset": off, "alg": digest_hex[:8]})
    for form in ("lower_hex", "upper_hex"):
        needle = digest_hex.encode() if form == "lower_hex" else digest_hex.upper().encode()
        off = blob.find(needle)
        if off >= 0:
            hits.append({"form": form + "_ascii", "offset": off, "alg": digest_hex[:8]})
    import base64
    for name, fn in (("base64", base64.b64encode), ("base64_no_pad", lambda d: base64.b64encode(d).rstrip(b"="))):
        needle = fn(raw)
        off = blob.find(needle)
        if off >= 0:
            hits.append({"form": name, "offset": off, "alg": digest_hex[:8]})
    return hits


def semantic_catalog_report(catalog_path: Path, *, candidate: Path | None = None,
                            target_name: str | None = None) -> dict:
    """Relatorio semantico do catalogo: estrutura, strings, assinatura,
    buscas de hash (bruto e Authenticode) e associacao ao executavel."""
    catalog_path = Path(catalog_path)
    out: dict = {
        "schema": "alpha_recovery.catalog_semantic/1",
        "catalog": str(catalog_path),
        "size": catalog_path.stat().st_size,
    }
    data = read_all_capped(catalog_path)
    r = parse_pe(data, deep=True)
    if not isinstance(r, Ok):
        out["error"] = str(r.error)
        return out
    pe = r.value
    out["pe"] = {
        "machine": f"0x{pe.machine:04x}", "magic": f"0x{pe.magic:04x}" if pe.magic else None,
        "subsystem": pe.subsystem, "subsystem_name": pe.subsystem_name,
        "sections": [{"name": s.name, "raw_offset": s.raw_pointer, "raw_size": s.raw_size} for s in pe.sections],
        "conclusion": pe.conclusion(),
    }
    out["signature"] = {
        "security_directory_present": pe.security is not None,
        "pkcs7_oid_present": bool(pe.security and pe.security.has_pkcs7_signed_data_oid),
        "cryptographic_verification_performed": False,
        "note": ("assinatura embutida detectada; verificacao da cadeia NAO executada (sem dependencia criptografica)"
                  if pe.security and pe.security.has_pkcs7_signed_data_oid else
                  "nenhuma assinatura embutida no catalogo; nada a verificar"),
    }
    sec = pe.sections[0] if pe.sections else None
    if sec:
        blob = data[sec.raw_pointer:sec.raw_pointer + sec.raw_size]
        pages = [blob[i * PAGE:(i + 1) * PAGE] for i in range(0, (len(blob) + PAGE - 1) // PAGE)]
        nz = [sum(1 for b in pg if b) for pg in pages]
        out["section_profile"] = {
            "raw_offset": sec.raw_pointer, "raw_size": sec.raw_size,
            "pages_4k": len(pages),
            "pages_with_content": sum(1 for x in nz if x > 0),
            "nonzero_page0_bytes": nz[0] if nz else None,
            "mean_nonzero_per_full_page": round(sum(nz[1:-1]) / max(1, len(nz) - 2), 1) if len(nz) > 2 else None,
            "interpretation": ("pagina 0 com cabecalho curto + paginas densas de dados binarios: consistente com "
                               "tabela de hashes do catalogo de codigo; decodificacao campo a campo do formato interno "
                               "e UNKNOWN (formato interno nao documentado publicamente)") if nz else None,
        }
        strings_hits = []
        if target_name:
            for enc, needle in (("ascii", target_name.encode()), ("utf16le", target_name.encode("utf-16-le"))):
                idx = 0
                while True:
                    off = blob.find(needle, idx)
                    if off < 0:
                        break
                    strings_hits.append({"encoding": enc, "offset_in_section": off})
                    idx = off + 1
        out["name_string_hits"] = strings_hits
        out["name_string_note"] = ("presenca do nome do executavel no catalogo" if strings_hits else
                                   "nome do executavel NAO encontrado em texto claro; associacao por nome UNKNOWN")
        if candidate:
            cand = Path(candidate)
            fd = file_digests(cand)
            try:
                ad = authenticode_digests(cand)
            except (struct.error, ValueError) as exc:
                ad = {"error": str(exc)}
            out["candidate_digests"] = {
                "file_raw": fd,
                "authenticode": {k: v for k, v in ad.items() if k in ("sha1", "sha256")},
                "authenticode_detail": ad.get("cert_table_excluded"),
                "distinction_note": "hash bruto cobre o arquivo inteiro; hash Authenticode exclui a tabela de certificados",
            }
            searches = []
            for kind, digests in (("file_raw", fd), ("authenticode", ad)):
                if not isinstance(digests, dict) or "sha1" not in digests:
                    continue
                for alg in ("sha1", "sha256"):
                    for hit in _search_forms(blob, digests[alg]):
                        hit.update({"digest_kind": kind, "alg": alg, "digest": digests[alg]})
                        searches.append(hit)
            out["hash_hits"] = searches
            out["hash_hits_note"] = ("hit com digest Authenticode e evidencia forte de identidade; hit com hash bruto "
                                     "e mais fraco (arquivos com certificados diferentes podem ter o mesmo hash bruto? "
                                     "nao - hash bruto cobre tudo; a distincao e sobre o QUE o catalogo indexa)")
        else:
            out["candidate_digests"] = None
            out["hash_hits"] = []
    return out


def read_all_capped(path: Path, cap: int = 64 << 20) -> bytes:
    size = path.stat().st_size
    if size > cap:
        with open(path, "rb") as fh:
            return fh.read(cap)
    return path.read_bytes()


def assess_identity(*, size_match: bool, machine_ok: bool, catalog_hash_hits: list | None,
                    catalog_name_hits: list | None, custody_documented: bool) -> dict:
    """Separacao rigida: SOURCE_RECOVERED nao e TARGET_IDENTITY_VERIFIED.

    IDENTIDADE so e VERIFIED com evidencia confiavel de correspondencia exata:
    tamanho exato + maquina compativel + hash Authenticode (ou bruto) do
    candidato presente no catalogo legivel + custodia documentada.
    """
    evidence = [
        {"id": "size_exact", "ok": bool(size_match), "weight": "necessary",
         "detail": "tamanho exatamente igual ao SegmentMetadata do XVC"},
        {"id": "machine_compatible", "ok": bool(machine_ok), "weight": "supporting",
         "detail": "maquina compativel com a plataforma (x64/PE32+)"},
        {"id": "catalog_hash_hit", "ok": bool(catalog_hash_hits), "weight": "strong",
         "detail": "hash (Authenticode ou bruto) do candidato presente no catalogo legivel"},
        {"id": "catalog_name_association", "ok": bool(catalog_name_hits), "weight": "supporting",
         "detail": "nome do executavel presente no catalogo"},
        {"id": "custody_documented", "ok": bool(custody_documented), "weight": "necessary",
         "detail": "custodia documentada (--provenance); a ausencia nao invalida os bytes, mas bloqueia VERIFIED"},
    ]
    strong_ok = bool(catalog_hash_hits)
    verified = bool(size_match and machine_ok and strong_ok and custody_documented)
    return {
        "schema": "alpha_recovery.identity/1",
        "status": "TARGET_IDENTITY_VERIFIED" if verified else "TARGET_IDENTITY_UNVERIFIED",
        "warning": "SOURCE_RECOVERED (bytes com prova de origem) e distinto de TARGET_IDENTITY_VERIFIED (correspondencia ao alvo); PE valido nao e correspondencia comprovada",
        "evidence": evidence,
        "rule": "VERIFIED exige: tamanho exato + maquina compativel + hash no catalogo + custodia documentada; sem qualquer deles, permanece UNVERIFIED e a classificacao maxima e COMPLETE_UNVERIFIED",
    }
