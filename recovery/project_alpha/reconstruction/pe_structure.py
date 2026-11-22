"""Estrutura PE: mapa de intervalos de um PE comprovado e inferencias do alvo.

Nunca inventa campos: tudo que nao foi observado fica explicitamente
UNKNOWN ou INFERRED com a base da inferencia registrada.
"""
from __future__ import annotations

from pathlib import Path

from .interval_map import EXACT_RECOVERED, MISSING

from xvcintel.core.result import Ok
from xvcintel.formats.pe import parse_pe


def pe_interval_map(path: Path, *, base: int = 0) -> dict:
    """Intervalos byte a byte de um PE em disco (todas as classes EXACT_RECOVERED
    quando o arquivo e completo; lacunas do carve viram MISSING)."""
    path = Path(path)
    size = path.stat().st_size()
    data_head_len = min(size, 4 << 20)
    with open(path, "rb") as fh:
        data = fh.read(data_head_len)
    r = parse_pe(data, deep=True)
    if not isinstance(r, Ok):
        return {"error": str(r.error)}
    pe = r.value
    from .interval_map import IntervalMap
    im = IntervalMap(size, base_label=MISSING)
    headers_end = min(pe.optional.get("SizeOfHeaders", 0) or 0, size)
    if headers_end:
        im.add(0, headers_end, EXACT_RECOVERED, source_file=str(path), source_offset=base,
               pe_section="<headers>", transform="identity")
    for s in pe.sections:
        raw_off = s.raw_pointer
        raw_size = s.raw_size
        if raw_off is None or raw_size is None:
            continue
        seg_end = min(raw_off + raw_size, size)
        if raw_off < size and seg_end > raw_off:
            im.add(raw_off, seg_end, EXACT_RECOVERED, source_file=str(path),
                   source_offset=base + raw_off, pe_section=s.name, transform="identity")
    out = im.to_json()
    out["pe_summary"] = {
        "machine": f"0x{pe.machine:04x}",
        "machine_name": pe.machine_name,
        "magic": f"0x{pe.magic:04x}" if pe.magic else None,
        "subsystem": pe.subsystem,
        "conclusion": pe.conclusion(),
        "sections": [{"name": s.name, "rva": s.virtual_address, "virtual_size": s.virtual_size,
                      "raw_offset": s.raw_pointer, "raw_size": s.raw_size} for s in pe.sections],
    }
    return out


def infer_target_structure(identity: dict, dll_pe_facts: list[dict] | None = None) -> dict:
    """Inferencias estruturais sobre o executavel alvo, sem inventar bytes."""
    fields: dict[str, dict] = {}
    fields["name"] = {"value": identity.get("name"), "level": "CONFIRMED",
                      "basis": "MicrosoftGame.Config + appxmanifest + hive + layout XVC"}
    fields["architecture"] = {"value": "x64 (PE32+ esperado)", "level": "INFERRED",
                              "basis": "plataforma Scarlett; 16 DLLs distribuidas sao PE32+ AMD64 (CONFIRMED nos bytes em disco); o header do alvo nunca foi observado"}
    fields["version"] = {"value": identity.get("package_version"), "level": "INFERRED",
                         "basis": "PackageVersion do cabecalho XVC == Identity@Version do config; versao do PE interna UNKNOWN"}
    fields["subsystem"] = {"value": None, "level": "UNKNOWN",
                           "basis": "imagens de console tipicamente nao usam subsystem Windows, mas nenhum byte do header foi observado; nao inferido"}
    fields["sections"] = {"value": None, "level": "UNKNOWN", "basis": "conteudo cifrado; nenhuma secao observada"}
    fields["imports"] = {"value": None, "level": "UNKNOWN",
                         "basis": "os nomes das DLLs distribuidas NAO sao evidencia de import do alvo"}
    fields["entry_point"] = {"value": None, "level": "UNKNOWN", "basis": "cabeçalho nao observado"}
    fields["pdb_path"] = {"value": None, "level": "UNKNOWN",
                          "basis": "nenhum PDB/MAP/OBJ/ILK do alvo existe no conjunto sobrevivente (auditoria anterior)"}
    return {
        "schema": "alpha_recovery.inferred_structure/1",
        "warning": "nenhum byte do executavel alvo foi recuperado; nada abaixo substitui bytes comprovados",
        "fields": fields,
    }
