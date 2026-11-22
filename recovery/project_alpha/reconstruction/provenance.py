"""Proveniencia: cada fragmento e cada intervalo com origem rastreavel.

Registro por evidencia: arquivo de origem, offset fisico, tamanho,
SHA-256 da regiao de origem, transformacao aplicada e destino gravado.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from _bootstrap import write_json_exclusive


class Provenance:
    def __init__(self):
        self.records: list[dict] = []

    def add(self, *, source: Path | str, source_offset: int, length: int,
            classification: str, destination: Path | str | None = None,
            transform: str = "identity", extra: dict | None = None) -> dict:
        rec = {
            "source": str(source), "source_offset": source_offset, "length": length,
            "sha256_source_region": self._region_sha(source, source_offset, length),
            "classification": classification, "transform": transform,
            "destination": str(destination) if destination else None,
        }
        if extra:
            rec.update(extra)
        self.records.append(rec)
        return rec

    @staticmethod
    def _region_sha(source, offset: int, length: int) -> str | None:
        try:
            h = hashlib.sha256()
            with open(source, "rb") as fh:
                fh.seek(offset)
                remaining = length
                while remaining > 0:
                    b = fh.read(min(4 << 20, remaining))
                    if not b:
                        break
                    h.update(b)
                    remaining -= len(b)
            return h.hexdigest() if remaining <= 0 else None
        except OSError:
            return None

    def fragment_manifest(self, out_dir: Path) -> dict:
        return {
            "schema": "alpha_recovery.fragment_manifest/1",
            "fragments": [r for r in self.records if r.get("destination")],
            "count": len([r for r in self.records if r.get("destination")]),
            "out_dir": str(out_dir),
        }

    def write_all(self, out_dir: Path, *, provenance_name: str = "recovery_provenance.json",
                  manifest_name: str = "fragment_manifest.json") -> tuple[Path, Path]:
        out_dir = Path(out_dir)
        prov = write_json_exclusive(out_dir / provenance_name, {
            "schema": "alpha_recovery.provenance/1",
            "records": sorted(self.records, key=lambda r: (r["source"], r["source_offset"])),
        })
        man = write_json_exclusive(out_dir / manifest_name, self.fragment_manifest(out_dir))
        return prov, man
