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


PAGE_BYTES = 0x1000


def source_provenance_report(source: Path, *, custody_claim: str | None,
                             digests: dict, extra: dict | None = None) -> dict:
    """source_provenance.json: fatos da fonte + declaracao de custodia.

    A declaracao (--provenance) NAO constitui prova: fica registrada como
    claim, separada da evidencia de identidade (que vive no relatorio de
    identidade/assessment). Nada aqui valida a autenticidade da fonte.
    """
    import datetime as _dt
    source = Path(source)
    st = source.stat()
    out = {
        "schema": "alpha_recovery.source_provenance/1",
        "source": {
            "path": str(source.resolve()),
            "size": st.st_size,
            "mtime_utc": _dt.datetime.fromtimestamp(st.st_mtime, _dt.timezone.utc).isoformat(timespec="seconds"),
            "digests": digests,
        },
        "custody_claim": custody_claim,
        "custody_claim_is_not_proof": True,
        "statements": [
            "a declaracao de custodia e um registro declaratorio; a ferramenta nao pode autenticar origem",
            "prova de identidade ao alvo e calculada separadamente (identity/assessment) e exige tamanho exato + hash no catalogo + custodia documentada",
            "bytes desta fonte sao SOURCE_RECOVERED; correspondencia ao alvo e TARGET_IDENTITY_VERIFIED, conceito distinto",
        ],
    }
    if extra:
        out["extra"] = extra
    return out


def page_slack_info(stored_len: int, page: int = PAGE_BYTES) -> dict:
    """Matematica de paginacao para reconciliacao de tamanho."""
    end_in_page = stored_len % page
    slack = (page - end_in_page) % page
    return {
        "page_bytes": page,
        "file_end_within_page": end_in_page,
        "bytes_to_next_page_boundary": slack,
        "size_page_aligned": stored_len + slack,
    }


def size_reconciliation(stored_len: int, actual_len: int, *, page: int = PAGE_BYTES,
                       tail_matches_xvc_continuation: bool | None = None) -> dict:
    """Reconciliacao de tamanho SEM truncamento automatico.

    Hipoteses testaveis sao listadas com estado; nada e descartado do
    arquivo real para 'fechar' o tamanho.
    """
    delta = actual_len - stored_len
    info = page_slack_info(stored_len, page)
    hypotheses: list[dict] = []
    if delta > 0:
        hyp = {
            "id": "page_slack_included_by_extraction",
            "detail": (f"o arquivo gravado termina em 0x{info['file_end_within_page']:X} dentro da pagina; "
                       f"o excedente de {delta} byte(s) bate com os {info['bytes_to_next_page_boundary']} byte(s) "
                       "de folga ate o limite da pagina do segmento"),
            "expected_delta": info["bytes_to_next_page_boundary"],
            "delta_matches": delta == info["bytes_to_next_page_boundary"],
        }
        if tail_matches_xvc_continuation is not None:
            hyp["tail_bytes_equal_xvc_continuation"] = tail_matches_xvc_continuation
            hyp["level"] = "CONFIRMED" if tail_matches_xvc_continuation else "REFUTED"
        else:
            hyp["level"] = "UNTESTED"
        hypotheses.append(hyp)
    elif delta < 0:
        hypotheses.append({"id": "truncated_copy", "detail": f"copia {abs(delta)} byte(s) MENOR que o tamanho gravado",
                           "level": "CONFIRMED"})
    else:
        hypotheses.append({"id": "exact_match", "detail": "tamanhos identicos", "level": "CONFIRMED"})
    return {
        "schema": "alpha_recovery.size_reconciliation/1",
        "expected_size_stored": stored_len,
        "actual_size": actual_len,
        "delta": delta,
        "page_math": info,
        "hypotheses": hypotheses,
        "policy": "nenhum truncamento automatico e aplicado; o arquivo real permanece intacto",
    }
