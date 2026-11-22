"""Mapa de intervalos classificados do executavel procurado (Fase 4).

Cada intervalo traz: arquivo de origem, offset fisico, regiao/segmento,
posicao virtual, secao PE (quando conhecida) e evidencia. Resolucao de
conflitos por segmento elementar: bytes comprovados (EXACT/MATCHED) nunca
sao substituidos por inferencia; fontes com bytes comprovados divergentes
viram CONFLICTING_EVIDENCE preservando as duas provas; lacunas recebem a
classe base declarada no construtor.
"""
from __future__ import annotations

EXACT_RECOVERED = "EXACT_RECOVERED"
MATCHED_COPY = "MATCHED_COPY"
STRUCTURAL_INFERENCE = "STRUCTURAL_INFERENCE"
ENCRYPTED_UNKNOWN = "ENCRYPTED_UNKNOWN"
MISSING = "MISSING"
CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
UNVERIFIED = "UNVERIFIED"

_BYTE_PROVEN = {EXACT_RECOVERED, MATCHED_COPY}
_PRIORITY = {EXACT_RECOVERED: 0, MATCHED_COPY: 1, STRUCTURAL_INFERENCE: 2, UNVERIFIED: 3}


class IntervalMap:
    def __init__(self, total_bytes: int, base_label: str = MISSING):
        if total_bytes <= 0:
            raise ValueError("alvo de tamanho nao positivo")
        self.total = total_bytes
        self.base_label = base_label
        self.intervals: list[dict] = []
        self.conflicts: list[dict] = []

    def add(self, start: int, end: int, classification: str, evidence: list[dict] | None = None,
            *, source_file: str | None = None, source_offset: int | None = None,
            virtual_offset: int | None = None, pe_section: str | None = None,
            region_segment: str | None = None, transform: str = "identity") -> None:
        if end <= start:
            raise ValueError(f"intervalo vazio: [{start}, {end})")
        if start < 0 or end > self.total:
            raise ValueError(f"intervalo [{start},{end}) fora do alvo de {self.total} bytes")
        ev = list(evidence or [])
        if source_file is not None:
            ev.append({"source_file": source_file, "source_offset": source_offset,
                       "transform": transform, "note": ""})
        self.intervals.append({
            "start": start, "end": end, "classification": classification,
            "evidence": ev, "virtual_offset": virtual_offset,
            "pe_section": pe_section, "region_segment": region_segment,
        })

    def resolve(self) -> list[dict]:
        bounds = sorted({0, self.total} | {i["start"] for i in self.intervals} | {i["end"] for i in self.intervals})
        resolved: list[dict] = []
        self.conflicts = []
        for s, e in zip(bounds, bounds[1:]):
            covering = [i for i in self.intervals if i["start"] <= s and i["end"] >= e]
            cls, evs, meta = self._classify(covering, s)
            seg = {"start": s, "end": e, "classification": cls, "evidence": evs,
                   "virtual_offset": s, "pe_section": meta.get("pe_section"),
                   "region_segment": meta.get("region_segment")}
            if resolved and resolved[-1]["classification"] == cls:
                resolved[-1]["end"] = e
                resolved[-1]["evidence"].extend(e for e in evs if e not in resolved[-1]["evidence"])
            else:
                resolved.append(seg)
        return resolved

    def _classify(self, covering: list[dict], seg_start: int) -> tuple[str, list[dict], dict]:
        if not covering:
            return self.base_label, [], {}
        proven = [i for i in covering if i["classification"] in _BYTE_PROVEN]
        if proven:
            hashes = set()
            for i in proven:
                hashes.update(x.get("sha256") for x in i["evidence"] if x.get("sha256"))
            if len(hashes) > 1:
                self.conflicts.append({
                    "start": seg_start,
                    "classes": sorted({i["classification"] for i in proven}),
                    "sha256_distinct": sorted(hashes),
                    "evidence": [e for i in proven for e in i["evidence"]],
                })
                return CONFLICTING_EVIDENCE, [e for i in proven for e in i["evidence"]], {}
            best = min(proven, key=lambda i: _PRIORITY[i["classification"]])
            return best["classification"], [e for i in proven for e in i["evidence"]], best
        for cls in (STRUCTURAL_INFERENCE, UNVERIFIED):
            hits = [i for i in covering if i["classification"] == cls]
            if hits:
                return cls, [e for i in hits for e in i["evidence"]], hits[0]
        return self.base_label, [e for i in covering for e in i["evidence"]], covering[0]

    def coverage(self, intervals: list[dict]) -> dict:
        stats: dict[str, int] = {}
        for iv in intervals:
            stats[iv["classification"]] = stats.get(iv["classification"], 0) + (iv["end"] - iv["start"])
        known = {EXACT_RECOVERED, MATCHED_COPY, STRUCTURAL_INFERENCE, ENCRYPTED_UNKNOWN,
                MISSING, CONFLICTING_EVIDENCE, UNVERIFIED}
        for k in known - set(stats):
            stats[k] = 0
        return {
            "total_bytes": self.total,
            "by_class_bytes": dict(sorted(stats.items())),
            "pct": {k: round(100.0 * v / self.total, 6) for k, v in sorted(stats.items())},
            "note": "bytes recuperados com prova e bytes inferidos nunca sao somados na mesma taxa",
        }

    def to_json(self) -> dict:
        ivs = self.resolve()
        return {
            "schema": "alpha_recovery.shadow_pe_map/1",
            "total_bytes": self.total,
            "base_label": self.base_label,
            "intervals": [
                {"start": i["start"], "end": i["end"], "classification": i["classification"],
                 "virtual_offset": i.get("virtual_offset"), "pe_section": i.get("pe_section"),
                 "region_segment": i.get("region_segment"), "evidence": i["evidence"]}
                for i in ivs
            ],
            "conflicts": self.conflicts,
            "coverage": self.coverage(ivs),
        }
