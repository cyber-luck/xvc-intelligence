"""Modelo de evidencias, resultados de checagem e achados.

Rotulos de confianca:
  CONFIRMED - verificado contra bytes deste pacote (por um check com id)
  INFERRED  - consistente mas nao provado, ou vindo de fonte publica sem verificacao local
  UNKNOWN   - nao determinado
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

CONFIRMED = "CONFIRMED"
INFERRED = "INFERRED"
UNKNOWN = "UNKNOWN"
LEVELS = (CONFIRMED, INFERRED, UNKNOWN)

PASS = "PASS"
FAIL = "FAIL"
SKIPPED = "SKIPPED"
INFO = "INFO"
PARTIAL = "PARTIAL"
STATUSES = (PASS, FAIL, SKIPPED, INFO, PARTIAL)


@dataclass
class Evidence:
    source: str                     # ex.: "xvc:cabecalho", "xvc:XvcInfo", "userdata:MicrosoftGame.config", "xvdtool"
    field: str = ""
    offset: int | None = None       # offset absoluto no .xvc (ou no arquivo citado)
    value: str | None = None
    test_id: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        if self.offset is not None:
            d["offset_hex"] = f"0x{self.offset:X}"
        return d


@dataclass
class CheckResult:
    id: str
    title: str
    status: str
    detail: str = ""
    coverage: str = ""              # o que foi examinado (amostra, limite, completo)
    counts: dict[str, Any] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(self.status)

    @property
    def passed(self) -> bool:
        return self.status == PASS

    def to_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "status": self.status, "detail": self.detail,
                "coverage": self.coverage, "counts": self.counts,
                "evidence": [e.to_dict() for e in self.evidence], "data": self.data}


@dataclass
class Finding:
    id: str
    category: str
    statement: str
    level: str
    evidence: list[Evidence] = field(default_factory=list)
    tests: list[str] = field(default_factory=list)          # ids de CheckResult / testes pytest
    how_to_test: str = ""                                     # teste que confirmaria/refutaria
    notes: str = ""

    def __post_init__(self) -> None:
        if self.level not in LEVELS:
            raise ValueError(self.level)

    def to_dict(self) -> dict:
        return {"id": self.id, "category": self.category, "statement": self.statement, "level": self.level,
                "evidence": [e.to_dict() for e in self.evidence], "tests": self.tests,
                "how_to_test": self.how_to_test, "notes": self.notes}


def level_from_check(c: CheckResult | None, when_pass: str = CONFIRMED) -> str:
    if c is None or c.status in (SKIPPED, INFO):
        return UNKNOWN
    return when_pass if c.status == PASS else UNKNOWN
