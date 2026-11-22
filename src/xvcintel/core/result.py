"""Tratamento de erro no estilo Result para entradas malformadas.

Parsers nunca levantam excecao por causa de bytes ruins: devolvem Ok(valor) ou
Err(ParseError). Excecoes ficam para erros de programacao e de E/S.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Generic, TypeVar, Union

T = TypeVar("T")
U = TypeVar("U")

# tipos de erro (algebra fechada; testes dependem destes nomes)
TRUNCATED = "truncated"          # faltam bytes para a estrutura
BAD_MAGIC = "bad_magic"          # assinatura ausente/errada
OUT_OF_BOUNDS = "out_of_bounds"  # offset/tamanho aponta para fora do buffer
INCONSISTENT = "inconsistent"    # campos contradizem uns aos outros
INVALID_VALUE = "invalid_value"  # valor fora do dominio aceito
UNSUPPORTED = "unsupported"      # variante do formato que nao sabemos ler com seguranca

ERROR_KINDS = (TRUNCATED, BAD_MAGIC, OUT_OF_BOUNDS, INCONSISTENT, INVALID_VALUE, UNSUPPORTED)


@dataclass(frozen=True)
class ParseError:
    kind: str
    message: str
    offset: int | None = None
    structure: str = ""

    def __post_init__(self) -> None:
        if self.kind not in ERROR_KINDS:
            raise ValueError(f"tipo de erro desconhecido: {self.kind}")

    def __str__(self) -> str:
        where = f" @0x{self.offset:x}" if self.offset is not None else ""
        st = f"[{self.structure}] " if self.structure else ""
        return f"{st}{self.kind}{where}: {self.message}"


@dataclass(frozen=True)
class Ok(Generic[T]):
    value: T

    @property
    def ok(self) -> bool:
        return True


@dataclass(frozen=True)
class Err:
    error: ParseError

    @property
    def ok(self) -> bool:
        return False


Result = Union[Ok[T], Err]


class ParseFailure(Exception):
    """Levantada apenas por unwrap(), quando o chamador exige sucesso."""

    def __init__(self, error: ParseError):
        super().__init__(str(error))
        self.error = error


def err(kind: str, message: str, offset: int | None = None, structure: str = "") -> Err:
    return Err(ParseError(kind, message, offset, structure))


def unwrap(r: "Result[T]") -> T:
    if isinstance(r, Ok):
        return r.value
    raise ParseFailure(r.error)


def map_ok(r: "Result[T]", fn: Callable[[T], U]) -> "Result[U]":
    return Ok(fn(r.value)) if isinstance(r, Ok) else r


def need(buf: bytes, offset: int, size: int, structure: str) -> Err | None:
    """Err(TRUNCATED/OUT_OF_BOUNDS) se buf[offset:offset+size] nao existir."""
    if offset < 0 or size < 0:
        return err(OUT_OF_BOUNDS, f"offset/tamanho negativo ({offset}, {size})", offset, structure)
    if offset + size > len(buf):
        kind = OUT_OF_BOUNDS if offset > len(buf) else TRUNCATED
        return err(kind, f"precisa de 0x{offset + size:x} bytes, buffer tem 0x{len(buf):x}", offset, structure)
    return None
