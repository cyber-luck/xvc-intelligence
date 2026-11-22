"""Funcoes pequenas e puras usadas por varios modulos."""
from __future__ import annotations

import collections
import datetime
import math
import struct

PAGE = 0x1000


def pages(n: int) -> int:
    return (n + PAGE - 1) // PAGE


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    n = len(b)
    return 0.0 - sum(c / n * math.log2(c / n) for c in collections.Counter(b).values())


def filetime(v: int) -> str:
    if not v:
        return "0"
    try:
        dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=v // 10)
        return dt.isoformat()
    except OverflowError:
        return "fora do intervalo"


def utf16z(raw: bytes) -> str:
    return raw.decode("utf-16-le", errors="replace").split("\0", 1)[0]


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def u64(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


def hx(v: int | None) -> str | None:
    return None if v is None else f"0x{v:X}"


def signed_diff32(a: int, b: int) -> int:
    """a - b em aritmetica de 32 bits com sinal."""
    return ((a - b + 2**31) % 2**32) - 2**31


def is_zero(b: bytes) -> bool:
    return not any(b)
