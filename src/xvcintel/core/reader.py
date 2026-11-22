"""Leitura somente leitura e em streaming.

FileSource abre o arquivo exclusivamente com modo "rb" e nao expoe nenhum
metodo de escrita. Leituras unicas acima de MAX_SINGLE_READ sao recusadas:
quem precisa de mais usa iter_chunks()/sha256_range(), que leem em blocos.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from typing import Iterator, Protocol

PAGE = 0x1000
MAX_SINGLE_READ = 256 * 1024 * 1024     # nunca carregar mais que 256 MB de uma vez
DEFAULT_CHUNK = 16 * 1024 * 1024


class ReadLimitError(Exception):
    pass


@dataclass
class ReadStats:
    reads: int = 0
    bytes_read: int = 0


class ByteSource(Protocol):
    size: int
    name: str
    stats: ReadStats

    def read_at(self, offset: int, length: int) -> bytes: ...


class _Base:
    size: int
    name: str
    stats: ReadStats

    def _check(self, offset: int, length: int) -> None:
        if offset < 0 or length < 0:
            raise ValueError(f"offset/tamanho negativo: {offset}, {length}")
        if length > MAX_SINGLE_READ:
            raise ReadLimitError(f"leitura unica de {length} bytes excede {MAX_SINGLE_READ}; use iter_chunks")

    def iter_chunks(self, offset: int, length: int, chunk: int = DEFAULT_CHUNK) -> Iterator[bytes]:
        """Gera blocos de no maximo `chunk` bytes; para cedo se o arquivo acabar."""
        chunk = min(chunk, MAX_SINGLE_READ)
        end = min(offset + length, self.size)
        pos = offset
        while pos < end:
            b = self.read_at(pos, min(chunk, end - pos))
            if not b:
                break
            yield b
            pos += len(b)

    def sha256_range(self, offset: int, length: int, chunk: int = DEFAULT_CHUNK) -> tuple[bytes, int]:
        """(digest, bytes efetivamente lidos)."""
        h = hashlib.sha256()
        n = 0
        for b in self.iter_chunks(offset, length, chunk):
            h.update(b)
            n += len(b)
        return h.digest(), n


class FileSource(_Base):
    """Arquivo aberto em "rb". Nunca escreve, renomeia nem altera atributos."""

    def __init__(self, path: str | os.PathLike):
        self.path = os.fspath(path)
        self.name = self.path
        self._f = open(self.path, "rb")          # unico modo permitido
        self.size = os.fstat(self._f.fileno()).st_size
        self.stats = ReadStats()

    def read_at(self, offset: int, length: int) -> bytes:
        self._check(offset, length)
        self._f.seek(offset)
        b = self._f.read(length)
        self.stats.reads += 1
        self.stats.bytes_read += len(b)
        return b

    @property
    def mode(self) -> str:
        return self._f.mode

    def close(self) -> None:
        self._f.close()

    def __enter__(self) -> "FileSource":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class BytesSource(_Base):
    """Fonte em memoria (fixtures sinteticas e extratos pequenos)."""

    def __init__(self, data: bytes, name: str = "<memoria>"):
        self._d = bytes(data)
        self.size = len(self._d)
        self.name = name
        self.stats = ReadStats()

    def read_at(self, offset: int, length: int) -> bytes:
        self._check(offset, length)
        b = self._d[offset:offset + length]
        self.stats.reads += 1
        self.stats.bytes_read += len(b)
        return b

    def close(self) -> None:
        pass

    def __enter__(self) -> "BytesSource":
        return self

    def __exit__(self, *exc) -> None:
        pass


def open_source(path: str | os.PathLike) -> FileSource:
    return FileSource(path)
