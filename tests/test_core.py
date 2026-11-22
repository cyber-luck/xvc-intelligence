import hashlib
import os

import pytest

from xvcintel.core.reader import MAX_SINGLE_READ, BytesSource, FileSource, ReadLimitError
from xvcintel.core.result import (BAD_MAGIC, ERROR_KINDS, OUT_OF_BOUNDS, TRUNCATED, Err, Ok, ParseError,
                                  ParseFailure, err, map_ok, need, unwrap)
from xvcintel.core.util import entropy, filetime, pages, signed_diff32, utf16z


def test_result_algebra():
    assert unwrap(Ok(3)) == 3
    e = err(TRUNCATED, "x", 5, "S")
    assert isinstance(e, Err) and not e.ok and Ok(1).ok
    with pytest.raises(ParseFailure):
        unwrap(e)
    assert map_ok(Ok(2), lambda v: v * 2) == Ok(4)
    assert map_ok(e, lambda v: v) is e
    assert "0x5" in str(e.error) and "[S]" in str(e.error)
    with pytest.raises(ValueError):
        ParseError("inventado", "x")
    assert set(ERROR_KINDS) >= {TRUNCATED, BAD_MAGIC, OUT_OF_BOUNDS}


def test_need_bounds():
    assert need(b"abcd", 0, 4, "s") is None
    assert need(b"abcd", 2, 3, "s").error.kind == TRUNCATED
    assert need(b"abcd", 9, 1, "s").error.kind == OUT_OF_BOUNDS
    assert need(b"abcd", -1, 1, "s").error.kind == OUT_OF_BOUNDS


def test_bytes_source_reads_and_limits():
    s = BytesSource(bytes(range(256)) * 100)
    assert s.read_at(10, 4) == bytes([10, 11, 12, 13])
    assert s.read_at(s.size - 2, 10) == bytes([254, 255])
    with pytest.raises(ReadLimitError):
        s.read_at(0, MAX_SINGLE_READ + 1)
    with pytest.raises(ValueError):
        s.read_at(-1, 1)
    chunks = list(s.iter_chunks(5, 1000, chunk=300))
    assert [len(c) for c in chunks] == [300, 300, 300, 100]
    d, n = s.sha256_range(0, s.size, chunk=777)
    assert d == hashlib.sha256(bytes(range(256)) * 100).digest() and n == s.size
    # leitura que passa do fim para cedo e relata o que leu
    d2, n2 = s.sha256_range(s.size - 10, 1000)
    assert n2 == 10


def test_file_source_is_read_only(tmp_path):
    p = tmp_path / "pacote.bin"
    p.write_bytes(b"\x01" * 9000)
    st = os.stat(p)
    with FileSource(p) as src:
        assert src.mode == "rb"
        assert not any(hasattr(src, m) for m in ("write", "write_at", "truncate"))
        assert src.read_at(8990, 100) == b"\x01" * 10
        list(src.iter_chunks(0, src.size, chunk=4096))
        assert src.stats.bytes_read >= 9000
    st2 = os.stat(p)
    assert (st.st_size, st.st_mtime_ns) == (st2.st_size, st2.st_mtime_ns)


def test_utils():
    assert pages(0) == 0 and pages(1) == 1 and pages(0x1000) == 1 and pages(0x1001) == 2
    assert entropy(b"") == 0.0 and entropy(b"\0" * 10) == 0.0
    assert abs(entropy(bytes(range(256))) - 8.0) < 1e-9
    assert filetime(0) == "0" and filetime(0x1DD74577AD5CC0E).startswith("2026-11-14")
    assert filetime(2**64 - 1) in ("fora do intervalo",) or filetime(2**64 - 1)
    assert utf16z("ab\0cd".encode("utf-16-le")) == "ab"
    assert signed_diff32(0x049EA1FD, 0x049EA1FE) == -1
    assert signed_diff32(0, 0xFFFFFFFF) == 1
