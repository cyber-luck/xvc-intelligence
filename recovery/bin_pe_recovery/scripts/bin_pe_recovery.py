#!/usr/bin/env python3
"""Recover structurally valid PE candidates from BIN/XVD/XVC/opaque containers.

READ ONLY on input.  No cryptographic decryption, key guessing, execution, or
signature spoofing.  Extracts only intact/partially-intact plain or decompressed
PE candidates.  Supports gzip, XZ, bzip2, ZIP, LZ4 (optional), Zstandard (optional),
and opt-in zlib heuristic scanning.

Python 3.10+; standard library except optional lz4 and zstandard.
"""
from __future__ import annotations

import argparse
import bz2
import datetime as dt
import hashlib
import json
import lzma
import math
import os
from pathlib import Path
import re
import struct
import sys
import zlib
import zipfile
from typing import Optional

MACHINES = {0x014c: "x86", 0x8664: "x64", 0xAA64: "ARM64", 0x01c4: "ARMv7", 0x0200: "IA64"}
MAGICS = {
    "gzip": b"\x1f\x8b\x08",
    "xz": b"\xfd7zXZ\x00",
    "bzip2": b"BZh",
    "zstd": b"\x28\xb5\x2f\xfd",
    "lz4": b"\x04\x22\x4d\x18",
}
DEFAULT_MAX_SCAN = 1 << 30  # One GiB; use --max-scan 0 for whole file.
DEFAULT_MAX_OUTPUT = 64 << 20


def u16(buf: bytes, off: int) -> int:
    return struct.unpack_from('<H', buf, off)[0]


def u32(buf: bytes, off: int) -> int:
    return struct.unpack_from('<I', buf, off)[0]


def entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    counts = [0] * 256
    for x in buf:
        counts[x] += 1
    n = len(buf)
    return -sum((v / n) * math.log2(v / n) for v in counts if v)


def parse_pe(data: bytes, start: int = 0, max_pe_size: int = 512 << 20) -> Optional[dict]:
    """Validate enough of a DOS+COFF+PE header to reject random MZ hits.

    Returns precise *minimum file extent* based on raw sections, NOT a claim
    that Authenticode, overlay, executable behavior or required DLLs are valid.
    """
    available = len(data) - start
    if start < 0 or available < 0x40 or data[start:start + 2] != b'MZ':
        return None
    pe_off = u32(data, start + 0x3c)
    if not 0x40 <= pe_off <= 0x100000 or pe_off + 24 > available:
        return None
    coff = start + pe_off
    if data[coff:coff + 4] != b'PE\x00\x00':
        return None
    machine, sections, timestamp, _, _, opt_size, characteristics = struct.unpack_from('<HHIIIHH', data, coff + 4)
    if not 1 <= sections <= 96 or not 0x60 <= opt_size <= 0x1000:
        return None
    opt_off = coff + 24
    sect_off = opt_off + opt_size
    if sect_off + 40 * sections > len(data):
        return None
    opt_magic = u16(data, opt_off)
    if opt_magic not in (0x10b, 0x20b):
        return None
    if opt_size < (96 if opt_magic == 0x10b else 112):
        return None
    image_size = u32(data, opt_off + 56)
    header_size = u32(data, opt_off + 60)
    subsystem = u16(data, opt_off + 68)
    entry_rva = u32(data, opt_off + 16)
    section_alignment = u32(data, opt_off + 32)
    file_alignment = u32(data, opt_off + 36)
    if not 0 < header_size <= max_pe_size or not 0 < image_size < (1 << 32):
        return None
    if header_size < sect_off + 40 * sections - start:
        return None
    if not 1 <= section_alignment <= (1 << 28) or not 1 <= file_alignment <= (1 << 24):
        return None
    min_extent = header_size
    sect_list = []
    for i in range(sections):
        s = sect_off + i * 40
        name = data[s:s+8].split(b'\x00', 1)[0].decode('ascii', 'replace')
        virtual_size = u32(data, s + 8)
        rva = u32(data, s + 12)
        raw_size = u32(data, s + 16)
        raw_offset = u32(data, s + 20)
        if raw_size:
            if raw_offset == 0 or raw_size > max_pe_size or raw_offset + raw_size > max_pe_size:
                return None
            min_extent = max(min_extent, raw_offset + raw_size)
        sect_list.append({"name": name, "rva": rva, "virtual_size": virtual_size,
                          "raw_offset": raw_offset, "raw_size": raw_size})
    # Include a declared certificate table when present.  It is indexed by
    # file offset, unlike most data directories; the certificate is optional.
    dirs_off = opt_off + (96 if opt_magic == 0x10b else 112)
    if dirs_off + 8 * 5 <= opt_off + opt_size:
        cert_off, cert_size = struct.unpack_from('<II', data, dirs_off + 8 * 4)
        if cert_off and cert_size and cert_off + cert_size <= max_pe_size:
            min_extent = max(min_extent, cert_off + cert_size)
    if min_extent > max_pe_size:
        return None
    truncated = min_extent > available
    pe_kind = "PE32+" if opt_magic == 0x20b else "PE32"
    if subsystem == 0x11:
        purpose = "xbox_code_catalog_candidate_not_game_executable"
        suggested_extension = ".catalog.bin"
    elif characteristics & 0x2000:
        purpose = "dll_candidate"
        suggested_extension = ".dll"
    else:
        purpose = "executable_candidate"
        suggested_extension = ".exe"
    return {
        "offset": start, "machine": f"0x{machine:04x}", "architecture": MACHINES.get(machine, "unknown"),
        "format": pe_kind, "subsystem": f"0x{subsystem:04x}", "purpose": purpose,
        "number_of_sections": sections, "timestamp": timestamp, "characteristics": f"0x{characteristics:04x}",
        "entry_point_rva": f"0x{entry_rva:x}", "image_size": image_size, "header_size": header_size,
        "minimum_file_extent": min_extent, "available_bytes": available,
        "truncated": truncated, "suggested_extension": suggested_extension,
        "sections": sect_list,
        "evidence": "PE headers and raw section extents validated; execution/signatures not validated",
    }


def parse_pe_file(path: Path, offset: int, max_pe_size: int) -> Optional[dict]:
    size = path.stat().st_size
    if offset >= size:
        return None
    with path.open('rb') as fh:
        fh.seek(offset)
        small = fh.read(min(size-offset, 2 << 20))
    # Parse headers using a small buffer.  Do not treat the rest of file as
    # 'unavailable' solely because it was not buffered.
    pe = parse_pe(small, 0, max_pe_size=max_pe_size)
    if not pe:
        return None
    pe["offset"] = offset
    pe["available_bytes"] = size-offset
    pe["truncated"] = pe["minimum_file_extent"] > size-offset
    return pe


def scan_offsets(path: Path, cap: int, max_mz: int, max_compressed: int, deep_zlib: bool):
    patterns = [("mz", b"MZ"), *MAGICS.items()]
    if deep_zlib:
        patterns.extend([("zlib", bytes((0x78, v))) for v in (0x01, 0x5e, 0x9c, 0xda)])
    found = {name: [] for name, _ in patterns}
    limit_hit = {name: False for name in found}
    step = 4 << 20
    overlap = max(map(lambda x: len(x[1]), patterns)) - 1
    with path.open('rb') as fh:
        pos = 0
        while pos < cap:
            chunk = fh.read(min(step + overlap, cap - pos))
            if not chunk:
                break
            # Only offsets within the "step" area belong to this iteration.
            owned = min(step, cap - pos)
            for name, sig in patterns:
                found_list = found[name]
                cap_hits = max_mz if name == "mz" else max_compressed
                idx = 0
                while True:
                    idx = chunk.find(sig, idx)
                    if idx < 0 or idx >= owned:
                        break
                    if len(found_list) < cap_hits:
                        found_list.append(pos + idx)
                    else:
                        limit_hit[name] = True
                    idx += 1
            pos += owned
            fh.seek(pos)
    return found, limit_hit


class LimitedInput:
    def __init__(self, path: Path, start: int, max_compressed: int):
        self.fh = path.open('rb')
        self.fh.seek(start)
        self.remaining = max_compressed

    def read(self, size: int = -1):
        if self.remaining <= 0:
            return b''
        if size < 0 or size > self.remaining:
            size = self.remaining
        chunk = self.fh.read(size)
        self.remaining -= len(chunk)
        return chunk

    def close(self):
        self.fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def decompress_limited(path: Path, start: int, kind: str, max_input: int, max_output: int):
    if kind in ("gzip", "zlib"):
        obj = zlib.decompressobj(31 if kind == "gzip" else 15)
    elif kind == "xz":
        obj = lzma.LZMADecompressor()
    elif kind == "bzip2":
        obj = bz2.BZ2Decompressor()
    elif kind == "zstd":
        try:
            import zstandard as zstd
        except ImportError:
            return None, "optional_dependency_missing:zstandard"
        try:
            with LimitedInput(path, start, max_input) as src:
                with zstd.ZstdDecompressor().stream_reader(src) as reader:
                    out = bytearray()
                    while len(out) <= max_output:
                        data = reader.read(min(65536, max_output + 1 - len(out)))
                        if not data:
                            break
                        out.extend(data)
                    if len(out) > max_output:
                        return None, "decompressed_output_limit"
                    return bytes(out), None
        except (Exception) as exc:
            return None, "invalid_or_incomplete_zstd:" + type(exc).__name__
    elif kind == "lz4":
        try:
            import lz4.frame
        except ImportError:
            return None, "optional_dependency_missing:lz4"
        try:
            with LimitedInput(path, start, max_input) as src:
                with lz4.frame.open(src, 'rb') as reader:
                    out = bytearray()
                    while len(out) <= max_output:
                        data = reader.read(min(65536, max_output + 1 - len(out)))
                        if not data:
                            break
                        out.extend(data)
                    if len(out) > max_output:
                        return None, "decompressed_output_limit"
                    return bytes(out), None
        except Exception as exc:
            return None, "invalid_or_incomplete_lz4:" + type(exc).__name__
    else:
        return None, "unknown_codec"
    out = bytearray()
    try:
        with LimitedInput(path, start, max_input) as src:
            while True:
                raw = src.read(64 << 10)
                if not raw:
                    break
                remaining = max_output + 1 - len(out)
                if remaining <= 0:
                    return None, "decompressed_output_limit"
                out.extend(obj.decompress(raw, remaining))
                if len(out) > max_output:
                    return None, "decompressed_output_limit"
                if obj.eof:
                    return bytes(out), None
    except (zlib.error, lzma.LZMAError, EOFError, OSError, ValueError) as exc:
        return None, "invalid_stream:" + type(exc).__name__
    return None, "incomplete_stream_or_input_limit"


def analyse_buffer_pe(buf: bytes, max_pe_size: int, max_mz: int = 2000):
    hits = []
    off = 0
    count = 0
    while count < max_mz:
        off = buf.find(b"MZ", off)
        if off < 0:
            break
        pe = parse_pe(buf, off, max_pe_size)
        if pe:
            hits.append(pe)
        off += 2
        count += 1
    return hits


def safe_write_json(path: Path, report: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
        fh.write('\n')


def write_carve(out_dir: Path, name: str, data: bytes, hash_: bool = True):
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / name
    with dest.open('xb') as fh:
        fh.write(data)
    return {"path": str(dest), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest() if hash_ else None}


def file_head_type(path: Path):
    with path.open('rb') as fh:
        h = fh.read(0x220)
    if len(h) >= 0x208 and h[0x200:0x208] == b'msft-xvd':
        return "xvd_or_xvc_container_header"
    for name, sig in MAGICS.items():
        if h.startswith(sig):
            return f"{name}_compressed_stream"
    if h.startswith(b'MZ'):
        return "dos_pe_candidate"
    if h.startswith(b'regf'):
        return "registry_hive"
    if h.startswith(b'PK\x03\x04'):
        return "zip_archive"
    return "unknown_bin"


def sample_file_entropy(path: Path):
    size = path.stat().st_size
    size_one = min(size, 65536)
    offsets = sorted(set((0, max(0, (size - size_one) // 2), max(0, size - size_one))))
    result = []
    with path.open('rb') as fh:
        for off in offsets:
            fh.seek(off)
            data = fh.read(size_one)
            result.append({"offset": off, "bytes": len(data), "entropy": round(entropy(data), 5)})
    return result


def run_scan(args):
    path = Path(args.path).resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size
    cap = size if args.max_scan == 0 else min(size, args.max_scan)
    found, limit_hit = scan_offsets(path, cap, args.max_mz, args.max_streams, args.deep_zlib)
    pe_hits = []
    for off in found['mz']:
        p = parse_pe_file(path, off, args.max_pe_size)
        if p:
            p['origin'] = {'kind': 'direct_bytes', 'offset': off}
            pe_hits.append(p)
    report = {
        "schema": "bin-pe-recovery/1", "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'),
        "source": str(path), "size": size, "header_kind": file_head_type(path),
        "scan": {"bytes_scanned": cap, "file_bytes": size, "coverage": round(cap / size, 6) if size else 1.0,
                 "entire_file_scanned": cap == size, "max_candidates_reached": limit_hit,
                 "raw_mz_hits": len(found['mz'])},
        "entropy_samples": sample_file_entropy(path),
        "pe_candidates": pe_hits, "compressed_streams": [], "extractions": [],
        "capability": {"plain_pe_carving": True, "known_compression": bool(args.compressed),
                       "cryptographic_decryption": False, "xvd_key_recovery": False},
        "limitations": ["MZ scanning cannot reveal AES-XTS-encrypted PE data",
                        "PE section carving may exclude overlay or external file dependencies",
                        "PE header validity does not establish a working executable"],
    }
    print(f"Input: {path} ({size:,} bytes) | scan: {cap:,} bytes | PE candidates: {len(pe_hits)}")
    out_dir = Path(args.extract_dir).resolve() if args.extract_dir else None
    if out_dir and (out_dir == path or path in out_dir.parents):
        # The original is a file; this is a deliberately conservative guard.
        raise ValueError("Output directory may not be nested under the input file path")
    for pe in pe_hits:
        if not out_dir or (pe['truncated'] and not args.extract_partial):
            continue
        with path.open('rb') as fh:
            fh.seek(pe['offset'])
            data = fh.read(min(pe['minimum_file_extent'], pe['available_bytes']))
        suffix = '.partial.bin' if pe['truncated'] else pe['suggested_extension']
        info = write_carve(out_dir, f"direct_0x{pe['offset']:012x}{suffix}", data)
        info.update({"kind": "direct", "source_offset": pe['offset'], "truncated": pe['truncated']})
        report['extractions'].append(info)
    if args.compressed:
        count = 0
        for kind in ("gzip", "xz", "bzip2", "zstd", "lz4", "zlib"):
            for off in found.get(kind, []):
                if count >= args.max_streams:
                    break
                count += 1
                blob, error = decompress_limited(path, off, kind, args.max_compressed_input, args.max_decompressed)
                ent = {"offset": off, "codec": kind, "status": error or "decompressed", "decoded_bytes": len(blob) if blob is not None else 0}
                if blob is not None:
                    pe_list = analyse_buffer_pe(blob, args.max_pe_size)
                    ent['pe_candidates'] = pe_list
                    for i, pe in enumerate(pe_list):
                        if not out_dir or (pe['truncated'] and not args.extract_partial):
                            continue
                        data = blob[pe['offset']:pe['offset'] + pe['minimum_file_extent']]
                        suffix = '.partial.bin' if pe['truncated'] else pe['suggested_extension']
                        info = write_carve(out_dir, f"{kind}_0x{off:012x}_pe{i:02d}{suffix}", data)
                        info.update({"kind": "decompressed", "source_offset": off, "codec": kind, "truncated": pe['truncated']})
                        report['extractions'].append(info)
                report['compressed_streams'].append(ent)
                if blob is not None and ent.get('pe_candidates'):
                    print(f"  {kind}@0x{off:x}: {len(ent['pe_candidates'])} PE candidate(s)")
        # ZIP containers: ZIP can retain a valid central directory even if it
        # is prepended by a self-extracting stub.  We extract only PE candidates,
        # never arbitrary archived paths, and enforce both size budgets.
        if count < args.max_streams and zipfile.is_zipfile(path):
            try:
                with zipfile.ZipFile(path) as archive:
                    for member in archive.infolist():
                        if count >= args.max_streams:
                            break
                        if member.is_dir():
                            continue
                        count += 1
                        entry = {"codec": "zip", "member": member.filename,
                                 "compressed_size": member.compress_size, "decoded_bytes": 0}
                        if member.flag_bits & 1:
                            entry['status'] = 'encrypted_zip_member_key_required'
                        elif member.file_size > args.max_decompressed or member.compress_size > args.max_compressed_input:
                            entry['status'] = 'size_limit'
                        else:
                            try:
                                with archive.open(member) as stream:
                                    blob = stream.read(args.max_decompressed + 1)
                                if len(blob) > args.max_decompressed:
                                    entry['status'] = 'decompressed_output_limit'
                                else:
                                    entry['status'] = 'decompressed'
                                    entry['decoded_bytes'] = len(blob)
                                    entry['pe_candidates'] = analyse_buffer_pe(blob, args.max_pe_size)
                                    for i, pe in enumerate(entry['pe_candidates']):
                                        if not out_dir or (pe['truncated'] and not args.extract_partial):
                                            continue
                                        payload = blob[pe['offset']:pe['offset'] + pe['minimum_file_extent']]
                                        suffix = '.partial.bin' if pe['truncated'] else pe['suggested_extension']
                                        info = write_carve(out_dir, f"zip_member{count:05d}_pe{i:02d}{suffix}", payload)
                                        info.update({"kind": "decompressed", "codec": "zip", "member": member.filename, "truncated": pe['truncated']})
                                        report['extractions'].append(info)
                            except (OSError, EOFError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
                                entry['status'] = 'invalid_zip_member:' + type(exc).__name__
                        report['compressed_streams'].append(entry)
            except (OSError, ValueError, zipfile.BadZipFile) as exc:
                report['compressed_streams'].append({'codec': 'zip', 'status': 'invalid_archive:' + type(exc).__name__})
        report['scan']['streams_attempted'] = count
    print(f"Recovered PE candidates: {len(pe_hits) + sum(len(s.get('pe_candidates', [])) for s in report['compressed_streams'])}; extracted files: {len(report['extractions'])}")
    if report['header_kind'] == 'xvd_or_xvc_container_header':
        print("Note: container may contain AES-XTS-encrypted regions; this scan does NOT decrypt them.")
    if cap < size:
        print("WARNING: scan was limited; absence of PE is not a whole-file conclusion.")
    if args.json:
        safe_write_json(Path(args.json).resolve(), report)
        print(f"JSON report: {args.json}")
    return 1 if args.require_pe and not pe_hits and not any(s.get('pe_candidates') for s in report['compressed_streams']) else 0


# These are raw-string clues, not an actual registry parser.
EXT_RE = r"(?:exe|dll|sys|xex)"
ASCII_EXE_RE = re.compile(rb"(?i)(?:[a-z]:\\|\\\\)?[a-z0-9._/\\:()\- ]{0,180}\." + EXT_RE.encode() + rb"\b")
WIDE_EXE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){1,200}\x2e\x00(?:e\x00x\x00e\x00|d\x00l\x00l\x00|s\x00y\x00s\x00)", re.I)


def run_refs(args):
    p = Path(args.path).resolve()
    size = p.stat().st_size
    cap = size if args.max_scan == 0 else min(size, args.max_scan)
    matches = []
    seen = set()
    with p.open('rb') as fh:
        pos = 0
        step = 1 << 20
        overlap = 1024
        while pos < cap:
            d = fh.read(min(step + overlap, cap - pos))
            if not d:
                break
            owned = min(step, cap-pos)
            for enc, rex in (("ascii", ASCII_EXE_RE), ("utf16le", WIDE_EXE_RE)):
                for m in rex.finditer(d):
                    if m.start() >= owned:
                        continue
                    off = pos + m.start()
                    if off in seen:
                        continue
                    seen.add(off)
                    txt = m.group().decode('utf-16-le' if enc == 'utf16le' else 'ascii', errors='replace').strip()
                    matches.append({"offset": off, "encoding": enc, "text": txt[-220:]})
                    if len(matches) >= args.max_results:
                        break
                if len(matches) >= args.max_results:
                    break
            if len(matches) >= args.max_results:
                break
            pos += owned
            fh.seek(pos)
    rep = {"schema": "bin-exe-references/1", "source": str(p), "size": size, "bytes_scanned": cap,
           "interpretation": "raw string references; not executable extraction or validated registry paths", "references": matches}
    print(f"Found {len(matches)} raw .exe/.dll/.sys references in {cap:,} bytes")
    for r in matches[:args.show]:
        print(f"  0x{r['offset']:x} {r['encoding']}: {r['text']}")
    if args.json:
        safe_write_json(Path(args.json).resolve(), rep)
    return 0


def check_legacy(argv):
    ap = argparse.ArgumentParser(description="Standalone PE check when xvcintel is not present")
    ap.add_argument('path')
    ap.add_argument('--json', metavar='FILE')
    args = ap.parse_args(argv)
    path = Path(args.path)
    if not path.is_file():
        print(f"file not found: {path}", file=sys.stderr)
        return 2
    pe = parse_pe_file(path, 0, 512 << 20)
    ok = pe is not None and not pe['truncated']
    rep = {"path": str(path.resolve()), "valid_pe": ok, "pe": pe}
    if args.json:
        safe_write_json(Path(args.json), rep)
    print(json.dumps(rep, indent=2))
    return 0 if ok else 1


def build_cli():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='action', required=True)
    s = sub.add_parser('scan', help='scan BIN for raw / compressed PE candidates')
    s.add_argument('path')
    s.add_argument('--json', help='write JSON report (does not overwrite)')
    s.add_argument('--extract-dir', help='write carved PE candidates to new files')
    s.add_argument('--compressed', action='store_true', help='try supported compressed streams')
    s.add_argument('--deep-zlib', action='store_true', help='detect candidate zlib streams (only with --compressed)')
    s.add_argument('--extract-partial', action='store_true', help='carve truncated PE as .partial.bin (explicit opt-in)')
    s.add_argument('--max-scan', type=lambda s: int(s, 0), default=DEFAULT_MAX_SCAN, help='bytes to inspect; 0=whole file (default 1 GiB)')
    s.add_argument('--max-mz', type=int, default=200000)
    s.add_argument('--max-streams', type=int, default=64)
    s.add_argument('--max-pe-size', type=lambda s: int(s, 0), default=512 << 20)
    s.add_argument('--max-decompressed', type=lambda s: int(s, 0), default=DEFAULT_MAX_OUTPUT)
    s.add_argument('--max-compressed-input', type=lambda s: int(s, 0), default=64 << 20)
    s.add_argument('--require-pe', action='store_true', help='exit 1 if no PE candidate found')
    r = sub.add_parser('refs', help='find raw .exe/.dll/.sys path strings, not actual hive parsing')
    r.add_argument('path')
    r.add_argument('--json')
    r.add_argument('--max-scan', type=lambda s: int(s, 0), default=DEFAULT_MAX_SCAN)
    r.add_argument('--max-results', type=int, default=1000)
    r.add_argument('--show', type=int, default=30)
    return p


def main(argv=None):
    parser = build_cli()
    args = parser.parse_args(argv)
    for name in ("max_scan", "max_streams"):
        if getattr(args, name, 0) < 0:
            parser.error(f"{name} must be >= 0")
    try:
        if args.action == 'scan':
            if args.deep_zlib and not args.compressed:
                parser.error('--deep-zlib requires --compressed')
            if args.max_decompressed < 1024 or args.max_compressed_input < 1024 or args.max_mz < 1:
                parser.error('resource limits are too small')
            return run_scan(args)
        return run_refs(args)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
