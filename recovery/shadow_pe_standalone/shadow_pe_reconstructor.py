#!/usr/bin/env python3
"""Shadow PE Reconstructor: evidence-led, read-only BIN/XVC/XVD triage.

Scans supplied files or folders for recoverable plaintext / compressed PE candidates,
references, exact block duplicates and user-supplied encrypted region annotations.
Never decrypts, guesses keys, fabricates executable bytes, or alters input files.
Python 3.10+; standard library only (optional zstandard/lz4 for codecs).
"""
from __future__ import annotations

import argparse
import bz2
import datetime as datetime
import hashlib
import html
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
from collections import defaultdict

SCHEMA = "shadow-pe/1.0"
CHUNK = 4 << 20
MACHINES = {0x14c: "x86", 0x8664: "x64", 0xAA64: "ARM64", 0x1c4: "ARMv7", 0x200: "IA64"}
STREAM_SIGNATURES = [("gzip", b"\x1f\x8b\x08"), ("xz", b"\xfd7zXZ\x00"),
                     ("bzip2", b"BZh"), ("zstd", b"\x28\xb5\x2f\xfd"),
                     ("lz4", b"\x04\x22\x4d\x18")]
REF_ASCII = re.compile(rb"[A-Za-z0-9_./\\:$() +\-]{1,150}\.(?:exe|dll|pdb|sys)(?![A-Za-z0-9_])", re.I)
REF_UTF16 = re.compile(rb"(?:(?:[A-Za-z0-9_./\\:$() +\-]\x00){1,150})\.(?:\x00[eE]\x00[xX]\x00[eE]\x00|\x00[dD]\x00[lL]\x00[lL]\x00|\x00[pP]\x00[dD]\x00[bB]\x00|\x00[sS]\x00[yY]\x00[sS]\x00)", re.I)


def sha256_stream(path: Path, maximum: int = 0) -> dict:
    count, h = 0, hashlib.sha256()
    with path.open('rb') as f:
        while True:
            limit = CHUNK if not maximum else min(CHUNK, maximum - count)
            if limit <= 0:
                break
            b = f.read(limit)
            if not b:
                break
            h.update(b)
            count += len(b)
    return {"sha256": h.hexdigest(), "hashed_bytes": count,
            "complete": count == path.stat().st_size,
            "kind": "full_sha256" if count == path.stat().st_size else "prefix_sha256_not_full_file"}


def entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    counts = [0] * 256
    for byte in buf:
        counts[byte] += 1
    n = len(buf)
    return round(-sum((v/n)*math.log2(v/n) for v in counts if v), 5)


def entropy_samples(path: Path, size: int) -> list[dict]:
    n = min(size, 16384)
    if not n:
        return []
    offsets = sorted({0, max(0, (size - n)//2), max(0, size - n)})
    with path.open('rb') as f:
        out = []
        for off in offsets:
            f.seek(off)
            b = f.read(n)
            out.append({"offset": off, "length": len(b), "bits_per_byte": entropy(b)})
        return out


def file_type(path: Path) -> str:
    with path.open('rb') as f:
        b = f.read(0x210)
    if len(b) >= 0x208 and b[0x200:0x208] == b'msft-xvd':
        return 'xvd_or_xvc_container'
    if b.startswith(b'regf'):
        return 'registry_hive'
    if b.startswith(b'PK\x03\x04'):
        return 'zip_container'
    if b.startswith(b'MZ'):
        return 'possible_pe'
    if b.startswith(b'\x7fELF'):
        return 'elf'
    if b[:1] in (b'{', b'[') or path.suffix.lower() in ('.json', '.xml', '.config', '.txt', '.md'):
        return 'potential_text_metadata'
    for kind, sig in STREAM_SIGNATURES:
        if b.startswith(sig):
            return f'{kind}_compressed'
    return 'unknown_binary'


def read_exact(f, off: int, n: int, size: int) -> bytes:
    if off < 0 or n < 0 or off+n > size:
        return b''
    f.seek(off)
    return f.read(n)


def parse_pe_at(f, start: int, file_size: int, max_pe: int) -> dict | None:
    """Validates structural PE metadata without loading/executing the image.

    Extent is only a lower bound; overlay, imports, execution and identity not validated.
    """
    head = read_exact(f, start, 0x40, file_size)
    if len(head) != 0x40 or head[:2] != b'MZ':
        return None
    pe_rel = struct.unpack_from('<I', head, 0x3c)[0]
    if not 0x40 <= pe_rel <= 0x100000:
        return None
    coff = read_exact(f, start + pe_rel, 24, file_size)
    if len(coff) != 24 or coff[:4] != b'PE\x00\x00':
        return None
    machine, nsects, timestamp, _, _, optsize, characts = struct.unpack_from('<HHIIIHH', coff, 4)
    if not 1 <= nsects <= 96 or not 0x60 <= optsize <= 0x1000:
        return None
    hdr = read_exact(f, start + pe_rel + 24, optsize + nsects*40, file_size)
    if len(hdr) != optsize+nsects*40:
        return None
    magic = struct.unpack_from('<H', hdr, 0)[0]
    if magic not in (0x10b, 0x20b) or optsize < (96 if magic == 0x10b else 112):
        return None
    get32 = lambda off: struct.unpack_from('<I', hdr, off)[0]
    img_size, head_size = get32(56), get32(60)
    file_align, sect_align = get32(36), get32(32)
    if not head_size or head_size > max_pe or not img_size or img_size > max_pe:
        return None
    if head_size < pe_rel + 24 + optsize + nsects*40:
        return None
    if not 1 <= file_align <= (1 << 24) or not 1 <= sect_align <= (1 << 28):
        return None
    min_extent, sections = head_size, []
    for i in range(nsects):
        off = optsize + i*40
        raw_name = hdr[off:off+8].split(b'\x00', 1)[0]
        name = raw_name.decode('ascii', 'replace')
        virtual_size, rva, raw_size, raw_off = struct.unpack_from('<IIII', hdr, off+8)
        if raw_size:
            if not raw_off or raw_size > max_pe or raw_off+raw_size > max_pe:
                return None
            min_extent = max(min_extent, raw_off+raw_size)
        sections.append({"name": name, "rva": rva, "virtual_size": virtual_size,
                         "raw_offset": raw_off, "raw_size": raw_size})
    # PE security directory address is a file offset (not a RVA).
    dirs_off = 96 if magic == 0x10b else 112
    if optsize >= dirs_off + 5*8:
        cert_off, cert_len = struct.unpack_from('<II', hdr, dirs_off+4*8)
        if cert_off and cert_len and cert_off+cert_len <= max_pe:
            min_extent = max(min_extent, cert_off+cert_len)
    if min_extent > max_pe:
        return None
    subsystem = struct.unpack_from('<H', hdr, 68)[0]
    purpose = ('xbox_code_catalog_candidate_not_game_executable' if subsystem == 0x11
               else 'dll_candidate' if characts & 0x2000 else 'executable_candidate')
    return {
        "file_offset": start, "format": 'PE32+' if magic == 0x20b else 'PE32',
        "machine": f'0x{machine:04x}', "architecture": MACHINES.get(machine, 'unknown'),
        "coff_timestamp": timestamp, "characteristics": f'0x{characts:04x}',
        "subsystem": f'0x{subsystem:04x}', "purpose": purpose,
        "entry_point_rva": get32(16), "image_size": img_size, "header_size": head_size,
        "minimum_file_extent": min_extent, "section_count": nsects, "optional_header_size": optsize, "sections": sections,
        "available_bytes": file_size-start, "truncated": min_extent > file_size-start,
        "validation": 'structural_pe_headers_only_not_identity_or_execution',
    }



def enrich_pe_metadata(f, start: int, file_size: int, pe: dict,
                       max_libraries: int = 64, max_functions: int = 256) -> None:
    """Read import table and CodeView debug paths when RVA->raw offsets are backed.

    Does not disassemble, resolve dependencies, or assert that the executable
    corresponds to a particular target.  Invalid/truncated data is skipped.
    """
    first = read_exact(f, start+0x3c, 4, file_size)
    if len(first) != 4:
        return
    pe_rel = struct.unpack('<I', first)[0]
    optional_offset = start+pe_rel+24
    prefix = read_exact(f, optional_offset, 120, file_size)
    if len(prefix) < 112:
        return
    pe64 = pe['format'] == 'PE32+'
    datadir = 112 if pe64 else 96
    numdir_offset = 108 if pe64 else 92
    declared_directories = struct.unpack_from('<I', prefix, numdir_offset)[0]

    def rva_to_pos(rva: int):
        if not rva:
            return None
        if rva < pe['header_size']:
            loc = start+rva
            return loc if loc < file_size else None
        for sect in pe['sections']:
            begin, raw_size = sect['rva'], sect['raw_size']
            if begin <= rva < begin+raw_size and sect['raw_offset']:
                loc = start+sect['raw_offset']+rva-begin
                if loc < file_size:
                    return loc
        return None

    def directory(idx: int):
        if declared_directories <= idx or pe["optional_header_size"] < datadir+(idx+1)*8:
            return None
        raw = read_exact(f, optional_offset+datadir+idx*8, 8, file_size)
        if len(raw) != 8:
            return None
        rva, length = struct.unpack('<II', raw)
        return (rva, length) if rva and length else None

    def cstring(pos, length=256):
        if pos is None:
            return None
        data = read_exact(f, pos, min(length, file_size-pos), file_size)
        if not data:
            return None
        raw = data.split(b'\x00', 1)[0]
        if not raw or any((byte < 32 or byte > 126) for byte in raw):
            return None
        return raw.decode('ascii', 'replace')

    imp = directory(1)
    if imp:
        loc = rva_to_pos(imp[0])
        libraries = []
        if loc is not None:
            for n in range(min(max_libraries, imp[1]//20)):
                descriptor = read_exact(f, loc+n*20, 20, file_size)
                if len(descriptor) != 20:
                    break
                oft, _, _, name_rva, ft = struct.unpack('<IIIII', descriptor)
                if not any((oft, name_rva, ft)):
                    break
                dll = cstring(rva_to_pos(name_rva))
                if not dll:
                    continue
                entry = {'dll': dll, 'names': [], 'ordinals': []}
                tloc = rva_to_pos(oft or ft)
                if tloc is not None:
                    unit = 8 if pe64 else 4
                    for i in range(max_functions):
                        raw = read_exact(f, tloc+i*unit, unit, file_size)
                        if len(raw) != unit:
                            break
                        value = int.from_bytes(raw, 'little')
                        if value == 0:
                            break
                        high_bit = 1 << (63 if pe64 else 31)
                        if value & high_bit:
                            entry['ordinals'].append(value & 0xffff)
                        else:
                            pos_name = rva_to_pos(value)
                            name = cstring(pos_name+2) if pos_name is not None else None
                            if name:
                                entry['names'].append(name)
                libraries.append(entry)
        if libraries:
            pe['imports'] = libraries
    debug = directory(6)
    if debug:
        pos = rva_to_pos(debug[0])
        paths = []
        if pos is not None:
            for i in range(min(debug[1]//28, 128)):
                data = read_exact(f, pos+i*28, 28, file_size)
                if len(data) != 28:
                    break
                _, _, _, _, dtype, dsize, _, pointer = struct.unpack('<IIHHIIII', data)
                if dtype == 2 and dsize >= 24 and pointer:
                    sig = read_exact(f, start+pointer, min(dsize, 1024), file_size)
                    if len(sig) >= 24 and sig[:4] == b'RSDS':
                        path = sig[24:].split(b'\x00', 1)[0].decode('utf-8', 'replace')
                        if path:
                            paths.append(path)
        if paths:
            pe['codeview_pdb_paths'] = paths

def find_candidates(path: Path, max_scan: int, max_mz: int, max_hits: int,
                    stream_limit: int, include_zlib: bool, forbidden_spans: list[dict]) -> tuple[list[dict], list[dict], dict]:
    file_size = path.stat().st_size
    cap = file_size if max_scan == 0 else min(file_size, max_scan)
    offsets, stream_hits = [], []
    raw_mz, omitted = 0, 0
    signatures = STREAM_SIGNATURES + ([("zlib", b"\x78\x01"), ("zlib", b"\x78\x9c"), ("zlib", b"\x78\xda")]
                                       if include_zlib else [])
    with path.open('rb') as f:
        pos = 0
        while pos < cap:
            owned = min(CHUNK, cap-pos)
            window = read_exact(f, pos, min(file_size-pos, owned+8), file_size)
            if not window:
                break
            i = 0
            while i < owned:
                j = window.find(b'MZ', i)
                if j < 0 or j >= owned:
                    break
                raw_mz += 1
                if len(offsets) < max_mz:
                    offsets.append(pos+j)
                else:
                    omitted += 1
                i = j+1
            for kind, sig in signatures:
                if len(stream_hits) >= stream_limit:
                    break
                i = 0
                while len(stream_hits) < stream_limit:
                    j = window.find(sig, i)
                    if j < 0 or j >= owned:
                        break
                    stream_hits.append({"codec": kind, "offset": pos+j})
                    i = j+1
            pos += owned
        hits = []
        for off in offsets:
            if len(hits) >= max_hits:
                break
            if any(region['offset'] <= off < region['offset']+region['length'] for region in forbidden_spans):
                continue
            candidate = parse_pe_at(f, off, file_size, 512 << 20)
            if candidate is not None:
                enrich_pe_metadata(f, off, file_size, candidate)
                hits.append(candidate)
    return hits, stream_hits, {"scanned_bytes": cap, "file_size": file_size,
                                "whole_file_scanned": cap == file_size, "raw_mz_hits": raw_mz,
                                "mz_hits_omitted_due_to_cap": omitted,
                                "pe_hit_limit_reached": len(hits) >= max_hits,
                                "stream_candidate_cap_reached": len(stream_hits) == stream_limit}


def decompress_at(path: Path, codec: str, offset: int, max_in: int, max_out: int) -> tuple[bytes | None, str]:
    """Bounded decompression of a recognized stream (no key guessing)."""
    if codec == 'zstd':
        try:
            import zstandard as zstd
        except ImportError:
            return None, 'missing_optional_zstandard'
        try:
            with path.open('rb') as raw:
                raw.seek(offset)
                with zstd.ZstdDecompressor().stream_reader(raw, read_across_frames=False) as reader:
                    out = bytearray()
                    while len(out) <= max_out:
                        chunk = reader.read(min(65536, max_out + 1 - len(out)))
                        if not chunk:
                            break
                        out.extend(chunk)
                        if raw.tell() - offset > max_in:
                            return None, 'compressed_input_limit'
                    if len(out) > max_out:
                        return None, 'decompressed_output_limit'
                    return bytes(out), 'decoded'
        except Exception as ex:
            return None, f'invalid_stream:{type(ex).__name__}'
    if codec == 'lz4':
        try:
            import lz4.frame
        except ImportError:
            return None, 'missing_optional_lz4'
        try:
            out = bytearray()
            with path.open('rb') as raw:
                raw.seek(offset)
                with lz4.frame.open(raw, 'rb') as reader:
                    while len(out) <= max_out:
                        chunk = reader.read(min(65536, max_out + 1 - len(out)))
                        if not chunk:
                            break
                        out.extend(chunk)
                        if raw.tell() - offset > max_in:
                            return None, 'compressed_input_limit'
                    if len(out) > max_out:
                        return None, 'decompressed_output_limit'
                    return bytes(out), 'decoded'
        except Exception as ex:
            return None, f'invalid_stream:{type(ex).__name__}'
    if codec in ('gzip', 'zlib'):
        obj = zlib.decompressobj(31 if codec == 'gzip' else 15)
    elif codec == 'xz':
        obj = lzma.LZMADecompressor()
    elif codec == 'bzip2':
        obj = bz2.BZ2Decompressor()
    else:
        return None, 'unknown_codec'
    try:
        out = bytearray()
        with path.open('rb') as f:
            f.seek(offset)
            rem = max_in
            while rem:
                chunk = f.read(min(65536, rem))
                if not chunk:
                    break
                rem -= len(chunk)
                budget = max_out + 1-len(out)
                if budget <= 0:
                    return None, 'decompressed_output_limit'
                out.extend(obj.decompress(chunk, budget))
                if len(out) > max_out:
                    return None, 'decompressed_output_limit'
                if obj.eof:
                    return bytes(out), 'decoded'
        return None, 'incomplete_compressed_input'
    except (OSError, ValueError, zlib.error, EOFError, lzma.LZMAError) as ex:
        return None, f'invalid_stream:{type(ex).__name__}'


def parse_pe_from_bytes(buf: bytes, offset: int = 0) -> dict | None:
    import io
    f = io.BytesIO(buf)
    found = parse_pe_at(f, offset, len(buf), 512 << 20)
    if found is not None:
        enrich_pe_metadata(f, offset, len(buf), found)
    return found


def references(path: Path, maximum: int, max_refs: int = 100) -> list[dict]:
    cap = min(maximum, path.stat().st_size)
    out, seen = [], set()
    with path.open('rb') as f:
        pos = 0
        while pos < cap and len(out) < max_refs:
            owned = min(CHUNK, cap-pos)
            f.seek(pos)
            chunk = f.read(min(cap-pos, owned+400))
            for enc, rgx in [('ascii', REF_ASCII), ('utf-16-le', REF_UTF16)]:
                for m in rgx.finditer(chunk):
                    if m.start() >= owned:
                        break
                    try:
                        s = m.group().decode('ascii' if enc == 'ascii' else 'utf-16-le').strip(' ./\\')
                    except UnicodeDecodeError:
                        continue
                    s = s[-160:]
                    k = (pos+m.start(), enc)
                    if k not in seen:
                        seen.add(k)
                        out.append({'offset': pos+m.start(), 'encoding': enc,
                                    'text': s, 'evidence': 'unverified_filename_string_not_file_content'})
                    if len(out) >= max_refs:
                        break
            pos += owned
    return sorted(out, key=lambda v: v['offset'])


def get_files(inputs: list[str], out_dir: Path, max_files: int) -> tuple[list[Path], bool]:
    files, seen, over = [], set(), False
    for item in inputs:
        p = Path(item).expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError(str(p))
        if p.is_file():
            paths = [p]
        elif p.is_dir():
            paths = []
            for root, dirs, names in os.walk(p, followlinks=False):
                here = Path(root).resolve()
                dirs[:] = sorted(d for d in dirs if not (Path(root)/d).is_symlink()
                                 and (Path(root)/d).resolve() != out_dir
                                 and out_dir not in (Path(root)/d).resolve().parents)
                if here == out_dir or out_dir in here.parents:
                    dirs.clear()
                    continue
                for name in sorted(names):
                    f = Path(root)/name
                    if not f.is_symlink() and f.is_file():
                        paths.append(f.resolve())
                    if len(paths) + len(files) > max_files:
                        over = True
                        break
                if over:
                    break
        else:
            raise ValueError(f'Not a regular file or directory: {p}')
        for f in paths:
            if f == out_dir or out_dir in f.parents:
                continue
            if f not in seen:
                seen.add(f)
                files.append(f)
                if len(files) >= max_files:
                    over = True
                    break
        if over:
            break
    return sorted(files, key=lambda p: str(p).casefold()), over


def read_region_map(map_file: Path | None) -> tuple[dict[str, list[dict]], list[str]]:
    """Explicit, user-provided region annotations. NOT inferred from entropy."""
    if map_file is None:
        return {}, []
    data = json.loads(map_file.read_text(encoding='utf-8'))
    if not isinstance(data, dict) or not isinstance(data.get('sources'), list):
        raise ValueError('Region manifest must contain sources: [{path, regions:[...]}]')
    output = defaultdict(list)
    warnings = []
    for source in data['sources']:
        if not isinstance(source, dict) or 'path' not in source:
            raise ValueError('Invalid region source')
        spath = Path(source['path'])
        source_path = (map_file.parent / spath).resolve() if not spath.is_absolute() else spath.resolve()
        if not source_path.is_file():
            warnings.append(f'region source missing: {source_path}')
            continue
        size = source_path.stat().st_size
        for rg in source.get('regions', []):
            off, length = rg.get('offset'), rg.get('length')
            if not isinstance(off, int) or not isinstance(length, int) or off < 0 or length <= 0 or off+length > size:
                raise ValueError(f'Invalid region interval for {source_path}: {rg!r}')
            label = str(rg.get('state', 'UNKNOWN')).upper()
            if label not in ('ENCRYPTED_UNKNOWN', 'UNVERIFIED', 'UNKNOWN'):
                raise ValueError(f'Invalid region state {label}')
            output[str(source_path)].append({"offset": off, "length": length, "state": label,
                                             "label": str(rg.get('label','')), "source": str(map_file),
                                             "evidence": 'user_supplied_annotation_not_independently_verified'})
    return dict(output), warnings


def sha256_range(path: Path, offset: int, count: int) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        f.seek(offset)
        n = count
        while n:
            b = f.read(min(CHUNK, n))
            if not b:
                raise IOError('Unexpected EOF while hashing fragment')
            h.update(b)
            n -= len(b)
    return h.hexdigest()


def copy_range_exclusive(src: Path, off: int, length: int, dest: Path):
    # The source is never opened for writing.  'xb' atomically rejects overwrite.
    dest.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        with src.open('rb') as f, dest.open('xb') as o:
            created = True
            f.seek(off)
            rem = length
            while rem:
                chunk = f.read(min(CHUNK, rem))
                if not chunk:
                    raise IOError('Unexpected EOF while carving')
                o.write(chunk)
                rem -= len(chunk)
    except Exception:
        if created and dest.exists():
            dest.unlink()
        raise


def extract_bytes_exclusive(data: bytes, dest: Path):
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open('xb') as f:
        f.write(data)


def matching_blocks(files: list[Path], max_bytes: int, block_size: int, max_blocks: int, max_pairs: int):
    seen, matched, indexed, scanned = {}, [], 0, 0
    cap_hit = False
    for source in files:
        with source.open('rb') as f:
            pos = 0
            cap = source.stat().st_size if max_bytes == 0 else min(max_bytes, source.stat().st_size)
            while pos + block_size <= cap:
                if indexed >= max_blocks:
                    cap_hit = True
                    break
                b = f.read(block_size)
                if len(b) != block_size:
                    break
                scanned += len(b)
                off = pos
                pos += block_size
                if b.count(b'\x00') >= block_size-16 or b.count(b'\xff') >= block_size-16:
                    continue
                # Skip very low-entropy repeated filler (not evidence of related executable code).
                if entropy(b[:min(4096, len(b))]) < 4.5:
                    continue
                h = hashlib.sha256(b).hexdigest()
                previous = seen.get(h)
                if previous and previous[0] != str(source) and len(matched) < max_pairs:
                    matched.append({'left': {'path': previous[0], 'offset': previous[1]},
                                    'right': {'path': str(source), 'offset': off},
                                    'length': block_size, 'sha256': h,
                                    'interpretation': 'identical_stored_bytes_not_proof_of_executable_identity'})
                if not previous:
                    seen[h] = (str(source), off)
                    indexed += 1
        if cap_hit:
            break
    return {"pairs": matched, "block_size": block_size, "indexed_unique_blocks": indexed,
            "total_bytes_examined": scanned, "index_limit_reached": cap_hit,
            "pair_limit_reached": len(matched) >= max_pairs}


def json_write_new(path: Path, obj):
    with path.open('x', encoding='utf-8', newline='\n') as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write('\n')


def render_html(report: dict) -> str:
    e = lambda s: html.escape(str(s))
    summ = report['summary']
    rows = ''.join('<tr><td>'+e(x['source'])+'</td><td>'+e(x['classification'])+'</td><td>'+
                   e(x.get('pe_count', 0))+'</td><td>'+e(x['scan']['scanned_bytes'])+'</td></tr>'
                   for x in report['sources'])
    pe_rows = ''.join('<tr><td>'+e(c['id'])+'</td><td>'+e(c['source'])+'</td><td>'+e(c['origin']['kind'])+'</td><td>'+
                      e(c['pe']['architecture'])+'</td><td>'+e(c['pe']['purpose'])+'</td><td>'+e(c['state'])+'</td></tr>'
                      for c in report['candidates'])
    return '''<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Shadow PE - relatório forense</title><style>body{font:15px system-ui,Arial;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#20232a}h1,h2{color:#102b46}table{border-collapse:collapse;width:100%;font-size:13px}th,td{padding:.6rem;border-bottom:1px solid #ddd;text-align:left;overflow-wrap:anywhere}th{background:#eef2f6}code{background:#eef2f6;padding:.15rem .3rem}p{line-height:1.55}strong{font-weight:650}</style></head><body>''' + (
        '<h1>Shadow PE — relatório</h1><p><strong>Resultado:</strong> '+e(summ['classification'])+'</p>'
        '<p>Fontes: '+e(summ['files_analyzed'])+'; candidatos PE: '+e(summ['pe_candidates'])+
        '; fragmentos extraídos: '+e(summ['fragments_written'])+'</p>'
        '<p><strong>Nota:</strong> nenhum byte criptografado foi descriptografado. ' 
        'Um PE estruturalmente válido não comprova a identidade do executável original.</p>'
        '<h2>Fontes</h2><table><tr><th>Arquivo</th><th>Tipo</th><th>PEs</th><th>Bytes verificados</th></tr>'+rows+'</table>'
        '<h2>Candidatos</h2><table><tr><th>ID</th><th>Fonte</th><th>Origem</th><th>Arquitetura</th><th>Propósito</th><th>Estado</th></tr>'+pe_rows+'</table>'
        '<p>Dados completos nos arquivos JSON associados.</p></body></html>')


def process(args) -> dict:
    out = Path(args.out).expanduser().resolve()
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise ValueError(f'Output directory must not exist or be empty: {out}')
    paths, capped = get_files(args.inputs, out, args.max_files)
    if not paths:
        raise ValueError('No input files found')
    region_map, warnings = read_region_map(Path(args.regions).resolve() if args.regions else None)
    out.mkdir(parents=True, exist_ok=True)
    inventory, candidates, provenance, maps, refs, source_rows = [], [], [], [], [], []
    stream_trials = 0
    total_scanned = 0
    fragment_count = 0
    for index, path in enumerate(paths):
        size = path.stat().st_size
        hash_data = sha256_stream(path, 0 if args.hash_full else args.hash_bytes)
        annotations = region_map.get(str(path), [])
        protected = [r for r in annotations if r['state'] == 'ENCRYPTED_UNKNOWN']
        item = {'source': str(path), 'size': size, 'type': file_type(path), 'hash': hash_data,
                'entropy_samples': entropy_samples(path, size), 'regions': annotations,
                'confidence': 'file_observed_metadata_not_decrypted'}
        inventory.append(item)
        remaining = max(0, args.max_total_scan-total_scanned) if args.max_total_scan else 0
        budget = args.max_scan if args.max_scan else size
        if args.max_total_scan:
            budget = min(budget, remaining)
        if budget == 0 and size > 0:
            pe, streams, scan = [], [], {'scanned_bytes': 0, 'file_size': size,
                'whole_file_scanned': False, 'raw_mz_hits': 0, 'mz_hits_omitted_due_to_cap': 0,
                'pe_hit_limit_reached': False, 'stream_candidate_cap_reached': False}
        else:
            pe, streams, scan = find_candidates(path, budget, args.max_mz, args.max_candidates,
                                                  args.max_streams if args.compressed else 0,
                                                  args.deep_zlib, protected)
        total_scanned += scan['scanned_bytes']
        item['scan'] = scan
        source_rows.append({'source': str(path), 'classification': item['type'],
                            'pe_count': len(pe), 'scan': scan})
        nrefs = references(path, args.max_reference_scan, args.max_refs) if args.references else []
        for ref in nrefs:
            ref['source'] = str(path)
        refs.extend(nrefs)
        for rg in annotations:
            maps.append({'source': str(path), 'origin': 'provided_region_manifest',
                         'state': rg['state'], 'source_interval': [rg['offset'], rg['offset']+rg['length']],
                         'identity_status': 'not_attributed_to_executable', 'evidence': rg['evidence'],
                         'label': rg['label']})
        for data in pe:
            if len(candidates) >= args.max_total_candidates:
                warnings.append('global PE candidate limit reached')
                break
            cid = f'pe_{len(candidates):05d}'
            n = min(data['minimum_file_extent'], data['available_bytes'])
            digest = sha256_range(path, data['file_offset'], n)
            record = {'id': cid, 'source': str(path), 'origin': {'kind': 'direct_plaintext_bytes', 'offset': data['file_offset']},
                      'pe': data, 'state': 'PARTIAL_RECOVERED' if data['truncated'] else 'PLAINTEXT_PE_CANDIDATE',
                      'recovered_extent': n, 'recovered_sha256': digest,
                      'original_executable_identity_verified': False}
            candidates.append(record)
            provenance.append({'candidate_id': cid, 'source': str(path), 'source_offset': data['file_offset'],
                               'length': n, 'transform': 'none', 'sha256': digest,
                               'evidence': 'exact_direct_bytes_validated_pe_structure'})
            maps.append({'candidate_id': cid, 'source': str(path), 'state': 'EXACT_RECOVERED',
                         'pe_interval': [0, n], 'source_interval': [data['file_offset'], data['file_offset']+n],
                         'note': 'candidate byte identity only; original game EXE not established'})
            if data['truncated']:
                maps.append({'candidate_id': cid, 'source': str(path), 'state': 'MISSING',
                             'pe_interval': [n, data['minimum_file_extent']],
                             'note': 'minimum declared PE extent exceeds available source bytes'})
            if args.extract:
                suffix = '.partial.bin' if data['truncated'] else ('.catalog.bin' if data['purpose'].startswith('xbox_code_catalog')
                                                                  else '.dll' if data['purpose'] == 'dll_candidate' else '.exe')
                dest = out/'recovered_fragments'/f'{cid}_direct_0x{data["file_offset"]:x}{suffix}'
                copy_range_exclusive(path, data['file_offset'], n, dest)
                record['extracted_to'] = str(dest)
                fragment_count += 1
        if args.compressed and streams:
            for desc in streams:
                if stream_trials >= args.max_streams_total:
                    warnings.append('global compressed stream attempt limit reached')
                    break
                if any(r['offset'] <= desc['offset'] < r['offset']+r['length'] for r in protected):
                    continue
                stream_trials += 1
                payload, status = decompress_at(path, desc['codec'], desc['offset'], args.max_compressed_input,
                                                args.max_decompressed)
                if payload is None:
                    continue
                # Decompressed data is only in memory (bounded), never executed.
                offsets = [i for i in range(max(0, len(payload)-1)) if payload[i:i+2] == b'MZ']
                for at in offsets[:args.max_mz]:
                    candidate = parse_pe_from_bytes(payload, at)
                    if candidate is None or len(candidates) >= args.max_total_candidates:
                        continue
                    cid = f'pe_{len(candidates):05d}'
                    n = min(candidate['minimum_file_extent'], len(payload)-at)
                    blob = payload[at:at+n]
                    digest = hashlib.sha256(blob).hexdigest()
                    candidate['available_bytes'] = len(payload)-at
                    candidate['truncated'] = n < candidate['minimum_file_extent']
                    record = {'id': cid, 'source': str(path), 'origin': {
                        'kind': 'decompressed_stream', 'codec': desc['codec'], 'source_offset': desc['offset'],
                        'decoded_offset': at}, 'pe': candidate,
                        'state': 'PARTIAL_RECOVERED' if candidate['truncated'] else 'PLAINTEXT_PE_CANDIDATE',
                        'recovered_extent': n, 'recovered_sha256': digest,
                        'original_executable_identity_verified': False}
                    candidates.append(record)
                    provenance.append({'candidate_id': cid, 'source': str(path), 'source_offset': desc['offset'],
                                       'decoded_offset': at, 'transform': f'decompress:{desc["codec"]}',
                                       'length': n, 'sha256': digest, 'evidence': 'decoded_bytes_validated_pe_structure'})
                    maps.append({'candidate_id': cid, 'source': str(path), 'state': 'EXACT_RECOVERED',
                                 'pe_interval': [0, n], 'source_interval': None,
                                 'note': 'bytes from known decompression; original game EXE not established'})
                    if args.extract:
                        suffix = '.partial.bin' if candidate['truncated'] else ('.catalog.bin' if candidate['purpose'].startswith('xbox_code_catalog')
                                                                              else '.dll' if candidate['purpose'] == 'dll_candidate' else '.exe')
                        dest = out/'recovered_fragments'/f'{cid}_{desc["codec"]}_0x{desc["offset"]:x}{suffix}'
                        extract_bytes_exclusive(blob, dest)
                        record['extracted_to'] = str(dest)
                        fragment_count += 1
        if args.compressed and item['type'] == 'zip_container':
            try:
                with zipfile.ZipFile(path) as z:
                    for member in z.infolist()[:args.max_zip_members]:
                        if stream_trials >= args.max_streams_total:
                            break
                        if member.is_dir() or member.flag_bits & 1 or member.file_size > args.max_decompressed:
                            continue
                        stream_trials += 1
                        with z.open(member) as f:
                            payload = f.read(args.max_decompressed+1)
                        if len(payload) > args.max_decompressed:
                            continue
                        # Only PE-like members are considered; archive paths are not used for writing.
                        for at in (0,):
                            if len(candidates) >= args.max_total_candidates:
                                break
                            candidate = parse_pe_from_bytes(payload, at)
                            if candidate is None:
                                continue
                            cid = f'pe_{len(candidates):05d}'
                            n = min(candidate['minimum_file_extent'], len(payload))
                            blob = payload[:n]
                            digest = hashlib.sha256(blob).hexdigest()
                            record = {'id': cid, 'source': str(path), 'origin': {
                                'kind': 'decompressed_zip_member', 'member': member.filename},
                                'pe': candidate, 'state': 'PARTIAL_RECOVERED' if candidate['truncated'] else 'PLAINTEXT_PE_CANDIDATE',
                                'recovered_extent': n, 'recovered_sha256': digest,
                                'original_executable_identity_verified': False}
                            candidates.append(record)
                            provenance.append({'candidate_id': cid, 'source': str(path), 'member': member.filename,
                                               'transform': 'zip_decompress', 'length': n, 'sha256': digest})
                            maps.append({'candidate_id': cid, 'source': str(path), 'state': 'EXACT_RECOVERED',
                                         'pe_interval': [0, n], 'source_interval': None,
                                         'note': 'decoded zip member; not attributed to target executable'})
                            if args.extract:
                                suffix = '.partial.bin' if candidate['truncated'] else ('.catalog.bin' if candidate['purpose'].startswith('xbox_code_catalog')
                                                                                      else '.dll' if candidate['purpose'] == 'dll_candidate' else '.exe')
                                dest = out/'recovered_fragments'/f'{cid}_zip{suffix}'
                                extract_bytes_exclusive(blob, dest)
                                record['extracted_to'] = str(dest)
                                fragment_count += 1
            except (OSError, zipfile.BadZipFile, ValueError, EOFError, RuntimeError) as ex:
                warnings.append(f'invalid zip archive: {path}: {type(ex).__name__}')
    match_report = matching_blocks(paths, args.max_match_bytes, args.block_size,
                                   args.max_indexed_blocks, args.max_block_matches) if args.match_blocks else None
    has_pe = len(candidates) > 0
    classification = ('PLAINTEXT_PE_CANDIDATES_FOUND' if has_pe else
                      'METADATA_ONLY' if refs or maps else 'NO_RECOVERABLE_PE_OBSERVED')
    summary = {
        'schema': SCHEMA, 'classification': classification, 'files_analyzed': len(paths),
        'files_limit_reached': capped, 'pe_candidates': len(candidates), 'fragments_written': fragment_count,
        'executable_original_proved': False, 'ciphertext_decrypted': False,
        'total_scanned_bytes': total_scanned, 'all_files_fully_scanned': all(x['scan']['whole_file_scanned'] for x in source_rows),
        'bytes_of_original_executable_recovered_proven': None,
        'reason_original_recovery_percent_unknown': 'original executable identity and total byte extent not proven',
        'regions_claiming_encrypted_based_on_user_annotations': len([r for r in maps if r['state'] == 'ENCRYPTED_UNKNOWN']),
        'limitations': ['no brute-force or decryption', 'high entropy does not prove encryption',
                        'structural PE candidate is not verification of original executable',
                        'user-supplied region annotations are not independently verified',
                        'partial scan cannot prove absence elsewhere in file',
                        'PE minimum extent may exclude overlays and external dependencies'],
        'warnings': warnings,
    }
    report = {'summary': summary, 'sources': source_rows, 'candidates': candidates}
    json_write_new(out/'binary_inventory.json', {'schema': SCHEMA, 'sources': inventory})
    json_write_new(out/'executable_candidates.json', {'schema': SCHEMA, 'pe_candidates': candidates,
                                                      'filename_references_unverified': refs,
                                                      'target_name_hint': args.target_exe})
    json_write_new(out/'shadow_pe_map.json', {'schema': SCHEMA, 'intervals': maps,
                                              'note': 'No manufactured bytes; no decrypted regions'})
    json_write_new(out/'recovery_provenance.json', {'schema': SCHEMA, 'records': provenance})
    if match_report is not None:
        json_write_new(out/'block_matches.json', {'schema': SCHEMA, **match_report})
    json_write_new(out/'summary.json', summary)
    with (out/'shadow_pe_report.html').open('x', encoding='utf-8') as f:
        f.write(render_html(report))
    return {'out': str(out), 'summary': summary}


def make_parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument('inputs', nargs='+', help='Input files or folders; never modified')
    p.add_argument('--out', required=True, help='New or EMPTY output directory')
    p.add_argument('--target-exe', help='Optional name hint; DOES NOT validate identity')
    p.add_argument('--regions', help='JSON manifest of user-provided encrypted/known spans')
    p.add_argument('--extract', action='store_true', help='Carve validated plaintext candidates to NEW files')
    p.add_argument('--compressed', action='store_true', help='Look for known compressed streams')
    p.add_argument('--deep-zlib', action='store_true', help='Also search generic zlib signatures (costly/heuristic)')
    p.add_argument('--match-blocks', action='store_true', help='Find identical stored blocks across inputs')
    p.add_argument('--hash-full', action='store_true', help='Full file SHA256 (may be costly for huge containers)')
    p.add_argument('--hash-bytes', type=int, default=64<<20, help='Hash prefix bytes unless --hash-full')
    p.add_argument('--max-files', type=int, default=10000)
    p.add_argument('--max-scan', type=int, default=64<<20, help='PE scan bytes per input, 0=entire file')
    p.add_argument('--max-total-scan', type=int, default=2<<30, help='PE scan bytes across inputs, 0=unlimited')
    p.add_argument('--max-mz', type=int, default=5000)
    p.add_argument('--max-candidates', type=int, default=100)
    p.add_argument('--max-total-candidates', type=int, default=1000)
    p.add_argument('--max-streams', type=int, default=32, help='Compressed candidates per input')
    p.add_argument('--max-streams-total', type=int, default=250)
    p.add_argument('--max-compressed-input', type=int, default=16<<20)
    p.add_argument('--max-decompressed', type=int, default=64<<20)
    p.add_argument('--max-zip-members', type=int, default=100)
    p.add_argument('--references', action=argparse.BooleanOptionalAction, default=True)
    p.add_argument('--max-reference-scan', type=int, default=8<<20)
    p.add_argument('--max-refs', type=int, default=100)
    p.add_argument('--max-match-bytes', type=int, default=64<<20, help='Block matching bytes per input')
    p.add_argument('--block-size', type=int, default=65536)
    p.add_argument('--max-indexed-blocks', type=int, default=40000)
    p.add_argument('--max-block-matches', type=int, default=1000)
    return p


def main(argv=None):
    p = make_parser()
    args = p.parse_args(argv)
    for name in ('hash_bytes','max_files','max_scan','max_total_scan','max_mz','max_candidates',
                 'max_total_candidates','max_streams','max_streams_total','max_compressed_input',
                 'max_decompressed','max_reference_scan','max_refs','max_match_bytes',
                 'max_indexed_blocks','max_block_matches','max_zip_members'):
        if getattr(args,name) < 0:
            p.error(f'--{name.replace("_","-")} must be >= 0')
    if args.block_size < 256 or args.block_size > (4<<20):
        p.error('--block-size must be between 256 and 4194304')
    if not args.hash_full and args.hash_bytes == 0:
        p.error('--hash-bytes 0 requires --hash-full to prevent misleading hash labels')
    try:
        out = process(args)
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0
    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as ex:
        print(f'ERROR: {ex}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
