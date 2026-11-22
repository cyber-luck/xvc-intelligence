"""Deterministic synthetic fixtures: no real console keys or executable execution."""
import gzip
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import zlib
import zipfile
import io

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'bin_pe_recovery.py'


def fixture_pe(subsystem=2):
    p = bytearray(0x400)
    p[:2] = b'MZ'
    struct.pack_into('<I', p, 0x3c, 0x80)
    p[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', p, 0x84, 0x8664, 1, 0, 0, 0, 0xf0, 0x22)
    o = 0x80 + 24
    struct.pack_into('<H', p, o, 0x20b)
    struct.pack_into('<I', p, o+16, 0x1000)
    struct.pack_into('<I', p, o+32, 0x1000)
    struct.pack_into('<I', p, o+36, 0x200)
    struct.pack_into('<I', p, o+56, 0x2000)
    struct.pack_into('<I', p, o+60, 0x200)
    struct.pack_into('<H', p, o+68, subsystem)
    sh = o + 0xf0
    p[sh:sh+8] = b'.text\0\0\0'
    struct.pack_into('<IIII', p, sh+8, 0x100, 0x1000, 0x200, 0x200)
    p[0x200:0x205] = b'HELLO'
    return bytes(p)


def run(tmp_path, content, *extra):
    source = tmp_path / 'input.bin'
    source.write_bytes(content)
    rpt = tmp_path / 'report.json'
    proc = subprocess.run([sys.executable, '-I', str(SCRIPT), 'scan', str(source),
                           '--json', str(rpt), *map(str, extra)], capture_output=True, text=True)
    return proc, json.loads(rpt.read_text()) if rpt.is_file() else None


def test_direct_embedded_and_extract(tmp_path):
    pe = fixture_pe()
    proc, report = run(tmp_path, b'prefix' * 3 + pe + b'tail', '--extract-dir', tmp_path / 'out')
    assert proc.returncode == 0, proc.stderr
    assert len(report['pe_candidates']) == 1
    assert report['pe_candidates'][0]['offset'] == 18
    out = list((tmp_path / 'out').glob('*.exe'))
    assert len(out) == 1 and out[0].read_bytes() == pe
    assert report['extractions'][0]['sha256']


def test_catalog_not_game_exe(tmp_path):
    proc, report = run(tmp_path, fixture_pe(0x11), '--extract-dir', tmp_path / 'out')
    assert proc.returncode == 0, proc.stderr
    assert report['pe_candidates'][0]['purpose'] == 'xbox_code_catalog_candidate_not_game_executable'
    assert (tmp_path / 'out' / 'direct_0x000000000000.catalog.bin').is_file()


def test_gzip(tmp_path):
    pe = fixture_pe()
    proc, report = run(tmp_path, b'junk' + gzip.compress(pe), '--compressed', '--extract-dir', tmp_path / 'out')
    assert proc.returncode == 0, proc.stderr
    assert any(len(s.get('pe_candidates', [])) == 1 for s in report['compressed_streams'])
    assert (tmp_path / 'out' / 'gzip_0x000000000004_pe00.exe').read_bytes() == pe


def test_deep_zlib(tmp_path):
    proc, report = run(tmp_path, zlib.compress(fixture_pe()), '--compressed', '--deep-zlib')
    assert proc.returncode == 0, proc.stderr
    assert any(len(s.get('pe_candidates', [])) == 1 for s in report['compressed_streams'])


def test_encrypted_like_no_claim(tmp_path):
    import hashlib
    content = b''.join(hashlib.sha256(i.to_bytes(4, 'little')).digest() for i in range(1024))
    proc, report = run(tmp_path, content)
    assert proc.returncode == 0
    assert not report['pe_candidates']
    assert not report['capability']['cryptographic_decryption']


def test_corrupted_header_not_accepted(tmp_path):
    bad = bytearray(fixture_pe())
    bad[0x80:0x84] = b'XXX!'
    proc, report = run(tmp_path, bad)
    assert proc.returncode == 0
    assert not report['pe_candidates']


def test_pe_check_legacy_fallback(tmp_path):
    pe = tmp_path / 'sample.exe'; pe.write_bytes(fixture_pe())
    script = SCRIPT.with_name('pe_check.py')
    proc = subprocess.run([sys.executable, '-I', str(script), str(pe)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert '"valid_pe": true' in proc.stdout


def test_regf_references_mode(tmp_path):
    hive = tmp_path / 'hive.bin'
    hive.write_bytes(b'regf' + b'... C:\\Game\\mygame.exe ...')
    script = SCRIPT.with_name('regf_dump.py')
    rpt = tmp_path / 'refs.json'
    proc = subprocess.run([sys.executable, '-I', str(script), '--find-exe', str(hive), '--json', str(rpt)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert any('mygame.exe' in ref['text'] for ref in json.loads(rpt.read_text())['references'])


def test_legacy_check_bad(tmp_path):
    pe = tmp_path / 'bad.bin'; pe.write_bytes(b'MZ' + b'x'*512)
    script = SCRIPT.with_name('pe_check.py')
    proc = subprocess.run([sys.executable, '-I', str(script), str(pe)], capture_output=True, text=True)
    assert proc.returncode == 1


def test_scan_limit_explicit(tmp_path):
    p = fixture_pe()
    proc, report = run(tmp_path, b'?'*100 + p, '--max-scan', '64')
    assert proc.returncode == 0
    assert report['scan']['entire_file_scanned'] is False
    assert not report['pe_candidates']


def test_existing_report_is_protected(tmp_path):
    source = tmp_path / 'input.bin'; source.write_bytes(fixture_pe())
    out = tmp_path / 'report.json'; out.write_text('STAY')
    proc = subprocess.run([sys.executable, '-I', str(SCRIPT), 'scan', str(source), '--json', str(out)], capture_output=True, text=True)
    assert proc.returncode == 2 and out.read_text() == 'STAY'


def test_zip_container_recovery(tmp_path):
    pe = fixture_pe()
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('assets/embedded.exe', pe)
    proc, report = run(tmp_path, out.getvalue(), '--compressed', '--extract-dir', tmp_path / 'out')
    assert proc.returncode == 0, proc.stderr
    assert any(len(s.get('pe_candidates', [])) == 1 for s in report['compressed_streams'])
    assert any(p.read_bytes() == pe for p in (tmp_path / 'out').glob('*.exe'))


def test_xvc_probe_new_mode(tmp_path):
    p = tmp_path / 'content.bin'; p.write_bytes(fixture_pe())
    script = SCRIPT.with_name('xvc_probe.py')
    proc = subprocess.run([sys.executable, '-I', str(script), '--pe-scan', str(p)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert 'PE candidates: 1' in proc.stdout
