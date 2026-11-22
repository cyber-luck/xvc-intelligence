"""Deterministic, synthetic-only tests; no real game images or keys needed."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
import zlib

SCRIPT = Path(__file__).resolve().parents[1] / 'shadow_pe_reconstructor.py'


def fake_pe(subsystem=2):
    data = bytearray(0x400)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, 0x84, 0x8664, 1, 0, 0, 0, 0xf0, 0x22)
    opt = 0x80+24
    struct.pack_into('<H', data, opt, 0x20b)
    for o, n in [(16, 0x1000), (32, 0x1000), (36, 0x200), (56, 0x2000), (60, 0x200)]:
        struct.pack_into('<I', data, opt+o, n)
    struct.pack_into('<H', data, opt+68, subsystem)
    sh = opt+0xf0
    data[sh:sh+8] = b'.text\0\0\0'
    struct.pack_into('<IIII', data, sh+8, 0x100, 0x1000, 0x200, 0x200)
    data[0x200:0x208] = b'ORIGINAL'
    return bytes(data)


class ShadowPETests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def run_tool(self, inputs, *args, out=None):
        out = out or self.root/'output'
        cmd = [sys.executable, '-I', str(SCRIPT), *map(str, inputs), '--out', str(out), *map(str, args)]
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return cp, out

    @staticmethod
    def report(out, name='summary.json'):
        return json.loads((out/name).read_text(encoding='utf-8'))

    def test_direct_pe_recovered_unmodified(self):
        pe = fake_pe()
        f = self.root/'a.bin'; f.write_bytes(pe)
        cp, out = self.run_tool([f], '--extract')
        self.assertEqual(cp.returncode, 0, cp.stderr)
        files = list((out/'recovered_fragments').glob('*.exe'))
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].read_bytes(), pe)
        self.assertEqual(f.read_bytes(), pe)
        self.assertFalse(self.report(out)['executable_original_proved'])

    def test_embedded_pe_offset(self):
        pe = fake_pe()
        f = self.root/'file.dat'; f.write_bytes(b'PREAMBLE'*3 + pe + b'END')
        cp, out = self.run_tool([f])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        c = self.report(out, 'executable_candidates.json')['pe_candidates'][0]
        self.assertEqual(c['origin']['offset'], 24)
        self.assertEqual(c['recovered_extent'], len(pe))
        self.assertNotIn('extracted_to', c)

    def test_catalog_not_labeled_game(self):
        f = self.root/'catalog.bin'; f.write_bytes(fake_pe(0x11))
        cp, out = self.run_tool([f])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn('catalog_candidate', self.report(out, 'executable_candidates.json')['pe_candidates'][0]['pe']['purpose'])

    def test_truncated_candidate_missing_map(self):
        f = self.root/'partial.bin'; f.write_bytes(fake_pe()[:0x350])
        cp, out = self.run_tool([f])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(self.report(out, 'executable_candidates.json')['pe_candidates'][0]['state'], 'PARTIAL_RECOVERED')
        self.assertIn('MISSING', [x['state'] for x in self.report(out,'shadow_pe_map.json')['intervals']])

    def test_fake_mz_rejected(self):
        content = bytearray(fake_pe()); content[0x80:0x84] = b'NOPE'
        f = self.root/'bad.bin'; f.write_bytes(content)
        cp, out = self.run_tool([f])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(self.report(out)['pe_candidates'], 0)

    def test_gzip_stream(self):
        f = self.root/'g.bin'; f.write_bytes(b'\x00'*18 + gzip.compress(fake_pe()))
        cp, out = self.run_tool([f], '--compressed', '--extract')
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(self.report(out)['pe_candidates'], 1)
        self.assertEqual(list((out/'recovered_fragments').glob('*.exe'))[0].read_bytes(), fake_pe())

    def test_zlib_stream(self):
        f = self.root/'z.bin'; f.write_bytes(zlib.compress(fake_pe()))
        cp, out = self.run_tool([f], '--compressed', '--deep-zlib')
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(self.report(out)['pe_candidates'], 1)

    def test_zip_member_safe_extract(self):
        buf=io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('../../evil.exe', fake_pe())
        f=self.root/'archive.zip'; f.write_bytes(buf.getvalue())
        cp,out=self.run_tool([f], '--compressed', '--extract')
        self.assertEqual(cp.returncode,0,cp.stderr)
        self.assertEqual(self.report(out)['pe_candidates'],1)
        self.assertFalse((self.root/'evil.exe').exists())
        self.assertEqual(len(list((out/'recovered_fragments').glob('*.exe'))),1)

    def test_metadata_references_not_code(self):
        f = self.root/'manifest.xml'; f.write_text('<Application Executable="main_scarlett.exe" />',encoding='utf-8')
        cp,out=self.run_tool([f])
        self.assertEqual(cp.returncode,0,cp.stderr)
        self.assertEqual(self.report(out)['classification'],'METADATA_ONLY')
        self.assertGreater(len(self.report(out,'executable_candidates.json')['filename_references_unverified']),0)

    def test_encrypted_annotation_blocks_fake_inside(self):
        f = self.root/'data.bin'; f.write_bytes(b'\x19'*400 + fake_pe())
        reg = self.root/'regions.json'; reg.write_text(json.dumps({'sources':[{'path':'data.bin', 'regions':[{
            'offset':400,'length':len(fake_pe()),'state':'ENCRYPTED_UNKNOWN','label':'XVC region 0x3E9'}]}]}))
        cp,out=self.run_tool([f], '--regions', reg)
        self.assertEqual(cp.returncode,0,cp.stderr)
        self.assertEqual(self.report(out)['pe_candidates'],0)
        self.assertEqual(self.report(out)['regions_claiming_encrypted_based_on_user_annotations'],1)

    def test_incomplete_scan_not_overclaim(self):
        f=self.root/'limited.bin'; f.write_bytes(b'A'*500+fake_pe())
        cp,out=self.run_tool([f], '--max-scan', 100)
        self.assertEqual(cp.returncode,0,cp.stderr)
        self.assertFalse(self.report(out)['all_files_fully_scanned'])
        self.assertEqual(self.report(out)['pe_candidates'],0)

    def test_existing_output_protected(self):
        f=self.root/'file.bin';f.write_bytes(fake_pe())
        out=self.root/'output';out.mkdir(); marker=out/'important.txt'; marker.write_text('KEEP')
        cp,_=self.run_tool([f], out=out)
        self.assertEqual(cp.returncode,2)
        self.assertEqual(marker.read_text(),'KEEP')

    def test_block_matching_cross_file(self):
        block=bytes(range(256))*256
        a=self.root/'one.bin';a.write_bytes(block)
        b=self.root/'two.bin';b.write_bytes(block)
        cp,out=self.run_tool([a,b],'--match-blocks','--max-match-bytes',len(block))
        self.assertEqual(cp.returncode,0,cp.stderr)
        matches=self.report(out,'block_matches.json')['pairs']
        self.assertEqual(len(matches),1)
        self.assertEqual(matches[0]['sha256'],hashlib.sha256(block).hexdigest())
        self.assertIn('not_proof',matches[0]['interpretation'])

    def test_full_and_prefix_hash_labeled(self):
        f=self.root/'pe.bin';f.write_bytes(fake_pe())
        cp,out=self.run_tool([f],'--hash-bytes',64)
        self.assertEqual(cp.returncode,0,cp.stderr)
        source=self.report(out,'binary_inventory.json')['sources'][0]
        self.assertFalse(source['hash']['complete'])
        self.assertEqual(source['hash']['kind'],'prefix_sha256_not_full_file')

    def test_output_inside_input_dir_is_skipped(self):
        f=self.root/'pe.bin'; f.write_bytes(fake_pe())
        cp,out=self.run_tool([self.root], '--max-files',200)
        self.assertEqual(cp.returncode,0,cp.stderr)
        self.assertEqual(self.report(out)['files_analyzed'],1)

    def test_imports_and_codeview_pdb(self):
        pe=bytearray(fake_pe())
        opt=0x80+24
        # Import directory: descriptor .text+0x20, name at .text+0x80.
        struct.pack_into('<I', pe, opt+108, 16)
        struct.pack_into('<II', pe, opt+112+8, 0x1020, 40)
        struct.pack_into('<IIIII', pe, 0x220, 0x1050, 0, 0, 0x1080, 0x1050)
        struct.pack_into('<Q', pe, 0x250, 0x10a0)
        pe[0x280:0x28d]=b'KERNEL32.dll\x00'
        pe[0x2a2:0x2af]=b'LoadLibraryA\x00'
        # IMAGE_DEBUG_DIRECTORY + CodeView RSDS at raw .text+0xe0.
        struct.pack_into('<II', pe, opt+112+6*8, 0x10c0, 28)
        codeview=b'RSDS' + bytes(range(16)) + (1).to_bytes(4,'little') + b'C:\\build\\mygame.pdb\x00'
        struct.pack_into('<IIHHIIII',pe,0x2c0,0,0,0,0,2,len(codeview),0x10e0,0x2e0)
        pe[0x2e0:0x2e0+len(codeview)] = codeview
        f=self.root/'with_imports.bin';f.write_bytes(pe)
        cp,out=self.run_tool([f])
        self.assertEqual(cp.returncode,0,cp.stderr)
        c=self.report(out,'executable_candidates.json')['pe_candidates'][0]['pe']
        self.assertEqual(c['imports'][0]['dll'],'KERNEL32.dll')
        self.assertIn('LoadLibraryA',c['imports'][0]['names'])
        self.assertIn('mygame.pdb', c['codeview_pdb_paths'][0])

    def test_utf16_reference_as_unverified(self):
        f=self.root/'info.dat';f.write_bytes(b'\x00'*8+'foo\\main.exe'.encode('utf-16-le'))
        cp,out=self.run_tool([f])
        self.assertEqual(cp.returncode,0,cp.stderr)
        rs=self.report(out,'executable_candidates.json')['filename_references_unverified']
        self.assertTrue(any('main.exe' in x['text'] for x in rs))

    def test_ciphertext_like_no_decryption(self):
        f=self.root/'opaque.bin';f.write_bytes(b''.join(hashlib.sha256(i.to_bytes(4,'little')).digest() for i in range(800)))
        cp,out=self.run_tool([f])
        self.assertEqual(cp.returncode,0,cp.stderr)
        self.assertEqual(self.report(out)['pe_candidates'],0)
        self.assertFalse(self.report(out)['ciphertext_decrypted'])


if __name__=='__main__':
    unittest.main()
