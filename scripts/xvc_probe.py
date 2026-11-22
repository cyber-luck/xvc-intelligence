"""Sonda de layout de um pacote XVD/XVC (somente leitura) - wrapper compativel.

Mesmas opcoes de linha de comando e mesmo schema do --json-report do
xvc_probe.py original; a analise agora vem da biblioteca xvcintel.
Correcao: o MDU vem de MutableDataPageCount (0x470), conferido com XVC-MDU.

Fases:
  1. cabecalho XVD e layout calculado
  2. XvcInfo (ancora ContentID == VDUID no offset calculado)
  3. regioes, segmentos, array por segmento, tabela de paginas
  4. user data, SegmentMetadata e mapa de arquivos
  5. strings de regiao e mapa de entropia     (pule com --skip-scan)
"""
import argparse
import collections
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from xvcintel.cli import SafetyError, guard_output  # noqa: E402
from xvcintel.core.reader import FileSource  # noqa: E402
from xvcintel.core.result import Err  # noqa: E402
from xvcintel.core.util import entropy, filetime  # noqa: E402
from xvcintel.engines.package import header_lines, layout_lines, load_package  # noqa: E402
from xvcintel.evidence.reports import files_report, write_json  # noqa: E402
from xvcintel.formats.userdata import safe_basename  # noqa: E402
from xvcintel.formats.xvcinfo import FIELDS, NO_KEY  # noqa: E402

DEFAULT = r"G:\MyGame_v1\28872443D20A7_1.0.2.1_neutral__k2ss7vbb13xte_xs.xvc"


def utf16(pattern_ascii):
    return b"".join(re.escape(bytes([c])) + b"\x00" for c in pattern_ascii)


LITERALS = [b"MSFT-XVC", b"msft-xvc", b"msft-xvd", b"FS-MD", b"XVC-EXVD"]
PATTERNS = re.compile(
    rb"(?P<a>XVC-[A-Z]{2,4}|" + b"|".join(re.escape(x) for x in LITERALS) + b")"
    + rb"|(?P<u>X\x00V\x00C\x00-\x00(?:[A-Z]\x00){2,4}|" + b"|".join(utf16(x) for x in LITERALS) + b")")
OVERLAP = 64


def scan_strings(src, end, chunk=1 << 24):
    hits, pos = [], 0
    while pos < end:
        limit = min(chunk, end - pos)
        b = src.read_at(pos, limit + OVERLAP)
        if not b:
            break
        for m in PATTERNS.finditer(b):
            if m.start() >= limit:
                break
            enc = "ascii" if m.group("a") else "utf16"
            hits.append((pos + m.start(), m.group().decode("ascii" if enc == "ascii" else "utf-16-le"), enc))
        pos += chunk
    return hits


def entropy_runs(src, end, window, stride, threshold, max_gap):
    runs, pos = [], 0
    while pos < end:
        b = src.read_at(pos, window)
        if not b:
            break
        h = entropy(b)
        if h < threshold:
            if runs and pos - runs[-1][1] <= max_gap:
                r = runs[-1]
                r[1], r[2], r[3] = pos + len(b), r[2] + 1, min(r[3], h)
            else:
                runs.append([pos, pos + len(b), 1, h])
        pos += stride
    return runs


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    num = lambda s: int(s, 0)  # noqa: E731
    ap.add_argument("path", nargs="?", default=DEFAULT)
    ap.add_argument("--mdu-pages", type=int, default=None, help="forca o tamanho do MDU em paginas (padrao: cabecalho 0x470)")
    ap.add_argument("--anchor-radius", type=int, default=64, help="paginas a procurar em volta do XvcInfo calculado")
    ap.add_argument("--skip-scan", action="store_true", help="pula strings/entropia (leitura longa)")
    ap.add_argument("--scan-end", type=num, default=None, help="fim da varredura (padrao: inicio do drive data + 64 MB)")
    ap.add_argument("--window", type=num, default=16 * 1024)
    ap.add_argument("--stride", type=num, default=256 * 1024)
    ap.add_argument("--threshold", type=float, default=6.0)
    ap.add_argument("--max-gap", type=num, default=4 * 1024 * 1024)
    ap.add_argument("--dump", type=num, default=0, help="bytes de hexdump no inicio do XvcInfo")
    ap.add_argument("--list-files", action="store_true", help="lista os arquivos com segmento e regiao")
    ap.add_argument("--extract-userdata", metavar="DIR", help="grava os arquivos do user data em DIR")
    ap.add_argument("--json-report", metavar="ARQUIVO", help="grava relatorio JSON dos arquivos (schema 1)")
    args = ap.parse_args()

    src = FileSource(args.path)
    r = load_package(src, anchor_radius=args.anchor_radius, mdu_pages=args.mdu_pages)
    if isinstance(r, Err):
        sys.exit(f"erro: {r.error}")
    p = r.value
    print("== cabecalho XVD")
    print("\n".join(header_lines(p.header)))
    print(f"   integridade={'sim' if p.layout.integrity else 'nao'}  resiliencia={'sim' if p.layout.resilient else 'nao'}")
    print("\n".join(layout_lines(p.layout, p.size)))
    print("== checagens de layout/XvcInfo")
    for c in p.checks:
        print(f"   [{'OK' if c.status == 'PASS' else c.status}] {c.title}  ({c.detail})")
    xi = p.xvcinfo
    if xi:
        print(f"== XvcInfo @ 0x{xi.base_offset:x}")
        for o, name, _, note in FIELDS:
            v = xi.fields[name]
            extra = f"  {filetime(v)}" if name == "FileTimeCreated" else ""
            print(f"   +0x{o:03x} {name:<22} {v:#x}{extra}" + (f"   ({note})" if note else ""))
        for i, k in enumerate(xi.keys):
            print(f"   +0x{0x10 + i * 16:03x} KeyId[{i}]{'':<14} {k}")
        print(f"== cabecalhos de regiao: {len(xi.regions)} x 0x80 em +0xda8")
        for rg in xi.regions:
            key = "-" if rg.key_id == NO_KEY else str(rg.key_id)
            print(f"   {rg.index:>2} {rg.id:>#10x} {key:>4} {rg.flags:>#5x} {rg.first_segment_index:>4} "
                  f"{len(xi.region_segments(rg)):>4} {rg.offset:>#14x} {rg.length:>#14x}  {rg.hash.hex()}  "
                  f"{rg.description or '-':<9} {p.layout.region_of(rg.offset)}")
        print(f"== update segments: {len(xi.segments)} em +0x{xi.seg_off:x}; valores por segmento em "
              f"+0x{xi.segval_off:x}; tabela de paginas: {len(xi.page_table)} em +0x{xi.table_off:x}")
        print(f"   apos a tabela: +0x{xi.tail_off:x}, {xi.tail_nonzero} bytes nao-zero")
    ud = p.userdata
    if ud:
        print(f"== user data (0x{ud.length:x} bytes) Version {ud.version}  PackageVersion {ud.package_version}  "
              f"PackageFullName {ud.package_full_name!r}  FileCount {len(ud.files)}")
        for f in ud.files:
            print(f"   {f.index} +0x{f.start:04x} 0x{f.size:<6x} {f.path:<26} {f.data[:4]!r}")
        if args.extract_userdata:
            out = guard_output(args.extract_userdata, args.path)
            os.makedirs(out, exist_ok=True)
            for f in ud.files:
                name = safe_basename(f.path)
                if name:
                    with open(os.path.join(out, name), "wb") as o:
                        o.write(f.data)
            print(f"   {len(ud.files)} arquivos extraidos em {out}")
    sm = p.segmeta
    if sm:
        print(f"== SegmentMetadata.bin: Version {sm.version}  Unknown08 {sm.unknown08}  {len(sm.entries)} arquivos  "
              f"GUID {sm.guid}  Unknown28 {sm.unknown28}")
        print("== validacao dos intervalos de arquivo")
        for name, ok, detail in p.file_checks:
            print(f"   [{'OK' if ok else 'FALHA'}] {name}" + (f"  ({detail})" if detail else ""))
        if args.list_files:
            print("   seg  regiao      offset          tamanho       arquivo")
            for row in p.rows:
                rid = f"0x{row.region.id:x}" if row.region else "-"
                print(f"   {row.index:>3}  {rid:<10}  0x{row.start:<12x}  0x{row.size:<11x} {row.name}")
    for e in p.errors:
        print(f"   ! {e}")

    if args.json_report:
        if not p.rows:
            print("== relatorio JSON nao gerado: mapa de arquivos indisponivel")
        else:
            out = guard_output(args.json_report, args.path)
            rep = files_report(p, keep_legacy_source_note=False)
            write_json(out, rep)
            states = collections.Counter((x["content_state"], x["encryption_status"]) for x in rep["files"])
            print(f"== relatorio JSON: {out} ({len(rep['files'])} arquivos)")
            for (st, enc), n in sorted(states.items()):
                print(f"   {n:>3}  {st:<20} {enc}")

    if args.dump and xi:
        d = src.read_at(xi.base_offset, args.dump)
        print(f"== dump XvcInfo @ 0x{xi.base_offset:x}")
        for i in range(0, len(d), 16):
            ch = d[i:i + 16]
            print(f"  {xi.base_offset + i:012x}  " + " ".join(f"{x:02x}" for x in ch).ljust(47)
                  + "  " + "".join(chr(x) if 32 <= x < 127 else "." for x in ch))
    if args.skip_scan:
        return
    drive_off = p.layout.get("drive data").offset
    scan_end = min(args.scan_end if args.scan_end is not None else drive_off + (64 << 20), p.size)
    print(f"== strings de regiao ate 0x{scan_end:x}")
    by_text = collections.defaultdict(list)
    for off, text, enc in scan_strings(src, scan_end):
        by_text[(text, enc)].append(off)
    if not by_text:
        print("   nenhuma")
    for (text, enc), offs in sorted(by_text.items(), key=lambda kv: kv[1][0]):
        shown = ", ".join(f"0x{o:x} [{p.layout.region_of(o)}]" for o in offs[:8])
        print(f"   {text!r:<14} {enc:<5} x{len(offs):<5} {shown}" + (f" ... (+{len(offs) - 8})" if len(offs) > 8 else ""))
    print(f"== janelas H<{args.threshold} ({args.window // 1024} KB a cada {args.stride // 1024} KB)")
    runs = entropy_runs(src, scan_end, args.window, args.stride, args.threshold, args.max_gap)
    if not runs:
        print("   nenhuma")
    for a, b, n, hmin in runs:
        print(f"   0x{a:x} - 0x{b:x}  ({(b - a) / 2**20:.1f} MB, {n} janelas, H_min={hmin:.2f})  [{p.layout.region_of(a)}]")


if __name__ == "__main__":
    try:
        main()
    except SafetyError as ex:
        sys.exit(str(ex))
