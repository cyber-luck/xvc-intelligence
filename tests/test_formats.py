"""XvcInfo, user data, SegmentMetadata e regf contra os extratos pequenos do pacote real."""
import struct

import pytest

from xvcintel.core.result import BAD_MAGIC, INCONSISTENT, INVALID_VALUE, OUT_OF_BOUNDS, TRUNCATED, Err, Ok
from xvcintel.formats.regf import dump_lines, parse_hive
from xvcintel.formats.userdata import parse_segment_metadata, parse_userdata, safe_basename
from xvcintel.formats.xvcinfo import parse_xvcinfo, region_flag_names, structural_checks

REAL_FILE_SIZE = 0x34771C6000


@pytest.fixture(scope="module")
def xi_raw(fixtures_dir):
    return (fixtures_dir / "xvcinfo.bin").read_bytes()


@pytest.fixture(scope="module")
def xi(xi_raw):
    return parse_xvcinfo(xi_raw, 0x63A27000).value


def test_xvcinfo_counts_and_offsets(xi):
    assert xi.fields["RegionCount"] == 31 and xi.fields["UpdateSegmentCount"] == 108
    assert xi.fields["PageTableCount"] == 76_469 == len(xi.page_table)
    assert xi.fields["RegionSpecifierCount"] == 0 and xi.fields["KeyCount"] == 1
    assert (xi.seg_off, xi.segval_off, xi.table_off, xi.tail_off) == (0x1D28, 0x2238, 0x23E8, 0x97990)
    assert xi.tail_nonzero == 0
    assert str(xi.content_id) == "3202719e-b4b4-421c-9f8f-70d1c4a7d60b"
    assert xi.fields["InitialPlayRegionId"] == 0xBC1 and xi.fields["InitialPlayOffset"] == REAL_FILE_SIZE


def test_xvcinfo_regions(xi):
    descs = {r.description: r for r in xi.regions if r.description}
    assert set(descs) == {"XVC-HD", "XVC-EXVD", "XVC-MDU", "XVC-MD", "FS-MD"}
    assert descs["XVC-MDU"].length == 0x1000 and descs["XVC-MD"].offset == 0x14BF6000
    assert descs["XVC-HD"].hash == descs["XVC-MD"].hash == bytes.fromhex("5c2b65ad36990544")
    exe = xi.region_by_id(0x3E9)
    assert exe.key_id == 0 and exe.offset == 0x64917000 and exe.first_segment_index == 12
    assert xi.region_segments(exe) == [12]
    assert xi.region_by_id(0xBC1).flags == 0x4
    assert region_flag_names(0x4) == ["Preview"] and region_flag_names(0x81) == ["Resident", "0x80?"]


def test_xvcinfo_structure_checks_pass(xi):
    res = structural_checks(xi, REAL_FILE_SIZE)
    assert all(ok for _, ok, _ in res), [r for r in res if not r[1]]


def test_page_table_and_segment_values(xi):
    pages = [p for p, _ in xi.page_table]
    assert all(a < b for a, b in zip(pages, pages[1:]))
    assert xi.page_table[0] == (0x63BCB, 0)
    assert len(xi.segment_values) == 108
    assert xi.segment_values[78] == 0x049EA1FD and xi.segment_values[90] == 0x11F80453
    assert xi.segment_values[107] == 0x16EA0DE4
    idx = {p: v for p, v in xi.page_table}
    # array por segmento == Value da entrada da 1a pagina, exceto 78/90/107 (CONFIRMED no pacote real via folhas)
    diff = [s.index for s in xi.segments if idx[s.page] != xi.segment_values[s.index]]
    assert diff == [78, 90, 107]


@pytest.mark.parametrize("cut", [0, 0x100, 0xDA7, 0x1D28 + 5, 0x23E8 + 7])
def test_xvcinfo_truncated(xi_raw, cut):
    r = parse_xvcinfo(xi_raw[:cut])
    assert isinstance(r, Err) and r.error.kind in (TRUNCATED, OUT_OF_BOUNDS)


def test_xvcinfo_bad_counts(xi_raw):
    b = bytearray(xi_raw)
    struct.pack_into("<I", b, 0xD14, 0xFFFFFF)       # RegionCount absurdo
    assert parse_xvcinfo(bytes(b)).error.kind == OUT_OF_BOUNDS
    b = bytearray(xi_raw)
    struct.pack_into("<H", b, 0xD1E, 0xC1)            # KeyCount > 0xC0
    assert parse_xvcinfo(bytes(b)).error.kind == INCONSISTENT
    b = bytearray(xi_raw)
    struct.pack_into("<I", b, 0xD54, 0x7FFFFFFF)
    assert isinstance(parse_xvcinfo(bytes(b)), Err)
    assert parse_xvcinfo(xi_raw, page_table_limit=1000).error.kind == INCONSISTENT


def test_xvcinfo_region_specifiers_not_guessed(xi_raw):
    b = bytearray(xi_raw)
    struct.pack_into("<I", b, 0xD50, 2)
    r = parse_xvcinfo(bytes(b)).value
    assert r.page_table == [] and r.segment_values == [] and r.warnings


def test_xvcinfo_detects_overlap(xi_raw):
    b = bytearray(xi_raw)
    struct.pack_into("<Q", b, 0xDA8 + 5 * 0x80 + 0x58, 0x400000)   # alonga uma regiao
    xi2 = parse_xvcinfo(bytes(b)).value
    res = dict((n, ok) for n, ok, _ in structural_checks(xi2, REAL_FILE_SIZE))
    assert res["regioes ladrilham o arquivo sem lacuna/sobreposicao"] is False


# ------------------------------------------------------------------ user data / PFX
@pytest.fixture(scope="module")
def ud(fixtures_dir):
    return parse_userdata((fixtures_dir / "userdata.bin").read_bytes()[:0x6A26]).value


def test_userdata(ud, fixtures_dir):
    assert ud.package_full_name == "RockstarGamesInc.28872443D20A7_1.0.2.1_neutral__k2ss7vbb13xte"
    assert [f.path for f in ud.files] == ["appxmanifest.xml", "microsoft_gameconfig.bin", "MicrosoftGame.config",
                                          "Summary.json", "Metadata.json", "SegmentMetadata.bin"]
    assert ud.files[-1].start + ud.files[-1].size == 0x6A26 and not ud.problems
    for f in ud.files:
        assert f.data == (fixtures_dir / "userdata_files" / f.path).read_bytes()


def test_userdata_malformed(fixtures_dir):
    raw = bytearray((fixtures_dir / "userdata.bin").read_bytes()[:0x6A26])
    assert parse_userdata(bytes(raw[:0x100])).error.kind == TRUNCATED
    b = bytearray(raw)
    struct.pack_into("<I", b, 8, 1)
    assert parse_userdata(bytes(b)).error.kind == INVALID_VALUE
    b = bytearray(raw)
    struct.pack_into("<I", b, 0x14 + 0x208, 1000)
    assert parse_userdata(bytes(b)).error.kind == OUT_OF_BOUNDS
    assert isinstance(parse_userdata(bytes(raw[:0x6000])), Err)       # ultimo arquivo cortado


def test_segment_metadata(fixtures_dir):
    sm = parse_segment_metadata((fixtures_dir / "userdata_files" / "SegmentMetadata.bin").read_bytes()).value
    assert (sm.version, sm.unknown08, sm.header_size, sm.count, sm.string_table_size, sm.unknown28) == (4, 2, 0x64, 108, 0x1AD4, 1)
    assert str(sm.guid) == "b364c736-a183-4185-b6ca-2145e57dcc38"
    exe = sm.find("GAME_SCARLETT_MASTER.EXE")
    assert exe.index == 12 and exe.size == 120_181_760 and sm.pages[12] == 0xD4C
    assert all(e.flags == 0 for e in sm.entries)
    assert sm.entries[107].name == "Update.alignmentchunk" and sm.entries[107].size == 1


def test_segment_metadata_malformed(fixtures_dir):
    d = (fixtures_dir / "userdata_files" / "SegmentMetadata.bin").read_bytes()
    assert parse_segment_metadata(d[:0x10]).error.kind == TRUNCATED
    assert parse_segment_metadata(b"XPFX" + d[4:]).error.kind == BAD_MAGIC
    assert parse_segment_metadata(d[:-4]).error.kind == INCONSISTENT
    b = bytearray(d)
    struct.pack_into("<I", b, 0x64 + 4, 0x10000)                       # NameOffset fora da tabela
    assert parse_segment_metadata(bytes(b)).error.kind == OUT_OF_BOUNDS
    b = bytearray(d)
    struct.pack_into("<I", b, 0xC, 4)                                   # HeaderSize pequeno demais
    assert parse_segment_metadata(bytes(b)).error.kind == INVALID_VALUE


def test_safe_basename():
    assert safe_basename("a\\b\\c.txt") == "c.txt"
    assert safe_basename("..") is None and safe_basename("x/") is None


# ------------------------------------------------------------------ regf
def test_regf_real_hive(fixtures_dir):
    name, root = parse_hive((fixtures_dir / "userdata_files" / "microsoft_gameconfig.bin").read_bytes()).value
    assert name.endswith("gc.bin")
    assert root.value("StoreId") == "9NL3WWNZLZZN" and root.value("TitleId") == 0x7952987A
    assert root.value("MSAAppId") == 0x4060F900
    ex = root.find("Executable\\00000000")
    assert ex.value("Name") == "game_scarlett_master.exe" and ex.value("Id") == "GTAO"
    assert root.find("PersistentLocalStorage").value("SizeMB") == 0x800
    assert any("game_scarlett_master.exe" in line for line in dump_lines(name, root))


def test_regf_malformed(fixtures_dir):
    d = (fixtures_dir / "userdata_files" / "microsoft_gameconfig.bin").read_bytes()
    assert parse_hive(b"").error.kind == TRUNCATED
    assert parse_hive(b"rexf" + d[4:]).error.kind == BAD_MAGIC
    b = bytearray(d)
    struct.pack_into("<I", b, 0x24, 0x7FFFFF00)                        # raiz fora do hive
    assert parse_hive(bytes(b)).error.kind == OUT_OF_BOUNDS
    r = parse_hive(d[:0x1100])                                         # celulas cortadas
    assert isinstance(r, Err)
