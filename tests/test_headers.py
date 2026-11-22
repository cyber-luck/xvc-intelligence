import struct
import uuid

from xvcintel.core.result import BAD_MAGIC, TRUNCATED, Err, Ok
from xvcintel.formats.layout import compute_layout
from xvcintel.formats.xvd_header import (FIELDS, decode_flags, parse_xvd_header, product_id_storeid_test,
                                         version_reversed)

import synthxvc


def _real_like_header() -> bytes:
    """Cabecalho com os valores de campo do pacote real (sem bytes do pacote)."""
    return bytes(synthxvc.make_header({
        "flags": 0x41, "drive_size": 0x34135FB000, "vduid": uuid.UUID("3202719e-b4b4-421c-9f8f-70d1c4a7d60b"),
        "emb_len": 0x14BF2000, "ud_len": 0x6A26, "xvc_len": 0x1A4000, "mdu": 1, "pls": 0x800,
        "pkg_version": (1, 2, 0, 1), "u471": 4, "min_sys": (0x25AF, 0x65F4, 0, 0x800A),
        "product_id": bytes.fromhex("394e4c3357574e30c05a4c5a5a4eaa00")}))


def test_field_table_is_contiguous_and_absolute():
    end = 0
    for off, name, size in FIELDS:
        assert off == end, name
        end = off + size
    assert end == 0x1000
    names = {n: o for o, n, _ in FIELDS}
    assert names["MutableDataPageCount"] == 0x470
    assert names["PersistentLocalStorageSize"] == 0x46C
    assert names["PECatalogHash"] == 0x30C and names["EmbeddedXVD_PDUID"] == 0x32C
    assert names["PackageVersion"] == 0x3BC and names["ProductId"] == 0x39C


def test_parse_header_fields():
    h = parse_xvd_header(_real_like_header()).value
    assert h.volume_flags == 0x41 and h.flag_names == ["ReadOnly", "RegionIdInXts"]
    assert h.integrity and not h.resilient and not h.encryption_disabled and h.is_xvc
    assert h.mutable_data_page_count == 1 and h.unknown_471 == 4
    assert h.package_version_str == "1.0.2.1"
    assert h.persistent_local_storage_size == 0x800
    assert h.min_sys_version == (0x25AF, 0x65F4, 0, 0x800A)
    assert h.content_type_name == "Title" and h.type_name == "Fixed"
    assert h.field_bytes("MutableDataPageCount") == b"\x01"


def test_layout_reproduces_real_offsets_from_header_values():
    """Offsets do pacote real recalculados so a partir dos valores de campo do cabecalho."""
    lay = compute_layout(parse_xvd_header(_real_like_header()).value)
    got = {r.name: (r.offset, r.size) for r in lay.regions}
    assert got["XVD embutido"] == (0x3000, 0x14BF2000)
    assert got["mutable data (MDU)"] == (0x14BF5000, 0x1000)
    assert got["hash tree"] == (0x14BF6000, 0x4EE2A000)
    assert got["user data"] == (0x63A20000, 0x7000)
    assert got["XvcInfo"] == (0x63A27000, 0x1A4000)
    assert got["drive data"] == (0x63BCB000, 0x34135FB000)
    assert lay.end == 0x34771C6000
    assert lay.hashed_pages == 54_605_734
    # o erro antigo (MDU = 0) deslocaria o XvcInfo uma pagina para tras
    assert compute_layout(parse_xvd_header(_real_like_header()).value, mdu_pages=0).get("XvcInfo").offset == 0x63A26000


def test_header_malformed():
    assert parse_xvd_header(b"").error.kind == TRUNCATED
    assert parse_xvd_header(_real_like_header()[:0xFFF]).error.kind == TRUNCATED
    bad = bytearray(_real_like_header())
    bad[0x200:0x208] = b"msft-xxx"
    r = parse_xvd_header(bytes(bad))
    assert isinstance(r, Err) and r.error.kind == BAD_MAGIC and r.error.offset == 0x200


def test_flags_and_versions():
    assert decode_flags(0x41) == ["ReadOnly", "RegionIdInXts"]
    assert decode_flags(0x105)[-1] == "0x100?"
    assert version_reversed((1, 2, 0, 1)) == "1.0.2.1"


def test_product_id_storeid():
    t = product_id_storeid_test(bytes.fromhex("394e4c3357574e30c05a4c5a5a4eaa00"), "9NL3WWNZLZZN")
    assert t["contains_all_12_in_order_split_7_5"] is True
    assert t["direct_ascii_16"] is False
    assert t["bytes_7_8"] == "30c0" and t["bytes_14_15"] == "aa00"
    assert t["guid_version_nibble"] == 3 and t["guid_variant_bits"] == "Microsoft"
    neg = product_id_storeid_test(bytes(16), "9NL3WWNZLZZN")
    assert neg["contains_all_12_in_order_split_7_5"] is False


def test_embedded_header_in_synthetic(synth_pkg):
    eh = synth_pkg.embedded_header
    assert eh is not None and eh.content_type == 3 and eh.pduid == synth_pkg.header.embedded_xvd_pduid
