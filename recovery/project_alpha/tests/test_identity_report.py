"""Regressao do relatorio independente de identidade: PDB GUID/age,
manifesto de build (layout x SegmentMetadata) e ambiente de dependencias."""
from __future__ import annotations

import struct
import uuid
from pathlib import Path

from correlation.identity_report import (
    build_layout_evidence, cross_validate_rsds_pdb, manifest_correspondence,
    pdb_info_stream,
)


def make_minimal_pdb(path: Path, *, guid: str, age: int, version: int = 20000404,
                     signature: int = 0x12345678) -> Path:
    """PDB MSF 7.00 minimo: superblock + diretorio + info stream + block map."""
    page = 0x400
    info = struct.pack("<III", version, signature, age) + uuid.UUID(guid).bytes_le
    info += b"\x00" * (page - len(info))

    num_streams = 2
    dir_bytes = struct.pack("<I", num_streams) + struct.pack("<II", 0xFFFFFFFF, len(info))
    dir_bytes += struct.pack("<I", 2)
    dir_bytes += b"\x00" * (page - len(dir_bytes))

    num_blocks = 4
    block_map_addr = 3
    sb = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
    sb += b"\x00" * (0x1C - len(sb))
    sb += struct.pack("<IIIIII", page, 1, num_blocks, page, 0, block_map_addr)
    sb += b"\x00" * (page - len(sb))

    block_map = struct.pack("<I", 1)
    block_map += b"\x00" * (page - len(block_map))
    path.write_bytes(sb + dir_bytes + info + block_map)
    return path


def test_pdb_info_stream_parses_guid_and_age(tmp_path):
    g = "12345678-1234-1234-1234-123456789abc"
    p = make_minimal_pdb(tmp_path / "test.pdb", guid=g, age=19)
    info = pdb_info_stream(p)
    assert info["guid"] == g
    assert info["age"] == 19
    assert info["msf_version"] == "VC80"
    assert info["signature"] == "0x12345678"


def test_pdb_info_stream_rejects_non_pdb(tmp_path):
    f = tmp_path / "not.pdb"
    f.write_bytes(b"\x00" * 512)
    assert "error" in pdb_info_stream(f)


def _fake_xvc_files() -> list[dict]:
    return [
        {"filename": "MicrosoftGame.Config", "segment_index": 1, "size": 2542, "key_id": 65535},
        {"filename": "game_scarlett_master.exe", "segment_index": 12, "size": 120181760, "key_id": 0},
        {"filename": "msvcp140.dll", "segment_index": 18, "size": 565232, "key_id": 0},
    ]


LAYOUT = r"""<?xml version="1.0" encoding="utf-8"?>
<Package>
  <Chunk Id="1000">
    <FileGroup SourcePath=".\..\..\content\" DestinationPath="\" Include="MicrosoftGame.Config" />
  </Chunk>
  <Chunk Id="1001">
    <FileGroup SourcePath=".\..\..\content\" DestinationPath="\" Include="game_scarlett_master.exe" />
  </Chunk>
  <Chunk Id="1002">
    <FileGroup SourcePath=".\..\..\content\" DestinationPath="\" Include="msvcp140.dll" />
  </Chunk>
  <Chunk Id="3009" Marker="Launch">
    <FileGroup SourcePath=".\..\..\content\" DestinationPath="\" Include="extra.bin" />
  </Chunk>
</Package>
"""


def test_manifest_correspondence(tmp_path):
    lf = tmp_path / "layout_test.xml"
    lf.write_text(LAYOUT, encoding="utf-8")
    layout = build_layout_evidence(lf)
    assert layout["launch_marker_chunk"] == "3009"
    corr = manifest_correspondence(layout, _fake_xvc_files())
    assert corr["confirmed_in_xvc"] == 3
    assert corr["missing_from_xvc"] == ["extra.bin"]
    assert corr["executable_in_layout"] == ["game_scarlett_master.exe"]
    assert corr["executable_in_xvc"] == ["game_scarlett_master.exe"]
    assert corr["layout_chunk_order_equals_segment_order"] is True
    by_file = {c["file"]: c for c in corr["checks"]}
    assert by_file["game_scarlett_master.exe"]["in_xvc_segment"] == 12
    assert by_file["extra.bin"]["status"] == "MISMATCH"

def test_manifest_correspondence_order_violation(tmp_path):
    lf = tmp_path / "layout_bad.xml"
    lf.write_text(LAYOUT, encoding="utf-8")
    layout = build_layout_evidence(lf)
    files = _fake_xvc_files()
    files[0]["segment_index"] = 20
    corr = manifest_correspondence(layout, files)
    assert corr["layout_chunk_order_equals_segment_order"] is False


def test_cross_validate_rsds_pdb_guid_age(tmp_path, monkeypatch):
    import correlation.identity_report as ir

    g = "aabbccdd-1122-3344-5566-77889900aabb"
    p = make_minimal_pdb(tmp_path / "ok.pdb", guid=g, age=19)
    pe = tmp_path / "pe.exe"
    pe.write_bytes(b"x" * 16)

    def fake_rsds(_path):
        return [{"guid": g, "age": 19, "pdb_path": "x.pdb"}]

    monkeypatch.setattr(ir, "rsds_records", fake_rsds)
    val = cross_validate_rsds_pdb(pe, p)
    assert val["verdict"] == "GUID_AGE_MATCH"
    assert val["guid_match"] is True and val["age_match"] is True
    assert "evidencia forte" in val["meaning"]

    def fake_rsds2(_path):
        return [{"guid": g, "age": 99, "pdb_path": "x.pdb"}]

    monkeypatch.setattr(ir, "rsds_records", fake_rsds2)
    val2 = cross_validate_rsds_pdb(pe, p)
    assert val2["verdict"] == "GUID_MATCH_AGE_MISMATCH"
    assert "NAO corresponde" in val2["meaning"]

    def fake_rsds3(_path):
        return []

    monkeypatch.setattr(ir, "rsds_records", fake_rsds3)
    val3 = cross_validate_rsds_pdb(pe, p)
    assert val3["verdict"] == "NOT_VALIDATED"
