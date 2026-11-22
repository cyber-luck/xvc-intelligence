"""Cabecalho XVD (offsets absolutos no arquivo).

Referencia publica: xvdtool (XvdHeader em XvdStructs.cs). Os comentarios do
xvdtool usam offsets relativos ao magic; aqui todos os offsets sao absolutos
(comentario do xvdtool + 0x200). Nomes de campos sao os do xvdtool; o que foi
conferido contra bytes deste pacote esta marcado nos testes/achados, nao aqui.
"""
from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field

from ..core.result import BAD_MAGIC, Ok, Result, err, need

XVD_MAGIC = b"msft-xvd"
SIGNATURE_SIZE = 0x200
HEADER_STRUCT_SIZE = 0x1000      # ate ResilientDataLength (0xFFC + 4)
HEADER_INCL_SIGNATURE_SIZE = 0x3000   # xvdtool: XVD_HEADER_INCL_SIGNATURE_SIZE

# xvdtool XvdVolumeFlags
VOLUME_FLAGS = {
    0x01: "ReadOnly",
    0x02: "EncryptionDisabled",
    0x04: "DataIntegrityDisabled",
    0x08: "LegacySectorSize",
    0x10: "ResiliencyEnabled",
    0x20: "SraReadOnly",
    0x40: "RegionIdInXts",
    0x80: "EraSpecific",
}
FLAG_ENCRYPTION_DISABLED = 0x02
FLAG_DATA_INTEGRITY_DISABLED = 0x04
FLAG_RESILIENCY_ENABLED = 0x10
FLAG_REGION_ID_IN_XTS = 0x40

# xvdtool XvdType / XvdContentType (nomes publicos; semantica nao verificada aqui)
XVD_TYPES = {0: "Fixed", 1: "Dynamic"}
CONTENT_TYPES = {
    0: "Data", 1: "Title", 2: "SystemOS", 3: "EraOS", 4: "Scratch", 5: "ResetData",
    6: "Application", 7: "HostOS", 8: "X360STFS", 9: "X360FATX", 10: "X360GDFX",
    11: "Updater", 12: "OfflineUpdater", 13: "Template", 14: "MteHost", 15: "MteApp",
    16: "MteTitle", 17: "MteEraOS", 18: "EraTools", 19: "SystemTools", 20: "SystemAux",
    21: "AcousticModel", 22: "SystemCodecsVolume", 23: "QasltPackage", 24: "AppDlc",
    25: "TitleDlc", 26: "UniversalDlc", 27: "SystemDataVolume", 28: "TestVolume",
    29: "HardwareTestVolume", 30: "KioskContent", 32: "HostProfiler", 33: "Uwa",
    34: "Unknown22", 35: "Unknown23", 36: "Unknown24", 37: "ServerAgent",
}

# (offset absoluto, nome, tamanho) - tabela usada para evidencias
FIELDS: list[tuple[int, str, int]] = [
    (0x000, "Signature", 0x200),
    (0x200, "Magic", 8),
    (0x208, "VolumeFlags", 4),
    (0x20C, "FormatVersion", 4),
    (0x210, "FileTimeCreated", 8),
    (0x218, "DriveSize", 8),
    (0x220, "VDUID", 16),
    (0x230, "UDUID", 16),
    (0x240, "TopHashBlockHash", 32),
    (0x260, "OriginalXvcDataHash", 32),
    (0x280, "Type", 4),
    (0x284, "ContentType", 4),
    (0x288, "EmbeddedXVDLength", 4),
    (0x28C, "UserDataLength", 4),
    (0x290, "XvcDataLength", 4),
    (0x294, "DynamicHeaderLength", 4),
    (0x298, "BlockSize", 4),
    (0x29C, "ExtEntries", 0x60),
    (0x2FC, "Capabilities", 0x10),
    (0x30C, "PECatalogHash", 32),
    (0x32C, "EmbeddedXVD_PDUID", 16),
    (0x33C, "Reserved33C", 16),
    (0x34C, "KeyMaterial", 32),
    (0x36C, "UserDataHash", 32),
    (0x38C, "SandboxId", 16),
    (0x39C, "ProductId", 16),
    (0x3AC, "PDUID", 16),
    (0x3BC, "PackageVersion", 8),
    (0x3C4, "PECatalogCaps", 0x20),
    (0x3E4, "PECatalogs", 0x80),
    (0x464, "WriteableExpirationDate", 4),
    (0x468, "WriteablePolicyFlags", 4),
    (0x46C, "PersistentLocalStorageSize", 4),
    (0x470, "MutableDataPageCount", 1),
    (0x471, "Unknown471", 1),
    (0x472, "Unknown472", 0x10),
    (0x482, "Reserved482", 0xA),
    (0x48C, "SequenceNumber", 8),
    (0x494, "MinSysVersion", 8),
    (0x49C, "OdkKeyslotID", 4),
    (0x4A0, "Reserved4A0", 0xB54),
    (0xFF4, "ResilientDataOffset", 8),
    (0xFFC, "ResilientDataLength", 4),
]
FIELD_OFFSET = {name: off for off, name, _ in FIELDS}


def decode_flags(v: int) -> list[str]:
    names = [n for bit, n in VOLUME_FLAGS.items() if v & bit]
    rest = v & ~sum(VOLUME_FLAGS)
    if rest:
        names.append(f"0x{rest:X}?")
    return names


def version_reversed(parts: tuple[int, int, int, int]) -> str:
    """Le os 4 u16 em ordem inversa (como o PackageVersion: 1,2,0,1 -> 1.0.2.1)."""
    return ".".join(str(p) for p in reversed(parts))


@dataclass(frozen=True)
class XvdHeader:
    base_offset: int
    volume_flags: int
    format_version: int
    file_time_created: int
    drive_size: int
    vduid: uuid.UUID
    uduid: uuid.UUID
    top_hash_block_hash: bytes
    original_xvc_data_hash: bytes
    type: int
    content_type: int
    embedded_xvd_length: int
    user_data_length: int
    xvc_data_length: int
    dynamic_header_length: int
    block_size: int
    ext_entries: bytes
    capabilities: bytes
    pe_catalog_hash: bytes
    embedded_xvd_pduid: bytes
    reserved_33c: bytes
    key_material: bytes
    user_data_hash: bytes
    sandbox_id: bytes
    product_id: bytes
    pduid: bytes
    package_version: tuple[int, int, int, int]
    pe_catalog_caps: tuple[int, ...]
    pe_catalogs: bytes
    writeable_expiration_date: int
    writeable_policy_flags: int
    persistent_local_storage_size: int
    mutable_data_page_count: int
    unknown_471: int
    unknown_472: bytes
    reserved_482: bytes
    sequence_number: int
    min_sys_version: tuple[int, int, int, int]
    odk_keyslot_id: int
    reserved_4a0_nonzero: int
    resilient_data_offset: int
    resilient_data_length: int
    raw: bytes = field(repr=False, default=b"")

    @property
    def flag_names(self) -> list[str]:
        return decode_flags(self.volume_flags)

    @property
    def integrity(self) -> bool:
        return not self.volume_flags & FLAG_DATA_INTEGRITY_DISABLED

    @property
    def resilient(self) -> bool:
        return bool(self.volume_flags & FLAG_RESILIENCY_ENABLED)

    @property
    def encryption_disabled(self) -> bool:
        return bool(self.volume_flags & FLAG_ENCRYPTION_DISABLED)

    @property
    def is_xvc(self) -> bool:
        return self.xvc_data_length > 0

    @property
    def type_name(self) -> str:
        return XVD_TYPES.get(self.type, f"desconhecido({self.type})")

    @property
    def content_type_name(self) -> str:
        return CONTENT_TYPES.get(self.content_type, f"desconhecido({self.content_type})")

    @property
    def package_version_str(self) -> str:
        return version_reversed(self.package_version)

    @property
    def min_sys_version_str(self) -> str:
        return version_reversed(self.min_sys_version)

    def field_bytes(self, name: str) -> bytes:
        off = FIELD_OFFSET[name]
        size = next(s for o, n, s in FIELDS if n == name)
        return self.raw[off:off + size]

    def summary(self) -> dict:
        return {
            "VolumeFlags": f"0x{self.volume_flags:X} ({'|'.join(self.flag_names) or '-'})",
            "FormatVersion": self.format_version,
            "DriveSize": f"0x{self.drive_size:X}",
            "VDUID": str(self.vduid),
            "UDUID": str(self.uduid),
            "Type": f"{self.type} ({self.type_name})",
            "ContentType": f"{self.content_type} ({self.content_type_name})",
            "EmbeddedXVDLength": f"0x{self.embedded_xvd_length:X}",
            "UserDataLength": f"0x{self.user_data_length:X}",
            "XvcDataLength": f"0x{self.xvc_data_length:X}",
            "DynamicHeaderLength": f"0x{self.dynamic_header_length:X}",
            "BlockSize": f"0x{self.block_size:X}",
            "TopHashBlockHash": self.top_hash_block_hash.hex(),
            "OriginalXvcDataHash": self.original_xvc_data_hash.hex(),
            "PECatalogHash": self.pe_catalog_hash.hex(),
            "EmbeddedXVD_PDUID": self.embedded_xvd_pduid.hex(),
            "KeyMaterial": "zeros" if not any(self.key_material) else "nao-zero (nao usado)",
            "UserDataHash": self.user_data_hash.hex(),
            "SandboxId": self.sandbox_id.hex(),
            "ProductId": self.product_id.hex(),
            "PDUID": self.pduid.hex(),
            "PackageVersion": f"{self.package_version} -> {self.package_version_str}",
            "PECatalogCaps": "zeros" if not any(self.pe_catalog_caps) else list(self.pe_catalog_caps),
            "PECatalogs": "zeros" if not any(self.pe_catalogs) else f"{sum(1 for b in self.pe_catalogs if b)} bytes nao-zero",
            "PersistentLocalStorageSize": f"0x{self.persistent_local_storage_size:X}",
            "MutableDataPageCount": self.mutable_data_page_count,
            "Unknown471": f"0x{self.unknown_471:X}",
            "SequenceNumber": self.sequence_number,
            "MinSysVersion": f"{tuple(f'0x{x:X}' for x in self.min_sys_version)}",
            "OdkKeyslotID": self.odk_keyslot_id,
            "Reserved4A0_nonzero_bytes": self.reserved_4a0_nonzero,
            "ResilientDataOffset": f"0x{self.resilient_data_offset:X}",
            "ResilientDataLength": f"0x{self.resilient_data_length:X}",
        }


def parse_xvd_header(buf: bytes, base_offset: int = 0) -> Result[XvdHeader]:
    """buf deve comecar no inicio do XVD (assinatura). Exige 0x1000 bytes."""
    e = need(buf, 0, HEADER_STRUCT_SIZE, "XvdHeader")
    if e:
        return e
    if buf[0x200:0x208] != XVD_MAGIC:
        return err(BAD_MAGIC, f"magic XVD ausente em 0x200: {buf[0x200:0x208]!r}", base_offset + 0x200, "XvdHeader")

    def U(fmt: str, o: int) -> int:
        return struct.unpack_from(fmt, buf, o)[0]

    h = XvdHeader(
        base_offset=base_offset,
        volume_flags=U("<I", 0x208),
        format_version=U("<I", 0x20C),
        file_time_created=U("<Q", 0x210),
        drive_size=U("<Q", 0x218),
        vduid=uuid.UUID(bytes_le=bytes(buf[0x220:0x230])),
        uduid=uuid.UUID(bytes_le=bytes(buf[0x230:0x240])),
        top_hash_block_hash=bytes(buf[0x240:0x260]),
        original_xvc_data_hash=bytes(buf[0x260:0x280]),
        type=U("<I", 0x280),
        content_type=U("<I", 0x284),
        embedded_xvd_length=U("<I", 0x288),
        user_data_length=U("<I", 0x28C),
        xvc_data_length=U("<I", 0x290),
        dynamic_header_length=U("<I", 0x294),
        block_size=U("<I", 0x298),
        ext_entries=bytes(buf[0x29C:0x2FC]),
        capabilities=bytes(buf[0x2FC:0x30C]),
        pe_catalog_hash=bytes(buf[0x30C:0x32C]),
        embedded_xvd_pduid=bytes(buf[0x32C:0x33C]),
        reserved_33c=bytes(buf[0x33C:0x34C]),
        key_material=bytes(buf[0x34C:0x36C]),
        user_data_hash=bytes(buf[0x36C:0x38C]),
        sandbox_id=bytes(buf[0x38C:0x39C]),
        product_id=bytes(buf[0x39C:0x3AC]),
        pduid=bytes(buf[0x3AC:0x3BC]),
        package_version=struct.unpack_from("<4H", buf, 0x3BC),
        pe_catalog_caps=struct.unpack_from("<16H", buf, 0x3C4),
        pe_catalogs=bytes(buf[0x3E4:0x464]),
        writeable_expiration_date=U("<I", 0x464),
        writeable_policy_flags=U("<I", 0x468),
        persistent_local_storage_size=U("<I", 0x46C),
        mutable_data_page_count=buf[0x470],
        unknown_471=buf[0x471],
        unknown_472=bytes(buf[0x472:0x482]),
        reserved_482=bytes(buf[0x482:0x48C]),
        sequence_number=U("<Q", 0x48C),
        min_sys_version=struct.unpack_from("<4H", buf, 0x494),
        odk_keyslot_id=U("<I", 0x49C),
        reserved_4a0_nonzero=sum(1 for b in buf[0x4A0:0xFF4] if b),
        resilient_data_offset=U("<Q", 0xFF4),
        resilient_data_length=U("<I", 0xFFC),
        raw=bytes(buf[:HEADER_STRUCT_SIZE]),
    )
    return Ok(h)


def product_id_storeid_test(product_id: bytes, store_id: str) -> dict:
    """Hipotese testavel: os 12 caracteres ASCII do StoreId aparecem no ProductId.

    Testa a forma observada: StoreId[0:7] em bytes 0-6 e StoreId[7:12] em bytes 9-13,
    e tambem a leitura como GUID (bytes_le) com versao/variante.
    """
    sid = store_id.encode("ascii", errors="replace")
    res: dict = {"store_id": store_id, "product_id": product_id.hex()}
    res["ascii_prefix_7"] = len(sid) >= 7 and product_id[0:7] == sid[0:7]
    res["ascii_suffix_5_at_9"] = len(sid) >= 12 and product_id[9:14] == sid[7:12]
    res["contains_all_12_in_order_split_7_5"] = bool(res["ascii_prefix_7"] and res["ascii_suffix_5_at_9"])
    res["direct_ascii_16"] = product_id[:len(sid)] == sid
    res["bytes_7_8"] = product_id[7:9].hex()
    res["bytes_14_15"] = product_id[14:16].hex()
    g = uuid.UUID(bytes_le=bytes(product_id))
    res["as_guid"] = str(g)
    res["guid_version_nibble"] = (product_id[7] >> 4) & 0xF
    v = product_id[8]
    res["guid_variant_bits"] = ("NCS" if v >> 7 == 0 else "RFC4122" if v >> 6 == 0b10
                                else "Microsoft" if v >> 5 == 0b110 else "reservado")
    return res
