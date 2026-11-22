from pathlib import Path
import os
import struct

PFX_PATH = Path(r"userdata_files\SegmentMetadata.bin")
XVC_PATH = Path(r"G:\MyGame_v1\28872443D20A7_1.0.2.1_neutral__k2ss7vbb13xte_xs.xvc")

TARGET = "game_scarlett_master.exe"
DRIVE_OFFSET = 0x63BCB000
PAGE_SIZE = 0x1000

pfx = PFX_PATH.read_bytes()

if pfx[:4] != b" PFX":
    raise ValueError("Assinatura PFX inválida")

header_size, count, strings_size = struct.unpack_from(
    "<III", pfx, 0x0C
)

if header_size != 0x64:
    raise ValueError("Tamanho de cabeçalho inesperado")

strings_off = header_size + count * 16
pages_off = strings_off + strings_size
expected_size = pages_off + count * 4

if len(pfx) != expected_size:
    raise ValueError("Tamanho do PFX inconsistente")

found = False

for i in range(count):
    reserved, name_len, name_rel, file_size = (
        struct.unpack_from("<HHIQ", pfx, header_size + i * 16)
    )

    name_start = strings_off + name_rel
    name_end = name_start + name_len * 2

    if not (strings_off <= name_start <= name_end <= pages_off):
        raise ValueError(f"Nome inválido na entrada {i}")

    name = pfx[name_start:name_end].decode("utf-16-le")

    if name.casefold() != TARGET.casefold():
        continue

    page_rel = struct.unpack_from(
        "<I", pfx, pages_off + i * 4
    )[0]

    absolute_offset = DRIVE_OFFSET + page_rel * PAGE_SIZE

    print("Arquivo:", name)
    print("Segmento:", i)
    print(f"Página relativa: 0x{page_rel:X}")
    print(f"Offset absoluto: 0x{absolute_offset:X}")
    print(f"Tamanho: 0x{file_size:X} ({file_size:,} bytes)")

    if absolute_offset + file_size > os.path.getsize(XVC_PATH):
        raise ValueError("Arquivo ultrapassa o tamanho do XVC")

    with open(XVC_PATH, "rb") as f:
        f.seek(absolute_offset)
        sample = f.read(min(64, file_size))

    print("Primeiros 64 bytes:", sample.hex(" "))
    print("Assinatura MZ:", sample.startswith(b"MZ"))

    found = True
    break

if not found:
    raise LookupError(f"{TARGET} não encontrado no PFX")
