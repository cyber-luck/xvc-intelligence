import struct
import sys
from pathlib import Path

# winnt.h IMAGE_SUBSYSTEM_*
SUBSYSTEMS = {
    0: "UNKNOWN",
    1: "NATIVE",
    2: "WINDOWS_GUI",
    3: "WINDOWS_CUI",
    5: "OS2_CUI",
    7: "POSIX_CUI",
    8: "NATIVE_WINDOWS",
    9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION",
    11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER",
    13: "EFI_ROM",
    14: "XBOX",
    16: "WINDOWS_BOOT_APPLICATION",
    17: "XBOX_CODE_CATALOG",
}
PE32 = 0x10B
PE32_PLUS = 0x20B
# winnt.h IMAGE_FILE_MACHINE_* -> magic esperado do optional header
MACHINES = {
    0x014C: ("I386", PE32),
    0x01C0: ("ARM", PE32),
    0x01C4: ("ARMNT", PE32),
    0x8664: ("AMD64", PE32_PLUS),
    0xAA64: ("ARM64", PE32_PLUS),
    0xA641: ("ARM64EC", PE32_PLUS),
    0xA64E: ("ARM64X", PE32_PLUS),
    0x0200: ("IA64", PE32_PLUS),
}
# offsets dentro do optional header; iguais em PE32 e PE32+ ate Subsystem
OPT_SIZE_OF_CODE = 4
OPT_ENTRY_POINT = 16
OPT_SECTION_ALIGNMENT = 32
OPT_FILE_ALIGNMENT = 36
OPT_SIZE_OF_HEADERS = 60
OPT_SUBSYSTEM = 68
OPT_MIN_SIZE = OPT_SUBSYSTEM + 2
SECTION_HEADER_SIZE = 40
# especificacao PE/COFF, campo FileAlignment: potencia de 2 entre 512 e 64K;
# se SectionAlignment for menor que a pagina da arquitetura, FileAlignment deve ser igual a ele
FILE_ALIGNMENT_MIN = 0x200
FILE_ALIGNMENT_MAX = 0x10000
ARCH_PAGE_SIZE = 0x1000

path = Path(sys.argv[1] if len(sys.argv) > 1 else r"G:\caminho\Catalog000.bin")
data = path.read_bytes()

if len(data) < 0x40 or data[:2] != b"MZ":
    print("Não possui cabeçalho MZ válido.")
    sys.exit(1)

pe_offset = struct.unpack_from("<I", data, 0x3C)[0]

if pe_offset + 24 > len(data):
    print("Offset PE fora dos limites.")
    sys.exit(1)
if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
    print("Assinatura PE não encontrada.")
    sys.exit(1)

machine, sections, _, _, _, opt_size, characteristics = struct.unpack_from(
    "<HHIIIHH", data, pe_offset + 4
)
opt = pe_offset + 24
machine_name, expected_magic = MACHINES.get(machine, ("desconhecida", None))

print("Formato PE identificado")
print(f"Arquitetura: 0x{machine:04X} ({machine_name})")
print(f"Seções: {sections}")
print(f"Características: 0x{characteristics:04X}")
print(f"Tamanho: {len(data):,} bytes")

if opt_size < OPT_MIN_SIZE:
    print(f"Optional header ausente ou curto demais (SizeOfOptionalHeader 0x{opt_size:X}).")
    sys.exit(1)
if opt + opt_size > len(data):
    print(f"Optional header ultrapassa o arquivo "
          f"(0x{opt:X} + 0x{opt_size:X} > 0x{len(data):X}).")
    sys.exit(1)

magic = struct.unpack_from("<H", data, opt)[0]
if magic not in (PE32, PE32_PLUS):
    print(f"Magic do optional header desconhecido: 0x{magic:04X}")
    sys.exit(1)

size_of_code = struct.unpack_from("<I", data, opt + OPT_SIZE_OF_CODE)[0]
entry_point = struct.unpack_from("<I", data, opt + OPT_ENTRY_POINT)[0]
section_alignment = struct.unpack_from("<I", data, opt + OPT_SECTION_ALIGNMENT)[0]
file_alignment = struct.unpack_from("<I", data, opt + OPT_FILE_ALIGNMENT)[0]
size_of_headers = struct.unpack_from("<I", data, opt + OPT_SIZE_OF_HEADERS)[0]
subsystem = struct.unpack_from("<H", data, opt + OPT_SUBSYSTEM)[0]
subsystem_name = SUBSYSTEMS.get(subsystem, "desconhecido")

print(f"Optional header: {'PE32+' if magic == PE32_PLUS else 'PE32'} (0x{magic:X}), 0x{opt_size:X} bytes")
print(f"SizeOfCode: 0x{size_of_code:X}")
print(f"Entry point (RVA): 0x{entry_point:X}")
print(f"Alinhamento: seções 0x{section_alignment:X}, arquivo 0x{file_alignment:X}; SizeOfHeaders 0x{size_of_headers:X}")
print(f"Subsystem: {subsystem} ({subsystem_name})")

problems = []
notes = []

# --- checagem 1: Machine x magic
if expected_magic is None:
    notes.append(f"Machine 0x{machine:04X} fora da tabela; combinação com o magic não verificada")
elif magic != expected_magic:
    problems.append(f"Machine {machine_name} exige magic 0x{expected_magic:X}, "
                    f"mas o optional header tem 0x{magic:X}")

# --- checagem 2: tabela de seções
table = opt + opt_size
table_end = table + sections * SECTION_HEADER_SIZE
print(f"Tabela de seções: 0x{table:X}..0x{table_end:X}")


def power_of_two(v):
    return v and not v & (v - 1)


if table_end > len(data):
    problems.append(f"tabela de seções ultrapassa o arquivo (0x{table_end:X} > 0x{len(data):X})")
else:
    if table_end > size_of_headers:
        problems.append(f"tabela de seções termina em 0x{table_end:X}, depois de SizeOfHeaders 0x{size_of_headers:X}")
    check_file_align = power_of_two(file_alignment)
    check_sect_align = power_of_two(section_alignment)
    if not check_file_align:
        problems.append(f"FileAlignment 0x{file_alignment:X} não é potência de 2")
    if not check_sect_align:
        problems.append(f"SectionAlignment 0x{section_alignment:X} não é potência de 2")
    if check_file_align and check_sect_align:
        if section_alignment < ARCH_PAGE_SIZE:
            if file_alignment != section_alignment:
                problems.append(f"SectionAlignment 0x{section_alignment:X} é menor que a página (0x{ARCH_PAGE_SIZE:X}), "
                                f"então FileAlignment deveria ser igual a ele, mas é 0x{file_alignment:X}")
        elif not FILE_ALIGNMENT_MIN <= file_alignment <= FILE_ALIGNMENT_MAX:
            problems.append(f"FileAlignment 0x{file_alignment:X} fora da faixa da especificação "
                            f"(0x{FILE_ALIGNMENT_MIN:X} a 0x{FILE_ALIGNMENT_MAX:X})")

    raw_ranges, virt_ranges = [], []
    for i in range(sections):
        s = table + i * SECTION_HEADER_SIZE
        name = data[s:s + 8].rstrip(b"\x00").decode("latin-1") or f"#{i}"
        vsize, va, rsize, rptr = struct.unpack_from("<IIII", data, s + 8)
        flags = struct.unpack_from("<I", data, s + 36)[0]
        print(f"  {name:<8} VA 0x{va:08X} VSize 0x{vsize:08X}  Raw 0x{rptr:08X} +0x{rsize:08X}  Flags 0x{flags:08X}")

        if rsize:
            if rptr + rsize > len(data):
                problems.append(f"seção {name}: dados brutos 0x{rptr:X}+0x{rsize:X} ultrapassam o arquivo (0x{len(data):X})")
            if check_file_align and rptr % file_alignment:
                problems.append(f"seção {name}: PointerToRawData 0x{rptr:X} não alinhado a 0x{file_alignment:X}")
            if rptr < size_of_headers:
                problems.append(f"seção {name}: dados brutos começam dentro dos cabeçalhos (0x{rptr:X} < 0x{size_of_headers:X})")
            raw_ranges.append((rptr, rptr + rsize, name))
        if check_sect_align and va % section_alignment:
            problems.append(f"seção {name}: VirtualAddress 0x{va:X} não alinhado a 0x{section_alignment:X}")
        # VirtualSize 0 faz o loader usar SizeOfRawData
        vext = vsize or rsize
        virt_ranges.append((va, va + vext, name))

    raw_ranges.sort()
    for (a0, a1, an), (b0, b1, bn) in zip(raw_ranges, raw_ranges[1:]):
        if b0 < a1:
            problems.append(f"seções {an} e {bn} se sobrepõem no arquivo (0x{b0:X} < 0x{a1:X})")
    for (a0, a1, an), (b0, b1, bn) in zip(virt_ranges, virt_ranges[1:]):
        if b0 < a1:
            problems.append(f"seções {an} e {bn} fora de ordem ou sobrepostas na memória (0x{b0:X} < 0x{a1:X})")

for n in notes:
    print(f"Aviso: {n}")
for p in problems:
    print(f"Problema: {p}")

if problems:
    conclusao = "estrutura PE inconsistente"
elif subsystem == 17:
    conclusao = "contêiner de catálogo de código Xbox"
    if entry_point == 0 and size_of_code == 0:
        conclusao += "; sem código nem ponto de entrada, não é um programa"
elif entry_point == 0:
    conclusao = "sem ponto de entrada (pode ser DLL só de recursos/dados)"
else:
    conclusao = "PE com ponto de entrada; execução no Windows ainda não verificada"
print(f"Conclusão: {conclusao}")
sys.exit(1 if problems else 0)
