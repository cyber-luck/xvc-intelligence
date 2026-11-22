"""Parser PE/COFF somente leitura (substitui e amplia pe_check.py).

Interpreta apenas o que esta efetivamente presente e dentro dos limites do
buffer: cabecalhos, secoes, data directories, imports, exports, recursos,
debug (CodeView/RSDS), security (WIN_CERTIFICATE) e tabela de simbolos COFF.
Nada e inferido a partir de nomes de arquivo: sem MZ/PE valido nao ha PE.

Referencia: especificacao Microsoft PE/COFF (winnt.h).
"""
from __future__ import annotations

import struct
import uuid
from dataclasses import asdict, dataclass, field

from ..core.result import BAD_MAGIC, INVALID_VALUE, OUT_OF_BOUNDS, TRUNCATED, Ok, Result, err

SUBSYSTEMS = {
    0: "UNKNOWN", 1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 5: "OS2_CUI", 7: "POSIX_CUI",
    8: "NATIVE_WINDOWS", 9: "WINDOWS_CE_GUI", 10: "EFI_APPLICATION", 11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER", 13: "EFI_ROM", 14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION", 17: "XBOX_CODE_CATALOG",
}
PE32 = 0x10B
PE32_PLUS = 0x20B
MACHINES = {
    0x014C: ("I386", PE32), 0x01C0: ("ARM", PE32), 0x01C4: ("ARMNT", PE32),
    0x8664: ("AMD64", PE32_PLUS), 0xAA64: ("ARM64", PE32_PLUS), 0xA641: ("ARM64EC", PE32_PLUS),
    0xA64E: ("ARM64X", PE32_PLUS), 0x0200: ("IA64", PE32_PLUS),
}
DIRECTORY_NAMES = ["EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG",
                   "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT",
                   "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED"]
DEBUG_TYPES = {0: "UNKNOWN", 1: "COFF", 2: "CODEVIEW", 3: "FPO", 4: "MISC", 5: "EXCEPTION", 6: "FIXUP",
               7: "OMAP_TO_SRC", 8: "OMAP_FROM_SRC", 9: "BORLAND", 10: "RESERVED10", 11: "CLSID",
               12: "VC_FEATURE", 13: "POGO", 14: "ILTCG", 15: "MPX", 16: "REPRO", 20: "EX_DLLCHARACTERISTICS"}
RESOURCE_TYPES = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING", 7: "FONTDIR",
                  8: "FONT", 9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR",
                  14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE", 19: "PLUGPLAY", 20: "VXD",
                  21: "ANICURSOR", 22: "ANIICON", 23: "HTML", 24: "MANIFEST"}
WIN_CERT_TYPES = {1: "X509", 2: "PKCS_SIGNED_DATA", 3: "RESERVED_1", 4: "TS_STACK_SIGNED"}
OID_SIGNED_DATA = bytes.fromhex("2a864886f70d010702")      # 1.2.840.113549.1.7.2
OID_CTL = bytes.fromhex("2b0601040182370a01")              # 1.3.6.1.4.1.311.10.1 (szOID_CTL)

OPT_SIZE_OF_CODE = 4
OPT_ENTRY_POINT = 16
OPT_SUBSYSTEM = 68
OPT_MIN_SIZE = OPT_SUBSYSTEM + 2
SECTION_HEADER_SIZE = 40
FILE_ALIGNMENT_MIN = 0x200
FILE_ALIGNMENT_MAX = 0x10000
ARCH_PAGE_SIZE = 0x1000

# travas de seguranca contra laços em entradas hostis (relatadas quando atingidas)
MAX_IMPORT_DLLS = 4096
MAX_THUNKS = 65536
MAX_EXPORTS = 65536
MAX_RESOURCES = 20000
MAX_DEBUG = 64
MAX_NAME = 512


@dataclass
class Section:
    index: int
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_pointer: int
    characteristics: int


@dataclass
class DataDirectory:
    index: int
    name: str
    rva: int
    size: int


@dataclass
class ImportedDll:
    dll: str
    functions: list[str]
    truncated: bool = False


@dataclass
class ExportInfo:
    dll_name: str
    ordinal_base: int
    number_of_functions: int
    number_of_names: int
    names: list[tuple[str, int, int, str | None]]   # (nome, ordinal, rva, forwarder)


@dataclass
class DebugEntry:
    type: int
    type_name: str
    size: int
    rva: int
    pointer: int
    codeview: dict | None = None


@dataclass
class SecurityInfo:
    file_offset: int
    size: int
    length: int | None
    revision: int | None
    cert_type: int | None
    cert_type_name: str | None
    has_pkcs7_signed_data_oid: bool
    has_ctl_oid: bool
    problem: str | None = None


@dataclass
class PEInfo:
    size: int
    e_lfanew: int
    machine: int
    machine_name: str
    number_of_sections: int
    time_date_stamp: int
    pointer_to_symbol_table: int
    number_of_symbols: int
    size_of_optional_header: int
    characteristics: int
    magic: int | None = None
    optional: dict = field(default_factory=dict)
    subsystem: int | None = None
    subsystem_name: str | None = None
    directories: list[DataDirectory] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)
    imports: list[ImportedDll] | None = None
    delay_imports: list[ImportedDll] | None = None
    exports: ExportInfo | None = None
    resources: dict | None = None
    debug: list[DebugEntry] | None = None
    security: SecurityInfo | None = None
    coff_symbols: dict | None = None
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def is_pe32_plus(self) -> bool:
        return self.magic == PE32_PLUS

    def directory(self, name: str) -> DataDirectory | None:
        return next((d for d in self.directories if d.name == name), None)

    def conclusion(self) -> str:
        if self.problems:
            return "estrutura PE inconsistente"
        ep = self.optional.get("AddressOfEntryPoint", 0)
        if self.subsystem == 17:
            c = "conteiner de catalogo de codigo Xbox"
            if ep == 0 and self.optional.get("SizeOfCode", 0) == 0:
                c += "; sem codigo nem ponto de entrada, nao e um programa"
            return c
        if ep == 0:
            return "sem ponto de entrada (pode ser DLL so de recursos/dados)"
        return "PE com ponto de entrada; execucao nao verificada"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["conclusion"] = self.conclusion()
        return d


class _Buf:
    def __init__(self, d: bytes):
        self.d = d

    def has(self, off: int, n: int) -> bool:
        return 0 <= off and off + n <= len(self.d)

    def u16(self, o: int) -> int:
        return struct.unpack_from("<H", self.d, o)[0]

    def u32(self, o: int) -> int:
        return struct.unpack_from("<I", self.d, o)[0]

    def u64(self, o: int) -> int:
        return struct.unpack_from("<Q", self.d, o)[0]

    def cstr(self, o: int, limit: int = MAX_NAME) -> str | None:
        if not self.has(o, 1):
            return None
        end = self.d.find(b"\0", o, min(len(self.d), o + limit))
        if end < 0:
            return None
        return self.d[o:end].decode("latin-1")


def _power_of_two(v: int) -> bool:
    return bool(v) and not v & (v - 1)


def rva_to_offset(pe: PEInfo, rva: int) -> int | None:
    """Converte RVA em offset de arquivo usando a tabela de secoes; None se nao mapear."""
    soh = pe.optional.get("SizeOfHeaders", 0)
    if rva < soh:
        return rva
    for s in pe.sections:
        span = max(s.virtual_size, s.raw_size)
        if s.virtual_address <= rva < s.virtual_address + span:
            delta = rva - s.virtual_address
            if delta >= s.raw_size:
                return None          # cai em parte nao inicializada (sem bytes no arquivo)
            return s.raw_pointer + delta
    return None


def parse_pe(data: bytes, deep: bool = True) -> Result[PEInfo]:
    b = _Buf(data)
    if len(data) < 0x40:
        return err(TRUNCATED, f"{len(data)} bytes: menor que o cabecalho DOS (0x40)", 0, "PE")
    if data[:2] != b"MZ":
        return err(BAD_MAGIC, "sem cabecalho MZ", 0, "PE")
    lfanew = b.u32(0x3C)
    if lfanew + 24 > len(data):
        return err(OUT_OF_BOUNDS, f"e_lfanew 0x{lfanew:X} + 24 fora do arquivo (0x{len(data):X})", 0x3C, "PE")
    if data[lfanew:lfanew + 4] != b"PE\0\0":
        return err(BAD_MAGIC, f"sem PE\\0\\0 em e_lfanew 0x{lfanew:X}", lfanew, "PE")
    machine, nsec, tds, psym, nsym, opt_size, chars = struct.unpack_from("<HHIIIHH", data, lfanew + 4)
    mname, expected_magic = MACHINES.get(machine, ("desconhecida", None))
    pe = PEInfo(len(data), lfanew, machine, mname, nsec, tds, psym, nsym, opt_size, chars)
    opt = lfanew + 24
    if opt_size < OPT_MIN_SIZE:
        return err(TRUNCATED, f"optional header ausente ou curto (SizeOfOptionalHeader 0x{opt_size:X})", lfanew + 20, "PE")
    if opt + opt_size > len(data):
        return err(TRUNCATED, f"optional header ultrapassa o arquivo (0x{opt:X}+0x{opt_size:X} > 0x{len(data):X})",
                   opt, "PE")
    magic = b.u16(opt)
    if magic not in (PE32, PE32_PLUS):
        return err(INVALID_VALUE, f"magic do optional header desconhecido 0x{magic:04X}", opt, "PE")
    pe.magic = magic
    plus = magic == PE32_PLUS
    o = {}
    o["MajorLinkerVersion"], o["MinorLinkerVersion"] = data[opt + 2], data[opt + 3]
    o["SizeOfCode"], o["SizeOfInitializedData"], o["SizeOfUninitializedData"] = struct.unpack_from("<III", data, opt + 4)
    o["AddressOfEntryPoint"], o["BaseOfCode"] = struct.unpack_from("<II", data, opt + 16)
    if plus:
        o["ImageBase"] = b.u64(opt + 24)
    else:
        o["BaseOfData"], o["ImageBase"] = struct.unpack_from("<II", data, opt + 24)
    (o["SectionAlignment"], o["FileAlignment"], o["MajorOperatingSystemVersion"], o["MinorOperatingSystemVersion"],
     o["MajorImageVersion"], o["MinorImageVersion"], o["MajorSubsystemVersion"], o["MinorSubsystemVersion"],
     o["Win32VersionValue"], o["SizeOfImage"], o["SizeOfHeaders"], o["CheckSum"], o["Subsystem"],
     o["DllCharacteristics"]) = struct.unpack_from("<IIHHHHHHIIIIHH", data, opt + 32)
    rest = opt + 72
    fmt = "<QQQQII" if plus else "<IIIIII"
    need_len = struct.calcsize(fmt)
    if rest + need_len <= opt + opt_size:
        (o["SizeOfStackReserve"], o["SizeOfStackCommit"], o["SizeOfHeapReserve"], o["SizeOfHeapCommit"],
         o["LoaderFlags"], o["NumberOfRvaAndSizes"]) = struct.unpack_from(fmt, data, rest)
        dd = rest + need_len
        n_dirs = o["NumberOfRvaAndSizes"]
        if n_dirs > 16:
            pe.notes.append(f"NumberOfRvaAndSizes={n_dirs} > 16; so 16 interpretados")
        for i in range(min(n_dirs, 16)):
            if dd + 8 * (i + 1) > opt + opt_size:
                pe.problems.append(f"data directory {i} fora do optional header")
                break
            rva, size = struct.unpack_from("<II", data, dd + 8 * i)
            pe.directories.append(DataDirectory(i, DIRECTORY_NAMES[i], rva, size))
        # bytes nos slots alem de NumberOfRvaAndSizes: registrados, nao interpretados
        extra = []
        for i in range(min(n_dirs, 16), 16):
            if dd + 8 * (i + 1) > opt + opt_size:
                break
            rva, size = struct.unpack_from("<II", data, dd + 8 * i)
            if rva or size:
                extra.append(f"{DIRECTORY_NAMES[i]}=0x{rva:08X}/0x{size:08X}")
        if extra:
            pe.notes.append("slots de diretorio alem de NumberOfRvaAndSizes com bytes nao-zero "
                            f"(nao interpretados pelo loader): {', '.join(extra)}")
    else:
        pe.notes.append("optional header sem campos de stack/heap/diretorios")
    pe.optional = o
    pe.subsystem = o["Subsystem"]
    pe.subsystem_name = SUBSYSTEMS.get(o["Subsystem"], "desconhecido")

    # Machine x magic
    if expected_magic is None:
        pe.notes.append(f"Machine 0x{machine:04X} fora da tabela; combinacao com o magic nao verificada")
    elif magic != expected_magic:
        pe.problems.append(f"Machine {mname} exige magic 0x{expected_magic:X}, mas o optional header tem 0x{magic:X}")

    # secoes
    table = opt + opt_size
    table_end = table + nsec * SECTION_HEADER_SIZE
    fa, sa, soh = o["FileAlignment"], o["SectionAlignment"], o["SizeOfHeaders"]
    if table_end > len(data):
        pe.problems.append(f"tabela de secoes ultrapassa o arquivo (0x{table_end:X} > 0x{len(data):X})")
    else:
        if table_end > soh:
            pe.problems.append(f"tabela de secoes termina em 0x{table_end:X}, depois de SizeOfHeaders 0x{soh:X}")
        cfa, csa = _power_of_two(fa), _power_of_two(sa)
        if not cfa:
            pe.problems.append(f"FileAlignment 0x{fa:X} nao e potencia de 2")
        if not csa:
            pe.problems.append(f"SectionAlignment 0x{sa:X} nao e potencia de 2")
        if cfa and csa:
            if sa < ARCH_PAGE_SIZE:
                if fa != sa:
                    pe.problems.append(f"SectionAlignment 0x{sa:X} e menor que a pagina (0x{ARCH_PAGE_SIZE:X}), "
                                       f"entao FileAlignment deveria ser igual a ele, mas e 0x{fa:X}")
            elif not FILE_ALIGNMENT_MIN <= fa <= FILE_ALIGNMENT_MAX:
                pe.problems.append(f"FileAlignment 0x{fa:X} fora da faixa da especificacao "
                                   f"(0x{FILE_ALIGNMENT_MIN:X} a 0x{FILE_ALIGNMENT_MAX:X})")
        raw_ranges, virt_ranges = [], []
        for i in range(nsec):
            s = table + i * SECTION_HEADER_SIZE
            name = data[s:s + 8].rstrip(b"\0").decode("latin-1") or f"#{i}"
            vsize, va, rsize, rptr = struct.unpack_from("<IIII", data, s + 8)
            flags = b.u32(s + 36)
            pe.sections.append(Section(i, name, vsize, va, rsize, rptr, flags))
            if rsize:
                if rptr + rsize > len(data):
                    pe.problems.append(f"secao {name}: dados brutos 0x{rptr:X}+0x{rsize:X} ultrapassam o arquivo (0x{len(data):X})")
                if cfa and rptr % fa:
                    pe.problems.append(f"secao {name}: PointerToRawData 0x{rptr:X} nao alinhado a 0x{fa:X}")
                if rptr < soh:
                    pe.problems.append(f"secao {name}: dados brutos comecam dentro dos cabecalhos (0x{rptr:X} < 0x{soh:X})")
                raw_ranges.append((rptr, rptr + rsize, name))
            if csa and va % sa:
                pe.problems.append(f"secao {name}: VirtualAddress 0x{va:X} nao alinhado a 0x{sa:X}")
            virt_ranges.append((va, va + (vsize or rsize), name))
        raw_ranges.sort()
        for (a0, a1, an), (b0, b1, bn) in zip(raw_ranges, raw_ranges[1:]):
            if b0 < a1:
                pe.problems.append(f"secoes {an} e {bn} se sobrepoem no arquivo (0x{b0:X} < 0x{a1:X})")
        for (a0, a1, an), (b0, b1, bn) in zip(virt_ranges, virt_ranges[1:]):
            if b0 < a1:
                pe.problems.append(f"secoes {an} e {bn} fora de ordem ou sobrepostas na memoria (0x{b0:X} < 0x{a1:X})")

    if deep:
        _parse_imports(pe, b)
        _parse_delay_imports(pe, b)
        _parse_exports(pe, b)
        _parse_resources(pe, b)
        _parse_debug(pe, b)
        _parse_security(pe, b)
        _parse_coff_symbols(pe, b)
    return Ok(pe)


def _dir(pe: PEInfo, name: str) -> DataDirectory | None:
    d = pe.directory(name)
    return d if d and d.rva and d.size else None


def _thunks(pe: PEInfo, b: _Buf, rva: int, plus: bool) -> tuple[list[str], bool]:
    out: list[str] = []
    off = rva_to_offset(pe, rva)
    if off is None:
        return out, True
    step = 8 if plus else 4
    flag = 1 << 63 if plus else 1 << 31
    for _ in range(MAX_THUNKS):
        if not b.has(off, step):
            return out, True
        v = b.u64(off) if plus else b.u32(off)
        if v == 0:
            return out, False
        if v & flag:
            out.append(f"#ordinal {v & 0xFFFF}")
        else:
            no = rva_to_offset(pe, v & 0x7FFFFFFF)
            name = b.cstr(no + 2) if no is not None else None
            out.append(name if name is not None else f"<nome invalido rva 0x{v & 0x7FFFFFFF:X}>")
        off += step
    pe.notes.append("lista de thunks atingiu a trava MAX_THUNKS")
    return out, True


def _parse_imports(pe: PEInfo, b: _Buf) -> None:
    d = _dir(pe, "IMPORT")
    if not d:
        return
    off = rva_to_offset(pe, d.rva)
    if off is None:
        pe.problems.append(f"IMPORT rva 0x{d.rva:X} nao mapeia para o arquivo")
        return
    pe.imports = []
    for i in range(MAX_IMPORT_DLLS):
        e = off + 20 * i
        if not b.has(e, 20):
            pe.problems.append("tabela de imports truncada")
            return
        oft, tds, fwd, name_rva, ft = struct.unpack_from("<IIIII", b.d, e)
        if not any((oft, tds, fwd, name_rva, ft)):
            return
        no = rva_to_offset(pe, name_rva)
        dll = (b.cstr(no) if no is not None else None) or f"<nome invalido rva 0x{name_rva:X}>"
        funcs, trunc = _thunks(pe, b, oft or ft, pe.is_pe32_plus)
        pe.imports.append(ImportedDll(dll, funcs, trunc))
    pe.notes.append("imports atingiram a trava MAX_IMPORT_DLLS")


def _parse_delay_imports(pe: PEInfo, b: _Buf) -> None:
    d = _dir(pe, "DELAY_IMPORT")
    if not d:
        return
    off = rva_to_offset(pe, d.rva)
    if off is None:
        return
    pe.delay_imports = []
    for i in range(MAX_IMPORT_DLLS):
        e = off + 32 * i
        if not b.has(e, 32):
            return
        attrs, name_rva, _hmod, _iat, int_rva = struct.unpack_from("<IIIII", b.d, e)
        if not name_rva:
            return
        no = rva_to_offset(pe, name_rva)
        dll = (b.cstr(no) if no is not None else None) or f"<nome invalido rva 0x{name_rva:X}>"
        funcs, trunc = _thunks(pe, b, int_rva, pe.is_pe32_plus) if int_rva else ([], True)
        pe.delay_imports.append(ImportedDll(dll, funcs, trunc))


def _parse_exports(pe: PEInfo, b: _Buf) -> None:
    d = _dir(pe, "EXPORT")
    if not d:
        return
    off = rva_to_offset(pe, d.rva)
    if off is None or not b.has(off, 40):
        pe.problems.append("diretorio de exports fora do arquivo")
        return
    (_c, _t, _maj, _min, name_rva, base, nfunc, nnames, funcs_rva, names_rva, ords_rva) = struct.unpack_from(
        "<IIHHIIIIIII", b.d, off)
    no = rva_to_offset(pe, name_rva)
    dll = (b.cstr(no) if no is not None else None) or ""
    names = []
    fo, nmo, oo = rva_to_offset(pe, funcs_rva), rva_to_offset(pe, names_rva), rva_to_offset(pe, ords_rva)
    if nnames and None not in (fo, nmo, oo):
        for i in range(min(nnames, MAX_EXPORTS)):
            if not (b.has(nmo + 4 * i, 4) and b.has(oo + 2 * i, 2)):
                pe.problems.append("tabela de nomes de export truncada")
                break
            nrva = b.u32(nmo + 4 * i)
            idx = b.u16(oo + 2 * i)
            no2 = rva_to_offset(pe, nrva)
            name = (b.cstr(no2) if no2 is not None else None) or f"<nome invalido rva 0x{nrva:X}>"
            frva = b.u32(fo + 4 * idx) if idx < nfunc and b.has(fo + 4 * idx, 4) else 0
            fwd = None
            if d.rva <= frva < d.rva + d.size:
                fo2 = rva_to_offset(pe, frva)
                fwd = b.cstr(fo2) if fo2 is not None else None
            names.append((name, base + idx, frva, fwd))
    pe.exports = ExportInfo(dll, base, nfunc, nnames, names)


def _parse_resources(pe: PEInfo, b: _Buf) -> None:
    d = _dir(pe, "RESOURCE")
    if not d:
        return
    root = rva_to_offset(pe, d.rva)
    if root is None:
        pe.problems.append("diretorio de recursos fora do arquivo")
        return
    counts: dict[str, int] = {}
    leaves = [0]
    visited: set[int] = set()

    def walk(off: int, depth: int, type_label: str | None) -> None:
        if off in visited or depth > 3 or leaves[0] >= MAX_RESOURCES or not b.has(off, 16):
            return
        visited.add(off)
        n_named, n_id = b.u16(off + 12), b.u16(off + 14)
        for i in range(n_named + n_id):
            e = off + 16 + 8 * i
            if not b.has(e, 8):
                return
            name_field, target = b.u32(e), b.u32(e + 4)
            label = type_label
            if depth == 0:
                if name_field & 0x80000000:
                    so = root + (name_field & 0x7FFFFFFF)
                    if b.has(so, 2):
                        ln = b.u16(so)
                        label = b.d[so + 2:so + 2 + 2 * ln].decode("utf-16-le", "replace")
                    else:
                        label = "<nome invalido>"
                else:
                    label = RESOURCE_TYPES.get(name_field, f"#{name_field}")
            if target & 0x80000000:
                walk(root + (target & 0x7FFFFFFF), depth + 1, label)
            else:
                leaves[0] += 1
                counts[label or "?"] = counts.get(label or "?", 0) + 1
    walk(root, 0, None)
    pe.resources = {"leaf_count": leaves[0], "by_type": counts}


def _parse_debug(pe: PEInfo, b: _Buf) -> None:
    d = _dir(pe, "DEBUG")
    if not d:
        return
    off = rva_to_offset(pe, d.rva)
    if off is None:
        pe.problems.append("diretorio de debug fora do arquivo")
        return
    pe.debug = []
    for i in range(min(d.size // 28, MAX_DEBUG)):
        e = off + 28 * i
        if not b.has(e, 28):
            pe.problems.append("diretorio de debug truncado")
            return
        _c, _t, _maj, _min, typ, size, rva, ptr = struct.unpack_from("<IIHHIIII", b.d, e)
        de = DebugEntry(typ, DEBUG_TYPES.get(typ, f"#{typ}"), size, rva, ptr)
        if typ == 2 and b.has(ptr, 24) and b.d[ptr:ptr + 4] == b"RSDS":
            guid = uuid.UUID(bytes_le=bytes(b.d[ptr + 4:ptr + 20]))
            age = b.u32(ptr + 20)
            path = b.cstr(ptr + 24, min(MAX_NAME, max(size - 24, 0) + 1)) or ""
            de.codeview = {"signature": "RSDS", "guid": str(guid), "age": age, "pdb_path": path,
                           "symbol_server_key": f"{guid.hex.upper()}{age:X}"}
        elif typ == 2 and b.has(ptr, 4):
            de.codeview = {"signature": b.d[ptr:ptr + 4].decode("latin-1")}
        pe.debug.append(de)


def _parse_security(pe: PEInfo, b: _Buf) -> None:
    d = pe.directory("SECURITY")
    if not d or not (d.rva or d.size):
        return
    # o campo "rva" do diretorio SECURITY e offset de arquivo, nao RVA
    if d.rva == 0xFFFFFFFF or d.size == 0xFFFFFFFF or not b.has(d.rva, 8) or d.rva + d.size > len(b.d):
        pe.security = SecurityInfo(d.rva, d.size, None, None, None, None, False, False,
                                   "diretorio SECURITY aponta para fora do arquivo")
        return
    length, rev, ctype = struct.unpack_from("<IHH", b.d, d.rva)
    blob = b.d[d.rva + 8:d.rva + min(length, d.size)]
    pe.security = SecurityInfo(d.rva, d.size, length, rev, ctype, WIN_CERT_TYPES.get(ctype),
                               OID_SIGNED_DATA in blob, OID_CTL in blob)


def _parse_coff_symbols(pe: PEInfo, b: _Buf) -> None:
    if not pe.pointer_to_symbol_table or not pe.number_of_symbols:
        return
    p, n = pe.pointer_to_symbol_table, pe.number_of_symbols
    end = p + 18 * n
    if end + 4 > len(b.d):
        pe.coff_symbols = {"pointer": p, "count": n, "problem": "tabela de simbolos COFF fora do arquivo"}
        return
    strtab_size = b.u32(end)
    pe.coff_symbols = {"pointer": p, "count": n, "string_table_size": strtab_size}


def legacy_pe_header(d: bytes) -> dict | None:
    """Mesmo dicionario do pe_header() do xvc_probe.py original (schema 1 do relatorio)."""
    if len(d) < 0x40 or d[:2] != b"MZ":
        return None
    lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    info = {"e_lfanew": f"0x{lfanew:X}", "pe_signature": False}
    if lfanew + 24 > len(d):
        info["problem"] = "e_lfanew fora da amostra"
        return info
    if d[lfanew:lfanew + 4] != b"PE\0\0":
        info["problem"] = "sem PE\\0\\0 em e_lfanew"
        return info
    machine, nsec, _, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", d, lfanew + 4)
    info.update(pe_signature=True, machine=f"0x{machine:04X}", number_of_sections=nsec,
                characteristics=f"0x{chars:04X}", size_of_optional_header=opt_size)
    opt = lfanew + 24
    if opt + 72 <= len(d) and opt_size >= 72:
        magic = struct.unpack_from("<H", d, opt)[0]
        if magic in (0x10B, 0x20B):
            sub = struct.unpack_from("<H", d, opt + 68)[0]
            legacy_names = {1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 10: "EFI_APPLICATION",
                            14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION", 17: "XBOX_CODE_CATALOG"}
            info.update(optional_magic=f"0x{magic:X}",
                        size_of_code=struct.unpack_from("<I", d, opt + 4)[0],
                        entry_point_rva=f"0x{struct.unpack_from('<I', d, opt + 16)[0]:X}",
                        subsystem=sub, subsystem_name=legacy_names.get(sub))
        else:
            info["problem"] = f"magic do optional header desconhecido 0x{magic:X}"
    return info


def report_lines(pe: PEInfo) -> list[str]:
    """Texto em portugues no estilo do pe_check.py original, ampliado."""
    o = pe.optional
    L = ["Formato PE identificado",
         f"Arquitetura: 0x{pe.machine:04X} ({pe.machine_name})",
         f"Secoes: {pe.number_of_sections}",
         f"Caracteristicas: 0x{pe.characteristics:04X}",
         f"Tamanho: {pe.size:,} bytes",
         f"Optional header: {'PE32+' if pe.is_pe32_plus else 'PE32'} (0x{pe.magic:X}), 0x{pe.size_of_optional_header:X} bytes",
         f"SizeOfCode: 0x{o.get('SizeOfCode', 0):X}",
         f"Entry point (RVA): 0x{o.get('AddressOfEntryPoint', 0):X}",
         f"Alinhamento: secoes 0x{o.get('SectionAlignment', 0):X}, arquivo 0x{o.get('FileAlignment', 0):X}; "
         f"SizeOfHeaders 0x{o.get('SizeOfHeaders', 0):X}",
         f"Subsystem: {pe.subsystem} ({pe.subsystem_name})",
         f"NumberOfRvaAndSizes: {o.get('NumberOfRvaAndSizes', 'ausente')}"]
    for s in pe.sections:
        L.append(f"  {s.name:<8} VA 0x{s.virtual_address:08X} VSize 0x{s.virtual_size:08X}  "
                 f"Raw 0x{s.raw_pointer:08X} +0x{s.raw_size:08X}  Flags 0x{s.characteristics:08X}")
    for d in pe.directories:
        if d.rva or d.size:
            L.append(f"  diretorio {d.name:<14} 0x{d.rva:08X} +0x{d.size:X}")
    if pe.imports is not None:
        L.append(f"Imports: {len(pe.imports)} DLLs, {sum(len(i.functions) for i in pe.imports)} funcoes")
        for imp in pe.imports[:50]:
            L.append(f"  {imp.dll}: {len(imp.functions)}")
    if pe.delay_imports:
        L.append(f"Delay imports: {len(pe.delay_imports)} DLLs")
    if pe.exports is not None:
        L.append(f"Exports: {pe.exports.dll_name!r} {pe.exports.number_of_names} nomes / {pe.exports.number_of_functions} funcoes")
    if pe.resources is not None:
        L.append(f"Recursos: {pe.resources['leaf_count']} folhas {pe.resources['by_type']}")
    if pe.debug is not None:
        for de in pe.debug:
            cv = f" {de.codeview}" if de.codeview else ""
            L.append(f"Debug: {de.type_name} tamanho 0x{de.size:X}{cv}")
    if pe.security is not None:
        s = pe.security
        L.append(f"Security: offset 0x{s.file_offset:X} +0x{s.size:X} tipo {s.cert_type_name} "
                 f"PKCS7={s.has_pkcs7_signed_data_oid}" + (f" ({s.problem})" if s.problem else ""))
    if pe.coff_symbols is not None:
        L.append(f"Simbolos COFF: {pe.coff_symbols}")
    for n in pe.notes:
        L.append(f"Aviso: {n}")
    for p in pe.problems:
        L.append(f"Problema: {p}")
    L.append(f"Conclusao: {pe.conclusion()}")
    return L
