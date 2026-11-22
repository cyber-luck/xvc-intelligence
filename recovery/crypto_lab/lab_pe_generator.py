"""FASE 4 - gerador de um executavel PE32+ x64 SINTETICO para o laboratorio.

Nada aqui vem de jogo comercial: todos os bytes sao produzidos por este modulo
(codigo x64 minimo escrito a mao, tabelas montadas aqui, dados de um gerador
deterministico rotulado). O binario nunca e executado pelo laboratorio.

Conteudo:
  * DOS MZ + stub, NT "PE\\0\\0", Machine 0x8664, Optional Header Magic 0x20B;
  * .text  - ponto de entrada (OutputDebugStringA, GetTickCount64, ExitProcess)
             seguido de funcoes-folha sinteticas (mov eax, imm32 ; ret);
  * .rdata - IAT/ILT/descritores de import (KERNEL32.dll, USER32.dll) e strings de teste;
  * .data  - identificador exclusivo do laboratorio + dados aleatorios controlados;
  * .rsrc  - RT_RCDATA #101 e RT_MANIFEST #1 (recursos opcionais);
  * checksum PE calculado.

`variant="B"` gera um segundo build com o MESMO tamanho e layout e diferencas
localizadas (strings, parte das funcoes, duas paginas de .data, TimeDateStamp).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

import lab_common  # noqa: F401
from lab_common import LAB_MARKER_STR, Rng, sha256_hex

IMAGE_BASE = 0x140000000
SECT_ALIGN = 0x1000
FILE_ALIGN = 0x200
E_LFANEW = 0x80
HEADERS_SIZE = 0x400

IMPORTS = {
    "KERNEL32.dll": ["ExitProcess", "GetTickCount64", "OutputDebugStringA", "GetModuleHandleW"],
    "USER32.dll": ["MessageBoxW"],
}
RT_RCDATA, RT_MANIFEST = 10, 24

TEXT_SIZE = 0x4000
DATA_SIZE = 0xB0000                 # ~181 paginas por PE: arvores de 2 niveis nos dois conteineres
B_CHANGED_DATA_PAGES = (3, 17)      # paginas de .data alteradas no build B
B_CHANGED_FUNCS = range(200, 260)   # funcoes-folha com imm32 diferente no build B


def align(v: int, a: int) -> int:
    return (v + a - 1) // a * a


@dataclass
class PeBuild:
    data: bytes
    info: dict = field(default_factory=dict)


def _strings(lab_id: str, variant: str) -> list[str]:
    return [
        f"{LAB_MARKER_STR}::PROJECT_ALPHA::CRYPTO_LAB",
        f"LABID-{lab_id}",
        f"BUILD_{variant}",
        f"crypto_lab synthetic executable build {variant} - never executed",
        "XVD/XVC AES-XTS laboratory test string 0001",
        "XVD/XVC AES-XTS laboratory test string 0002",
        "Este executavel e sintetico e foi gerado pelo lab_pe_generator.py",
    ]


def _dos_header() -> bytes:
    h = bytearray(E_LFANEW)
    h[0:2] = b"MZ"
    struct.pack_into("<HHHHHHHHHHHHHH", h, 2, 0x90, 3, 0, 4, 0, 0xFFFF, 0, 0xB8, 0, 0, 0, 0x40, 0, 0)
    struct.pack_into("<I", h, 0x3C, E_LFANEW)
    stub = bytes.fromhex("0e1fba0e00b409cd21b8014ccd21") + b"This program cannot be run in DOS mode.\r\r\n$"
    h[0x40:0x40 + len(stub)] = stub
    return bytes(h)


def _resources(rva: int, lab_id: str, variant: str) -> bytes:
    """Arvore de recursos: raiz -> tipo -> nome -> idioma -> data entry."""
    rcdata = f"{LAB_MARKER_STR} resource payload; LABID-{lab_id}; BUILD_{variant}\0".encode("utf-16-le")
    manifest = (f'<?xml version="1.0" encoding="UTF-8"?><assembly xmlns="urn:schemas-microsoft-com:asm.v1" '
                f'manifestVersion="1.0"><description>{LAB_MARKER_STR} crypto_lab {variant}</description>'
                f'</assembly>').encode()

    def directory(n_id: int) -> bytes:
        return struct.pack("<IIHHHH", 0, 0, 0, 0, 0, n_id)

    # leiaute fixo (3 niveis de diretorio, como o Windows espera):
    #   raiz/tipo (16+2*8) | nome RT_RCDATA (16+8) | nome RT_MANIFEST (16+8) |
    #   idioma #101 (16+8) | idioma #1 (16+8) | 2 data entries (16 cada) | blobs
    hi = 0x80000000
    off_t10 = 16 + 2 * 8
    off_t24 = off_t10 + 24
    off_l101 = off_t24 + 24
    off_l1 = off_l101 + 24
    off_de1 = off_l1 + 24
    off_de2 = off_de1 + 16
    off_blob1 = align(off_de2 + 16, 8)
    off_blob2 = align(off_blob1 + len(rcdata), 8)
    b = bytearray()
    b += directory(2) + struct.pack("<II", RT_RCDATA, hi | off_t10) + struct.pack("<II", RT_MANIFEST, hi | off_t24)
    b += directory(1) + struct.pack("<II", 101, hi | off_l101)       # nome -> diretorio de idioma
    b += directory(1) + struct.pack("<II", 1, hi | off_l1)
    b += directory(1) + struct.pack("<II", 0x409, off_de1)           # idioma -> data entry (sem bit alto)
    b += directory(1) + struct.pack("<II", 0x409, off_de2)
    assert len(b) == off_de1
    b += struct.pack("<IIII", rva + off_blob1, len(rcdata), 0, 0)
    b += struct.pack("<IIII", rva + off_blob2, len(manifest), 0, 0)
    b = b.ljust(off_blob1, b"\0") + rcdata
    b = b.ljust(off_blob2, b"\0") + manifest
    return bytes(b)


def _checksum(data: bytes, cks_off: int) -> int:
    s = 0
    n = len(data)
    padded = data + (b"\0" if n % 2 else b"")
    for i in range(0, len(padded), 2):
        if i == cks_off or i == cks_off + 2:
            continue
        s += padded[i] | (padded[i + 1] << 8)
        s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (s + n) & 0xFFFFFFFF


def build_pe(rng: Rng, lab_id: str, variant: str = "A") -> PeBuild:
    if variant not in ("A", "B"):
        raise ValueError("variant deve ser A ou B")
    strings = _strings(lab_id, variant)
    names = [".text", ".rdata", ".data", ".rsrc"]
    rva = {".text": 0x1000}

    # ---------------- .rdata (precisa do RVA para os ponteiros)
    rva[".rdata"] = rva[".text"] + align(TEXT_SIZE, SECT_ALIGN)
    rd_base = rva[".rdata"]
    dlls = list(IMPORTS)
    iat_layout = []                 # (dll, [rva da entrada IAT por funcao])
    off = 0
    iat_start = off
    for dll in dlls:
        entries = []
        for _ in IMPORTS[dll]:
            entries.append(rd_base + off)
            off += 8
        off += 8                     # terminador
        iat_layout.append((dll, entries))
    iat_size = off - iat_start
    desc_off = align(off, 16)
    off = desc_off + 20 * (len(dlls) + 1)
    ilt_off = {}
    for dll in dlls:
        ilt_off[dll] = off
        off += 8 * (len(IMPORTS[dll]) + 1)
    hn_off = {}
    hint_names = bytearray()
    hn_base = off
    for dll in dlls:
        for i, fn in enumerate(IMPORTS[dll]):
            hn_off[(dll, fn)] = hn_base + len(hint_names)
            hint_names += struct.pack("<H", i) + fn.encode() + b"\0"
            if len(hint_names) % 2:
                hint_names += b"\0"
    off = hn_base + len(hint_names)
    name_off = {}
    names_blob = bytearray()
    for dll in dlls:
        name_off[dll] = off + len(names_blob)
        names_blob += dll.encode() + b"\0"
    off += len(names_blob)
    str_off = {}
    str_blob = bytearray()
    off = align(off, 16)
    for s in strings:
        str_off[s] = off + len(str_blob)
        str_blob += s.encode() + b"\0"
    rdata = bytearray(off + len(str_blob))
    for dll, entries in iat_layout:
        for fn, ent_rva in zip(IMPORTS[dll], entries):
            thunk = rd_base + hn_off[(dll, fn)]
            struct.pack_into("<Q", rdata, ent_rva - rd_base, thunk)
            j = IMPORTS[dll].index(fn)
            struct.pack_into("<Q", rdata, ilt_off[dll] + 8 * j, thunk)
    for k, (dll, entries) in enumerate(iat_layout):
        struct.pack_into("<IIIII", rdata, desc_off + 20 * k, rd_base + ilt_off[dll], 0, 0,
                         rd_base + name_off[dll], entries[0])
    rdata[hn_base:hn_base + len(hint_names)] = hint_names
    rdata[hn_base + len(hint_names):hn_base + len(hint_names) + len(names_blob)] = names_blob
    rdata[off:off + len(str_blob)] = str_blob
    rdata = bytes(rdata)
    iat_rva = {(dll, fn): ent for dll, entries in iat_layout for fn, ent in zip(IMPORTS[dll], entries)}

    # ---------------- .text
    text = bytearray()
    ep_rva = rva[".text"]

    def rip_rel(target_rva: int, instr_end_rva: int) -> bytes:
        return struct.pack("<i", target_rva - instr_end_rva)

    def emit(b: bytes) -> None:
        text.extend(b)

    emit(bytes.fromhex("4883ec28"))                                         # sub rsp, 28h
    msg = strings[3]
    emit(bytes.fromhex("488d0d") + rip_rel(rd_base + str_off[msg], ep_rva + len(text) + 7))   # lea rcx,[msg]
    for fn in ("OutputDebugStringA", "GetTickCount64"):
        emit(bytes.fromhex("ff15") + rip_rel(iat_rva[("KERNEL32.dll", fn)], ep_rva + len(text) + 6))
    emit(bytes.fromhex("31c9"))                                             # xor ecx, ecx
    emit(bytes.fromhex("ff15") + rip_rel(iat_rva[("KERNEL32.dll", "ExitProcess")], ep_rva + len(text) + 6))
    emit(b"\xcc" * (16 - len(text) % 16))
    imms = rng.stream("pe:text:imm", 4 * (TEXT_SIZE // 16))
    imms_b = rng.stream("pe:text:imm:B", 4 * (TEXT_SIZE // 16))
    func = 0
    while len(text) + 16 <= TEXT_SIZE:
        src = imms_b if (variant == "B" and func in B_CHANGED_FUNCS) else imms
        imm = src[4 * func:4 * func + 4]
        # push rbp ; mov rbp,rsp ; mov eax,imm32 ; pop rbp ; ret ; int3 x6
        emit(bytes.fromhex("554889e5b8") + imm + bytes.fromhex("5dc3") + b"\xcc" * 5)
        func += 1
    text = bytes(text).ljust(TEXT_SIZE, b"\xcc")

    # ---------------- .data
    rva[".data"] = rd_base + align(len(rdata), SECT_ALIGN)
    data = bytearray(rng.stream("pe:data", DATA_SIZE))
    if variant == "B":
        alt = rng.stream("pe:data:B", DATA_SIZE)
        for p in B_CHANGED_DATA_PAGES:
            data[p * 0x1000:(p + 1) * 0x1000] = alt[p * 0x1000:(p + 1) * 0x1000]
    tag = f"{LAB_MARKER_STR}::DATA::LABID-{lab_id}::BUILD_{variant}\0".encode()
    data[0:len(tag)] = tag
    data = bytes(data)

    # ---------------- .rsrc
    rva[".rsrc"] = rva[".data"] + align(len(data), SECT_ALIGN)
    rsrc = _resources(rva[".rsrc"], lab_id, variant)
    image_size = rva[".rsrc"] + align(len(rsrc), SECT_ALIGN)

    raw = {".text": text, ".rdata": rdata, ".data": data, ".rsrc": rsrc}
    chars = {".text": 0x60000020, ".rdata": 0x40000040, ".data": 0xC0000040, ".rsrc": 0x40000040}
    ptr = HEADERS_SIZE
    sections = []
    for n in names:
        rs = align(len(raw[n]), FILE_ALIGN)
        sections.append({"name": n, "virtual_address": rva[n], "virtual_size": len(raw[n]), "raw_pointer": ptr,
                         "raw_size": rs, "characteristics": chars[n]})
        ptr += rs
    file_size = ptr

    # ---------------- cabecalhos
    tds = 0x5A1B0000 if variant == "A" else 0x5A1B0B0B
    coff = struct.pack("<HHIIIHH", 0x8664, len(names), tds, 0, 0, 240, 0x0022)
    dirs = [(0, 0)] * 16
    dirs[1] = (rd_base + desc_off, 20 * (len(dlls) + 1))
    dirs[2] = (rva[".rsrc"], len(rsrc))
    dirs[12] = (rd_base + iat_start, iat_size)
    opt = struct.pack("<HBBIIIII", 0x20B, 14, 38, align(len(text), FILE_ALIGN),
                      sum(align(len(raw[n]), FILE_ALIGN) for n in names[1:]), 0, ep_rva, rva[".text"])
    opt += struct.pack("<QIIHHHHHHIIIIHHQQQQII", IMAGE_BASE, SECT_ALIGN, FILE_ALIGN, 6, 0, 0, 0, 6, 0, 0,
                       image_size, HEADERS_SIZE, 0, 3, 0x8160, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"".join(struct.pack("<II", a, s) for a, s in dirs)
    assert len(opt) == 240
    sect_tab = b"".join(struct.pack("<8sIIIIIIHHI", s["name"].encode(), s["virtual_size"], s["virtual_address"],
                                    s["raw_size"], s["raw_pointer"], 0, 0, 0, 0, s["characteristics"])
                        for s in sections)
    hdr = bytearray(_dos_header() + b"PE\0\0" + coff + opt + sect_tab)
    assert len(hdr) <= HEADERS_SIZE
    hdr = hdr.ljust(HEADERS_SIZE, b"\0")
    img = bytearray(hdr)
    for s in sections:
        img += raw[s["name"]].ljust(s["raw_size"], b"\0")
    assert len(img) == file_size
    cks_off = E_LFANEW + 4 + 20 + 64
    struct.pack_into("<I", img, cks_off, _checksum(bytes(img), cks_off))
    img = bytes(img)

    for s in sections:
        s["sha256"] = sha256_hex(img[s["raw_pointer"]:s["raw_pointer"] + s["raw_size"]])
    info = {
        "variant": variant,
        "lab_id": lab_id,
        "size": len(img),
        "sha256": sha256_hex(img),
        "machine": "0x8664",
        "optional_magic": "0x20B",
        "entry_point_rva": f"0x{ep_rva:X}",
        "image_base": f"0x{IMAGE_BASE:X}",
        "time_date_stamp": f"0x{tds:08X}",
        "checksum": f"0x{struct.unpack_from('<I', img, cks_off)[0]:08X}",
        "sections": sections,
        "imports": {dll: list(fns) for dll, fns in IMPORTS.items()},
        "strings": strings,
        "resources": [{"type": "RT_RCDATA", "id": 101, "lang": 0x409}, {"type": "RT_MANIFEST", "id": 1, "lang": 0x409}],
        "data_random_label": "pe:data",
        "changed_vs_A": ({"data_pages": list(B_CHANGED_DATA_PAGES),
                          "text_functions": [B_CHANGED_FUNCS.start, B_CHANGED_FUNCS.stop - 1],
                          "strings": True, "time_date_stamp": True} if variant == "B" else None),
    }
    return PeBuild(img, info)


def extract_strings(data: bytes, min_len: int = 8) -> list[str]:
    """Strings ASCII e UTF-16LE imprimiveis (para comparar recuperacao)."""
    import re
    out = [m.group().decode() for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data)]
    out += [m.group().decode("utf-16-le") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data)]
    return out
