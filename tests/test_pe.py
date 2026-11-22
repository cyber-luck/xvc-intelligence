"""PE: fixtures sinteticas do pe_check.py original, Catalog000.bin e PEs do Windows (somente leitura)."""
import importlib.util
import os
from pathlib import Path

import pytest

from xvcintel.core.result import BAD_MAGIC, INVALID_VALUE, OUT_OF_BOUNDS, TRUNCATED, Err, Ok
from xvcintel.formats.pe import legacy_pe_header, parse_pe, report_lines, rva_to_offset

FIX = Path(__file__).parent / "fixtures"
PE = FIX / "pe"

# resultado do pe_check.py original para cada fixture (problema esperado ou tipo de erro)
EXPECTED = {
    "vazio.bin": ("err", TRUNCATED),
    "png.bin": ("err", BAD_MAGIC),
    "mz_curto_0x3f.bin": ("err", TRUNCATED),
    "mz_lfanew_fora.bin": ("err", OUT_OF_BOUNDS),
    "mz_pe_1_byte_curto.bin": ("err", OUT_OF_BOUNDS),
    "mz_pe_limite_exato.bin": ("err", TRUNCATED),
    "mz_sem_pe.bin": ("err", BAD_MAGIC),
    "opt_ausente.bin": ("err", TRUNCATED),
    "opt_magic_ruim.bin": ("err", INVALID_VALUE),
    "opt_truncado.bin": ("err", TRUNCATED),
    "dll_recursos.bin": ("problems", ["SizeOfHeaders 0x0", "FileAlignment 0x0", "SectionAlignment 0x0"]),
    "pe32_gui.bin": ("problems", ["exige magic 0x20B", "FileAlignment 0x0"]),
    "pe32plus_cui.bin": ("problems", ["FileAlignment 0x0"]),
    "fa_0x10000_sa_0x10000.bin": ("ok", None),
    "fa_0x100_sa_0x1000.bin": ("problems", ["FileAlignment 0x100 fora da faixa"]),
    "fa_0x20000_sa_0x20000.bin": ("problems", ["FileAlignment 0x20000 fora da faixa"]),
    "fa_0x200_sa_0x1000.bin": ("ok", None),
    "fa_0x200_sa_0x400.bin": ("problems", ["deveria ser igual"]),
    "fa_sa_0x200_iguais.bin": ("ok", None),
    "fa_sa_0x20_iguais.bin": ("ok", None),
    "s_amd64_ok.bin": ("ok", None),
    "s_amd64_pe32.bin": ("problems", ["Machine AMD64 exige magic 0x20B"]),
    "s_i386_ok.bin": ("ok", None),
    "s_i386_pe32plus.bin": ("problems", ["Machine I386 exige magic 0x10B"]),
    "s_machine_desconhecida.bin": ("ok_note", "Machine 0x1234 fora da tabela"),
    "s_raw_desalinhado.bin": ("problems", ["PointerToRawData 0x410 nao alinhado a 0x200"]),
    "s_raw_fora.bin": ("problems", ["0xC00+0x10000 ultrapassam o arquivo"]),
    "s_raw_sobreposto.bin": ("problems", ["se sobrepoem no arquivo (0x800 < 0xC00)"]),
    "s_tabela_truncada.bin": ("problems", ["tabela de secoes ultrapassa o arquivo (0x198 > 0x17A)"]),
    "s_va_sobreposto.bin": ("problems", ["sobrepostas na memoria (0x2000 < 0x2800)"]),
}


def test_all_fixtures_covered():
    assert set(EXPECTED) == {p.name for p in PE.glob("*.bin")}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_ported_fixture(name):
    kind, exp = EXPECTED[name]
    r = parse_pe((PE / name).read_bytes())
    if kind == "err":
        assert isinstance(r, Err) and r.error.kind == exp, r
        return
    pe = r.value
    if kind == "ok":
        assert pe.problems == [] and pe.conclusion().startswith("PE com ponto de entrada")
    elif kind == "ok_note":
        assert pe.problems == [] and any(exp in n for n in pe.notes)
    else:
        text = " | ".join(pe.problems)
        for frag in exp:
            assert frag in text, (frag, text)
        assert pe.conclusion() == "estrutura PE inconsistente"
    assert report_lines(pe)[-1].startswith("Conclusao:")


def _legacy_probe():
    spec = importlib.util.spec_from_file_location("legacy_probe", Path(__file__).parents[1] / "legacy" / "xvc_probe.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("name", sorted(EXPECTED) + ["../Catalog000.bin"])
def test_legacy_pe_header_identical_to_original(name):
    """O dicionario 'pe' do relatorio schema 1 tem que ser identico ao do probe original."""
    d = (PE / name).read_bytes()[:0x10000]
    assert legacy_pe_header(d) == _legacy_probe().pe_header(d)


def test_catalog000():
    pe = parse_pe((FIX / "Catalog000.bin").read_bytes()).value
    assert pe.machine == 0x8664 and pe.is_pe32_plus and pe.subsystem_name == "XBOX_CODE_CATALOG"
    assert pe.optional["SizeOfCode"] == 0 and pe.optional["AddressOfEntryPoint"] == 0
    assert pe.optional["NumberOfRvaAndSizes"] == 0 and pe.directories == []
    assert len(pe.sections) == 1
    s = pe.sections[0]
    assert (s.name, s.raw_pointer, s.raw_size, s.virtual_size, s.characteristics) == ("#0", 0x1000, 0xC6000, 0, 0x40000000)
    assert any("SECURITY=0xFFFFFFFF/0xFFFFFFFF" in n for n in pe.notes)
    assert pe.imports is None and pe.exports is None and pe.security is None
    assert pe.conclusion().startswith("conteiner de catalogo de codigo Xbox")


def test_rva_to_offset_unmapped():
    pe = parse_pe((PE / "s_amd64_ok.bin").read_bytes()).value
    assert rva_to_offset(pe, 0x7FFFFFF0) is None


# ------------------------------------------------------------------ PEs reais do Windows
SYS = [p for p in (r"C:\Windows\System32\kernel32.dll", r"C:\Windows\System32\notepad.exe",
                   r"C:\Windows\SysWOW64\kernel32.dll", r"C:\Windows\System32\ntdll.dll",
                   r"C:\Windows\System32\shell32.dll") if os.path.exists(p)]


@pytest.mark.skipif(not SYS, reason="sem PEs do Windows disponiveis")
@pytest.mark.parametrize("path", SYS)
def test_windows_pe_against_pefile(path):
    pefile = pytest.importorskip("pefile")
    with open(path, "rb") as f:          # somente leitura
        data = f.read()
    mine = parse_pe(data).value
    ref = pefile.PE(data=data, fast_load=False)
    assert mine.machine == ref.FILE_HEADER.Machine
    assert mine.magic == ref.OPTIONAL_HEADER.Magic
    assert mine.optional["AddressOfEntryPoint"] == ref.OPTIONAL_HEADER.AddressOfEntryPoint
    assert mine.optional["SizeOfImage"] == ref.OPTIONAL_HEADER.SizeOfImage
    assert [s.name for s in mine.sections] == [s.Name.rstrip(b"\0").decode("latin-1") for s in ref.sections]
    assert [(s.virtual_address, s.raw_pointer) for s in mine.sections] == \
           [(s.VirtualAddress, s.PointerToRawData) for s in ref.sections]
    if hasattr(ref, "DIRECTORY_ENTRY_IMPORT"):
        assert [i.dll.lower() for i in mine.imports] == [e.dll.decode().lower() for e in ref.DIRECTORY_ENTRY_IMPORT]
        assert [len(i.functions) for i in mine.imports] == [len(e.imports) for e in ref.DIRECTORY_ENTRY_IMPORT]
    if hasattr(ref, "DIRECTORY_ENTRY_EXPORT"):
        ref_names = sorted(s.name.decode() for s in ref.DIRECTORY_ENTRY_EXPORT.symbols if s.name)
        assert sorted(n for n, *_ in mine.exports.names) == ref_names
        fw_ref = {s.name.decode(): s.forwarder.decode() for s in ref.DIRECTORY_ENTRY_EXPORT.symbols if s.name and s.forwarder}
        fw_mine = {n: f for n, _, _, f in mine.exports.names if f}
        assert fw_mine == fw_ref
    if hasattr(ref, "DIRECTORY_ENTRY_DEBUG"):
        assert [d.type for d in mine.debug] == [d.struct.Type for d in ref.DIRECTORY_ENTRY_DEBUG]
        for d, rd in zip(mine.debug, ref.DIRECTORY_ENTRY_DEBUG):
            if d.codeview and d.codeview.get("signature") == "RSDS":
                assert d.codeview["pdb_path"] == rd.entry.PdbFileName.rstrip(b"\0").decode("latin-1")
                assert d.codeview["age"] == rd.entry.Age
    if hasattr(ref, "DIRECTORY_ENTRY_RESOURCE"):
        assert mine.resources["leaf_count"] > 0
    assert mine.problems == [], mine.problems


@pytest.mark.skipif(not SYS, reason="sem PEs do Windows disponiveis")
def test_truncated_windows_pe_never_crashes():
    data = open(SYS[0], "rb").read()
    for cut in (0x40, 0x100, 0x200, 0x400, 0x1000, len(data) // 3, len(data) // 2):
        r = parse_pe(data[:cut])
        assert isinstance(r, (Ok, Err))
        if isinstance(r, Ok):
            assert r.value.problems, cut      # secoes passam do fim do arquivo cortado
