"""Motor de integridade: topo da arvore, ligacoes entre niveis, folhas x paginas,
hash de regiao e hash de segmento.

Nada aqui decifra nada: so calcula SHA-256 dos bytes como estao gravados.
Verificacoes caras tem limite (cap_bytes por item) e o que foi pulado e relatado.
"""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass

from ..core.util import PAGE, pages
from ..evidence.model import FAIL, INFO, PARTIAL, PASS, SKIPPED, CheckResult, Evidence
from ..formats import layout as L
from ..formats.hashtree import ENTRIES_PER_PAGE, HASH_ENTRY_SIZE, sha256
from .package import Package
from .treeio import TreeReader

DEFAULT_CAP = 160 * 1024 * 1024


@dataclass
class IntegrityOptions:
    cap_bytes: int = DEFAULT_CAP          # maximo por regiao/segmento para hash completo
    leaf_level_samples: int = 64          # paginas L0 conferidas contra L1 (se nao full)
    full_leaf_level: bool = False         # confere TODAS as paginas L0 contra L1 (~1,3 GB aqui)
    data_page_samples_per_region: int = 3 # paginas de dados conferidas contra a folha por regiao
    random_data_pages: int = 32           # paginas de dados aleatorias extras (semente fixa)
    seed: int = 1234


def check_top_hash(pkg: Package, tr: TreeReader) -> CheckResult:
    h = pkg.header
    if not pkg.layout.integrity or not pkg.layout.geometry.levels:
        return CheckResult("integrity.top_hash", "SHA-256(pagina 0 da arvore) == TopHashBlockHash", SKIPPED,
                           "integridade desativada no cabecalho")
    d = sha256(tr.tree_page(0))
    ok = d == h.top_hash_block_hash
    return CheckResult("integrity.top_hash", "SHA-256(pagina 0 da arvore) == TopHashBlockHash",
                       PASS if ok else FAIL, f"calculado {d.hex()}", coverage="1 pagina (completo)",
                       evidence=[Evidence("xvc:cabecalho", "TopHashBlockHash", h.base_offset + 0x240,
                                          h.top_hash_block_hash.hex(), "integrity.top_hash"),
                                 Evidence("xvc:hash tree", "pagina 0", tr.base, d.hex())])


def check_level_links(pkg: Package, tr: TreeReader, opt: IntegrityOptions) -> list[CheckResult]:
    geo = pkg.layout.geometry
    out = []
    for level in range(geo.levels - 2, -1, -1):
        n = geo.level_pages[level]
        full = level > 0 or opt.full_leaf_level
        bad, checked = [], 0
        if full:
            tr.prefetch(geo.level_start(level + 1), geo.level_pages[level + 1])
            # streaming do nivel inteiro; pai lido via cache (nivel de cima e pequeno)
            for idx, page in tr.iter_level_pages(level):
                tp, e = geo.parent_location(level, idx)
                if sha256(page)[:HASH_ENTRY_SIZE] != tr.entry(tp, e):
                    bad.append(idx)
                checked += 1
        else:
            rnd = random.Random(opt.seed + level)
            k = min(n, opt.leaf_level_samples)
            idxs = sorted({0, n - 1} | set(rnd.sample(range(n), max(0, k - 2))))
            for idx in idxs:
                page = tr.tree_page(geo.level_start(level) + idx)
                tp, e = geo.parent_location(level, idx)
                if sha256(page)[:HASH_ENTRY_SIZE] != tr.entry(tp, e):
                    bad.append(idx)
                checked += 1
        status = FAIL if bad else (PASS if full else PARTIAL)
        out.append(CheckResult(
            f"integrity.link_L{level}_to_L{level + 1}",
            f"SHA-256(pagina do nivel L{level})[:0x18] == entrada no nivel L{level + 1}",
            status, f"{checked - len(bad)}/{checked} conferem" + (f"; falhas (indices): {bad[:10]}" if bad else ""),
            coverage=("completo" if full else f"amostra {checked}/{n} (semente {opt.seed + level})"),
            counts={"checked": checked, "level_pages": n, "mismatches": len(bad)}))
    return out


def _keyed_for_offset(pkg: Package, off: int) -> tuple[bool, str]:
    xi = pkg.xvcinfo
    r = xi.region_at(off) if xi else None
    if r is None:
        return False, "?"
    return r.keyed, r.label()


def check_data_pages(pkg: Package, tr: TreeReader, opt: IntegrityOptions) -> CheckResult:
    """Pagina de dados x folha: regiao com KeyId compara 0x14 bytes, sem KeyId compara 0x18."""
    lay = pkg.layout
    if not lay.geometry.levels:
        return CheckResult("integrity.leaf_vs_data", "folha x SHA-256 da pagina de dados", SKIPPED, "sem arvore")
    first = lay.user_data_page
    last = first + lay.hashed_pages - 1
    targets: set[int] = set()
    for nm in (L.USER_DATA, L.XVC_INFO):
        r = lay.get(nm)
        if r.size:
            targets |= {r.offset // PAGE, (r.end - 1) // PAGE}
    if pkg.xvcinfo:
        for reg in pkg.xvcinfo.regions:
            if reg.offset // PAGE < first:
                continue
            a, b = reg.offset // PAGE, (reg.end - 1) // PAGE
            picks = [a, b, (a + b) // 2][:opt.data_page_samples_per_region]
            targets |= set(picks)
    rnd = random.Random(opt.seed)
    for _ in range(opt.random_data_pages):
        targets.add(rnd.randint(first, last))
    targets = {p for p in targets if first <= p <= last}
    stats = {"keyed_ok": 0, "keyed_bad": 0, "plain_ok": 0, "plain_bad": 0}
    bad = []
    for p in sorted(targets):
        page = pkg.src.read_at(p * PAGE, PAGE)
        entry = tr.leaf_for_page(p)
        keyed, label = _keyed_for_offset(pkg, p * PAGE)
        d = sha256(page)
        ok = entry[:0x14] == d[:0x14] if keyed else entry == d[:0x18]
        k = ("keyed_" if keyed else "plain_") + ("ok" if ok else "bad")
        stats[k] += 1
        if not ok:
            bad.append((hex(p), label))
    n = len(targets)
    return CheckResult(
        "integrity.leaf_vs_data", "folha da arvore x SHA-256 da pagina gravada (regra por KeyId)",
        FAIL if bad else PARTIAL,
        f"{n - len(bad)}/{n} conferem; regioes com KeyId: {stats['keyed_ok']} ok/{stats['keyed_bad']} falha "
        f"(entry[:0x14]); sem KeyId/metadados: {stats['plain_ok']} ok/{stats['plain_bad']} falha (entry[:0x18])"
        + (f"; falhas {bad[:10]}" if bad else ""),
        coverage=f"amostra de {n} de {lay.hashed_pages} paginas hasheadas (inicio/meio/fim de cada regiao + "
                 f"{opt.random_data_pages} aleatorias, semente {opt.seed})",
        counts=stats)


def check_region_hashes(pkg: Package, opt: IntegrityOptions) -> CheckResult:
    """Hash da regiao (8 bytes em +0x60) x SHA-256(bytes gravados da regiao)[:8]."""
    xi = pkg.xvcinfo
    if not xi:
        return CheckResult("integrity.region_hash", "hash de regiao", SKIPPED, "sem XvcInfo")
    rows, ok_n, bad, skipped = [], 0, [], []
    for r in xi.regions:
        row = {"region": f"0x{r.id:X}", "desc": r.description, "length": r.length, "stored": r.hash.hex()}
        if r.description == "XVC-EXVD":
            row["rule"] = "== EmbeddedXVD_PDUID[:8]"
            row["match"] = r.hash == pkg.header.embedded_xvd_pduid[:8]
        elif r.description in ("XVC-HD", "XVC-MD") or not any(r.hash):
            row["rule"] = "nao testado aqui (ver hipoteses)"
            row["match"] = None
        elif r.length > opt.cap_bytes:
            row["rule"] = f"SHA-256(regiao)[:8] - pulado (> limite {opt.cap_bytes})"
            row["match"] = None
            skipped.append(f"0x{r.id:X}")
        else:
            d, n = pkg.src.sha256_range(r.offset, r.length)
            row["rule"] = "SHA-256(regiao gravada)[:8]"
            row["computed"] = d[:8].hex()
            row["match"] = d[:8] == r.hash and n == r.length
        if row["match"] is True:
            ok_n += 1
        elif row["match"] is False:
            bad.append(row["region"])
        rows.append(row)
    tested = ok_n + len(bad)
    return CheckResult(
        "integrity.region_hash", "hash de regiao (+0x60) x SHA-256(bytes gravados)[:8] (EXVD: PDUID do XVD embutido)",
        FAIL if bad else (PASS if not skipped else PARTIAL),
        f"{ok_n}/{tested} testadas conferem; puladas por limite: {skipped}" + (f"; falhas {bad}" if bad else ""),
        coverage=f"regioes <= {opt.cap_bytes} bytes; {len(skipped)} puladas por tamanho",
        counts={"tested": tested, "ok": ok_n, "skipped_by_cap": len(skipped)}, data={"regions": rows})


def check_segment_hashes(pkg: Package, opt: IntegrityOptions) -> CheckResult:
    """Hash do segmento (8 bytes) x SHA-256(paginas do segmento ate o proximo/fim da regiao)[:8]."""
    xi = pkg.xvcinfo
    if not xi:
        return CheckResult("integrity.segment_hash", "hash de segmento", SKIPPED, "sem XvcInfo")
    rows, ok_n, bad, skipped = [], 0, [], []
    for s in xi.segments:
        end = xi.segment_end(s.index, pkg.size)
        length = end - s.offset
        row = {"segment": s.index, "page": f"0x{s.page:X}", "length": length, "stored": s.hash.hex()}
        if length > opt.cap_bytes:
            row["match"] = None
            skipped.append(s.index)
        else:
            d, n = pkg.src.sha256_range(s.offset, length)
            row["computed"] = d[:8].hex()
            row["match"] = d[:8] == s.hash and n == length
            if row["match"]:
                ok_n += 1
            else:
                bad.append(s.index)
        rows.append(row)
    tested = ok_n + len(bad)
    return CheckResult(
        "integrity.segment_hash", "hash de segmento x SHA-256(paginas gravadas do segmento)[:8]",
        FAIL if bad else (PASS if not skipped else PARTIAL),
        f"{ok_n}/{tested} testados conferem; {len(skipped)} pulados por limite" + (f"; falhas {bad}" if bad else ""),
        coverage=f"segmentos <= {opt.cap_bytes} bytes; pulados: {skipped}",
        counts={"tested": tested, "ok": ok_n, "skipped_by_cap": len(skipped)}, data={"segments": rows})


def metadata_hash_hypotheses(pkg: Package) -> CheckResult:
    """Testa candidatos baratos para o hash compartilhado de XVC-HD/XVC-MD e para OriginalXvcDataHash.

    Inclui a serializacao do VerifyXvcHash do xvdtool (XvcInfo 0xDA8 + regioes + segmentos
    com ajuste da hash tree, preenchido com zeros ate XvcDataLength).
    """
    h, xi, lay = pkg.header, pkg.xvcinfo, pkg.layout
    if not xi:
        return CheckResult("hypothesis.metadata_hash", "candidatos de hash de metadados", SKIPPED, "sem XvcInfo")
    target8 = {r.description: r.hash for r in xi.regions if r.description in ("XVC-HD", "XVC-MD")}
    raw_xvc = pkg.src.read_at(pkg.xvcinfo_offset, h.xvc_data_length)
    hdr = pkg.src.read_at(0, 0x3000)
    ht = lay.get(L.HASH_TREE)
    ht_size = ht.size
    ht_end_page = ht.end // PAGE

    def xvdtool_serialization(adjust: bool) -> bytes:
        import struct as st
        b = bytearray(raw_xvc[:0xDA8])
        if adjust:
            for fo in (0xD28, 0xD40):        # InitialPlayOffset / PreviewOffset
                v = st.unpack_from("<Q", b, fo)[0]
                if v > ht.offset:
                    st.pack_into("<Q", b, fo, v - ht_size)
        for r in xi.regions:
            rb = bytearray(raw_xvc[r.rel:r.rel + 0x80])
            if adjust:
                off, ln = r.offset, r.length
                if off < ht.offset < off + ln:
                    ln -= ht_size
                elif off > ht.offset:
                    off -= ht_size
                st.pack_into("<QQ", rb, 0x50, off, ln)
            b += rb
        for s in xi.segments:
            sb = bytearray(raw_xvc[xi.seg_off + 12 * s.index:xi.seg_off + 12 * (s.index + 1)])
            if adjust and s.page >= ht_end_page:
                st.pack_into("<I", sb, 0, s.page - ht_size // PAGE)
            b += sb
        return bytes(b).ljust(h.xvc_data_length, b"\0")

    cands = {
        "xvdtool VerifyXvcHash (com ajuste da hash tree)": xvdtool_serialization(True),
        "xvdtool VerifyXvcHash (sem ajuste)": xvdtool_serialization(False),
        "XvcInfo gravado inteiro": raw_xvc,
        "XvcInfo gravado ate o fim da tabela": raw_xvc[:xi.tail_off],
        "cabecalho 0x3000": hdr,
        "cabecalho 0x200..0x3000": hdr[0x200:],
        "cabecalho 0x200..0x1000": hdr[0x200:0x1000],
        "user data (UserDataLength)": pkg.src.read_at(lay.get(L.USER_DATA).offset, h.user_data_length),
        "user data (paginas)": pkg.src.read_at(lay.get(L.USER_DATA).offset, lay.get(L.USER_DATA).size),
    }
    results = []
    any_hit = False
    for name, blob in cands.items():
        d = hashlib.sha256(blob).digest()
        hit_orig = d == h.original_xvc_data_hash
        hit_md = {k: d[:8] == v for k, v in target8.items()}
        any_hit |= hit_orig or any(hit_md.values())
        results.append({"candidate": name, "sha256": d.hex(), "== OriginalXvcDataHash": hit_orig,
                        "[:8] == hash XVC-HD/XVC-MD": hit_md})
    for name, val in (("OriginalXvcDataHash", h.original_xvc_data_hash), ("TopHashBlockHash", h.top_hash_block_hash),
                      ("PDUID", h.pduid), ("VDUID", h.vduid.bytes_le)):
        for tname, tv in target8.items():
            if val[:8] == tv or hashlib.sha256(val).digest()[:8] == tv:
                any_hit = True
                results.append({"candidate": f"{name} (ou SHA-256 dele) [:8]", "matches": tname})
    return CheckResult(
        "hypothesis.metadata_hash", "candidatos para OriginalXvcDataHash e para o hash compartilhado XVC-HD/XVC-MD",
        INFO, "algum candidato confere" if any_hit else "nenhum candidato confere (hipoteses refutadas)",
        coverage=f"{len(cands)} serializacoes testadas", data={"results": results,
                                                                  "targets": {k: v.hex() for k, v in target8.items()}})


def check_embedded_xvd(pkg: Package, opt: IntegrityOptions) -> list[CheckResult]:
    """Segunda amostra: XVD embutido. Confere topo da arvore e o vinculo de PDUID."""
    eh, el = pkg.embedded_header, pkg.embedded_layout
    out: list[CheckResult] = []
    if not eh or not el:
        return [CheckResult("embedded.header", "cabecalho do XVD embutido", SKIPPED, "ausente")]
    base = pkg.layout.get(L.EMBEDDED).offset
    out.append(CheckResult("embedded.pduid_link", "cabecalho principal EmbeddedXVD_PDUID == PDUID do XVD embutido",
                           PASS if pkg.header.embedded_xvd_pduid == eh.pduid else FAIL,
                           f"principal {pkg.header.embedded_xvd_pduid.hex()} / embutido {eh.pduid.hex()}",
                           evidence=[Evidence("xvc:cabecalho", "EmbeddedXVD_PDUID", 0x32C),
                                     Evidence("xvc:XVD embutido", "PDUID", base + 0x3AC)]))
    if el.geometry.levels:
        ht = el.get(L.HASH_TREE)
        d = sha256(pkg.src.read_at(base + ht.offset, PAGE))
        out.append(CheckResult("embedded.top_hash",
                               "XVD embutido: SHA-256(pagina 0 da arvore no layout calculado) == TopHashBlockHash",
                               PASS if d == eh.top_hash_block_hash else FAIL,
                               f"arvore em 0x{base + ht.offset:X}; niveis {list(el.geometry.level_pages)}",
                               coverage="1 pagina"))
        # um link L0->L1 e uma folha de user data, como teste de generalidade do layout
        if el.geometry.levels >= 2:
            g = el.geometry
            p0 = pkg.src.read_at(base + ht.offset + g.level_start(0) * PAGE, PAGE)
            tp, e = g.parent_location(0, 0)
            parent = pkg.src.read_at(base + ht.offset + tp * PAGE + e * HASH_ENTRY_SIZE, HASH_ENTRY_SIZE)
            out.append(CheckResult("embedded.link_L0_L1", "XVD embutido: L0[0] -> entrada em L1",
                                   PASS if sha256(p0)[:HASH_ENTRY_SIZE] == parent else FAIL, coverage="1 pagina"))
        ud = el.get(L.USER_DATA)
        if ud.size and el.hashed_pages:
            page = pkg.src.read_at(base + ud.offset, PAGE)
            tp, e = el.geometry.leaf_location(0)
            leaf = pkg.src.read_at(base + ht.offset + tp * PAGE + e * HASH_ENTRY_SIZE, HASH_ENTRY_SIZE)
            d2 = sha256(page)
            out.append(CheckResult("embedded.leaf_user_data0",
                                   "XVD embutido: folha 0 x SHA-256(1a pagina do user data)",
                                   PASS if leaf[:0x14] == d2[:0x14] else FAIL,
                                   f"[:0x18] igual: {leaf == d2[:0x18]}; [0x14:0x18]=0x{int.from_bytes(leaf[0x14:], 'little'):X}",
                                   coverage="1 pagina"))
    if any(eh.user_data_hash) and eh.user_data_length <= opt.cap_bytes:
        ud = el.get(L.USER_DATA)
        exact, _ = pkg.src.sha256_range(base + ud.offset, eh.user_data_length)
        padded, _ = pkg.src.sha256_range(base + ud.offset, ud.size)
        hit = "exato" if exact == eh.user_data_hash else "paginas" if padded == eh.user_data_hash else None
        out.append(CheckResult("embedded.user_data_hash",
                               "hipotese: UserDataHash == SHA-256(user data gravado do XVD embutido)",
                               PASS if hit else INFO, f"confere ({hit})" if hit else "nao confere (hipotese refutada "
                               "para bytes gravados; pode ser sobre o conteudo decifrado - nao testavel sem chave)",
                               coverage=f"{eh.user_data_length} bytes"))
    return out


def run_integrity(pkg: Package, opt: IntegrityOptions | None = None) -> list[CheckResult]:
    opt = opt or IntegrityOptions()
    tr = TreeReader(pkg.src, pkg.layout)
    out = [check_top_hash(pkg, tr)]
    if pkg.layout.geometry.levels:
        out += check_level_links(pkg, tr, opt)
        out.append(check_data_pages(pkg, tr, opt))
    out.append(check_region_hashes(pkg, opt))
    out.append(check_segment_hashes(pkg, opt))
    out.append(metadata_hash_hypotheses(pkg))
    out += check_embedded_xvd(pkg, opt)
    return out
