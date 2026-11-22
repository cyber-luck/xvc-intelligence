"""Inteligencia de paginas: tabela (PageNum, Value) x unidade de dados das folhas.

Modelo testado (RLE): para toda pagina p de regiao com KeyId, a unidade de dados
da folha (entry[0x14:0x18]) vale Value + (p - PageNum) da entrada que governa p
(a ultima entrada com PageNum <= p). O significado "unidade de dados XTS" vem do
xvdtool (INFERRED); a igualdade estrutural e verificada aqui contra os bytes.
"""
from __future__ import annotations

import bisect
import random
from dataclasses import dataclass, field

from ..core.util import PAGE, signed_diff32
from ..evidence.model import FAIL, INFO, PARTIAL, PASS, SKIPPED, CheckResult, Evidence
from ..formats.layout import DRIVE
from .package import Package
from .treeio import TreeReader


@dataclass(frozen=True)
class Run:
    index: int
    region_id: int
    keyed: bool
    page: int
    length: int
    value: int


@dataclass
class PageOptions:
    full_scan: bool = False        # le todas as folhas do drive data (~1,3 GB neste pacote)
    pair_samples: int = 400        # pares de paginas com a mesma unidade de dados a comparar
    window: int = 2000             # janela (paginas) para procurar o valor do segmento
    seed: int = 1234


def build_runs(pkg: Package) -> list[Run]:
    xi = pkg.xvcinfo
    runs = []
    t = xi.page_table
    for i, (p, v) in enumerate(t):
        r = xi.region_at(p * PAGE)
        rend = r.end // PAGE if r else p + 1
        nxt = t[i + 1][0] if i + 1 < len(t) else rend
        runs.append(Run(i, r.id if r else -1, bool(r and r.keyed), p, min(nxt, rend) - p, v))
    return runs


class RleModel:
    def __init__(self, runs: list[Run]):
        self.runs = runs
        self.pages = [r.page for r in runs]

    def governing(self, p: int) -> Run | None:
        k = bisect.bisect_right(self.pages, p) - 1
        return self.runs[k] if k >= 0 else None

    def predict(self, p: int) -> int | None:
        r = self.governing(p)
        return None if r is None else (r.value + p - r.page) & 0xFFFFFFFF


def check_values_vs_leaf(pkg: Package, tr: TreeReader, runs: list[Run]) -> CheckResult:
    miss = []
    for r in runs:
        du = tr.data_unit(r.page)
        if du != r.value:
            miss.append({"entry": r.index, "page": f"0x{r.page:X}", "value": f"0x{r.value:X}", "leaf_du": f"0x{du:X}",
                         "region": f"0x{r.region_id:X}", "keyed": r.keyed})
    n = len(runs)
    keyed_miss = [m for m in miss if m["keyed"]]
    return CheckResult(
        "pages.value_eq_leaf_du", "Value da entrada == unidade de dados da folha na pagina PageNum",
        PASS if not keyed_miss else FAIL,
        f"{n - len(miss)}/{n} conferem; divergencias: {miss[:5]}",
        coverage="completo (todas as entradas)", counts={"entries": n, "mismatches": len(miss),
                                                         "mismatches_in_keyed_regions": len(keyed_miss)},
        data={"mismatches": miss[:50]})


def check_rle(pkg: Package, tr: TreeReader, runs: list[Run], opt: PageOptions) -> CheckResult:
    model = RleModel(runs)
    drive = pkg.layout.get(DRIVE)
    first_page = drive.offset // PAGE
    n_pages = drive.size // PAGE
    exc_by_region: dict[str, dict] = {}
    checked = 0
    bad_keyed = 0
    keyed_checked = 0
    keyed_regions = [(r.offset // PAGE, r.end // PAGE) for r in pkg.xvcinfo.regions if r.keyed]

    def is_keyed(p: int) -> bool:
        return any(a <= p < b for a, b in keyed_regions)

    def note(p: int, du: int) -> None:
        nonlocal bad_keyed
        r = pkg.xvcinfo.region_at(p * PAGE)
        key = f"0x{r.id:X}" if r else "?"
        d = exc_by_region.setdefault(key, {"keyed": bool(r and r.keyed), "count": 0, "examples": []})
        d["count"] += 1
        if len(d["examples"]) < 3:
            d["examples"].append(f"0x{p:X}:du=0x{du:X}")
        if r and r.keyed:
            bad_keyed += 1

    if opt.full_scan:
        h0 = pkg.layout.hashed_index_of_page(first_page)
        k = 0
        for h, entry in tr.iter_data_units(h0, n_pages):
            p = first_page + (h - h0)
            while k + 1 < len(runs) and runs[k + 1].page <= p:
                k += 1
            r = runs[k]
            du = int.from_bytes(entry[0x14:0x18], "little")
            if r.page > p or du != (r.value + p - r.page) & 0xFFFFFFFF:
                note(p, du)
            checked += 1
            keyed_checked += r.keyed
        coverage = f"completo: {checked} paginas do drive data"
    else:
        targets = set()
        for r in runs:
            targets.add(r.page)
            targets.add(r.page + r.length - 1)
            targets.add(r.page + r.length // 2)
        for p in sorted(targets):
            du = tr.data_unit(p)
            if du != model.predict(p):
                note(p, du)
            checked += 1
            keyed_checked += is_keyed(p)
        coverage = (f"amostra: inicio, meio e fim de cada uma das {len(runs)} sequencias = {checked} paginas "
                    f"de {n_pages}")
    total_exc = sum(d["count"] for d in exc_by_region.values())
    status = FAIL if bad_keyed else (PASS if opt.full_scan else PARTIAL)
    return CheckResult(
        "pages.rle_model", "unidade de dados(p) == Value + (p - PageNum) da entrada que governa p",
        status, f"paginas com KeyId: {keyed_checked - bad_keyed}/{keyed_checked} conferem; sem KeyId: "
                f"{checked - keyed_checked - (total_exc - bad_keyed)}/{checked - keyed_checked} conferem "
                f"(as que conferem sao as paginas que abrem entrada, cujo Value e copia dos bytes da folha); "
                f"excecoes por regiao: "
                + ", ".join(f"{k}={'KeyId' if v['keyed'] else 'sem KeyId'}:{v['count']}" for k, v in exc_by_region.items()),
        coverage=coverage, counts={"checked": checked, "exceptions": total_exc, "exceptions_in_keyed": bad_keyed,
                                   "keyed_checked": keyed_checked},
        data={"exceptions_by_region": exc_by_region})


def check_redundancy(runs: list[Run]) -> CheckResult:
    red = [r.index for a, r in zip(runs, runs[1:])
           if a.region_id == r.region_id and r.value == (a.value + a.length) & 0xFFFFFFFF]
    return CheckResult("pages.no_redundant_entries",
                       "nenhuma entrada apenas continua a sequencia anterior (codificacao minima)",
                       PASS if not red else INFO, f"{len(red)} entradas redundantes",
                       coverage="completo (tabela)", counts={"redundant": len(red)})


def transition_stats(runs: list[Run]) -> CheckResult:
    back = fwd = 0
    hist: dict[str, int] = {}
    for a, b in zip(runs, runs[1:]):
        if a.region_id != b.region_id or not b.keyed:
            continue
        d = b.value - (a.value + a.length)
        if d < 0:
            back += 1
        elif d > 0:
            fwd += 1
        bucket = "0" if d == 0 else ("-" if d < 0 else "+") + ("<=16" if abs(d) <= 16 else "<=4096" if abs(d) <= 4096 else ">4096")
        hist[bucket] = hist.get(bucket, 0) + 1
    return CheckResult("pages.transitions",
                       "mudanca de Value entre entradas consecutivas na mesma regiao (Value - continuacao)",
                       INFO, f"para tras {back}, para frente {fwd}", coverage="completo (tabela)",
                       counts={"backward": back, "forward": fwd}, data={"histogram": hist})


def data_unit_reuse(pkg: Package, tr: TreeReader, runs: list[Run], opt: PageOptions) -> CheckResult:
    """Conta paginas cuja unidade de dados se repete na mesma regiao (pelo modelo RLE)
    e confere diretamente uma amostra de pares lendo as folhas."""
    by_region: dict[int, list[Run]] = {}
    for r in runs:
        if r.keyed and r.length > 0:
            by_region.setdefault(r.region_id, []).append(r)
    per_region = {}
    total_pages = total_shared = total_distinct = 0
    pairs: list[tuple[int, int, int]] = []
    rnd = random.Random(opt.seed)
    for rid, rs in by_region.items():
        ev = []
        for r in rs:
            ev.append((r.value, 1))
            ev.append((r.value + r.length, -1))
        ev.sort()
        cov = 0
        last = None
        distinct = shared = 0
        for x, d in ev:
            if last is not None and cov > 0 and x > last:
                distinct += x - last
                if cov >= 2:
                    shared += (x - last) * cov
            cov += d
            last = x
        pages_ = sum(r.length for r in rs)
        total_pages += pages_
        total_shared += shared
        total_distinct += distinct
        if shared:
            per_region[f"0x{rid:X}"] = {"pages": pages_, "distinct_data_units": distinct,
                                        "pages_sharing_a_data_unit": shared}
            # pares concretos: sobreposicao entre sequencias ordenadas por valor
            srt = sorted(rs, key=lambda r: r.value)
            best = None
            for r in srt:
                if best and r.value < best.value + best.length:
                    ov = min(best.value + best.length, r.value + r.length) - r.value
                    j = rnd.randrange(ov)
                    pairs.append((rid, best.page + (r.value - best.value) + j, r.page + j))
                if best is None or r.value + r.length > best.value + best.length:
                    best = r
    rnd.shuffle(pairs)
    pairs = pairs[:opt.pair_samples]
    du_eq = hash_eq = 0
    for _, a, b in pairs:
        la, lb = tr.leaf_for_page(a), tr.leaf_for_page(b)
        du_eq += la[0x14:] == lb[0x14:]
        hash_eq += la[:0x14] == lb[:0x14]
    return CheckResult(
        "pages.data_unit_reuse", "unidades de dados repetidas dentro da mesma regiao com KeyId",
        INFO, f"{total_shared} de {total_pages} paginas compartilham a unidade de dados com outra pagina da mesma "
              f"regiao ({total_distinct} valores distintos); amostra direta: {du_eq}/{len(pairs)} pares com a mesma "
              f"unidade nas folhas, {hash_eq}/{len(pairs)} com o mesmo hash gravado (entry[:0x14])",
        coverage=f"contagem pelo modelo RLE (completa); {len(pairs)} pares conferidos nas folhas (semente {opt.seed})",
        counts={"keyed_pages": total_pages, "pages_sharing": total_shared, "distinct": total_distinct,
                "pairs_checked": len(pairs), "pairs_same_du": du_eq, "pairs_same_stored_hash": hash_eq},
        data={"per_region": per_region})


def segment_values(pkg: Package, tr: TreeReader, runs: list[Run], opt: PageOptions) -> CheckResult:
    """Array u32 por segmento x unidade de dados da 1a pagina; contexto das excecoes."""
    xi = pkg.xvcinfo
    if not xi.segment_values:
        return CheckResult("pages.segment_values", "array por segmento", SKIPPED, "array nao decodificado")
    rows = []
    exc = []
    for s in xi.segments:
        v = xi.segment_values[s.index]
        du = tr.data_unit(s.page)
        if v == du:
            continue
        r = xi.region_at(s.offset)
        prev_du = tr.data_unit(s.page - 1)
        k = bisect.bisect_right([x.page for x in runs], s.page) - 1
        ctx = {
            "segment": s.index,
            "file": pkg.rows[s.index].name if s.index < len(pkg.rows) else None,
            "page": f"0x{s.page:X}",
            "region": f"0x{r.id:X}" if r else None,
            "value": f"0x{v:08X}",
            "du_first_page": f"0x{du:08X}",
            "value_minus_du": signed_diff32(v, du),
            "du_previous_page": f"0x{prev_du:08X}",
            "value_eq_du_prev_plus_1": v == (prev_du + 1) & 0xFFFFFFFF,
            "segment_pages": (xi.segment_end(s.index, pkg.size) - s.offset) // PAGE,
            "runs_in_segment": sum(1 for x in runs if s.offset // PAGE <= x.page < xi.segment_end(s.index, pkg.size) // PAGE),
        }
        # o valor aparece como unidade de dados em alguma pagina na janela?
        lo = max(pkg.layout.get(DRIVE).offset // PAGE, s.page - opt.window)
        hi = min(pkg.size // PAGE - 1, s.page + opt.window)
        hits = [p - s.page for p in range(lo, hi + 1) if tr.data_unit(p) == v]
        ctx["window_pages_with_du_eq_value"] = hits[:10]
        # o valor cai dentro de alguma sequencia da tabela (seria a unidade de alguma pagina)?
        inrun = [(x.index, f"0x{x.page + v - x.value:X}", f"0x{x.region_id:X}") for x in runs
                 if x.keyed and x.value <= v < x.value + x.length]
        ctx["runs_where_value_is_a_data_unit"] = inrun[:5]
        ctx["value_in_any_run"] = bool(inrun)
        ctx["governing_entry"] = {"index": k, "page": f"0x{runs[k].page:X}", "value": f"0x{runs[k].value:X}"}
        exc.append(ctx)
    n = len(xi.segments)
    return CheckResult(
        "pages.segment_values", "array u32 por segmento (XvcInfo apos os segmentos) == unidade de dados da 1a pagina",
        INFO if exc else PASS, f"{n - len(exc)}/{n} conferem; excecoes: "
        + ", ".join(f"seg {e['segment']} ({e['file']}) {e['value_minus_du']:+d}" for e in exc),
        coverage=f"completo (todos os segmentos); janela de busca +/-{opt.window} paginas para excecoes",
        counts={"segments": n, "exceptions": len(exc)}, data={"exceptions": exc})


def run_pages(pkg: Package, opt: PageOptions | None = None) -> list[CheckResult]:
    opt = opt or PageOptions()
    if not pkg.xvcinfo or not pkg.xvcinfo.page_table or not pkg.layout.geometry.levels:
        return [CheckResult("pages.rle_model", "tabela de paginas", SKIPPED, "tabela ou arvore ausente")]
    tr = TreeReader(pkg.src, pkg.layout, cache_pages=16384)
    runs = build_runs(pkg)
    return [check_values_vs_leaf(pkg, tr, runs), check_rle(pkg, tr, runs, opt), check_redundancy(runs),
            transition_stats(runs), data_unit_reuse(pkg, tr, runs, opt), segment_values(pkg, tr, runs, opt)]
