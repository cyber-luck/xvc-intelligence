"""Grafo de conhecimento: pacote, regioes, segmentos, arquivos, chaves, configs, DLLs.

Cada aresta carrega evidencia {fonte, offset, campo, teste} e confianca
(CONFIRMED/INFERRED/UNKNOWN). Serializa para JSON e responde consultas.
"""
from __future__ import annotations

import bisect
import json
from dataclasses import dataclass, field

from ..core.util import PAGE
from ..evidence.model import CONFIRMED, INFERRED, UNKNOWN, CheckResult
from ..formats.layout import EMBEDDED
from .configs import Configs, load_configs
from .package import Package


@dataclass
class Graph:
    nodes: dict[str, dict] = field(default_factory=dict)
    edges: list[dict] = field(default_factory=list)

    def node(self, nid: str, kind: str, **attrs) -> str:
        n = self.nodes.setdefault(nid, {"id": nid, "kind": kind})
        n.update(attrs)
        return nid

    def edge(self, src: str, rel: str, dst: str, confidence: str, evidence: dict, note: str = "") -> None:
        self.edges.append({"source": src, "relation": rel, "target": dst, "confidence": confidence,
                           "evidence": evidence, "note": note})

    def to_dict(self) -> dict:
        return {"schema": "xvcintel.graph/1", "nodes": list(self.nodes.values()), "edges": self.edges}

    @classmethod
    def from_dict(cls, d: dict) -> "Graph":
        g = cls()
        for n in d["nodes"]:
            g.nodes[n["id"]] = n
        g.edges = list(d["edges"])
        return g

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=1, ensure_ascii=False)

    @classmethod
    def load(cls, path: str) -> "Graph":
        with open(path, encoding="utf-8") as f:
            return cls.from_dict(json.load(f))

    def resolve(self, query: str) -> list[str]:
        if query in self.nodes:
            return [query]
        q = query.casefold()
        exact = [n for n in self.nodes if n.casefold() == q or n.casefold().endswith(":" + q)]
        if exact:
            return exact
        return [n for n in self.nodes if q in n.casefold()]

    def neighbors(self, nid: str, relation: str | None = None) -> list[dict]:
        return [e for e in self.edges if (e["source"] == nid or e["target"] == nid)
                and (relation is None or e["relation"] == relation)]


def _ev(source: str, field_: str = "", offset: int | None = None, test: str | None = None) -> dict:
    d = {"source": source, "field": field_, "test": test}
    if offset is not None:
        d["offset"] = f"0x{offset:X}"
    return d


def build_graph(pkg: Package, checks: list[CheckResult] | None = None, configs: Configs | None = None) -> Graph:
    g = Graph()
    xi, h = pkg.xvcinfo, pkg.header
    cfg = configs or load_configs(pkg)
    status = {c.id: c.status for c in (checks or []) + pkg.checks}
    seg_hash_ok = {}
    for c in checks or []:
        if c.id == "integrity.segment_hash":
            seg_hash_ok = {r["segment"]: r["match"] for r in c.data.get("segments", [])}
    reg_hash_ok = {}
    for c in checks or []:
        if c.id == "integrity.region_hash":
            reg_hash_ok = {r["region"]: r["match"] for r in c.data.get("regions", [])}

    pkg_id = g.node("package", "package", path=pkg.path, size=pkg.size, vduid=str(h.vduid),
                    package_version=h.package_version_str, content_type=h.content_type_name)
    for i, k in enumerate(xi.keys):
        g.node(f"key:{i}", "key_id", guid=str(k), note="identificador; nenhuma chave e usada")
    for r in xi.regions:
        rid = g.node(f"region:0x{r.id:X}", "region", description=r.description, offset=f"0x{r.offset:X}",
                     length=r.length, key_id=r.key_id, flags=f"0x{r.flags:X}", hash=r.hash.hex(),
                     hash_verified=reg_hash_ok.get(f"0x{r.id:X}"))
        g.edge(pkg_id, "CONTAINS_REGION", rid, CONFIRMED,
               _ev("xvc:XvcInfo", "region header", xi.base_offset + r.rel, "xvcinfo.struct.03"),
               "regioes ladrilham o arquivo")
        if r.keyed:
            g.edge(rid, "USES_KEY_ID", f"key:{r.key_id}", CONFIRMED,
                   _ev("xvc:XvcInfo", "region KeyId", xi.base_offset + r.rel + 4, "xvcinfo.struct.02"),
                   "KeyId como indice da lista de chaves: semantica do xvdtool (INFERRED); valor CONFIRMED")
    for s in xi.segments:
        sid = g.node(f"segment:{s.index}", "segment", page=f"0x{s.page:X}", hash=s.hash.hex(),
                     hash_verified=seg_hash_ok.get(s.index),
                     value_u32=f"0x{xi.segment_values[s.index]:08X}" if xi.segment_values else None)
        r = xi.region_at(s.offset)
        if r:
            g.edge(f"region:0x{r.id:X}", "CONTAINS_SEGMENT", sid, CONFIRMED,
                   _ev("xvc:XvcInfo", "segment PageNum", xi.base_offset + xi.seg_off + 12 * s.index, "xvcinfo.struct.06"))
    filemap_ok = all(ok for _, ok, _ in pkg.file_checks)
    tpages = [p for p, _ in xi.page_table]
    for row in pkg.rows:
        fid = g.node(f"file:{row.name}", "file", size=row.size, offset=f"0x{row.start:X}",
                     pages=(row.size + PAGE - 1) // PAGE)
        g.edge(f"segment:{row.index}", "STORES_FILE", fid, CONFIRMED if filemap_ok else UNKNOWN,
               _ev("userdata:SegmentMetadata.bin", "page[i] == segment PageNum - drive page",
                   None, "filemap: inicio do arquivo == PageNum do segmento"))
        n_runs = (bisect.bisect_left(tpages, xi.segment_end(row.index, pkg.size) // PAGE)
                  - bisect.bisect_left(tpages, row.start // PAGE))
        g.nodes[fid]["page_table_runs"] = n_runs
    # configs
    for f in (pkg.userdata.files if pkg.userdata else []):
        g.node(f"config:{f.path}", "userdata_file", size=f.size)
        g.edge(pkg_id, "HAS_USERDATA_FILE", f"config:{f.path}", CONFIRMED,
               _ev("xvc:user data", "entry", pkg.layout.get("user data").offset + f.entry_offset))
    for ex in cfg.game_config.get("executables", []):
        name = ex.get("Name")
        if name and f"file:{name}" in g.nodes:
            g.edge("config:MicrosoftGame.config", "DECLARES_EXECUTABLE", f"file:{name}", CONFIRMED,
                   _ev("userdata:MicrosoftGame.config", "ExecutableList/Executable@Name"), f"Id={ex.get('Id')}")
    for app in cfg.manifest.get("applications", []):
        name = app.get("Executable")
        if name and f"file:{name}" in g.nodes:
            g.edge("config:appxmanifest.xml", "DECLARES_APPLICATION", f"file:{name}", CONFIRMED,
                   _ev("userdata:appxmanifest.xml", "Application@Executable"),
                   f"Id={app.get('Id')}, EntryPoint={app.get('EntryPoint')}")
    for ex in cfg.hive.get("executables", []):
        name = ex.get("Name")
        if name and f"file:{name}" in g.nodes:
            g.edge("config:microsoft_gameconfig.bin", "DECLARES_EXECUTABLE", f"file:{name}", CONFIRMED,
                   _ev("userdata:microsoft_gameconfig.bin", "Executable\\00000000\\Name"))
    for dep in cfg.manifest.get("dependencies", []):
        did = g.node(f"dependency:{dep.get('Name')}", "os_dependency", **{("dep_kind" if k == "kind" else k): v for k, v in dep.items() if k != "Name"})
        g.edge("config:appxmanifest.xml", "DECLARES_DEPENDENCY", did, CONFIRMED,
               _ev("userdata:appxmanifest.xml", dep.get("kind", "")))
    for k in ("TitleId", "StoreId", "MSAAppId"):
        if cfg.game_config.get(k):
            iid = g.node(f"identity:{k}={cfg.game_config[k]}", "identity")
            g.edge("config:MicrosoftGame.config", "DECLARES_IDENTITY", iid, CONFIRMED,
                   _ev("userdata:MicrosoftGame.config", k))
    # executaveis e DLLs: so co-empacotamento
    exes = [r for r in pkg.rows if r.name.lower().endswith(".exe")]
    dlls = [r for r in pkg.rows if r.name.lower().endswith(".dll")]
    for e in exes:
        for d in dlls:
            g.edge(f"file:{e.name}", "CO_PACKAGED_WITH", f"file:{d.name}", CONFIRMED,
                   _ev("userdata:SegmentMetadata.bin", "mesmo pacote"),
                   "nao implica import: conteudo do executavel e opaco")
            g.edge(f"file:{e.name}", "IMPORTS", f"file:{d.name}", UNKNOWN,
                   _ev("n/a", "tabela de imports ilegivel"), "nao determinavel sem um PE legivel")
    # XVD embutido
    if pkg.embedded_header:
        eid = g.node("embedded_xvd", "xvd", offset=f"0x{pkg.layout.get(EMBEDDED).offset:X}",
                     content_type=pkg.embedded_header.content_type_name, pduid=pkg.embedded_header.pduid.hex(),
                     version_raw=list(pkg.embedded_header.package_version))
        g.edge(pkg_id, "EMBEDS_XVD", eid,
               CONFIRMED if status.get("embedded.pduid_link") == "PASS" else INFERRED,
               _ev("xvc:cabecalho", "EmbeddedXVD_PDUID", 0x32C, "embedded.pduid_link"))
    return g


def query_lines(g: Graph, query: str, relation: str | None = None) -> list[str]:
    ids = g.resolve(query)
    if not ids:
        return [f"nenhum no corresponde a {query!r}"]
    out = []
    for nid in ids[:5]:
        n = g.nodes[nid]
        out.append(f"== no {nid} ({n['kind']})")
        for k, v in n.items():
            if k not in ("id", "kind"):
                out.append(f"   {k}: {v}")
        es = g.neighbors(nid, relation)
        out.append(f"   arestas: {len(es)}")
        for e in es:
            arrow = f"-> {e['target']}" if e["source"] == nid else f"<- {e['source']}"
            ev = e["evidence"]
            evs = f"{ev.get('source')} {ev.get('field', '')} {ev.get('offset', '')} teste={ev.get('test')}".strip()
            out.append(f"   [{e['confidence']:<9}] {e['relation']:<22} {arrow}   ({evs})" + (f" - {e['note']}" if e["note"] else ""))
    if len(ids) > 5:
        out.append(f"... mais {len(ids) - 5} nos correspondem")
    return out
