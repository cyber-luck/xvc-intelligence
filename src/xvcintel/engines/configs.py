"""Leitura das configuracoes do user data (MicrosoftGame.config, appxmanifest, hive, Summary.json)."""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from ..core.result import Ok
from ..formats.regf import parse_hive
from .package import Package


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1]


def _parse_xml(data: bytes):
    try:
        return ET.fromstring(data.decode("utf-8-sig", errors="replace"))
    except ET.ParseError:
        return None


@dataclass
class Configs:
    game_config: dict = field(default_factory=dict)
    manifest: dict = field(default_factory=dict)
    hive: dict = field(default_factory=dict)
    summary: dict = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)


def parse_game_config(data: bytes) -> dict:
    root = _parse_xml(data)
    if root is None:
        return {}
    out: dict = {"executables": [], "virtual_machine": {}, "resources": []}
    for el in root.iter():
        t = _strip_ns(el.tag)
        if t in ("MSAAppId", "TitleId", "StoreId") and el.text:
            out[t] = el.text.strip()
        elif t == "Identity":
            out["Identity"] = dict(el.attrib)
        elif t == "Executable":
            out["executables"].append(dict(el.attrib))
        elif t == "SizeMB" and el.text:
            out["PersistentLocalStorageSizeMB"] = int(el.text)
        elif t in ("SMTEnabled", "XboxLockhartTitleMemory", "XboxAnacondaTitleMemory") and el.text:
            out["virtual_machine"][t] = el.text.strip()
        elif t == "Resource":
            out["resources"].append(el.attrib.get("Language"))
        elif t == "ShellVisuals":
            out["ShellVisuals"] = dict(el.attrib)
    return out


def parse_manifest(data: bytes) -> dict:
    root = _parse_xml(data)
    if root is None:
        return {}
    out: dict = {"applications": [], "dependencies": [], "capabilities": [], "protocols": []}
    for el in root.iter():
        t = _strip_ns(el.tag)
        if t == "Identity":
            out["Identity"] = dict(el.attrib)
        elif t == "Application":
            out["applications"].append(dict(el.attrib))
        elif t in ("TargetDeviceFamily", "OSPackageDependency", "PackageDependency"):
            out["dependencies"].append({"kind": t, **el.attrib})
        elif t in ("Capability", "DeviceCapability"):
            out["capabilities"].append(el.attrib.get("Name"))
        elif t == "Protocol":
            out["protocols"].append(el.attrib.get("Name"))
    return out


def parse_hive_config(data: bytes) -> dict:
    r = parse_hive(data)
    if not isinstance(r, Ok):
        return {"error": str(r.error)}
    name, root = r.value
    out = {"internal_name": name, "root_key": root.name, "values": {v.name: v.decoded() for v in root.values},
           "executables": []}
    ex = root.find("Executable")
    if ex:
        for k in ex.subkeys:
            out["executables"].append({v.name: v.decoded() for v in k.values})
    pls = root.find("PersistentLocalStorage")
    if pls:
        out["PersistentLocalStorage"] = {v.name: v.decoded() for v in pls.values}
    return out


def load_configs(pkg: Package) -> Configs:
    c = Configs()
    ud = pkg.userdata
    if not ud:
        c.problems.append("user data ausente")
        return c
    f = ud.file("MicrosoftGame.config")
    if f:
        c.game_config = parse_game_config(f.data)
    f = ud.file("appxmanifest.xml")
    if f:
        c.manifest = parse_manifest(f.data)
    f = ud.file("microsoft_gameconfig.bin")
    if f:
        c.hive = parse_hive_config(f.data)
    f = ud.file("Summary.json")
    if f:
        try:
            c.summary = json.loads(f.data.decode("utf-8-sig"))
        except (ValueError, UnicodeDecodeError) as e:
            c.problems.append(f"Summary.json: {e}")
    return c
