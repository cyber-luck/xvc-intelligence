"""Indice de artefatos por hash: duplicacoes exatas e colisoes de nome."""
from __future__ import annotations


def build_index(inventory: dict) -> dict:
    by_sha: dict[str, list[dict]] = {}
    by_name: dict[str, list[dict]] = {}
    for r in inventory.get("files", []):
        if r.get("sha256_mode") == "full" and r.get("sha256"):
            by_sha.setdefault(r["sha256"], []).append({"path": r["path"], "size": r["size"]})
        by_name.setdefault(r["name"].lower(), []).append({"path": r["path"], "size": r["size"], "sha256": r.get("sha256")})
    duplicates = {h: v for h, v in by_sha.items() if len(v) > 1}
    return {
        "schema": "alpha_recovery.artifact_index/1",
        "files_indexed": len(inventory.get("files", [])),
        "sha256_full_indexed": sum(len(v) for v in by_sha.values()),
        "exact_duplicates": {h: v for h, v in sorted(duplicates.items())},
        "same_name_different_bytes": {
            n: v for n, v in sorted(by_name.items())
            if len({x.get("sha256") for x in v}) > 1 and len(v) > 1
        },
        "note": "hash parcial head+tail nunca entra no indice de duplicados",
    }
