#!/usr/bin/env python3
"""SENTINEL-M SBOM generator (Phase 7).

Emits a CycloneDX 1.5 JSON software bill of materials from the *installed*
package metadata of the current Python environment (importlib.metadata — no
network calls). The result is a truthful inventory of what actually runs in
this build; it is not a curated or aspirational list.

Usage:
    python scripts/generate_sbom.py [--out docs/SBOM.json]
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from importlib.metadata import distributions
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_OUT = _REPO_ROOT / "docs" / "SBOM.json"


def collect() -> list[dict]:
    components: list[dict] = []
    for dist in distributions():
        name = dist.metadata["Name"]
        if not name:
            continue
        version = dist.version
        entry = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name.lower()}@{version}",
        }
        lic_ = dist.metadata.get("License-Expression") or dist.metadata.get("License")
        if lic_ and "UNKNOWN" not in lic_:
            entry["licenses"] = [{"license": {"id": lic_}}] if " " not in lic_ else [{"license": {"name": lic_}}]
        components.append(entry)
    components.sort(key=lambda c: c["name"].lower())
    return components


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate a CycloneDX SBOM from installed packages")
    ap.add_argument("--out", default=str(_DEFAULT_OUT))
    args = ap.parse_args()

    components = collect()
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "SENTINEL-M", "name": "generate_sbom.py",
                       "version": "1.0"}],
            "component": {
                "type": "application",
                "name": "SENTINEL-M",
                "version": "0.6.0",
                "description": "Autonomous multimodal cyber defense platform (local-first)",
            },
        },
        "components": components,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bom, indent=2), encoding="utf-8")
    print(f"SBOM written: {out} ({len(components)} components)")
    return 0


if __name__ == "__main__":
    sys.exit(main())