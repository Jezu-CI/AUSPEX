#!/usr/bin/env python3
"""Images de conteneurs livrées avec Auspex, en JSON (pour l'analyse de vulnérabilités).

    python tools/images-livrees.py

Sources : lignes FROM des Dockerfile (images figées par empreinte) et images
tierces du docker-compose du central. Les images construites par Auspex
(auspex-*) en sont exclues : leurs bases figurent déjà dans la liste.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIGEE = re.compile(r"^FROM\s+(\S+@sha256:[0-9a-f]{64})", re.M)
COMPOSE = re.compile(r"^\s+image:\s*([^\s$]+)\s*$", re.M)


def images() -> list[str]:
    out: set[str] = set()
    for df in sorted(ROOT.glob("**/Dockerfile")):
        if "build" in df.relative_to(ROOT).parts or ".git" in df.parts:
            continue
        out.update(FIGEE.findall(df.read_text(encoding="utf-8")))
    for img in COMPOSE.findall((ROOT / "deploy/docker-compose.yml").read_text(encoding="utf-8")):
        if not img.startswith("auspex-"):
            out.add(img)
    return sorted(out)


if __name__ == "__main__":
    print(json.dumps(images()))
