#!/usr/bin/env python3
"""Résume les logs Zeek et les résultats de tests en annotations GitHub Actions.

Les annotations sont visibles sur la page du run et lisibles par l'API GitHub,
ce qui permet un diagnostic sans télécharger les journaux complets.

Usage : python tools/ci_annotate.py RÉPERTOIRE_LOGS RÉSULTATS_JUNIT.xml
"""

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

MAX = 60000  # taille maximale d'une annotation


def esc(s: str) -> str:
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def annotate(level: str, title: str, body: str) -> None:
    print(f"::{level} title={title}::{esc(body[:MAX])}")


def main(logs: str, junit: str | None) -> None:
    lines = []
    for p in sorted(Path(logs).glob("*.log")):
        recs = []
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("{"):
                try:
                    recs.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        fields = sorted({k for r in recs for k in r})
        lines.append(f"== {p.name} ({len(recs)} enregistrements)\nchamps : {', '.join(fields)}")
        if p.stem not in {"conn", "packet_filter", "loaded_scripts"}:
            for r in recs[:2]:
                lines.append("  " + json.dumps(r, ensure_ascii=False)[:600])
    annotate("notice", "Logs Zeek", "\n".join(lines) or "aucun log")

    conn = Path(logs) / "conn.log"
    if conn.exists():
        svc = sorted({f"{r.get('id.resp_p')}/{r.get('proto')}={r.get('service', '-')}:{r.get('conn_state')}"
                      for r in map(json.loads, (l for l in conn.read_text().splitlines() if l.startswith("{")))})
        annotate("notice", "Services conn.log", "\n".join(svc))

    if junit and Path(junit).exists():
        root = ET.parse(junit).getroot()
        out = []
        for case in root.iter("testcase"):
            for tag in ("failure", "error", "skipped"):
                el = case.find(tag)
                if el is not None:
                    msg = (el.get("message") or "") + "\n" + (el.text or "")[-1500:]
                    out.append(f"[{tag}] {case.get('name')}\n{msg.strip()}")
        annotate("warning" if out else "notice", "Tests d'intégration", "\n\n".join(out) or "tout est passé")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
