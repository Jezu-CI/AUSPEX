#!/usr/bin/env python3
"""Site web du projet (GitHub Pages), construit depuis le dépôt.

  python tools/site.py [--build]

Assemble build/site-src : pages du site (site/), guide (README), documentation
technique (docs/), journal des versions, sécurité, composants tiers et galerie
des captures d'écran (site/assets/captures/index.json). Les liens relatifs vers
des fichiers du dépôt qui ne sont pas des pages du site deviennent des liens
vers GitHub. --build lance ensuite « mkdocs build --strict » (liens vérifiés).
"""

from __future__ import annotations

import json
import posixpath
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "build" / "site-src"
GITHUB = "https://github.com/Jezu-CI/AUSPEX"

# Fichier du dépôt → page du site
PAGES = {
    "README.md": "guide.md",
    "CHANGELOG.md": "versions.md",
    "SECURITY.md": "securite.md",
    "THIRD-PARTY.md": "composants-tiers.md",
    "docs/README.md": "documentation/index.md",
}
for doc in sorted((ROOT / "docs").glob("*.md")):
    PAGES.setdefault(f"docs/{doc.name}", f"documentation/{doc.name}")

LINK = re.compile(r"(\]\()([^)\s]+)(\))")


def rewrite(text: str, source: str, page: str) -> str:
    """Liens relatifs du fichier `source` (chemin dans le dépôt) pour la page `page` du site."""
    def repl(m: re.Match) -> str:
        target = m.group(2)
        if re.match(r"^[a-z]+:|^#|^/", target):
            return m.group(0)
        path, _, anchor = target.partition("#")
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(source), path))
        if resolved in PAGES:
            new = posixpath.relpath(PAGES[resolved], posixpath.dirname(page) or ".")
        else:
            kind = "tree" if (ROOT / resolved).is_dir() else "blob"
            new = f"{GITHUB}/{kind}/main/{resolved}"
        return f"{m.group(1)}{new}{'#' + anchor if anchor else ''}{m.group(3)}"
    return LINK.sub(repl, text)


def gallery() -> str:
    shots = json.loads((ROOT / "site/assets/captures/index.json").read_text(encoding="utf-8"))
    lines = ["---", "title: Captures d'écran", "---", "", "# Captures d'écran", "",
             "Écrans réels d'un central Auspex de démonstration, produits automatiquement "
             "par la CI ([workflow « Captures d'écran »]"
             f"({GITHUB}/blob/main/.github/workflows/captures.yml)). Données de démonstration : "
             "aucun système réel.", ""]
    stage = None
    for s in shots:
        if s["stage"] != stage:
            stage = s["stage"]
            lines += [f"## {stage}", ""]
        lines += [f"### {s['title']}", "", s["text"], "",
                  f"![{s['title']}](assets/captures/{s['file']})", ""]
    return "\n".join(lines)


def assemble() -> None:
    shutil.rmtree(OUT, ignore_errors=True)
    shutil.copytree(ROOT / "site", OUT)
    for src, page in PAGES.items():
        dest = OUT / page
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(rewrite((ROOT / src).read_text(encoding="utf-8"), src, page), encoding="utf-8")
    (OUT / "captures.md").write_text(gallery(), encoding="utf-8")


def main(argv: list[str]) -> int:
    assemble()
    print(f"Sources du site : {OUT.relative_to(ROOT)} ({sum(1 for _ in OUT.rglob('*.md'))} pages)")
    if "--build" in argv:
        return subprocess.call(["mkdocs", "build", "--strict", "-f", str(ROOT / "mkdocs.yml")], cwd=ROOT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
