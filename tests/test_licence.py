"""Licence (AGPL v3 + attribution) et liens internes du dépôt public."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ATTRIBUTION = "Basé sur Auspex, projet conçu par Yann Mathon"


def test_license_is_agpl_v3():
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert text.lstrip().startswith("GNU AFFERO GENERAL PUBLIC LICENSE")
    assert "Version 3, 19 November 2007" in text
    assert "13. Remote Network Interaction; Use with the GNU General Public License." in text
    assert len(text.splitlines()) > 600  # texte intégral


def test_notice_attribution_term():
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    assert ATTRIBUTION in notice and "https://github.com/Jezu-CI/AUSPEX" in notice
    assert "article 7, alinéa b" in notice and "Yann Mathon" in notice


def test_attribution_shown_in_plugin():
    tpl = ROOT / "netbox-plugin/netbox_auspex/templates/netbox_auspex"
    assert ATTRIBUTION in (tpl / "widgets/_attribution.html").read_text(encoding="utf-8")
    for page in ("widgets/service.html", "findings.html"):
        assert '{% include "netbox_auspex/widgets/_attribution.html" %}' in (tpl / page).read_text(encoding="utf-8")


def test_license_declared_everywhere():
    assert 'license = { text = "AGPL-3.0-only" }' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "licence-AGPL%20v3" in readme and "[GNU AGPL v3](LICENSE)" in readme
    assert "licence AGPL v3" in (ROOT / "mkdocs.yml").read_text(encoding="utf-8")
    assert "licence GNU AGPL v3" in (ROOT / "THIRD-PARTY.md").read_text(encoding="utf-8")


LINK = re.compile(r"\]\(([^)\s]+)\)")


def test_relative_links_resolve():
    """Aucun lien relatif d'un fichier Markdown du dépôt ne pointe vers un fichier absent."""
    broken = []
    for md in ROOT.rglob("*.md"):
        rel = md.relative_to(ROOT)
        if rel.parts[0] in ("build", ".git", ".pytest_cache", "site") or "node_modules" in rel.parts:  # site/ : vérifié par mkdocs --strict
            continue
        for target in LINK.findall(md.read_text(encoding="utf-8")):
            if re.match(r"^[a-z]+:|^#|^/", target):
                continue
            path = target.split("#")[0]
            if path and not (md.parent / path).exists():
                broken.append(f"{rel} → {target}")
    assert not broken, broken


def test_github_links_to_repo_files_resolve():
    """Liens absolus vers des fichiers du dépôt (blob/tree main) : le fichier existe."""
    broken = []
    pat = re.compile(r"https://github\.com/Jezu-CI/AUSPEX/(?:blob|tree)/main/([^)\s#\"'`]+)")
    for f in list(ROOT.rglob("*.md")) + list(ROOT.rglob("*.yml")) + list(ROOT.rglob("*.py")):
        rel = f.relative_to(ROOT)
        if rel.parts[0] in ("build", ".git") or f.name == "test_licence.py":
            continue
        for path in pat.findall(f.read_text(encoding="utf-8", errors="ignore")):
            if not (ROOT / path).exists():
                broken.append(f"{rel} → {path}")
    assert not broken, broken
