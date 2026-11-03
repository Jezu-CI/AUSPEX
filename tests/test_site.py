"""Site web : assemblage des sources, navigation complète, liens réécrits."""
import importlib.util
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def _site():
    spec = importlib.util.spec_from_file_location("site_tool", ROOT / "tools" / "site.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _nav_pages(nav):
    for item in nav:
        if isinstance(item, str):
            yield item
        else:
            for v in item.values():
                yield from ([v] if isinstance(v, str) else _nav_pages(v))


def test_every_nav_page_is_assembled():
    site = _site()
    site.assemble()
    conf = yaml.load((ROOT / "mkdocs.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    for page in _nav_pages(conf["nav"]):
        assert (site.OUT / page).is_file(), page
    # Chaque document technique est dans la navigation
    nav = set(_nav_pages(conf["nav"]))
    for doc in (ROOT / "docs").glob("*.md"):
        assert site.PAGES[f"docs/{doc.name}"] in nav, doc.name


def test_links_rewritten():
    site = _site()
    out = site.rewrite("[a](docs/02-capteur.md#x) [b](deploy/install.sh) [c](https://e.org) [d](#y)",
                       "README.md", "guide.md")
    assert "(documentation/02-capteur.md#x)" in out
    assert "(https://github.com/Jezu-CI/AUSPEX/blob/main/deploy/install.sh)" in out
    assert "(https://e.org)" in out and "(#y)" in out
    back = site.rewrite("[r](../README.md)", "docs/02-capteur.md", "documentation/02-capteur.md")
    assert "(../guide.md)" in back


def test_gallery_images_exist():
    site = _site()
    for img in re.findall(r"\]\((assets/captures/[^)]+)\)", site.gallery()):
        assert (ROOT / "site" / img).is_file(), img


def test_pages_workflow_pinned():
    wf = (ROOT / ".github/workflows/site.yml").read_text(encoding="utf-8")
    assert '"mkdocs>=1.6,<2"' in wf and '"mkdocs-material>=9.5,<10"' in wf
    assert "tools/site.py --build" in wf and "deploy-pages" in wf
