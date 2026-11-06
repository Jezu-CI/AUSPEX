"""Site web : assemblage des sources, navigation complète, liens réécrits."""
import importlib.util
import json
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
    assert "--require-hashes -r requirements/site.txt" in wf
    # Bornes (MkDocs 1.x, Material 9.x) dans le fichier source, versions exactes figées dans site.txt
    src = (ROOT / "requirements/site.in").read_text(encoding="utf-8")
    assert "mkdocs>=1.6,<2" in src and "mkdocs-material>=9.5,<10" in src
    lock = (ROOT / "requirements/site.txt").read_text(encoding="utf-8")
    assert re.search(r"^mkdocs==1\.\d+", lock, re.M) and re.search(r"^mkdocs-material==9\.\d+", lock, re.M)
    assert "tools/site.py --build" in wf and "deploy-pages" in wf


def _front_matter(path):
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return {}
    return yaml.safe_load(text.split("---\n", 2)[1]) or {}


def test_every_page_has_a_description():
    """Référencement : chaque page du menu a une description précise (balise meta, aperçus)."""
    site = _site()
    site.assemble()
    conf = yaml.load((ROOT / "mkdocs.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    for page in _nav_pages(conf["nav"]):
        desc = _front_matter(site.OUT / page).get("description", "")
        assert 70 <= len(desc) <= 300, (page, len(desc))


def test_faq_structured_data():
    site = _site()
    items = yaml.safe_load((ROOT / "site/faq.yaml").read_text(encoding="utf-8"))
    page = site.faq()
    data = json.loads(re.search(r'<script type="application/ld\+json">(.*?)</script>', page, re.S).group(1))
    assert data["@type"] == "FAQPage" and len(data["mainEntity"]) == len(items) >= 10
    for q in data["mainEntity"]:
        text = q["acceptedAnswer"]["text"]
        assert "](" not in text and "**" not in text  # texte brut, sans Markdown


def test_llms_txt_links_exist():
    """llms.txt (moteurs de réponse IA) : chaque lien du site pointe vers une page assemblée."""
    site = _site()
    site.assemble()
    text = (ROOT / "site/llms.txt").read_text(encoding="utf-8")
    links = re.findall(r"\(https://jezu-ci\.github\.io/AUSPEX/([^)]*)\)", text)
    assert len(links) >= 10
    for link in links:
        path = link.rstrip("/")
        assert path == "" or (site.OUT / f"{path}.md").is_file() or (site.OUT / path / "index.md").is_file(), link


def test_seo_template_and_social_image():
    tpl = (ROOT / "overrides/main.html").read_text(encoding="utf-8")
    for needle in ('property="og:image"', 'name="twitter:card"', '"@type": "SoftwareApplication"', "hreflang"):
        assert needle in tpl
    assert (ROOT / "site/assets/auspex-apercu-social.png").is_file()
    assert "overrides/**" in (ROOT / ".github/workflows/site.yml").read_text(encoding="utf-8")
