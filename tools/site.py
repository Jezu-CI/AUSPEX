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

# Description de chaque page assemblée (balise meta description, aperçus de partage) :
# une phrase précise, avec les mots que cherchent les visiteurs.
DESCRIPTIONS = {
    "guide.md": "Guide d'Auspex : installer le central NetBox + Auspex, déployer un capteur passif "
                "(Docker ou appliance ISO), règles de flux, identification des actifs, commandes.",
    "versions.md": "Journal des versions d'Auspex, CMDB passive IT/OT : nouveautés, corrections et "
                   "changements de chaque version.",
    "securite.md": "Politique de sécurité d'Auspex : signaler une vulnérabilité, versions maintenues, "
                   "engagements et limites connues.",
    "composants-tiers.md": "Composants tiers d'Auspex (NetBox, Zeek, analyseurs ICSNPP, Valkey…) et "
                           "leurs licences, compatibles avec l'AGPL v3.",
    "documentation/index.md": "Documentation d'Auspex : authentification, capteurs, exports d'audit, "
                              "exploitation, référence de configuration et preuves automatisées.",
    "documentation/01-authentification.md": "Authentification dans Auspex et NetBox : MFA (TOTP, e-mail, "
        "clé de sécurité WebAuthn), carte à puce, LDAPS, OIDC, SAML, compte de secours.",
    "documentation/02-capteur.md": "Capteurs Auspex : écoute passive d'un port miroir ou d'un TAP avec Zeek "
        "et ICSNPP, appliance ISO durcie, envoi des journaux, mises à jour signées A/B.",
    "documentation/03-audits.md": "Exports d'audit d'Auspex pour NIS2, DORA et IEC 62443 : contenu, format, "
        "signature, chaînage et vérification sans Auspex.",
    "documentation/04-exploitation.md": "Exploiter Auspex : installation, mise à jour et retour arrière, "
        "sauvegardes, supervision, journaux et dépannage.",
    "documentation/05-configuration.md": "Référence de configuration d'Auspex : auspex.yaml, .env, "
        "capteur.conf, chaque clé expliquée, sorties SIEM (syslog CEF/JSON, webhook).",
    "documentation/06-preuves-ci.md": "Ce que la CI d'Auspex prouve à chaque modification : vrai NetBox, "
        "vrai navigateur, appliance en machine virtuelle, captures industrielles réelles.",
}


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


# Titre de l'onglet et des résultats de recherche (le menu garde son libellé court)
TITLES = {
    "guide.md": "Guide d'installation et d'utilisation",
    "documentation/01-authentification.md": "Authentification : MFA, WebAuthn, carte à puce, LDAPS, OIDC, SAML",
    "documentation/02-capteur.md": "Capteur passif : Zeek, ICSNPP et appliance ISO",
    "documentation/03-audits.md": "Exports d'audit NIS2, DORA et IEC 62443",
    "documentation/04-exploitation.md": "Exploitation : installation, mises à jour, sauvegardes",
    "documentation/05-configuration.md": "Référence de configuration",
    "documentation/06-preuves-ci.md": "Preuves automatisées : ce que la CI vérifie",
}


def with_description(text: str, page: str) -> str:
    """Ajoute titre et description de la page en tête (front matter), sauf si le fichier en a déjà un."""
    desc = DESCRIPTIONS.get(page)
    if not desc or text.startswith("---\n"):
        return text
    head = [f"description: {json.dumps(desc, ensure_ascii=False)}"]
    if page in TITLES:
        head.insert(0, f"title: {json.dumps(TITLES[page], ensure_ascii=False)}")
    return "---\n" + "\n".join(head) + "\n---\n\n" + text


def _plain(markdown: str) -> str:
    """Texte brut d'une réponse Markdown (données structurées)."""
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", markdown)
    return re.sub(r"\*\*([^*]+)\*\*", r"\1", text).strip()


def faq() -> str:
    """Page FAQ et ses données structurées schema.org/FAQPage (moteurs de recherche et IA)."""
    import yaml
    items = yaml.safe_load((ROOT / "site/faq.yaml").read_text(encoding="utf-8"))
    data = {"@context": "https://schema.org", "@type": "FAQPage", "inLanguage": "fr",
            "mainEntity": [{"@type": "Question", "name": i["q"],
                            "acceptedAnswer": {"@type": "Answer", "text": _plain(i["a"])}} for i in items]}
    lines = ["---", "title: Questions fréquentes sur Auspex",
             "description: " + json.dumps("Questions fréquentes sur Auspex, CMDB passive IT/OT : écoute "
                                          "passive, protocoles industriels, segmentation, NIS2, DORA, "
                                          "IEC 62443, NetBox, licence, prérequis.", ensure_ascii=False),
             "---", "", "# Questions fréquentes", ""]
    for i in items:
        lines += [f"## {i['q']}", "", i["a"].strip(), ""]
    lines += ['<script type="application/ld+json">', json.dumps(data, ensure_ascii=False, indent=1), "</script>", ""]
    return "\n".join(lines)


def gallery() -> str:
    shots = json.loads((ROOT / "site/assets/captures/index.json").read_text(encoding="utf-8"))
    lines = ["---", "title: Captures d'écran",
             "description: " + json.dumps("Captures d'écran d'Auspex : tableau de bord, carte des actifs IT/OT, "
                                          "écarts de segmentation, exports d'audit NIS2, authentification MFA "
                                          "et SSO.", ensure_ascii=False),
             "---", "", "# Captures d'écran", "",
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
                  f"![{s['title']}](assets/captures/{s['file']}){{ loading=lazy }}", ""]
    return "\n".join(lines)


def assemble() -> None:
    shutil.rmtree(OUT, ignore_errors=True)
    shutil.copytree(ROOT / "site", OUT)
    for src, page in PAGES.items():
        dest = OUT / page
        dest.parent.mkdir(parents=True, exist_ok=True)
        text = rewrite((ROOT / src).read_text(encoding="utf-8"), src, page)
        dest.write_text(with_description(text, page), encoding="utf-8")
    (OUT / "captures.md").write_text(gallery(), encoding="utf-8")
    (OUT / "faq.md").write_text(faq(), encoding="utf-8")
    (OUT / "faq.yaml").unlink()


def main(argv: list[str]) -> int:
    assemble()
    print(f"Sources du site : {OUT.relative_to(ROOT)} ({sum(1 for _ in OUT.rglob('*.md'))} pages)")
    if "--build" in argv:
        return subprocess.call(["mkdocs", "build", "--strict", "-f", str(ROOT / "mkdocs.yml")], cwd=ROOT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
