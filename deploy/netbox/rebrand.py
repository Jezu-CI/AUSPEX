"""Marque Auspex dans l'image NetBox (exécuté à la construction de l'image).

- logos et icône remplacés (mêmes noms de fichiers : les gabarits de NetBox
  restent inchangés pour cela) ;
- titre des onglets « … | Auspex » ;
- liens commerciaux et support de NetBox Labs retirés (trompeurs pour un
  utilisateur d'Auspex), mention « basé sur NetBox Community » conservée
  (licence Apache 2.0 et transparence) ;
- feuille de style de la charte « Scanner Auspex » chargée après celles de
  NetBox.

Les remplacements essentiels (logos, titre, feuille de style) doivent
s'appliquer, sinon la construction échoue : une nouvelle version de NetBox
qui change ses gabarits est ainsi détectée au lieu de passer inaperçue.

Usage : python rebrand.py <racine NetBox> <répertoire branding>
"""

from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

root, branding = Path(sys.argv[1]), Path(sys.argv[2])
static, templates = root / "static", root / "templates"
problems: list[str] = []


def replace(path: Path, old: str, new: str, required: bool = True, regex: bool = False) -> None:
    text = path.read_text(encoding="utf-8")
    count = len(re.findall(old, text, re.S)) if regex else text.count(old)
    if count == 0:
        (problems.append if required else print)(f"{path.relative_to(root)} : motif introuvable : {old!r}")
        return
    text = re.sub(old, new, text, flags=re.S) if regex else text.replace(old, new)
    path.write_text(text, encoding="utf-8")
    print(f"{path.relative_to(root)} : {count} remplacement(s)")


# --- Fichiers statiques -----------------------------------------------------------
for name, src in (("logo_netbox_dark_teal.svg", "auspex-logo-light.svg"),   # thème clair
                  ("logo_netbox_bright_teal.svg", "auspex-logo-dark.svg"),  # thème sombre
                  ("netbox_icon.svg", "auspex-icon.svg")):
    target = static / name
    if not target.exists():
        problems.append(f"static/{name} absent")
        continue
    shutil.copyfile(branding / src, target)
    print(f"static/{name} ← {src}")
(static / "auspex").mkdir(exist_ok=True)
shutil.copyfile(branding / "auspex.css", static / "auspex" / "auspex.css")
shutil.copyfile(branding / "auspex-icon.svg", static / "auspex" / "favicon.svg")

# --- Gabarits ----------------------------------------------------------------------------
base, layout, login = templates / "base" / "base.html", templates / "base" / "layout.html", templates / "login.html"
replace(base, "| NetBox</title>", "| Auspex</title>")
replace(base, "</head>", '  <link rel="stylesheet" href="{% static \'auspex/auspex.css\' %}">\n'
                         '  <link rel="icon" type="image/svg+xml" href="{% static \'auspex/favicon.svg\' %}">\n</head>')
# Menu latéral sombre dans les deux thèmes : toujours le logo à texte clair.
replace(layout, '{% static \'logo_netbox_dark_teal.svg\' %}" alt="{% trans "NetBox Logo" %}" '
                'class="navbar-brand-image hide-theme-dark"',
        '{% static \'logo_netbox_bright_teal.svg\' %}" alt="Auspex" class="navbar-brand-image hide-theme-dark"')
for tpl in (layout, login):
    replace(tpl, '{% trans "NetBox Logo" %}', "Auspex")
# Liens commerciaux (Cloud, Enterprise) → mention « basé sur NetBox Community »
replace(layout, r'<a href="https://netboxlabs\.com/netbox-cloud/"[^>]*>.*?</a>\s*\|\s*'
                r'<a href="https://netboxlabs\.com/netbox-enterprise/"[^>]*>.*?</a>',
        '<span class="auspex-credit">Auspex · basé sur NetBox Community (Apache 2.0)</span>', regex=True)
# Support de NetBox Labs : sans objet pour Auspex
replace(layout, r'<a href="mailto:support@netboxlabs\.com"[^>]*>.*?</a>', "", required=False, regex=True)
# Connexion par carte à puce : bouton vers le port carte du front HTTPS (si configurée)
replace(login, "{# SSO login #}",
        '{% if settings.AUSPEX_CARTE_URL %}<div class="card-body pt-0"><a href="{{ settings.AUSPEX_CARTE_URL }}'
        '{% if \'next\' in request.GET %}?next={{ request.GET.next|urlencode }}{% endif %}" '
        'class="btn btn-outline-primary w-100" id="auspex-carte">Connexion par carte à puce</a></div>{% endif %}\n'
        '        {# SSO login #}')
replace(templates / "rest_framework" / "api.html", ">NetBox</a>", ">Auspex</a>", required=False)
replace(templates / "rest_framework" / "api.html", "NetBox {% trans \"REST API\" %}", "Auspex {% trans \"REST API\" %}",
        required=False)
replace(templates / "media_failure.html", "Static Media Failure - NetBox", "Static Media Failure - Auspex",
        required=False)

if problems:
    print("\n".join(problems), file=sys.stderr)
    sys.exit("marque Auspex : gabarits de NetBox inattendus (nouvelle version ?)")
print("marque Auspex appliquée")
