#!/usr/bin/env python3
"""Preuve « tableau de bord » sur le central complet (exécuté par la CI).

Instantané écrit par le vrai service, widgets enregistrés dans NetBox et
rendus, tableau de bord par défaut d'un utilisateur, page des écarts, le tout
avec une vraie session (utilisateur SSO de tools/ci_saml.py).

Usage (dans deploy/, après ci_saml.py) : python ../tools/ci_dashboard.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_mfa import URL  # noqa: E402
from ci_oidc import WORK, SSOBrowser  # noqa: E402
from ci_saml import saml_login  # noqa: E402

WIDGETS = ("FindingsWidget", "ServiceWidget", "InventoryWidget", "ZoneMatrixWidget")
RESULTS: list[tuple[str, bool]] = []

SHELL = r"""
import json
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from netbox.registry import registry
names = sorted(k for k in registry['widgets'] if k.startswith('netbox_auspex.'))
out = {'widgets': names, 'render': {}}
admin = get_user_model().objects.get(username='admin')
for k in names:
    r = RequestFactory().get('/')
    r.user = admin
    html = registry['widgets'][k](config={}).render(r)
    out['render'][k] = {'len': len(html), 'error': 'Traceback' in html,
                        'markers': [m for m in ('auspex-severity-counters', 'auspex-service-state',
                                                'auspex-inventory-counters', 'auspex-zone-matrix') if m in html]}
from extras.dashboard.utils import get_default_dashboard
d = get_default_dashboard()
out['default'] = sorted({str(v.get('class')) for v in d.config.values()})
print('AUSPEX_JSON=' + json.dumps(out))
"""


def check(label: str, ok: bool) -> None:
    ok = bool(ok)
    RESULTS.append((label, ok))
    print(f"  {'OK ' if ok else 'ÉCHEC'}  {label}", flush=True)
    # Pas d'annotation ici : l'étape CI remonte les lignes ÉCHEC (10 annotations au plus par étape).


def main() -> int:
    print("Instantané écrit par le service")
    snap_path = Path("data/state/tableau/dashboard.json")
    snap = json.loads(snap_path.read_text()) if snap_path.exists() else {}
    check("data/state/tableau/dashboard.json présent et lisible", bool(snap))
    check(f"écarts ouverts dans l'instantané : {snap.get('findings_total')}", (snap.get("findings_total") or 0) > 0)
    check("état du service : en service", (snap.get("service") or {}).get("ok") is True)
    check(f"inventaire : {(snap.get('inventory') or {}).get('total')} actifs",
          ((snap.get("inventory") or {}).get("total") or 0) > 0)

    print("Widgets dans NetBox")
    r = subprocess.run(["docker", "compose", "exec", "-T", "netbox", "/opt/netbox/venv/bin/python",
                        "/opt/netbox/netbox/manage.py", "shell", "-c", SHELL], capture_output=True, text=True,
                       timeout=180)
    line = next((l for l in r.stdout.splitlines() if l.startswith("AUSPEX_JSON=")), None)
    if line is None:
        for l in (r.stdout + r.stderr).splitlines()[-15:]:
            print(f"::error title=Tableau de bord shell::{l[:300]}", flush=True)
        check("inspection des widgets dans NetBox", False)
        return 1
    info = json.loads(line.split("=", 1)[1])
    check(f"4 widgets Auspex enregistrés ({', '.join(info['widgets'])})",
          sorted(info["widgets"]) == sorted(f"netbox_auspex.{w}" for w in WIDGETS))
    for name, res in info["render"].items():
        check(f"{name} rendu ({res['len']} caractères, {res['markers']})",
              res["len"] > 100 and not res["error"] and res["markers"])
    check(f"tableau de bord par défaut : {info['default']}",
          all(f"netbox_auspex.{w}" in info["default"] for w in WIDGETS))

    print("Avec une vraie session (utilisateur SSO saml1, droits par son groupe)")
    creds = json.loads((WORK / "saml-users.json").read_text())
    b = SSOBrowser()
    saml_login("saml1", creds["saml1"], b=b)
    status, _, page = b.open(f"{URL}/")
    check(f"page d'accueil de NetBox → HTTP {status}", status == 200)
    check("tableau de bord Auspex affiché (titres des widgets)",
          "Auspex — Écarts ouverts" in page and "Auspex — Matrice des zones" in page)
    check("widgets rendus dans la page (compteurs, matrice)",
          "auspex-severity-counters" in page and "auspex-zone-matrix" in page)
    status, _, page = b.open(f"{URL}/plugins/auspex/ecarts/")
    rows = page.count("<tr>") - 1
    check(f"page « Écarts de conformité » → HTTP {status}, {rows} écart(s) listé(s)",
          status == 200 and 'id="auspex-findings"' in page and rows == min(snap.get("findings_total", 0), 500))
    status, _, page = b.open(f"{URL}/plugins/auspex/ecarts/?gravite=critical")
    critical = snap.get("findings_by_severity", {}).get("critical", 0)
    listed = 0 if "Aucun écart ouvert" in page else page.count("<tr>") - 1
    check(f"filtre « critique » → HTTP {status}, {listed} ligne(s) (attendu {critical})",
          status == 200 and listed == critical)
    check("entrée « Écarts de conformité » dans le menu de NetBox", "Écarts de conformité" in b.open(f"{URL}/")[2])

    print("Carte interactive")
    map_path = snap_path.parent / "carte.json"
    carte = json.loads(map_path.read_text()) if map_path.exists() else {}
    nodes, edges = len(carte.get("nodes", [])), len(carte.get("edges", []))
    check(f"data/state/tableau/carte.json écrit par le service : {nodes} actifs, {edges} flux",
          nodes > 0 and edges > 0)
    status, _, page = b.open(f"{URL}/plugins/auspex/carte/")
    check(f"page « Carte des actifs » → HTTP {status}",
          status == 200 and 'data-src="/plugins/auspex/carte/donnees/"' in page)
    status, _, body = b.open(f"{URL}/plugins/auspex/carte/donnees/")
    try:
        served = json.loads(body)
    except ValueError:
        served = {}
    check(f"données de la carte → HTTP {status}, {len(served.get('nodes', []))} actifs servis",
          status == 200 and len(served.get("nodes", [])) == nodes and len(served.get("edges", [])) == edges)
    for asset in ("carte.js", "carte.css"):
        status, _, body = b.open(f"{URL}/static/netbox_auspex/{asset}")
        check(f"fichier statique {asset} servi → HTTP {status}", status == 200 and len(body) > 500)
    check("entrée « Carte des actifs » dans le menu de NetBox", "Carte des actifs" in b.open(f"{URL}/")[2])

    failed = [label for label, ok in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} vérifications réussies")
    return 1 if failed else 0


if __name__ == "__main__":
    import traceback
    try:
        rc = main()
    except SystemExit:
        raise
    except Exception:
        for line in traceback.format_exc().splitlines()[-12:]:
            print(f"::error title=Tableau de bord exception::{line}", flush=True)
        rc = 1
    print(f"::notice title=Tableau de bord::{sum(ok for _, ok in RESULTS)}/{len(RESULTS)} vérifications réussies",
          flush=True)
    raise SystemExit(rc)
