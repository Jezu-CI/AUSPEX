#!/usr/bin/env python3
"""Vérifie que les licences des dépendances livrées sont compatibles avec l'AGPL v3.

    trivy rootfs --scanners license --format json -o licences.json VENV
    python tools/verifier-licences.py licences.json

Entrée : rapport JSON de Trivy (analyse de licences des paquets Python
installés). Chaque paquet doit porter au moins une licence de la liste
ACCEPTEES (expression « A OR B » : une seule suffit ; « A AND B » : toutes).
Une licence absente de la liste, inconnue ou illisible fait échouer : on la
vérifie à la main puis on l'ajoute ici, avec sa justification, si elle est
compatible. Code de sortie 0 si tout est conforme, 1 sinon.
"""
from __future__ import annotations

import json
import re
import sys

# Licences dont le code peut être combiné avec un programme sous AGPL v3 et
# redistribué sous l'AGPL v3 (liste de compatibilité de la FSF).
ACCEPTEES = {
    "0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "CC0-1.0", "HPND", "ISC",
    "MIT", "MIT-0", "MPL-2.0", "PSF-2.0", "Python-2.0", "Unlicense", "Zlib",
    "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-3.0-only", "AGPL-3.0-or-later",
}

# Libellés courants des métadonnées Python ramenés à l'identifiant SPDX.
ALIAS = {
    "mit license": "MIT", "the mit license": "MIT", "mit-cmu": "HPND",
    "bsd": "BSD-3-Clause", "bsd license": "BSD-3-Clause", "new bsd license": "BSD-3-Clause",
    "bsd-3": "BSD-3-Clause", "simplified bsd": "BSD-2-Clause",
    "apache 2.0": "Apache-2.0", "apache-2": "Apache-2.0", "apache software license": "Apache-2.0",
    "apache license 2.0": "Apache-2.0", "apache license, version 2.0": "Apache-2.0",
    "psf": "PSF-2.0", "psfl": "PSF-2.0", "python software foundation license": "PSF-2.0",
    "mpl 2.0": "MPL-2.0", "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "isc license": "ISC", "the unlicense": "Unlicense",
}


def normaliser(nom: str) -> str:
    nom = nom.strip().strip("()")
    return ALIAS.get(nom.lower(), nom)


def acceptee(expression: str) -> bool:
    """Expression SPDX simple : « A OR B » (une suffit), « A AND B » (toutes)."""
    expression = expression.strip()
    if not expression:
        return False
    alternatives = re.split(r"\s+OR\s+|\s*/\s*", expression)
    for alt in alternatives:
        parties = re.split(r"\s+AND\s+", alt)
        if all(normaliser(p) in ACCEPTEES for p in parties):
            return True
    return False


def licences(rapport: dict) -> dict[str, list[str]]:
    """{paquet: [licences]} d'après le rapport de Trivy."""
    out: dict[str, list[str]] = {}
    for res in rapport.get("Results") or []:
        for lic in res.get("Licenses") or []:
            paquet = lic.get("PkgName") or ""
            if paquet:
                out.setdefault(paquet, []).append(lic.get("Name") or "")
    return out


def verifier(rapport: dict) -> list[str]:
    """Problèmes trouvés (liste vide : tout est conforme)."""
    trouvees = licences(rapport)
    if not trouvees:
        return ["aucune licence trouvée : le rapport est vide ou l'analyse a échoué"]
    problemes = []
    for paquet, noms in sorted(trouvees.items()):
        if not any(acceptee(n) for n in noms):
            problemes.append(f"{paquet} : {' ; '.join(noms) or 'licence inconnue'}")
    return problemes


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as fh:
        rapport = json.load(fh)
    trouvees = licences(rapport)
    for paquet, noms in sorted(trouvees.items()):
        print(f"  {paquet:24s} {' ; '.join(noms)}")
    problemes = verifier(rapport)
    if problemes:
        print("\nLicences non acceptées (à vérifier, voir ACCEPTEES dans ce script) :")
        for p in problemes:
            print(f"  - {p}")
        return 1
    print(f"\n{len(trouvees)} paquets, licences toutes compatibles avec l'AGPL v3.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
