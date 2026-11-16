"""Analyse des dépendances livrées : licences (AGPL v3), images, installation de Trivy."""
import importlib.util
import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent


def _charger(nom, fichier):
    spec = importlib.util.spec_from_file_location(nom, ROOT / "tools" / fichier)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


licences = _charger("verifier_licences", "verifier-licences.py")
images = _charger("images_livrees", "images-livrees.py")


def _rapport(*paquets):
    return {"Results": [{"Target": "Python license",
                         "Licenses": [{"PkgName": p, "Name": n} for p, n in paquets]}]}


@pytest.mark.parametrize("expression", [
    "MIT", "MIT-0", "PSF-2.0", "Apache-2.0 OR BSD-3-Clause", "BSD License", "MIT License",
    "Apache Software License", "LGPL-3.0-or-later", "GPL-2.0-or-later", "AGPL-3.0-only",
    "MIT AND BSD-3-Clause", "(MIT)", "BSD-2-Clause / MIT",
])
def test_licences_compatibles(expression):
    assert licences.acceptee(expression)


@pytest.mark.parametrize("expression", [
    "GPL-2.0-only",               # pas de passage à la v3 : incompatible
    "SSPL-1.0", "BUSL-1.1", "CC-BY-NC-4.0", "Proprietary", "UNKNOWN", "",
    "MIT AND SSPL-1.0",           # toutes les parties d'un AND doivent passer
    "Commons-Clause",
])
def test_licences_refusees(expression):
    assert not licences.acceptee(expression)


def test_rapport_conforme_et_paquet_refuse():
    ok = _rapport(("PyYAML", "MIT"), ("cryptography", "Apache-2.0 OR BSD-3-Clause"))
    assert licences.verifier(ok) == []
    ko = _rapport(("PyYAML", "MIT"), ("module-x", "SSPL-1.0"))
    assert licences.verifier(ko) == ["module-x : SSPL-1.0"]


def test_rapport_vide_refuse():
    """Une analyse qui ne trouve rien ne doit pas passer pour conforme."""
    assert licences.verifier({"Results": []})
    assert licences.verifier({})


def test_une_licence_acceptee_suffit_pour_un_paquet_a_plusieurs_licences():
    assert licences.verifier(_rapport(("double", "LicenseRef-x"), ("double", "MIT"))) == []


def test_sortie_et_code_retour(tmp_path, capsys):
    f = tmp_path / "licences.json"
    f.write_text(json.dumps(_rapport(("openpyxl", "MIT"))), encoding="utf-8")
    assert licences.main(["x", str(f)]) == 0
    f.write_text(json.dumps(_rapport(("module-x", "BUSL-1.1"))), encoding="utf-8")
    assert licences.main(["x", str(f)]) == 1
    assert "module-x : BUSL-1.1" in capsys.readouterr().out


def test_images_livrees():
    liste = images.images()
    assert liste == sorted(set(liste))
    assert not [i for i in liste if i.startswith("auspex-")]
    # Bases du produit : NetBox, Python (central), Zeek (capteur), nginx (accès).
    for nom in ("netboxcommunity/netbox:", "python:", "zeek/zeek:", "nginxinc/nginx-unprivileged:"):
        assert any(i.startswith(nom) and "@sha256:" in i for i in liste), nom
    # Images tierces du docker-compose (données, cache).
    assert any(i.startswith("postgres:") and "@sha256:" in i for i in liste)
    assert any(i.startswith("valkey/valkey:") and "@sha256:" in i for i in liste)


def test_trivy_installe_a_version_figee():
    script = (ROOT / "tools/installer-trivy.sh").read_text(encoding="utf-8")
    assert re.search(r'^VERSION="0\.69\.3"$', script, re.M)
    assert re.search(r'^SHA256="[0-9a-f]{64}"$', script, re.M)
    assert "sha256sum -c" in script


def test_workflow_sans_action_trivy():
    """Les étiquettes de trivy-action et setup-trivy ont été détournées (CVE-2026-33634)."""
    texte = (ROOT / ".github/workflows/dependances.yml").read_text(encoding="utf-8")
    assert "aquasecurity/" not in texte
    wf = yaml.safe_load(texte)
    etapes = [s for j in wf["jobs"].values() for s in j["steps"]]
    assert sum("tools/installer-trivy.sh" in s.get("run", "") for s in etapes) == 2
    assert any("tools/verifier-licences.py licences.json" in s.get("run", "") for s in etapes)
    assert any("--require-hashes -r requirements/execution.txt" in s.get("run", "") for s in etapes)
    assert any("--exit-code 1" in s.get("run", "") for s in wf["jobs"]["python"]["steps"])
