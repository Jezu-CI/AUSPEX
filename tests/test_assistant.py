"""Assistant de première configuration (auspex init) et son appel par install.sh."""
import io
import json
from pathlib import Path

import pytest
import yaml

from auspex import assistant
from auspex.cli import main
from auspex.config import parse_config

ROOT = Path(__file__).resolve().parent.parent
MODELE = ROOT / "deploy" / "auspex.yaml.template"

# Parcours complet : deux zones (une saisie erronée corrigée à chaque étape), un SIEM TLS,
# deux référentiels, confirmation.
PARCOURS = [
    "o",                         # décrire les zones
    "Ville de Démo",             # organisation
    "1", "",                     # type Tier 0, nom proposé (T0-AD)
    "10.0.0.0/33",               # plage invalide…
    "10.0.0.0/24",               # …corrigée
    "o",                         # autre zone
    "?", "9", "OT N2",           # « ? » réaffiche les types ; Purdue 2, nom invalide (espace)…
    "OT-N2",                     # …corrigé
    "10.0.0.128/25",             # chevauche T0-AD…
    "172.16.2.0/24, 172.16.20.0/24",
    "n",                         # plus de zone
    "o", "1", "siem.demo.local", "70000", "",   # SIEM TLS, port invalide puis 6514
    "1",                         # CEF
    "1,9",                       # référentiel inexistant…
    "1, 3",                      # …NIS2, IEC 62443
]


def _dialogue(lignes):
    entree = iter([ligne + "\n" for ligne in lignes])
    sortie = []
    return assistant.Dialogue(lambda: next(entree, ""), sortie.append), sortie


def test_parcours_complet():
    d, sortie = _dialogue(PARCOURS)
    rep = assistant.questionner(d)
    assert rep.organisation == "Ville de Démo"
    assert rep.zones == [
        {"name": "T0-AD", "class": "tier0", "prefixes": ["10.0.0.0/24"]},
        {"name": "OT-N2", "class": "purdue2", "prefixes": ["172.16.2.0/24", "172.16.20.0/24"]},
    ]
    assert rep.siem == {"transport": "tls", "hote": "siem.demo.local", "port": 6514, "format": "cef"}
    assert rep.referentiels == ["nis2", "iec62443"]
    texte = "".join(sortie)
    for erreur in ("n'est pas une plage", "Nom invalide", "chevauche", "Port entre", "Numéros entre"):
        assert erreur in texte

    cfg = parse_config(yaml.safe_load(assistant.construire(rep, MODELE.read_text())), base_dir=ROOT / "deploy")
    assert [z.name for z in cfg.zones] == ["T0-AD", "OT-N2"]
    assert cfg.organisation == "Ville de Démo"
    assert cfg.audit.frameworks == ("nis2", "iec62443")
    assert [o.url for o in cfg.alerts.outputs if o.type == "syslog"] == ["tls://siem.demo.local:6514"]


def test_le_fichier_garde_les_commentaires_du_modele():
    rep = assistant.Reponses(zones=[{"name": "Z", "class": "other", "prefixes": ["10.0.0.0/8"]}])
    texte = assistant.construire(rep, MODELE.read_text())
    assert "# Restriction des connexions à NetBox par IP source" in texte
    assert "T1-serveurs" not in texte                    # zones d'exemple remplacées


def test_garder_l_exemple():
    d, _ = _dialogue(["n"])
    assert assistant.questionner(d) is None


def test_un_nom_ne_peut_pas_injecter_de_structure():
    rep = assistant.Reponses(organisation='Ville "A"\nzones: []  # piège',
                             zones=[{"name": "Z", "class": "other", "prefixes": ["10.0.0.0/8"]}])
    raw = yaml.safe_load(assistant.construire(rep, MODELE.read_text()))
    assert raw["organisation"] == 'Ville "A"\nzones: []  # piège'
    assert raw["zones"][0]["name"] == "Z"


@pytest.mark.parametrize("texte, attendu", [
    ("10.0.0.0/24", ["10.0.0.0/24"]),
    ("10.0.0.5/24 ; 192.168.1.0/24", ["10.0.0.0/24", "192.168.1.0/24"]),
    ("2001:db8::/32", ["2001:db8::/32"]),
])
def test_plages(texte, attendu):
    assert assistant.plages(texte) == attendu


@pytest.mark.parametrize("texte", ["", "10.0.0.0/33", "0.0.0.0/0", "serveurs"])
def test_plages_refusees(texte):
    with pytest.raises(ValueError):
        assistant.plages(texte)


def _init(monkeypatch, capsys, entree, *args):
    monkeypatch.setattr("sys.stdin", io.StringIO(entree))
    code = main(["init", "--modele", str(MODELE), *args])
    return code, capsys.readouterr()


def test_commande_sortie_propre(monkeypatch, capsys):
    """Questions sur la sortie d'erreur, configuration seule sur la sortie standard."""
    code, out = _init(monkeypatch, capsys, "\n".join(PARCOURS + ["o"]) + "\n")
    assert code == 0
    assert "Zone n° 1" in out.err and "Récapitulatif" in out.err
    assert out.err.count("Tier 1 : serveurs") == 2      # liste montrée une fois, puis sur « ? »
    assert "Zone n° 1" not in out.out
    assert yaml.safe_load(out.out)["organisation"] == "Ville de Démo"


def test_commande_interrompue_rend_le_modele(monkeypatch, capsys):
    code, out = _init(monkeypatch, capsys, "o\nVille\n")       # fin de saisie au milieu
    assert code == 0 and out.out == MODELE.read_text()
    assert "interrompu" in out.err


def test_commande_refus_au_recapitulatif(monkeypatch, capsys):
    code, out = _init(monkeypatch, capsys, "\n".join(PARCOURS + ["n"]) + "\n")
    assert code == 0 and out.out == MODELE.read_text()


def test_commande_avec_fichier_de_reponses(monkeypatch, capsys, tmp_path):
    f = tmp_path / "reponses.json"
    f.write_text(json.dumps({"organisation": "Site A", "referentiels": ["dora"],
                             "zones": [{"name": "SRV", "class": "tier1", "prefixes": ["10.1.0.0/16"]}],
                             "siem": {"transport": "udp", "hote": "10.9.0.5", "port": 514, "format": "json"}}))
    code, out = _init(monkeypatch, capsys, "", "--reponses", str(f))
    assert code == 0
    raw = yaml.safe_load(out.out)
    assert raw["zones"] == [{"name": "SRV", "class": "tier1", "prefixes": ["10.1.0.0/16"]}]
    f.write_text(json.dumps({"zones": [{"name": "A", "class": "tier1", "prefixes": ["10.1.0.0/16"]},
                                       {"name": "B", "class": "tier2", "prefixes": ["10.1.0.0/16"]}]}))
    code, out = _init(monkeypatch, capsys, "", "--reponses", str(f))
    assert code == 1 and "déclaré dans 'A' et dans 'B'" in out.err and out.out == ""


def test_install_sh_appelle_l_assistant_a_la_premiere_installation_seulement():
    s = (ROOT / "deploy" / "install.sh").read_text()
    assert 'premiere_config=1' in s
    assert '[ -t 0 ] || [ -n "${AUSPEX_REPONSES:-}" ]' in s      # jamais de question en CI ou en script
    assert "AUSPEX_SANS_QUESTIONS" in s
    assert "auspex init" in s
    # L'assistant tourne après la construction de l'image qui le contient.
    assert s.index("docker compose build") < s.index("auspex init")
