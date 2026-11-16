"""Effacement d'actifs sur demande (auspex oublier), sur le scénario de démonstration."""

import importlib.util
import json
import re
import shutil
from pathlib import Path

import pytest

from auspex.cli import main
from auspex.config import load_config
from auspex.oubli import OubliError, _filtrer, verrou_etat

DEMO = Path(__file__).resolve().parent.parent / "examples" / "demo"


@pytest.fixture
def site(tmp_path, monkeypatch):
    work = tmp_path / "site"
    shutil.copytree(DEMO, work, ignore=shutil.ignore_patterns("state", "logs"))
    spec = importlib.util.spec_from_file_location("gen", work / "generate_logs.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    gen.generate(work / "logs", days=7)
    monkeypatch.chdir(work)
    assert main(["apply"]) == 0
    assert main(["daemon", "--logs", "logs", "--once"]) == 0
    return work


def _etat(site):
    return load_config(site / "auspex.yaml").state_dir


def _cible(site):
    """Adresse source d'un écart ouvert : présente dans l'inventaire, les flux et les alertes."""
    alertes = json.loads((_etat(site) / "alerts.json").read_text())
    return next(a["finding"]["src"] for a in alertes.values() if a["status"] == "open" and a["finding"].get("src"))


def _fichiers(etat):
    """Fichiers d'état concernés : hors exports d'audit scellés, registre d'ingestion et
    alertes déjà livrées (sortie « fichier » de la démonstration, comme un SIEM)."""
    return {p: p.read_bytes() for p in sorted(etat.rglob("*"))
            if p.is_file() and "audits" not in p.parts
            and p.name not in ("ingest.json", ".verrou", "siem.jsonl")}


def _cite(etat, ip):
    """Fichiers où l'adresse apparaît, y compris dans un texte (message d'alerte)."""
    motif = re.compile(rf"(?<![0-9A-Za-z.:]){re.escape(ip)}(?![0-9A-Za-z]|\.[0-9])".encode())
    return [p.name for p, b in _fichiers(etat).items() if motif.search(b)]


def test_simulation_ne_modifie_rien(site, capsys):
    etat, ip = _etat(site), _cible(site)
    avant = _fichiers(etat)
    assert main(["oublier", ip]) == 0
    assert _fichiers(etat) == avant
    out = capsys.readouterr().out
    assert "Simulation uniquement" in out and "fiche d'actif            : 1" in out


def test_effacement_complet(site, capsys):
    etat, ip = _etat(site), _cible(site)
    assert _cite(etat, ip)
    actifs_avant = len(json.loads((etat / "assets.json").read_text()))
    assert main(["oublier", ip, "--apply"]) == 0
    assert "Effacé." in capsys.readouterr().out
    assert _cite(etat, ip) == []                       # plus aucune trace dans l'état ni les vues
    assert len(json.loads((etat / "assets.json").read_text())) == actifs_avant - 1   # les autres restent
    # Le cycle suivant ne la fait pas revenir (logs déjà lus) et le service tourne.
    assert main(["daemon", "--logs", "logs", "--once"]) == 0
    assert _cite(etat, ip) == []


def test_alertes_en_attente_vers_le_siem_retirees(site):
    etat, ip = _etat(site), _cible(site)
    boite = etat / "outbox"
    boite.mkdir(exist_ok=True)
    garde = {"event": "open", "src_endpoint": {"ip": "192.0.2.1"}}
    (boite / "00-syslog.jsonl").write_text(
        json.dumps({"event": "open", "src_endpoint": {"ip": ip}}) + "\n" + json.dumps(garde) + "\n")
    assert main(["oublier", ip, "--apply"]) == 0
    assert [json.loads(li) for li in (boite / "00-syslog.jsonl").read_text().splitlines()] == [garde]


def test_adresse_inconnue_et_invalide(site, capsys):
    assert main(["oublier", "192.0.2.250"]) == 0
    assert "Rien à effacer" in capsys.readouterr().out
    assert main(["oublier", "pas-une-ip"]) == 1


def test_netbox_et_preuves_signalees(site, capsys):
    ip = _cible(site)
    main(["oublier", ip])
    out = capsys.readouterr().out
    assert f"l'adresse IP {ip}" in out and "exports d'audit signés" in out
    assert "AUSPEX_LOGS_RETENTION_DAYS" in out and "alertes déjà livrées" in out


def test_filtre_ne_retire_que_ce_qui_cite_l_adresse():
    doc = {"total": 3, "10.0.0.5": {"x": 1}, "liste": [
        {"ip": "10.0.0.5/24"}, {"ip": "10.0.0.50"}, "10.0.0.5", {"zone": {"nom": "T0", "ip": "10.0.0.5"}}]}
    out, n = _filtrer(doc, {"10.0.0.5"})
    assert out == {"total": 3, "liste": [{"ip": "10.0.0.50"}, {}]}   # sous-enregistrement « zone » retiré
    assert n == 4


def test_verrou_partage_avec_le_service(tmp_path):
    with verrou_etat(tmp_path):
        with pytest.raises(OubliError, match="occupé"):
            with verrou_etat(tmp_path, attente=0.6):
                pass
    with verrou_etat(tmp_path, attente=0.6):   # libéré
        pass


def test_alertes_resolues_purgees_avec_la_retention(tmp_path):
    from datetime import datetime, timedelta, timezone

    from auspex.state import AlertStore
    now = datetime(2026, 11, 15, tzinfo=timezone.utc)
    store = AlertStore(tmp_path)
    store.path.write_text(json.dumps({
        "ancienne": {"status": "resolved", "resolved_at": (now - timedelta(days=200)).isoformat()},
        "recente": {"status": "resolved", "resolved_at": (now - timedelta(days=10)).isoformat()},
        "ouverte": {"status": "open", "opened_at": (now - timedelta(days=400)).isoformat()},
    }))
    assert store.prune(now, 180) == 1
    assert set(store.load()) == {"recente", "ouverte"}   # une alerte ouverte n'est jamais purgée


def test_journaux_des_conteneurs_bornes():
    import yaml
    compose = yaml.safe_load((Path(__file__).resolve().parent.parent / "deploy/docker-compose.yml").read_text())
    for nom, svc in compose["services"].items():
        assert svc.get("logging", {}).get("options", {}).get("max-size"), nom


def test_adresse_citee_seulement_dans_le_message(tmp_path):
    """Équipement à plusieurs adresses (« actif silencieux ») : le champ src ne porte
    que la première, le message les cite toutes. Effacer la seconde retire l'alerte,
    l'envoi en attente et l'écart du rapport ; une adresse voisine n'est pas touchée."""
    from auspex.oubli import oublier
    msg = "automate-3 (10.0.0.5, 10.0.0.7) est déclaré actif mais n'a pas été observé depuis le 2026-11-01"
    finding = {"id": "AUSPEX-1", "type": "actif_silencieux", "src": "10.0.0.5", "message": msg}
    voisin = {"id": "AUSPEX-2", "type": "actif_silencieux", "src": "10.0.0.70",
              "message": "automate-4 (10.0.0.70, 10.0.0.77:502, fd00::7) …"}
    (tmp_path / "alerts.json").write_text(json.dumps({
        "AUSPEX-1": {"status": "open", "finding": finding}, "AUSPEX-2": {"status": "open", "finding": voisin}}))
    (tmp_path / "report.json").write_text(json.dumps({"findings_detail": [finding, voisin]}))
    (tmp_path / "outbox").mkdir()
    (tmp_path / "outbox" / "00-syslog.jsonl").write_text(
        json.dumps({"event": "open", "message": msg}) + "\n" + json.dumps({"event": "open", **voisin}) + "\n")
    bilan = oublier(tmp_path, {"10.0.0.7"}, appliquer=True)
    assert (bilan.alertes, bilan.envois, bilan.vues) == (1, 1, {"report.json": 1})
    assert set(json.loads((tmp_path / "alerts.json").read_text())) == {"AUSPEX-2"}
    assert json.loads((tmp_path / "report.json").read_text()) == {"findings_detail": [voisin]}
    assert "10.0.0.7," not in (tmp_path / "outbox" / "00-syslog.jsonl").read_text()
    # Adresse avec port, et IPv6 écrite autrement : reconnues aussi
    assert oublier(tmp_path, {"10.0.0.77"}, appliquer=False).alertes == 1
    assert oublier(tmp_path, {"fd00:0:0:0:0:0:0:7"}, appliquer=False).alertes == 1
