"""Raccordement d'un capteur par code d'invitation : central, réception et capteur."""
import base64
import hashlib
import importlib.util
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auspex import invitation as inv
from auspex.cli import main
from auspex.config import load_config
from auspex.reception import render_authorized_keys

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("rejoindre", ROOT / "sensor" / "rejoindre.py")
rej = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rej)


def _cle_ssh():
    pub = Ed25519PrivateKey.generate().public_key()
    return pub.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()


def _empreinte(cle):
    return "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(cle.split()[1])).digest()).decode().rstrip("=")


@pytest.fixture
def central(tmp_path):
    """Central minimal : configuration, état, clé d'hôte de la réception."""
    (tmp_path / "auspex.yaml").write_text(yaml.safe_dump({
        "version": 1, "state_dir": "data/state",
        "zones": [{"name": "OT-N2", "class": "purdue2", "prefixes": ["172.16.2.0/24"]},
                  {"name": "T1", "class": "tier1", "prefixes": ["10.1.0.0/16"]}],
        "sensors": [{"name": "existant", "zone": "T1", "interface": "eth1"}],
    }))
    (tmp_path / "data/state").mkdir(parents=True)
    hote = _cle_ssh()
    (tmp_path / "data/reception").mkdir(parents=True)
    (tmp_path / "data/reception/ssh_host_ed25519_key.pub").write_text(hote + " auspex-reception\n")
    return tmp_path, hote


def _cfg(central):
    return load_config(central[0] / "auspex.yaml")


# --- Code ------------------------------------------------------------------------

def test_code_format_et_saisie_tolerante():
    code = inv.nouveau_code("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU")
    assert len(code) == 34 and code.count("-") == 6
    brut = inv.normaliser(code)
    assert inv.normaliser(code.lower().replace("-", " ")) == brut
    assert inv.normaliser(brut.replace("0", "O").replace("1", "l")) == brut
    for faux in ("", "ABCD", code + "X", code.replace(code[0], "U", 1)):
        with pytest.raises(inv.InvitationError):
            inv.normaliser(faux)


def test_le_code_porte_le_debut_de_l_empreinte_du_central():
    fp = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
    assert inv.normaliser(inv.nouveau_code(fp))[12:] == inv.prefixe_empreinte(fp)
    assert inv.nouveau_code(fp)[:14] != inv.nouveau_code(fp)[:14]          # secret aléatoire


def test_capteur_et_central_derivent_la_meme_cle():
    """Ed25519 en Python pur (capteur) et avec cryptography (central) : même clé."""
    for _ in range(5):
        seed = os.urandom(32)
        ref = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        assert rej.cle_publique_ed25519(seed) == ref
    code = inv.nouveau_code("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU")
    assert rej.graine(code) == inv.graine(code)
    fichier = rej.cle_privee_openssh(rej.graine(code))
    cle = serialization.load_ssh_private_key(fichier.encode(), None).public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    assert cle == inv.cle_publique_invitation(code)


# --- Central -----------------------------------------------------------------------

def test_invitation_et_ligne_de_la_reception(central):
    cfg = _cfg(central)
    maintenant = datetime(2026, 11, 16, 10, 0, tzinfo=timezone.utc)
    code = inv.inviter(cfg, _empreinte(central[1]), "capteur-ot", "OT-N2", "eth1", ["10.9.0.20"],
                       maintenant=maintenant)
    (i,) = inv.charger(cfg.state_dir, maintenant)
    assert i.cle == inv.cle_publique_invitation(code)
    assert code not in (cfg.state_dir / "invitations.json").read_text()    # le secret n'est pas gardé
    assert i.ligne() == (f'restrict,expiry-time="202611161100Z",from="10.9.0.20",'
                         f'command="/usr/local/bin/auspex-inscrire capteur-ot" {i.cle} auspex-invitation:capteur-ot')
    assert i.ligne() in render_authorized_keys(cfg.sensors, [i])
    assert inv.charger(cfg.state_dir, maintenant + timedelta(hours=2)) == []   # expirée


@pytest.mark.parametrize("nom, zone, allow, message", [
    ("Capteur OT", "OT-N2", [], "minuscules"),
    ("capteur-ot", "INCONNUE", [], "inconnue"),
    ("existant", "T1", [], "existe déjà"),
    ("capteur-ot", "OT-N2", ["0.0.0.0/0"], "invalide"),
])
def test_invitations_refusees(central, nom, zone, allow, message):
    with pytest.raises(inv.InvitationError, match=message):
        inv.inviter(_cfg(central), _empreinte(central[1]), nom, zone, "eth1", allow)


def test_inscription_complete(central):
    cfg = _cfg(central)
    inv.inviter(cfg, _empreinte(central[1]), "capteur-ot", "OT-N2", "eth2", ["10.9.0.20"])
    dossier = central[0] / "data/reception/inscriptions"
    dossier.mkdir()
    cle = _cle_ssh()
    (dossier / "capteur-ot.pub").write_text(cle + "\n")
    (resultat,) = inv.traiter_inscriptions(cfg.state_dir, dossier)
    assert resultat[0] == "capteur-ot" and resultat[1].startswith("raccordé")
    assert list(dossier.iterdir()) == []
    assert inv.charger(cfg.state_dir) == []                                    # code consommé
    cfg = _cfg(central)                                                         # relu : capteurs.yaml fusionné
    s = next(s for s in cfg.sensors if s.name == "capteur-ot")
    assert (s.zone, s.interface, s.key, [str(n) for n in s.allow]) == ("OT-N2", "eth2", cle, ["10.9.0.20/32"])
    keys = render_authorized_keys(cfg.sensors, inv.charger(cfg.state_dir))
    assert "auspex:capteur-ot" in keys and "auspex-invitation" not in keys
    assert "existant" in [s.name for s in cfg.sensors]                          # auspex.yaml intact


@pytest.mark.parametrize("cas", ["sans_invitation", "expiree", "cle_invalide"])
def test_inscriptions_refusees(central, cas):
    cfg = _cfg(central)
    dossier = central[0] / "data/reception/inscriptions"
    dossier.mkdir()
    maintenant = datetime.now(timezone.utc)
    if cas != "sans_invitation":
        inv.inviter(cfg, _empreinte(central[1]), "capteur-ot", "OT-N2", "eth1", [],
                    duree=timedelta(minutes=5), maintenant=maintenant)
    (dossier / "capteur-ot.pub").write_text("ssh-ed25519 AAAA\n" if cas == "cle_invalide" else _cle_ssh())
    plus_tard = maintenant + (timedelta(hours=1) if cas == "expiree" else timedelta(0))
    (resultat,) = inv.traiter_inscriptions(cfg.state_dir, dossier, plus_tard)
    assert resultat[1].startswith("refusé")
    assert list(dossier.iterdir()) == []
    assert "capteur-ot" not in [s.name for s in _cfg(central).sensors]


def test_commandes_inviter_lister_retirer(central, capsys):
    racine, _ = central
    conf = str(racine / "auspex.yaml")
    assert main(["-c", conf, "capteur", "inviter", "capteur-ot", "--zone", "OT-N2",
                 "--adresse", "10.9.0.20", "--central", "auspex.ville.fr"]) == 0
    out = capsys.readouterr().out
    code = next(m for m in out.split() if m.count("-") == 6 and len(m) == 34)
    assert f"rejoindre auspex.ville.fr {code}" in out
    keys = (racine / "data/state/reception/authorized_keys").read_text()
    assert "auspex-invitation:capteur-ot" in keys                              # effet immédiat
    assert main(["-c", conf, "capteur", "liste"]) == 0
    assert "invitation en attente" in capsys.readouterr().out
    assert main(["-c", conf, "capteur", "retirer", "capteur-ot"]) == 0
    assert inv.charger(racine / "data/state") == []
    assert main(["-c", conf, "capteur", "retirer", "existant"]) == 1           # déclaré dans auspex.yaml
    assert main(["-c", conf, "capteur", "inviter", "x", "--zone", "OT-N2", "--minutes", "2"]) == 1


# --- Réception ---------------------------------------------------------------------

def _inscrire(tmp_path, nom, entree):
    script = (ROOT / "deploy/reception/auspex-inscrire").read_text().replace(
        "/var/lib/reception/inscriptions", str(tmp_path / "insc"))
    (tmp_path / "s.sh").write_text(script)
    return subprocess.run(["sh", str(tmp_path / "s.sh"), nom], input=entree, capture_output=True, text=True)


def test_reception_depose_une_seule_fois(tmp_path):
    cle = _cle_ssh()
    assert _inscrire(tmp_path, "capteur-ot", cle + " commentaire\n").returncode == 0
    assert (tmp_path / "insc/capteur-ot.pub").read_text() == cle + "\n"
    r = _inscrire(tmp_path, "capteur-ot", _cle_ssh())
    assert r.returncode == 1 and "déjà servi" in r.stderr
    assert (tmp_path / "insc/capteur-ot.pub").read_text() == cle + "\n"


@pytest.mark.parametrize("nom, entree", [
    ("../x", "ssh-ed25519 AAAA"), ("capteur", "ssh-rsa AAAA"), ("capteur", "ssh-ed25519 AA$(id)"),
    ("capteur", ""),
])
def test_reception_refuse(tmp_path, nom, entree):
    assert _inscrire(tmp_path, nom, entree).returncode == 1
    assert not list((tmp_path / "insc").glob("*")) if (tmp_path / "insc").exists() else True


# --- Capteur -----------------------------------------------------------------------

def _faux_reseau(monkeypatch, cle_hote, refus=False):
    """ssh-keyscan rend la clé d'hôte ; ssh vérifie la clé d'invitation présentée."""
    appels = {}

    def run(cmd, **kw):
        if cmd[0] == "ssh-keyscan":
            return subprocess.CompletedProcess(cmd, 0, f"[h]:2222 {cle_hote}\n", "")
        ident = Path(cmd[cmd.index("-i") + 1]).read_text()
        appels["cle_invitation"] = serialization.load_ssh_private_key(ident.encode(), None).public_key() \
            .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        appels["envoye"] = kw["input"]
        appels["known"] = Path(next(o for o in cmd if o.startswith("UserKnownHostsFile=")).split("=", 1)[1]).read_text()
        return subprocess.CompletedProcess(cmd, 1 if refus else 0, "", "refusé" if refus else "")
    monkeypatch.setattr(rej.subprocess, "run", run)
    return appels


def test_rejoindre(tmp_path, monkeypatch):
    cle_hote = _cle_ssh()
    code = inv.nouveau_code(_empreinte(cle_hote))
    (tmp_path / "cle.pub").write_text(cle_capteur := _cle_ssh())
    appels = _faux_reseau(monkeypatch, cle_hote)
    assert rej.main(["auspex.ville.fr", code.lower(), "--cle", str(tmp_path / "cle.pub"),
                     "--conf", str(tmp_path)]) == 0
    assert appels["cle_invitation"] == inv.cle_publique_invitation(code)
    assert appels["envoye"] == cle_capteur + "\n"
    assert cle_hote in appels["known"]
    assert (tmp_path / "central.env").read_text() == (
        f"AUSPEX_CENTRAL=auspex.ville.fr:2222\nAUSPEX_CENTRAL_EMPREINTE={_empreinte(cle_hote)}\n")


def test_rejoindre_refuse_un_faux_central(tmp_path, monkeypatch, capsys):
    code = inv.nouveau_code(_empreinte(_cle_ssh()))            # code d'un autre central
    (tmp_path / "cle.pub").write_text(_cle_ssh())
    appels = _faux_reseau(monkeypatch, _cle_ssh())
    assert rej.main(["h", code, "--cle", str(tmp_path / "cle.pub"), "--conf", str(tmp_path)]) == 1
    assert "faux central" in capsys.readouterr().err
    assert "envoye" not in appels and not (tmp_path / "central.env").exists()


def test_rejoindre_code_refuse_par_le_central(tmp_path, monkeypatch, capsys):
    cle_hote = _cle_ssh()
    (tmp_path / "cle.pub").write_text(_cle_ssh())
    _faux_reseau(monkeypatch, cle_hote, refus=True)
    assert rej.main(["h:2223", inv.nouveau_code(_empreinte(cle_hote)), "--cle", str(tmp_path / "cle.pub"),
                     "--conf", str(tmp_path)]) == 1
    assert "refusé le code" in capsys.readouterr().err and not (tmp_path / "central.env").exists()


@pytest.mark.parametrize("texte, attendu", [
    ("auspex.ville.fr", ("auspex.ville.fr", 2222)), ("10.9.0.10:2200", ("10.9.0.10", 2200)),
    ("[2001:db8::1]:2222", ("2001:db8::1", 2222)), ("[2001:db8::1]", ("2001:db8::1", 2222)),
])
def test_adresse_du_central(texte, attendu):
    assert rej.hote_port(texte) == attendu
