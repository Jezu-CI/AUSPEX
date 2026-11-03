"""Réception des logs des capteurs : clés, fichier des clés autorisées, configuration, commandes."""

import base64
import os
import shutil
import struct
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from auspex import reception
from auspex.cli import main
from auspex.config import ConfigError, load_config, parse_config
from auspex.deploy import compute_plan

DEMO = Path(__file__).resolve().parent.parent / "examples" / "demo"


def new_key(comment="capteur@test") -> str:
    k = ed25519.Ed25519PrivateKey.generate().public_key()
    return k.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode() + " " + comment


def blob(kind: bytes, key: bytes, extra: bytes = b"") -> str:
    data = struct.pack(">I", len(kind)) + kind + struct.pack(">I", len(key)) + key + extra
    return base64.b64encode(data).decode()


# --- Clés ---------------------------------------------------------------------------------

def test_valid_key_normalised():
    k = new_key("un commentaire avec espaces")
    out = reception.parse_public_key("  " + k + "  ")
    assert out == " ".join(k.split()[:2])                     # commentaire non recopié


@pytest.mark.parametrize("value, why", [
    ('command="/bin/sh" ssh-ed25519 AAAA', "type"),                       # options en tête
    ("ssh-ed25519 {b}\ncommand=\"sh\" ssh-ed25519 {b}", "une seule ligne"),
    ("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ", "type"),
    ("ssh-ed25519 !!pasdubase64!!", "base64"),
    ("ssh-ed25519", "forme"),
    (12, "texte"),
])
def test_refused_keys(value, why):
    if isinstance(value, str):
        value = value.format(b=new_key().split()[1])
    with pytest.raises(reception.SensorKeyError) as exc:
        reception.parse_public_key(value)
    assert why in str(exc.value)


@pytest.mark.parametrize("data", [
    blob(b"ssh-rsa", b"\0" * 32),                 # type annoncé ≠ type réel
    blob(b"ssh-ed25519", b"\0" * 31),             # longueur
    blob(b"ssh-ed25519", b"\0" * 32, b"x"),       # données en trop
    base64.b64encode(b"\0\0\0\x0bssh").decode(),  # tronquée
])
def test_forged_blobs_refused(data):
    with pytest.raises(reception.SensorKeyError):
        reception.parse_public_key(f"ssh-ed25519 {data}")


def test_fingerprint_openssh_format():
    k = reception.parse_public_key(new_key())
    fp = reception.fingerprint(k)
    raw = base64.b64decode(k.split()[1])
    assert fp.startswith("SHA256:") and "=" not in fp and len(fp) == 7 + 43
    import hashlib
    assert base64.b64decode(fp[7:] + "=") == hashlib.sha256(raw).digest()


# --- Configuration ----------------------------------------------------------------------

def raw_with(sensors):
    raw = yaml.safe_load((DEMO / "auspex.yaml").read_text())
    raw["sensors"] = sensors
    return raw


def test_sensor_key_and_allow_parsed():
    k = new_key()
    cfg = parse_config(raw_with([{"name": "capteur-ot", "zone": "OT-N2", "interface": "eth1", "key": k,
                                  "allow": ["10.9.0.20", "10.9.1.0/28"]}]), DEMO)
    s = cfg.sensors[0]
    assert s.key == " ".join(k.split()[:2]) and [str(n) for n in s.allow] == ["10.9.0.20/32", "10.9.1.0/28"]


def test_sensor_config_errors():
    k = new_key()
    raw = raw_with([
        {"name": "Capteur OT", "zone": "OT-N2", "interface": "eth1", "key": k},
        {"name": "b", "zone": "OT-N2", "interface": "eth1", "key": k},                     # même clé
        {"name": "c", "zone": "OT-N2", "interface": "eth1", "key": "ssh-rsa AAAA"},
        {"name": "d", "zone": "OT-N2", "interface": "eth1", "key": new_key(), "allow": ["0.0.0.0/0"]},
        {"name": "e", "zone": "OT-N2", "interface": "eth1", "allow": ["10.0.0.1"]},
        {"name": "b", "zone": "OT-N2", "interface": "eth1"},                                 # nom en double
    ])
    with pytest.raises(ConfigError) as exc:
        parse_config(raw, DEMO)
    text = " | ".join(exc.value.problems)
    for needle in ("sensors[0].name : avec une clé d'envoi", "déjà celle d'un autre capteur",
                   "sensors[2].key : type", "n'importe où", "sensors[4].allow : sans clé",
                   "nom « b » déclaré deux fois"):
        assert needle in text, needle


# --- Fichier des clés autorisées et plan -------------------------------------------------

@pytest.fixture
def site(tmp_path, monkeypatch):
    work = tmp_path / "site"
    shutil.copytree(DEMO, work, ignore=shutil.ignore_patterns("state", "logs"))
    monkeypatch.chdir(work)
    return work


def set_sensors(site, sensors):
    raw = yaml.safe_load((site / "auspex.yaml").read_text())
    raw["sensors"] = sensors
    (site / "auspex.yaml").write_text(yaml.safe_dump(raw, allow_unicode=True))
    return load_config(site / "auspex.yaml")


def section(cfg):
    return next(s for s in compute_plan(cfg) if s.title == "Réception des capteurs")


def test_authorized_keys_lines(site):
    k = new_key()
    cfg = set_sensors(site, [{"name": "capteur-ot", "zone": "OT-N2", "interface": "eth1", "key": k,
                              "allow": ["10.9.0.20"]},
                             {"name": "capteur-it", "zone": "T1-serveurs", "interface": "eth1"}])
    text = reception.render_authorized_keys(cfg.sensors)
    lines = [line for line in text.splitlines() if not line.startswith("#")]
    assert lines == [f'restrict,from="10.9.0.20/32",command="/usr/local/bin/auspex-recevoir capteur-ot" '
                     f'{" ".join(k.split()[:2])} auspex:capteur-ot']           # capteur sans clé : absent


def test_plan_add_change_remove(site):
    k1, k2 = new_key(), new_key()
    base = {"zone": "OT-N2", "interface": "eth1"}
    cfg = set_sensors(site, [{"name": "a", "key": k1, **base}])
    sec = section(cfg)
    assert sec.changes == [f"+ a ({reception.fingerprint(reception.parse_public_key(k1))})"] and sec.action
    sec.action()
    path = reception.authorized_path(cfg.state_dir)
    assert oct(path.stat().st_mode & 0o777) == "0o644"
    assert not section(cfg).changes                                           # idempotent
    cfg = set_sensors(site, [{"name": "a", "key": k1, "allow": ["10.0.0.9"], **base}, {"name": "b", "key": k2, **base}])
    assert sorted(section(cfg).changes)[0].startswith("+ b") and "~ a (clé ou adresses autorisées)" in section(cfg).changes
    section(cfg).action()
    cfg = set_sensors(site, [{"name": "b", "key": k2, **base}])
    assert section(cfg).changes == ["- a"]
    section(cfg).action()
    assert list(reception.current_lines(cfg.state_dir)) == ["b"]


def test_no_sensor_key_no_file(site):
    cfg = load_config(site / "auspex.yaml")
    sec = section(cfg)
    assert not sec.changes and "aucun capteur avec clé" in sec.notes[0]
    assert not reception.authorized_path(cfg.state_dir).exists()


# --- Commandes ----------------------------------------------------------------------------

def test_cli_fingerprint_and_list(site, capsys):
    k = new_key()
    cfg = set_sensors(site, [{"name": "capteur-ot", "zone": "OT-N2", "interface": "eth1", "key": k},
                             {"name": "capteur-it", "zone": "T1-serveurs", "interface": "eth1"}])
    assert main(["capteur", "empreinte"]) == 1                     # réception pas encore démarrée
    host = new_key("auspex-reception")
    (cfg.state_dir.parent / "reception").mkdir(parents=True)
    (cfg.state_dir.parent / "reception" / reception.HOST_KEY_PUB).write_text(host + "\n")
    capsys.readouterr()
    assert main(["capteur", "empreinte"]) == 0
    assert reception.fingerprint(reception.parse_public_key(host)) in capsys.readouterr().out

    logs = site / "recus"
    assert main(["capteur", "liste", "--logs", str(logs)]) == 0
    out = capsys.readouterr().out
    assert "pas encore appliquée" in out and "sans clé d'envoi" in out
    assert main(["apply"]) == 0
    (logs / "capteur-ot").mkdir(parents=True)
    (logs / "capteur-ot" / "conn.log").write_text("{}\n")
    capsys.readouterr()
    assert main(["capteur", "liste", "--logs", str(logs)]) == 0
    out = capsys.readouterr().out
    assert "autorisé (SHA256:" in out and "dernier dépôt il y a 0 min, 1 fichier(s)" in out


def test_symlinks_in_logs_ignored(tmp_path):
    from auspex.zeek import list_log_files
    (tmp_path / "capteur").mkdir()
    (tmp_path / "capteur" / "conn.log").write_text("x")
    outside = tmp_path.parent / f"{tmp_path.name}-dehors"
    outside.mkdir()
    (outside / "secret.log").write_text("s")
    os.symlink(outside / "secret.log", tmp_path / "capteur" / "lien.log")
    os.symlink(outside, tmp_path / "autre-capteur")
    assert [p.name for p in list_log_files(tmp_path)] == ["conn.log"]
