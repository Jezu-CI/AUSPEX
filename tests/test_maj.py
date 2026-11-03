"""Mises à jour signées de l'analyse : publication (central) et vérification (capteur, bash)."""

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from auspex import maj

ROOT = Path(__file__).resolve().parent.parent / "appliance" / "config" / "includes.chroot"
LIB = ROOT / "usr/local/lib/auspex/lib.sh"
MAJLIB = ROOT / "usr/local/lib/auspex/maj.sh"
IMAGE = b"hsqs" + os.urandom(4096)

needs_tools = pytest.mark.skipif(not (shutil.which("bash") and shutil.which("openssl")), reason="bash/openssl absents")


def _image(tmp_path, version="0.2.0", data=IMAGE) -> Path:
    p = tmp_path / "depot" / f"auspex-capteur-{version}.squashfs"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


@pytest.fixture
def state(tmp_path):
    s = tmp_path / "data" / "state"
    s.mkdir(parents=True)
    return s


# --- Central ------------------------------------------------------------------------------

def test_publish_and_current(state, tmp_path):
    info = maj.publish(state, _image(tmp_path), now=datetime(2026, 11, 1, tzinfo=timezone.utc))
    assert info["version"] == "0.2.0" and info["taille"] == len(IMAGE)
    cur_dir = maj.publish_root(state) / "courant"
    assert sorted(p.name for p in cur_dir.iterdir()) == ["image.squashfs", "manifeste", "manifeste.sig"]
    assert all(oct(p.stat().st_mode)[-3:] == "644" for p in cur_dir.iterdir())
    assert (cur_dir / "image.squashfs").read_bytes() == IMAGE
    cur = maj.current(state)
    assert cur["valide"] and cur["version"] == "0.2.0" and cur["publie_le"] == "2026-11-01T00:00:00Z"
    key_file = state / "cles" / maj.KEY_FILE
    assert oct(key_file.stat().st_mode)[-3:] == "600"
    assert not (state / "cles" / "audit-ed25519.pem").exists()      # clé distincte de celle des audits


def test_publish_rotation_and_no_downgrade(state, tmp_path):
    maj.publish(state, _image(tmp_path, "0.2.0"))
    maj.publish(state, _image(tmp_path, "0.2.1"))
    root = maj.publish_root(state)
    assert maj.parse_manifest((root / "precedent" / "manifeste").read_bytes())["version"] == "0.2.0"
    for v in ("0.2.1", "0.2.0", "0.1.9"):
        with pytest.raises(maj.MajError, match="pas plus récente"):
            maj.publish(state, _image(tmp_path, v))
    assert maj.publish(state, _image(tmp_path, "0.2.0"), force=True)["version"] == "0.2.0"
    assert maj.publish(state, _image(tmp_path, "0.10.0"))["version"] == "0.10.0"     # tri numérique, pas texte


@pytest.mark.parametrize("name, data, needle", [
    ("image.squashfs", IMAGE, "version introuvable"),
    ("auspex-capteur-1.squashfs", IMAGE, "invalide"),
    ("auspex-capteur-1.0.squashfs", b"PK\x03\x04" + IMAGE, "pas une image squashfs"),
    ("auspex-capteur-1.0.squashfs", b"", "hors limites"),
])
def test_publish_refusals(state, tmp_path, name, data, needle):
    p = tmp_path / name
    p.write_bytes(data)
    with pytest.raises(maj.MajError, match=needle):
        maj.publish(state, p)
    assert maj.current(state) is None


def test_current_detects_tampering(state, tmp_path):
    maj.publish(state, _image(tmp_path))
    m = maj.publish_root(state) / "courant" / "manifeste"
    m.write_bytes(m.read_bytes().replace(b"0.2.0", b"9.9.9"))
    cur = maj.current(state)
    assert cur["valide"] is False and "signature" in cur["raison"]


def test_sensor_status(tmp_path):
    folder = tmp_path / "capteur-ot"
    folder.mkdir()
    (folder / "auspex-etat.json").write_text(json.dumps({"analyse": "0.2.1", "maj": "echec", "detail": "x" * 500}))
    st = maj.sensor_status(tmp_path, "capteur-ot")
    assert st["analyse"] == "0.2.1" and st["maj"] == "echec" and len(st["detail"]) == 120
    (folder / "auspex-etat.json").write_text("[1, 2]")
    assert maj.sensor_status(tmp_path, "capteur-ot") is None
    assert maj.sensor_status(tmp_path, "absent") is None


def test_status_file_not_ingested_as_zeek_log(tmp_path):
    from auspex.zeek import list_log_files
    (tmp_path / "c1").mkdir()
    (tmp_path / "c1" / "auspex-etat.json").write_text("{}")
    (tmp_path / "c1" / "conn.json").write_text("{}")
    assert [p.name for p in list_log_files(tmp_path)] == ["conn.json"]


def test_cli_update_key_and_publish(state, tmp_path, capsys, monkeypatch):
    from auspex import cli
    cfg = type("C", (), {"state_dir": state})()
    monkeypatch.setattr(cli, "_load", lambda args: cfg)
    assert cli.cmd_sensor_update_key(None) == 0
    out = capsys.readouterr().out
    line = [x for x in out.splitlines() if x.startswith("MAJ_CLE=")][0]
    assert len(line) == len("MAJ_CLE=") + 60 and line.startswith("MAJ_CLE=MCowBQYDK2VwAyEA")
    args = type("A", (), {"image": str(_image(tmp_path)), "version": None, "force": False})()
    assert cli.cmd_sensor_publish(args) == 0
    assert cli.cmd_sensor_publish(args) == 1                     # même version : refusée


# --- Capteur (bash, openssl) : vérification de ce que le central publie ----------------------

def bash(script: str, tmp_path, **env) -> subprocess.CompletedProcess:
    full = (f'set -uo pipefail; DATA="{tmp_path}/capteur"; . "{LIB}"; msg(){{ echo "$*"; }}; '
            f'MAJ="{tmp_path}/capteur/maj"; USINE_VERSION="{tmp_path}/version"; . "{MAJLIB}"; {script}')
    return subprocess.run(["bash", "-c", full], capture_output=True, text=True, timeout=60,
                          env={**os.environ, **env})


@pytest.fixture
def published(state, tmp_path):
    maj.publish(state, _image(tmp_path, "0.2.0"))
    (tmp_path / "version").write_text("0.1.0\n")
    pem = tmp_path / "maj.pem"
    value = maj.public_value(maj.key(state))
    return maj.publish_root(state) / "courant", value, pem


@needs_tools
def test_sensor_verifies_central_publication(published, tmp_path):
    folder, value, pem = published
    r = bash(f'maj_pem "{value}" "{pem}" && maj_verifier "{folder}" "{pem}" image && '
             'echo "OK ${M[version]} ${M[taille]}"', tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"OK 0.2.0 {len(IMAGE)}" in r.stdout


@needs_tools
@pytest.mark.parametrize("tamper, needle", [
    ("manifest", "signature invalide"),
    ("other_key", "signature invalide"),
    ("image", "empreinte de l'image"),
    ("truncate", "taille de l'image"),
    ("symlink", "image absente"),
    ("no_sig", "absents"),
    ("short_sig", "taille anormale"),
])
def test_sensor_refusals(published, tmp_path, tamper, needle):
    folder, value, pem = published
    work = tmp_path / "copie"
    shutil.copytree(folder, work)
    if tamper == "manifest":
        m = work / "manifeste"
        m.write_bytes(m.read_bytes().replace(b"version=0.2.0", b"version=0.2.9"))
    elif tamper == "other_key":
        from cryptography.hazmat.primitives.asymmetric import ed25519
        (work / "manifeste.sig").write_bytes(ed25519.Ed25519PrivateKey.generate().sign((work / "manifeste").read_bytes()))
    elif tamper == "image":
        data = bytearray((work / "image.squashfs").read_bytes())
        data[100] ^= 1
        (work / "image.squashfs").write_bytes(bytes(data))
    elif tamper == "truncate":
        (work / "image.squashfs").write_bytes(IMAGE[:-1])
    elif tamper == "symlink":
        (work / "image.squashfs").unlink()
        (work / "image.squashfs").symlink_to(folder / "image.squashfs")
    elif tamper == "no_sig":
        (work / "manifeste.sig").unlink()
    elif tamper == "short_sig":
        (work / "manifeste.sig").write_bytes(b"\0" * 10)
    r = bash(f'maj_pem "{value}" "{pem}"; maj_verifier "{work}" "{pem}" image; rc=$?; echo "RC=$rc $MAJ_RAISON"', tmp_path)
    assert "RC=1" in r.stdout and needle in r.stdout, r.stdout + r.stderr


@needs_tools
def test_signed_but_malformed_manifest_refused(state, tmp_path):
    """Même signé par la bonne clé, un manifeste hors format est refusé (rien n'est exécuté)."""
    k = maj.key(state)
    folder = tmp_path / "pub"
    folder.mkdir()
    for content, needle in ((b"format=auspex-maj-capteur/1\nversion=$(reboot)\n", "mal formé"),
                            (b"format=autre/2\nversion=1.0\nsha256=" + b"a" * 64 + b"\ntaille=1\n", "format"),
                            (b"format=auspex-maj-capteur/1\nversion=1.0\nsha256=zz\ntaille=1\n", "empreinte invalide"),
                            (b"format=auspex-maj-capteur/1\nversion=1.0\nsha256=" + b"a" * 64 + b"\ntaille=99999999999\n",
                             "taille invalide")):
        (folder / "manifeste").write_bytes(content)
        (folder / "manifeste.sig").write_bytes(k.sign(content))
        pem = tmp_path / "k.pem"
        r = bash(f'maj_pem "{maj.public_value(k)}" "{pem}"; maj_verifier "{folder}" "{pem}"; echo "RC=$? $MAJ_RAISON"',
                 tmp_path)
        assert "RC=1" in r.stdout and needle in r.stdout, (content, r.stdout, r.stderr)


@needs_tools
def test_version_order_and_state(tmp_path):
    r = bash('''
for p in "0.2.0 0.1.9" "0.10.0 0.9.9" "1.0.0.1 1.0.0" "0.2.0 0.2.0" "0.1.9 0.2.0"; do
    set -- $p; version_gt "$1" "$2" && echo "GT $1 $2" || echo "LE $1 $2"
done
mkdir -p "$MAJ"
printf 'actif=$(reboot)\\nactif=b\\nessai=1\\nprecedent=../x\\nrefusees=1.0; id\\n' > "$MAJ/etat"
etat_lire; echo "E ${E[actif]} ${E[precedent]} ${E[essai]} [${E[refusees]}]"
for i in $(seq 1 25); do refuser "0.$i"; done; refuser 0.25
etat_ecrire; etat_lire; echo "N $(echo ${E[refusees]} | wc -w) ${E[refusees]%% *}"
refusee 0.25 && echo "R oui"; refusee 0.2 && echo "R0.2" || echo "R0.2 non"
echo "AUTRE $(autre_slot a) $(autre_slot b) $(autre_slot usine)"
''', tmp_path)
    out = r.stdout
    assert "GT 0.2.0 0.1.9" in out and "GT 0.10.0 0.9.9" in out and "GT 1.0.0.1 1.0.0" in out
    assert "LE 0.2.0 0.2.0" in out and "LE 0.1.9 0.2.0" in out
    assert "E b usine 1 []" in out                         # valeurs hostiles ignorées
    assert "N 20 0.6" in out and "R oui" in out and "R0.2 non" in out
    assert "AUTRE b a a" in out


@needs_tools
@pytest.mark.parametrize("line, ok", [
    ("MAJ_CLE=MCowBQYDK2VwAyEA" + "A" * 43 + "=", True),
    ("MAJ_CLE=MCowBQYDK2VwAyEA" + "A" * 42 + "=", False),
    ("MAJ_CLE=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA", False),       # RSA : refusé
    ("MAJ_FREQUENCE=1", True), ("MAJ_FREQUENCE=1440", True), ("MAJ_FREQUENCE=1441", False),
    ("MAJ_FREQUENCE=0", False), ("MAJ_FREQUENCE=08", False),
    ("MAJ_ESSAI=30", True), ("MAJ_ESSAI=29", False), ("MAJ_ESSAI=3601", False), ("MAJ_ESSAI=60;reboot", False),
])
def test_config_keys(tmp_path, line, ok):
    conf = tmp_path / "capteur.conf"
    conf.write_text("NOM=c\nECOUTE_INTERFACE=eth1\nCENTRAL=10.0.0.1\n"
                    "CENTRAL_EMPREINTE=SHA256:+8+04yc02vxEmBR97SlJdLwWAwkQLtcLUpIgi1Sa7rI\n" + line + "\n")
    r = subprocess.run(["bash", "-c", f'. "{LIB}"; msg(){{ echo "$*"; }}; load_conf "{conf}"'],
                       capture_output=True, text=True, timeout=30)
    assert (r.returncode == 0) == ok, r.stdout


def test_reception_read_only_channel():
    """Lecture (--sender) : publication seule, en lecture seule ; tout le reste : dépôt de logs."""
    script = (Path(__file__).resolve().parent.parent / "deploy/reception/auspex-recevoir").read_text()
    assert '"rsync --server --sender "*)' in script and "rrsync -ro /mises-a-jour" in script
    assert "rrsync -wo -no-del -munge" in script
    compose = (Path(__file__).resolve().parent.parent / "deploy/docker-compose.yml").read_text()
    assert "./data/mises-a-jour:/mises-a-jour:ro" in compose


def test_appliance_wiring():
    units = ROOT / "etc/systemd/system"
    capteur = (units / "auspex-capteur.service").read_text()
    assert "RootDirectory=/run/auspex/racine" in capteur and "Requires=" in capteur and "auspex-racine.service" in capteur
    majunit = (units / "auspex-maj.service").read_text()
    for opt in ("PrivateTmp", "ProtectHome", "ProtectSystem", "PrivateMounts", "ProtectKernelModules"):
        assert f"\n{opt}=" not in majunit, opt          # le montage doit être vu par auspex-capteur
    racine = (ROOT / "usr/local/sbin/auspex-racine").read_text()
    assert "ro,loop,nodev,nosuid" in racine and "maj_verifier" in racine
    build = (ROOT.parent.parent / "build.sh").read_text()
    assert "mksquashfs" in build and ".auspex/sensor.env" in build
    assert "openssl" in (ROOT.parent / "package-lists/auspex.list.chroot").read_text().split()


def test_read_only_root_has_mount_points():
    """Relevé en CI : racine d'analyse en lecture seule, systemd ne peut plus créer les points
    de montage de BindPaths / TemporaryFileSystem : l'image doit les contenir."""
    unit = (ROOT / "etc/systemd/system/auspex-capteur.service").read_text()
    build = (ROOT.parent.parent / "build.sh").read_text()
    racine = (ROOT / "usr/local/sbin/auspex-racine").read_text()
    targets = [b.split(":")[1] for line in unit.splitlines() if line.startswith("BindPaths=")
               for b in line.split("=", 1)[1].split()]
    targets += line_tmp if (line_tmp := [t for line in unit.splitlines() if line.startswith("TemporaryFileSystem=")
                                         for t in line.split("=", 1)[1].split()]) else []
    assert targets == ["/logs", "/etc/auspex-capteur", "/tmp", "/run"]
    for t in targets:
        assert f'"$R{t}"' in build, t
        assert t.lstrip("/") in racine, t
