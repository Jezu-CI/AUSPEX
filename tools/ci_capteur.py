#!/usr/bin/env python3
"""Preuve « capteur → central » sur le central complet (exécuté par la CI).

Vrai capteur (image auspex-sensor) : clé générée sur le capteur, déclarée dans
auspex.yaml du central, empreinte du central vérifiée par le capteur, logs
Zeek envoyés par SSH + rsync et analysés par le central. Puis les attaques :
faux central, clé inconnue, bonne clé depuis une mauvaise adresse, lecture,
évasion du dossier, commande arbitraire, suppression, révocation.

Usage (dans deploy/, après l'installation du central, image capteur construite
sous le nom auspex-sensor:ci) : python ../tools/ci_capteur.py
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_mfa import CONFIG  # noqa: E402

A = ["docker", "compose", "exec", "-T", "auspex", "auspex", "-c", "/etc/auspex/auspex.yaml"]
IMAGE = "auspex-sensor:ci"
NET = "auspex_default"
SENSOR_IP, OTHER_IP = "172.31.250.77", "172.31.250.78"
WORK = Path("capteur-ci").resolve()
LOGS = Path("logs").resolve()
STATE = Path("data/state")
RESULTS: list[tuple[str, bool]] = []


def check(label: str, ok) -> None:
    ok = bool(ok)
    RESULTS.append((label, ok))
    print(f"  {'OK ' if ok else 'ÉCHEC'}  {label}", flush=True)


def run(*cmd, timeout=300) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def sensor(*args, conf="conf", ip=SENSOR_IP, env=None, logs="logs", entrypoint=None, extra=()):
    cmd = ["docker", "run", "--rm", "--network", NET, "--ip", ip,
           "-v", f"{WORK / conf}:/etc/auspex-capteur", "-v", f"{WORK / logs}:/logs"]
    for host, inside in extra:
        cmd += ["-v", f"{host}:{inside}:ro"]
    for k, v in (env or {}).items():
        cmd += ["-e", f"{k}={v}"]
    if entrypoint:
        cmd += ["--entrypoint", entrypoint]
    return run(*cmd, IMAGE, *args)


def set_sensors(entries) -> None:
    cfg = yaml.safe_load(CONFIG.read_text())
    cfg["sensors"] = entries
    CONFIG.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))


def wait_authorized(present: bool, name="capteur-ci", tries=30) -> bool:
    path = STATE / "reception" / "authorized_keys"
    for _ in range(tries):
        text = path.read_text() if path.exists() else ""
        if (f"auspex:{name}" in text) == present:
            return True
        time.sleep(3)
    return False


def heartbeat() -> dict:
    try:
        return json.loads((STATE / "heartbeat.json").read_text())
    except (OSError, ValueError):
        return {}


def ssh_cmd() -> list[str]:
    """ssh/rsync à la main depuis le conteneur capteur (pour les tentatives d'attaque)."""
    return ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR", "-i", "/etc/auspex-capteur/cle", "-p", "2222"]


def main() -> int:
    WORK.mkdir(exist_ok=True)
    (WORK / "logs").mkdir(exist_ok=True)

    print("Service de réception")
    r = run("docker", "compose", "exec", "-T", "reception", "id", "-u")
    check(f"réception sans privilèges (uid {r.stdout.strip()})", r.returncode == 0 and r.stdout.strip() not in ("", "0"))
    r = run("docker", "compose", "exec", "-T", "reception", "sh", "-c", "echo x > /etc/piege")
    check("système de fichiers de la réception en lecture seule", r.returncode != 0)
    r = run(*A, "capteur", "empreinte")
    fp = (re.search(r"SHA256:[A-Za-z0-9+/]{43}", r.stdout) or [None])[0]
    logs = run("docker", "compose", "logs", "--no-color", "reception").stdout
    from_sshd = (re.search(r"clé d'hôte (SHA256:\S+)", logs) or [None, None])[1]
    check(f"empreinte du central (Auspex = ssh-keygen) : {fp}", fp and fp == from_sshd)

    print("Inscription du capteur")
    r = sensor("cle")
    key = r.stdout.strip().splitlines()[0] if r.returncode == 0 and r.stdout.strip() else ""
    check(f"clé générée sur le capteur : {key[:30]}…", key.startswith("ssh-ed25519 "))
    set_sensors([{"name": "capteur-ci", "zone": "OT-N2", "interface": "eth1", "key": key, "allow": [SENSOR_IP]}])
    check("clé déclarée dans auspex.yaml, appliquée par le service", wait_authorized(True))
    r = run(*A, "capteur", "liste", "--logs", "/var/lib/auspex/logs")
    check("auspex capteur liste : autorisé, rien reçu", "autorisé (SHA256:" in r.stdout and "aucun dépôt" in r.stdout)

    print("Envoi des logs")
    Path(WORK / "pcap").mkdir(exist_ok=True)
    run(sys.executable, str(Path(__file__).parent / "pcapgen.py"), str(WORK / "pcap" / "lab.pcap"))
    r = run("docker", "run", "--rm", "--network", "none", "-v", f"{WORK / 'pcap'}:/pcap:ro",
            "-v", f"{WORK / 'logs'}:/logs", IMAGE, "read", "/pcap/lab.pcap")
    check("Zeek a produit les logs sur le capteur", r.returncode == 0 and (WORK / "logs" / "lab" / "conn.log").exists())
    env = {"AUSPEX_CENTRAL": "reception:2222", "AUSPEX_CENTRAL_EMPREINTE": fp}
    shipped_at = datetime.now(timezone.utc)
    r = sensor("envoyer", env=env)
    received = sorted(p.name for p in (LOGS / "capteur-ci" / "lab").glob("*.log")) if (LOGS / "capteur-ci").exists() else []
    check(f"envoi accepté, {len(received)} fichier(s) reçu(s) dans logs/capteur-ci/", r.returncode == 0
          and "conn.log" in received)
    check("journal du capteur : envoi_ok", "envoi_ok" in r.stderr)
    ingested = False
    for _ in range(30):
        hb = heartbeat()
        started = datetime.fromisoformat(hb["started"]) if hb.get("started") else None
        if started and started > shipped_at and (hb.get("analyse") or {}).get("records", 0) > 0:
            ingested = True
            break
        time.sleep(3)
    check(f"logs du capteur analysés par le central ({(heartbeat().get('analyse') or {}).get('records')} "
          "enregistrement(s) au cycle suivant)", ingested)
    r = sensor("envoyer", env=env)
    check("nouvel envoi : rien de recopié en double (même résultat, toujours accepté)", r.returncode == 0)
    r = run(*A, "capteur", "liste", "--logs", "/var/lib/auspex/logs")
    check("auspex capteur liste : dernier dépôt affiché", "dernier dépôt il y a" in r.stdout)

    print("Attaques")
    r = sensor("envoyer", env={**env, "AUSPEX_CENTRAL_EMPREINTE": "SHA256:" + "A" * 43})
    check("faux central (empreinte différente) : rien n'est envoyé", r.returncode != 0
          and "envoi_empreinte_differente" in r.stderr)
    (WORK / "inconnu").mkdir(exist_ok=True)
    r = sensor("envoyer", conf="inconnu", env=env)
    check("clé non déclarée : refusée", r.returncode != 0 and not (LOGS / "inconnu").exists())
    r = sensor("envoyer", ip=OTHER_IP, env=env)
    check(f"bonne clé depuis une autre adresse ({OTHER_IP}) : refusée", r.returncode != 0)
    rs = ["rsync", "-rt", "-e", "ssh " + " ".join(ssh_cmd())]
    # La lecture ne sert que la publication des mises à jour (/mises-a-jour, lecture seule) :
    # aucun chemin ne mène aux logs reçus.
    pull = " ".join(rs[:3]) + f" '{rs[3]}'"
    r = sensor("-c", f"{pull} capteur@reception: /tmp/vol/ && find /tmp/vol -type f", entrypoint="sh")
    check("lecture : seule la publication des mises à jour est servie (aucun log)",
          ".log" not in r.stdout and "conn" not in r.stdout)
    leaks = []
    for path in ("capteur-ci/", "lab/", "../logs/", "/logs/capteur-ci/", "../../logs/capteur-ci/"):
        r = sensor("-c", f"{pull} 'capteur@reception:{path}' /tmp/vol/ && find /tmp/vol -name '*.log'",
                   entrypoint="sh")
        if r.returncode == 0 and ".log" in r.stdout:
            leaks.append(path)
    check(f"lecture des logs reçus : refusée par tous les chemins {leaks or ''}", not leaks)
    r = sensor("-c", "echo piege > /tmp/evil.log && " + " ".join(rs[:3]) + f" '{rs[3]}' /tmp/evil.log "
               "'capteur@reception:../evil.log'", entrypoint="sh")
    escaped = [p for p in LOGS.rglob("evil.log") if (LOGS / "capteur-ci") not in p.parents]
    check("écriture hors du dossier du capteur : refusée", not escaped and not (LOGS.parent / "evil.log").exists())
    r = sensor("-c", "ssh " + " ".join(ssh_cmd()) + " capteur@reception id; ssh " + " ".join(ssh_cmd())
               + " -t capteur@reception sh", entrypoint="sh")
    check("commande arbitraire et shell : refusés", "uid=" not in r.stdout and "uid=" not in r.stderr)
    # Sonde PostgreSQL (SSLRequest) : seule une vraie base répond « S » ou « N ».
    (WORK / "sonde").mkdir(exist_ok=True)       # conf/ appartient à root (créé par le conteneur)
    (WORK / "sonde" / "sonde.py").write_text(
        "import socket, struct\n"
        "try:\n"
        "    s = socket.create_connection(('127.0.0.1', 15432), 3); s.settimeout(3)\n"
        "    s.send(struct.pack('>II', 8, 80877103)); r = s.recv(1)\n"
        "    print('TUNNEL_OUVERT' if r in (b'S', b'N') else 'ferme')\n"
        "except OSError:\n"
        "    print('ferme')\n")
    r = sensor("-c", "ssh " + " ".join(ssh_cmd()) + " -N -L 15432:postgres:5432 capteur@reception & sleep 5; "
               "python3 /sonde/sonde.py; kill %1 2>/dev/null; true",
               entrypoint="sh", extra=[(WORK / "sonde", "/sonde")])
    check("redirection de port vers la base NetBox : refusée", "TUNNEL_OUVERT" not in r.stdout)
    before = sorted(p.name for p in (LOGS / "capteur-ci" / "lab").glob("*"))
    r = sensor("-c", "mkdir -p /tmp/vide && " + " ".join(rs[:3]) + f" '{rs[3]}' --delete /tmp/vide/ "
               "capteur@reception:lab/", entrypoint="sh")
    after = sorted(p.name for p in (LOGS / "capteur-ci" / "lab").glob("*"))
    check("suppression des logs reçus : refusée", before == after and before)
    r = sensor("-c", "ln -sf /etc/passwd /tmp/lien.log && " + " ".join(rs[:3]) + f" '{rs[3]}' -l /tmp/lien.log "
               "capteur@reception:", entrypoint="sh")
    link = LOGS / "capteur-ci" / "lien.log"
    check("lien symbolique neutralisé (cible inaccessible)", not link.exists())

    print("Révocation")
    set_sensors([])
    check("capteur retiré de auspex.yaml : clé retirée par le service", wait_authorized(False))
    r = sensor("envoyer", env=env)
    check("capteur révoqué : envoi refusé", r.returncode != 0)

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
            print(f"::error title=Capteur exception::{line}", flush=True)
        rc = 1
    print(f"::notice title=Capteur → central::{sum(ok for _, ok in RESULTS)}/{len(RESULTS)} vérifications réussies",
          flush=True)
    raise SystemExit(rc)
