#!/usr/bin/env python3
"""Preuve « appliance capteur » : l'ISO démarre en machine virtuelle et alimente le central.

- ISO construite par appliance/build.sh, démarrée par QEMU avec deux cartes :
  administration (vers le central) et écoute (trafic rejoué par tcpreplay) ;
- un disque de données vide (formaté au premier démarrage) et un support
  AUSPEX-CONF (configuration et clé fournies, comme pour un déploiement en
  série) ;
- les logs Zeek arrivent au central et y sont analysés ;
- trafic capturé sur les deux cartes pendant tout l'essai : AUCUNE trame émise
  sur l'écoute, et sur l'administration rien d'autre que DHCP et le central ;
- mises à jour signées de l'analyse : publication falsifiée refusée, version
  plus récente installée et validée, version défaillante abandonnée avec
  retour automatique à la précédente.

Usage (dans deploy/, central installé, ISO dans ../appliance/out/) :
python ../tools/ci_appliance.py
"""

from __future__ import annotations

import json
import os
import re
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_mfa import CONFIG  # noqa: E402

A = ["docker", "compose", "exec", "-T", "auspex", "auspex", "-c", "/etc/auspex/auspex.yaml"]
WORK = Path("appliance-ci").resolve()
ISO = next(Path("../appliance/out").glob("auspex-capteur-*.iso"), None)
SQUASH = next(Path("../appliance/out").glob("auspex-capteur-*.squashfs"), None)
DEPOT = Path("data/depot-maj")                # vu par le service Auspex sous /var/lib/auspex/depot-maj
STATE, LOGS = Path("data/state"), Path("logs")
ADM_MAC, CAP_MAC = "52:54:00:a0:00:01", "52:54:00:a0:00:02"
GATEWAY = "172.31.250.1"     # QEMU (réseau utilisateur) → port publié du central : vu depuis la passerelle Docker
RESULTS: list[tuple[str, bool]] = []


def check(label: str, ok) -> None:
    ok = bool(ok)
    RESULTS.append((label, ok))
    print(f"  {'OK ' if ok else 'ÉCHEC'}  {label}", flush=True)


def run(*cmd, check_rc=False, timeout=600, **kw) -> subprocess.CompletedProcess:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)
    if check_rc and r.returncode != 0:
        raise RuntimeError(f"{' '.join(map(str, cmd))} : {r.stderr.strip()[-400:]}")
    return r


def serial() -> str:
    try:
        return (WORK / "serie.log").read_text(errors="replace")
    except OSError:
        return ""


def wait_serial(pattern: str, timeout: int) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if re.search(pattern, serial()):
            return True
        time.sleep(5)
    return False


def frames(path: Path):
    """Trames Ethernet d'un pcap (format classique écrit par filter-dump de QEMU)."""
    data = path.read_bytes() if path.exists() else b""
    if len(data) < 24:
        return
    endian = "<" if data[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    off = 24
    while off + 16 <= len(data):
        _, _, incl, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        yield data[off + 16:off + 16 + incl]
        off += 16 + incl


def mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def describe(frame: bytes) -> tuple[str, str | None]:
    """(résumé, motif de refus ou None) pour une trame émise par l'appliance."""
    etype = struct.unpack(">H", frame[12:14])[0]
    if etype == 0x0806:
        return "ARP", None
    if etype == 0x86DD:
        return "IPv6", "IPv6 émis (désactivé sur l'appliance)"
    if etype != 0x0800:
        return f"ethertype {etype:#06x}", "protocole inattendu"
    ip = frame[14:]
    ihl, proto = (ip[0] & 0x0F) * 4, ip[9]
    dst = ".".join(map(str, ip[16:20]))
    l4 = ip[ihl:]
    sport, dport = struct.unpack(">HH", l4[:4]) if proto in (6, 17) and len(l4) >= 4 else (None, None)
    what = f"{ {6: 'tcp', 17: 'udp', 1: 'icmp'}.get(proto, proto)} → {dst}:{dport}"
    if proto == 17 and (sport, dport) == (68, 67):
        return "DHCP", None
    if proto == 6 and dst == "10.0.2.2" and dport == 2222:
        return "central", None
    return what, "sortie non autorisée"


def publish(image: Path, version: str) -> subprocess.CompletedProcess:
    DEPOT.mkdir(exist_ok=True)
    target = DEPOT / f"auspex-capteur-{version}.squashfs"
    target.write_bytes(image.read_bytes())
    r = run(*A, "capteur", "publier", f"/var/lib/auspex/depot-maj/{target.name}")
    print(f"    {(r.stdout + r.stderr).strip()[:200]}")
    return r


def broken_image(version: str) -> Path:
    """Image signée mais défaillante : l'analyse s'arrête aussitôt (doit être abandonnée)."""
    tree, out = WORK / "casse", WORK / f"casse-{version}.squashfs"
    run("sudo", "rm", "-rf", str(tree))
    run("sudo", "unsquashfs", "-q", "-d", str(tree), str(SQUASH), check_rc=True, timeout=900)
    run("sudo", "sh", "-c", f"printf '#!/bin/sh\\necho analyse cassee >&2\\nexit 1\\n' > {tree}/opt/auspex/entrypoint.sh",
        check_rc=True)
    run("sudo", "mksquashfs", str(tree), str(out), "-noappend", "-comp", "gzip", "-quiet", "-no-progress",
        check_rc=True, timeout=900)
    run("sudo", "chown", f"{os.getuid()}:{os.getgid()}", str(out))
    run("sudo", "rm", "-rf", str(tree))
    return out


def sensor_state() -> dict:
    try:
        return json.loads((LOGS / "capteur-vm" / "auspex-etat.json").read_text())
    except (OSError, ValueError):
        return {}


def updates(pcap: Path) -> None:
    print("Mises à jour signées de l'analyse")
    if not SQUASH:
        check("image de mise à jour présente (appliance/out/*.squashfs)", False)
        return
    base = re.search(r"auspex-capteur-([0-9.]+)\.squashfs", SQUASH.name).group(1)
    good, bad = f"{base}.1", f"{base}.2"

    # 1. Publication falsifiée (manifeste modifié après signature) : refusée.
    publish(SQUASH, good)
    m = Path("data/mises-a-jour/courant/manifeste")
    m.write_text(m.read_text().replace(f"version={good}", "version=99.0.0"))
    check("publication falsifiée : refusée par le capteur (signature invalide)",
          wait_serial(r"mise à jour refusée : signature invalide", 240))
    check("publication falsifiée : rien d'installé", "mise à jour 99.0.0" not in serial())

    # 2. Version plus récente, correctement signée : installée, mise à l'essai, validée.
    r = publish(SQUASH, good)
    check(f"auspex capteur publier {good}", r.returncode == 0)
    check(f"mise à jour {good} téléchargée et installée",
          wait_serial(rf"mise à jour {re.escape(good)} installée \(emplacement a\)", 900))
    check(f"analyse redémarrée sur la mise à jour (emplacement a)",
          wait_serial(rf"analyse : version {re.escape(good)} \(emplacement a\)", 120))
    check(f"mise à jour {good} validée après l'essai", wait_serial(rf"mise à jour {re.escape(good)} validée", 180))

    # 3. Version signée mais défaillante : abandonnée, retour automatique à la précédente.
    r = publish(broken_image(bad), bad)
    check(f"auspex capteur publier {bad} (image défaillante)", r.returncode == 0)
    check(f"mise à jour {bad} installée dans l'autre emplacement (b)",
          wait_serial(rf"mise à jour {re.escape(bad)} installée \(emplacement b\)", 900))
    check(f"mise à jour {bad} en échec : retour automatique à {good}",
          wait_serial(rf"mise à jour {re.escape(bad)} en échec \(.*\) : retour à {re.escape(good)}", 240))
    check(f"analyse revenue sur {good} (emplacement a)",
          wait_serial(rf"(?s)en échec.*analyse : version {re.escape(good)} \(emplacement a\)", 120))
    time.sleep(90)
    check(f"version abandonnée jamais retentée", serial().count(f"mise à jour {bad} installée") == 1)

    # 4. Le central voit la version de chaque capteur, et l'analyse continue.
    since = time.time()
    st = {}
    for _ in range(24):
        run("sudo", "tcpreplay", "-q", "-i", "tapcap", "--mbps", "20", str(pcap))
        st = sensor_state()
        fresh = [f for f in (LOGS / "capteur-vm").rglob("conn*.log") if f.stat().st_mtime > since]
        if st.get("analyse") == good and st.get("maj") == "echec" and fresh:
            break
        time.sleep(10)
    check(f"état reçu par le central : analyse {st.get('analyse')}, dernière mise à jour {st.get('maj')}",
          st.get("analyse") == good and st.get("maj") == "echec")
    check("logs toujours reçus après le retour arrière",
          any(f.stat().st_mtime > since for f in (LOGS / "capteur-vm").rglob("conn*.log")))
    r = run(*A, "capteur", "liste", "--logs", "/var/lib/auspex/logs")
    print("    " + r.stdout.strip().replace("\n", "\n    "))
    check(f"auspex capteur liste : analyse {good}, publication {bad}",
          f"analyse {good}" in r.stdout and f"mise à jour publiée : {bad}" in r.stdout)


def main() -> int:
    if not ISO:
        check("ISO présente dans appliance/out", False)
        return 1
    WORK.mkdir(exist_ok=True)
    print(f"Préparation ({ISO.name}, {ISO.stat().st_size // 1_000_000} Mo)")
    key = WORK / "cle"
    if not key.exists():
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "capteur-vm", "-f", str(key), check_rc=True)
    pub = (WORK / "cle.pub").read_text().strip()
    fp = re.search(r"SHA256:\S{43}", run(*A, "capteur", "empreinte").stdout)
    check("empreinte du central obtenue", fp)
    cfg = yaml.safe_load(CONFIG.read_text())
    cfg["sensors"] = [{"name": "capteur-vm", "zone": "OT-N2", "interface": "ecoute", "key": pub, "allow": [GATEWAY]}]
    CONFIG.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))
    for _ in range(30):
        if "auspex:capteur-vm" in (STATE / "reception" / "authorized_keys").read_text(errors="replace") \
                if (STATE / "reception" / "authorized_keys").exists() else False:
            break
        time.sleep(3)
    majcle = re.search(r"^MAJ_CLE=\S+$", run(*A, "capteur", "cle-maj").stdout, re.M)
    check("clé de mises à jour du central (auspex capteur cle-maj)", majcle)
    (WORK / "capteur.conf").write_text(
        "# Capteur de la CI\nNOM=capteur-vm\n"
        f"ADMIN_INTERFACE=mac:{ADM_MAC}\nADMIN_ADRESSE=dhcp\n"
        f"ECOUTE_INTERFACE=mac:{CAP_MAC}\n"
        f"CENTRAL=10.0.2.2:2222\nCENTRAL_EMPREINTE={fp.group(0) if fp else ''}\n"
        f"{majcle.group(0) if majcle else ''}\nMAJ_FREQUENCE=1\nMAJ_ESSAI=45\n")
    seed = WORK / "seed.img"
    seed.unlink(missing_ok=True)
    run("mkfs.vfat", "-n", "AUSPEX-CONF", "-C", str(seed), "2048", check_rc=True)
    for f in ("capteur.conf", "cle", "cle.pub"):
        run("mcopy", "-i", str(seed), str(WORK / f), "::", check_rc=True)
    data = WORK / "donnees.qcow2"
    data.unlink(missing_ok=True)
    run("qemu-img", "create", "-q", "-f", "qcow2", str(data), "4G", check_rc=True)
    user = os.environ.get("USER") or run("id", "-un").stdout.strip()
    run("sudo", "ip", "tuntap", "add", "dev", "tapcap", "mode", "tap", "user", user)
    run("sudo", "ip", "link", "set", "tapcap", "up", check_rc=True)

    print("Démarrage de l'appliance")
    kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)
    qemu = ["qemu-system-x86_64", "-m", "2048", "-smp", "2", "-display", "none", "-no-reboot",
            *(["-enable-kvm", "-cpu", "host"] if kvm else []),
            "-cdrom", str(ISO.resolve()), "-boot", "d",
            "-drive", f"file={data},if=virtio,format=qcow2",
            "-drive", f"file={seed},if=virtio,format=raw",
            "-netdev", "user,id=adm", "-device", f"virtio-net-pci,netdev=adm,mac={ADM_MAC}",
            "-object", f"filter-dump,id=dadm,netdev=adm,file={WORK / 'admin.pcap'}",
            "-netdev", "tap,id=cap,ifname=tapcap,script=no,downscript=no",
            "-device", f"virtio-net-pci,netdev=cap,mac={CAP_MAC}",
            "-object", f"filter-dump,id=dcap,netdev=cap,file={WORK / 'ecoute.pcap'}",
            "-serial", f"file:{WORK / 'serie.log'}"]
    vm = subprocess.Popen(qemu, stdout=subprocess.DEVNULL, stderr=open(WORK / "qemu.err", "w"))
    check(f"QEMU lancé ({'KVM' if kvm else 'émulation'})", vm.poll() is None)
    boot = 600 if kvm else 1500
    try:
        check("disque de données vide (le disque virtuel) formaté au premier démarrage",
              wait_serial(r"disque de données vide trouvé \(/dev/vd", boot) and "/dev/fd0" not in serial())
        check("configuration et clé importées du support AUSPEX-CONF",
              wait_serial(r"configuration importée depuis AUSPEX-CONF", 120) and "clé d'envoi importée" in serial())
        check("pare-feu : sorties limitées au central", wait_serial(r"pare-feu : sorties limitées au central", 120))
        check("écoute sans adresse", wait_serial(r"réseau : administration \S+ \(dhcp\), écoute \S+ sans adresse", 120))
        check("analyse Zeek démarrée", wait_serial(r"capteur démarré \(écoute", 180))
        check("analyse : image d'usine de l'ISO", re.search(r"analyse : version \S+ \(image d'usine\)", serial()))

        print("Trafic rejoué sur l'interface d'écoute, envoi au central")
        pcap = WORK / "lab.pcap"
        run(sys.executable, str(Path(__file__).parent / "pcapgen.py"), str(pcap), check_rc=True)
        shipped = False
        started = datetime.now(timezone.utc)
        for _ in range(16):
            run("sudo", "tcpreplay", "-q", "-i", "tapcap", "--mbps", "20", str(pcap))
            time.sleep(20)
            files = list((LOGS / "capteur-vm").rglob("conn*.log")) if (LOGS / "capteur-vm").exists() else []
            if any(f.stat().st_size > 0 for f in files):
                shipped = True
                break
        check(f"logs de l'appliance reçus par le central (logs/capteur-vm/)", shipped)
        ingested = False
        for _ in range(30):
            try:
                hb = json.loads((STATE / "heartbeat.json").read_text())
            except (OSError, ValueError):
                hb = {}
            if hb.get("started") and datetime.fromisoformat(hb["started"]) > started \
                    and (hb.get("analyse") or {}).get("records", 0) > 0:
                ingested = True
                break
            time.sleep(5)
        check("logs analysés par le central", ingested)
        assets = run(*A, "assets", "--json").stdout
        check("automate du trafic rejoué présent dans l'inventaire (172.16.2.50)", "172.16.2.50" in assets)
        r = run(*A, "capteur", "liste", "--logs", "/var/lib/auspex/logs")
        check("auspex capteur liste : dernier dépôt de capteur-vm", "capteur-vm" in r.stdout and "dernier dépôt" in r.stdout)
        updates(pcap)
    finally:
        vm.terminate()
        try:
            vm.wait(30)
        except subprocess.TimeoutExpired:
            vm.kill()
        run("sudo", "ip", "link", "delete", "tapcap")

    print("Ce que l'appliance a émis")
    cap = list(frames(WORK / "ecoute.pcap"))
    emitted = [f for f in cap if mac(f[6:12]) == CAP_MAC]
    check(f"interface d'écoute : {len(cap)} trame(s) reçue(s), {len(emitted)} émise(s) (attendu : 0)",
          cap and not emitted)
    adm = [f for f in frames(WORK / "admin.pcap") if mac(f[6:12]) == ADM_MAC]
    kinds: dict[str, int] = {}
    bad: dict[str, int] = {}
    for f in adm:
        what, why = describe(f)
        (bad if why else kinds)[what] = (bad if why else kinds).get(what, 0) + 1
    check(f"administration : {sum(kinds.values())} trame(s) autorisée(s) {kinds}", "central" in kinds)
    check(f"administration : aucune autre sortie {bad or ''}", not bad)
    refused = serial().count("auspex-sortie-refusee")
    print(f"  (sorties bloquées par le pare-feu de l'appliance : {refused})")
    check("aucun compte de connexion sur la console série", not re.search(r"login:\s*$", serial(), re.M))

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
            print(f"::error title=Appliance exception::{line}", flush=True)
        rc = 1
    # Console série : lignes d'Auspex et échecs (tout le démarrage), puis la fin
    lines = serial().replace("\r", "").splitlines()
    keep = [line for line in lines if re.search(r"auspex|ERREUR|[Ff]ailed|dhclient|DHCP", line)][:150]
    print("\n--- Console série : Auspex et échecs ---\n" + "\n".join(keep), flush=True)
    print("\n--- Console série : fin ---\n" + "\n".join(lines[-40:]), flush=True)
    print(f"::notice title=Appliance::{sum(ok for _, ok in RESULTS)}/{len(RESULTS)} vérifications réussies",
          flush=True)
    raise SystemExit(rc)
