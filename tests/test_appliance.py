"""Appliance capteur : contrôles statiques (l'ISO elle-même est construite et démarrée en CI)."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent / "appliance" / "config"
CHROOT = ROOT / "includes.chroot"
LIB = CHROOT / "usr/local/lib/auspex/lib.sh"
FP = "SHA256:+8+04yc02vxEmBR97SlJdLwWAwkQLtcLUpIgi1Sa7rI"

pytestmark = pytest.mark.skipif(not shutil.which("bash"), reason="bash absent")


def load(tmp_path, text):
    conf = tmp_path / "capteur.conf"
    conf.write_text(text)
    r = subprocess.run(["bash", "-c", f'. "{LIB}"; msg(){{ echo "$*"; }}; load_conf "{conf}"; rc=$?; '
                       'for k in "${!C[@]}"; do echo "C:$k=${C[$k]}"; done; exit $rc'],
                       capture_output=True, text=True, timeout=30)
    values = dict(line[2:].split("=", 1) for line in r.stdout.splitlines() if line.startswith("C:"))
    return r.returncode, values, r.stdout


def test_valid_configuration(tmp_path):
    rc, c, out = load(tmp_path, f"""# capteur
NOM=capteur-ot
ADMIN_INTERFACE=mac:52:54:00:00:00:01
ADMIN_ADRESSE=10.9.0.20/24
ADMIN_PASSERELLE=10.9.0.1
DNS=10.9.0.53
NTP=ntp.ville.fr
ECOUTE_INTERFACE=ens4
CENTRAL="auspex.ville.fr:2222"
CENTRAL_EMPREINTE={FP}
""")
    assert rc == 0, out
    assert c["CENTRAL"] == "auspex.ville.fr:2222" and c["ADMIN_INTERFACE"] == "mac:52:54:00:00:00:01"


def test_injection_refused(tmp_path):
    marker = tmp_path / "pwned"
    rc, c, out = load(tmp_path, f"""NOM=$(touch {marker})
CENTRAL=10.0.0.1;reboot
DNS=8.8.8.8 `id`
ECOUTE_INTERFACE=eth0 x
PATH=/tmp
LD_PRELOAD=/tmp/x.so
CENTRAL_EMPREINTE=SHA256:court
""")
    assert rc != 0 and not marker.exists() and "PATH" not in c and "LD_PRELOAD" not in c
    for needle in ("valeur invalide pour NOM", "valeur invalide pour CENTRAL", "clé inconnue PATH",
                   "valeur invalide pour CENTRAL_EMPREINTE"):
        assert needle in out


@pytest.mark.parametrize("text, needle", [
    (f"NOM=a\nECOUTE_INTERFACE=eth1\nCENTRAL=auspex.ville.fr\nCENTRAL_EMPREINTE={FP}\n", "renseigner DNS"),
    (f"NOM=a\nECOUTE_INTERFACE=eth1\nCENTRAL=10.0.0.1\nCENTRAL_EMPREINTE={FP}\nADMIN_ADRESSE=10.0.0.5/24\n",
     "ADMIN_PASSERELLE nécessaire"),
    ("NOM=a\n", "CENTRAL manquant"),
])
def test_incomplete_configuration(tmp_path, text, needle):
    rc, _, out = load(tmp_path, text)
    assert rc != 0 and needle in out


def test_units_and_scripts_consistent():
    units = sorted((CHROOT / "etc/systemd/system").glob("auspex-*.service"))
    hook = (ROOT / "hooks/normal/9000-auspex.hook.chroot").read_text()
    for unit in units:
        assert unit.stem in hook, f"{unit.name} non activé par le hook"
        for exe in re.findall(r"^ExecStart=(/usr/local/sbin/\S+)", unit.read_text(), re.M):
            script = CHROOT / exe.lstrip("/")
            assert script.exists(), exe
            assert subprocess.run(["bash", "-n", str(script)]).returncode == 0
    capteur = (CHROOT / "etc/systemd/system/auspex-capteur.service").read_text()
    assert "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN\n" in capteur and "NoNewPrivileges=yes" in capteur


def test_no_login_no_remote_access():
    packages = (ROOT / "package-lists/auspex.list.chroot").read_text().split()
    assert "openssh-server" not in packages and "live-config" not in packages
    hook = (ROOT / "hooks/normal/9000-auspex.hook.chroot").read_text()
    assert "passwd -l root" in hook and "serial-getty@ttyS0.service" in hook and "getty@tty1.service" in hook
    build = (ROOT.parent / "build.sh").read_text()
    assert "rm -f config/package-lists/live.list.chroot" in build      # pas de compte « user » de live-config


def test_boot_firewall_closed():
    nft = (CHROOT / "etc/nftables.conf").read_text()
    assert nft.count("policy drop") == 3 and "accept" not in nft.replace("iif lo accept", "").replace(
        "oif lo accept", "")
    parefeu = (CHROOT / "usr/local/sbin/auspex-parefeu").read_text()
    assert "hook egress device" in parefeu and parefeu.count("policy drop") == 4
    sysctl = (CHROOT / "etc/sysctl.d/90-auspex.conf").read_text()
    assert "arp_ignore" not in sysctl                                   # l'administration doit répondre à ARP


def test_silent_before_configuration():
    """Avant la configuration, aucune interface n'émet (relevé en CI : dhclient de live-boot
    sur toutes les interfaces, écoute comprise)."""
    hook = (ROOT / "hooks/normal/9000-auspex.hook.chroot").read_text()
    assert "apt-get purge -y ifupdown isc-dhcp-client" in hook and "auspex-silence" in hook
    silence = (CHROOT / "etc/systemd/system/auspex-silence.service").read_text()
    assert "Before=systemd-networkd.service" in silence
    assert "hook egress device" in (CHROOT / "usr/local/sbin/auspex-silence").read_text()
    default = (CHROOT / "etc/systemd/network/99-auspex-defaut.network").read_text()
    assert "Unmanaged=yes" in default
