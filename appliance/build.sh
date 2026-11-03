#!/bin/bash
# Construction de l'image du capteur Auspex (ISO hybride : clé USB, CD, VM).
#
# À lancer dans un conteneur Debian 12 privilégié (live-build monte /proc
# dans le chroot) ; voir appliance/README.md :
#
#   docker build -t auspex-sensor sensor
#   tools/appliance-rootfs.sh auspex-sensor appliance/out     # racine du capteur
#   docker run --rm --privileged -v "$PWD:/src" debian:bookworm /src/appliance/build.sh
#
# Résultat : appliance/out/auspex-capteur-<version>.iso (installation) et
# auspex-capteur-<version>.squashfs (mise à jour de l'analyse, à publier par le
# central), avec leurs empreintes.
set -euo pipefail
SRC=/src
OUT="$SRC/appliance/out"
VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$SRC/src/auspex/__init__.py")
[ -f "$OUT/sensor-rootfs.tar" ] || { echo "manque $OUT/sensor-rootfs.tar (tools/appliance-rootfs.sh)" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends live-build debootstrap xorriso squashfs-tools \
    syslinux-utils isolinux grub-efi-amd64-bin grub-pc-bin mtools dosfstools ca-certificates > /dev/null

W=$(mktemp -d)
cd "$W"
lb config \
    --distribution bookworm \
    --archive-areas "main non-free-firmware" \
    --binary-images iso-hybrid \
    --debian-installer none \
    --apt-recommends false \
    --apt-indices false \
    --memtest none \
    --firmware-binary false \
    --firmware-chroot false \
    --iso-volume "AUSPEX-CAPTEUR" \
    --iso-application "Auspex capteur $VERSION" \
    --iso-publisher "Auspex" \
    --bootappend-live "boot=live quiet ipv6.disable=1 console=tty1 console=ttyS0,115200n8 hostname=auspex-capteur" \
    --mirror-bootstrap http://deb.debian.org/debian \
    --mirror-chroot http://deb.debian.org/debian \
    --mirror-binary http://deb.debian.org/debian \
    --mirror-chroot-security http://deb.debian.org/debian-security \
    --mirror-binary-security http://deb.debian.org/debian-security \
    > /dev/null

# Menu de démarrage : entrée par défaut au bout de 3 s (sinon le menu attend une touche).
cp -a /usr/share/live/build/bootloaders config/
find config/bootloaders -type f -name '*.cfg' -exec sed -i \
    -e 's/^\([[:space:]]*\)timeout .*/\1timeout 30/' -e 's/^\([[:space:]]*\)set timeout=.*/\1set timeout=3/' {} +
grep -rqs 'timeout 30' config/bootloaders/isolinux || echo 'timeout 30' >> config/bootloaders/isolinux/isolinux.cfg

# live-config (compte « user » au mot de passe connu) : jamais installé.
rm -f config/package-lists/live.list.chroot
cp -a "$SRC/appliance/config/." config/
echo "$VERSION" > config/includes.chroot/etc/auspex-version

# Racine du capteur (Zeek, ICSNPP) : exportée de l'image Docker testée en CI.
R=config/includes.chroot/opt/auspex-sensor
mkdir -p "$R"
tar -xf "$OUT/sensor-rootfs.tar" -C "$R"
mkdir -p "$R/.auspex"
# Points de montage du service auspex-capteur : la racine est montée en lecture
# seule, systemd ne peut pas les créer (relevé en CI).
mkdir -p "$R/logs" "$R/etc/auspex-capteur" "$R/tmp" "$R/run" "$R/proc" "$R/sys" "$R/dev"
touch "$R/etc/resolv.conf" "$R/etc/hosts"
cp "$OUT/sensor.env" "$R/.auspex/sensor.env"
echo "$VERSION" > "$R/.auspex/version"

# Même racine en image de mise à jour (squashfs), à publier par le central :
#   auspex capteur publier auspex-capteur-<version>.squashfs
mksquashfs "$R" "$OUT/auspex-capteur-$VERSION.squashfs" -noappend -comp xz -quiet -no-progress

lb build 2>&1 | tail -20
iso=$(ls -1 ./*.iso | head -1)
[ -n "$iso" ] || { echo "aucune ISO produite" >&2; exit 1; }
mkdir -p "$OUT"
mv "$iso" "$OUT/auspex-capteur-$VERSION.iso"
(cd "$OUT" && sha256sum "auspex-capteur-$VERSION.iso" > "auspex-capteur-$VERSION.iso.sha256" \
    && sha256sum "auspex-capteur-$VERSION.squashfs" > "auspex-capteur-$VERSION.squashfs.sha256")
ls -la "$OUT"
