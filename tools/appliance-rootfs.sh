#!/bin/bash
# Racine du capteur pour l'appliance, exportée de l'image Docker du capteur.
#   tools/appliance-rootfs.sh IMAGE RÉPERTOIRE_DE_SORTIE
# Produit sensor-rootfs.tar (sans les outils de compilation, inutiles à
# l'exécution) et sensor.env (variables d'environnement de l'image : PATH…).
set -euo pipefail
IMAGE="$1"; OUT="$2"
mkdir -p "$OUT"
cid=$(docker create "$IMAGE")
# Script écrit dans un fichier : passé par « python3 - <<EOF », il prendrait la
# place de l'entrée standard, où arrive l'archive de « docker export ».
filter=$(mktemp --suffix=.py)
trap 'docker rm -f "$cid" >/dev/null; rm -f "$filter"' EXIT
cat > "$filter" <<'PY'
import copy, sys, tarfile
# Outils de compilation (zkg les utilise à la construction de l'image) : retirés.
DROP = ("usr/lib/gcc/", "usr/include/", "usr/share/doc/", "usr/share/man/", "usr/share/info/",
        "usr/lib/x86_64-linux-gnu/perl/", "var/cache/", "var/lib/apt/lists/", "root/.cache/")
src = tarfile.open(sys.argv[1])          # accès direct : besoin du contenu des cibles de liens
dst = tarfile.open(sys.argv[2], "w")
members = src.getmembers()
by_name = {m.name.removeprefix("./"): m for m in members}
kept = dropped = 0
gone = set()
for m in members:
    name = m.name.removeprefix("./")
    if name.startswith(DROP) or (name.startswith(("dev/", "proc/", "sys/")) and m.isfile()):
        gone.add(name)
        dropped += 1
        continue
    if m.islnk() and m.linkname.removeprefix("./") in gone:
        # Lien physique vers un fichier retiré : conservé comme fichier ordinaire.
        target = by_name[m.linkname.removeprefix("./")]
        copy_ = copy.copy(target)
        copy_.name, copy_.mode, copy_.mtime = m.name, m.mode, m.mtime
        dst.addfile(copy_, src.extractfile(target))
        kept += 1
        continue
    dst.addfile(m, src.extractfile(m) if m.isfile() else None)
    kept += 1
dst.close()
print(f"racine du capteur : {kept} entrées, {dropped} retirées", file=sys.stderr)
PY
export_tar=$(mktemp --suffix=.tar)
trap 'docker rm -f "$cid" >/dev/null; rm -f "$filter" "$export_tar"' EXIT
docker export "$cid" > "$export_tar"
python3 "$filter" "$export_tar" "$OUT/sensor-rootfs.tar"
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$IMAGE" | grep -E '^(PATH|ZEEK[A-Z_]*|LANG)=' > "$OUT/sensor.env"
cat "$OUT/sensor.env"
