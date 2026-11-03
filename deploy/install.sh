#!/usr/bin/env bash
# Installation du central Auspex en une commande.
#
#   cd deploy && ./install.sh
#
# Crée les secrets (.env), la configuration de départ, démarre NetBox,
# PostgreSQL, Redis et Auspex, et crée dans NetBox le compte de service
# « Librarian » aux droits restreints. Le conteneur Auspex ne reçoit QUE le
# jeton de Librarian ; le jeton administrateur reste sur cette machine, dans
# .env, et ne sert qu'à la mise en place (ici et dans update.sh).
# Relancer le script est sans danger : rien d'existant n'est écrasé.
set -euo pipefail
cd "$(dirname "$0")"

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
fail() { printf '\nErreur : %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null || fail "Docker est requis."
docker compose version >/dev/null 2>&1 || fail "Docker Compose (v2) est requis."

# Secret aléatoire. pipefail est coupé localement : tr reçoit SIGPIPE quand
# head a lu assez de caractères, ce qui est normal ici.
rand() { ( set +o pipefail; LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1" ); }
rand_hex() { ( set +o pipefail; LC_ALL=C tr -dc 'a-f0-9' </dev/urandom | head -c "$1" ); }

# Valeur d'une variable de .env, SANS la charger dans le shell : Docker Compose
# donne priorité aux variables du shell sur .env, une variable exportée ici
# masquerait la valeur du fichier.
env_get() { grep -E "^$1=" .env | head -1 | cut -d= -f2-; }

# Les services ne tournent jamais en root : installation en root → compte 10001.
if [ "$(id -u)" -eq 0 ]; then AUSPEX_RUN_UID=10001; AUSPEX_RUN_GID=10001; else
    AUSPEX_RUN_UID=$(id -u); AUSPEX_RUN_GID=$(id -g); fi

if [ ! -f .env ]; then
    say "Création des secrets (.env)"
    # umask limité à la création de .env (sous-shell)
    ( umask 077
    cat > .env <<EOF
# Généré par install.sh le $(date -u +%Y-%m-%dT%H:%M:%SZ). Ne jamais versionner ce fichier.
NETBOX_VERSION=v4.4
AUSPEX_VERSION=local
DB_PASSWORD=$(rand 32)
NETBOX_SECRET_KEY=$(rand 60)
NETBOX_ADMIN_PASSWORD=$(rand 24)
# Jeton administrateur NetBox : imposé à NetBox (sans lui, l'image crée un
# jeton par défaut connu publiquement) et utilisé UNIQUEMENT pour la mise en
# place. Il n'est jamais transmis au conteneur Auspex.
NETBOX_ADMIN_TOKEN=$(rand_hex 40)
# Jeton du compte de service « Librarian » : le seul dont dispose Auspex.
LIBRARIAN_TOKEN=$(rand_hex 40)
AUSPEX_UID=$AUSPEX_RUN_UID
AUSPEX_GID=$AUSPEX_RUN_GID
AUSPEX_INTERVAL=${AUSPEX_INTERVAL:-300}
EOF
    )
    chmod 600 .env
fi

# Installation antérieure : le jeton administrateur s'appelait NETBOX_TOKEN,
# et Librarian n'existait pas.
if ! grep -q '^NETBOX_ADMIN_TOKEN=' .env && grep -q '^NETBOX_TOKEN=' .env; then
    sed -i 's/^NETBOX_TOKEN=/NETBOX_ADMIN_TOKEN=/' .env
fi
grep -q '^LIBRARIAN_TOKEN=' .env || echo "LIBRARIAN_TOKEN=$(rand_hex 40)" >> .env
grep -q '^AUSPEX_PROXY_SECRET=' .env || echo "AUSPEX_PROXY_SECRET=$(rand_hex 64)" >> .env

# Répertoires montés : créés ici (et non par Docker, qui les créerait au nom de root)
mkdir -p tls config/tls data/state/tableau data/state/reception data/state/acces data/reception data/mises-a-jour logs backups
if [ "$(id -u)" -eq 0 ]; then
    chown -R "$(env_get AUSPEX_UID):$(env_get AUSPEX_GID)" data logs
fi
[ -f config/auspex.yaml ] || cp auspex.yaml.template config/auspex.yaml
[ -f config/regles-flux.csv ] || cp regles-flux.template.csv config/regles-flux.csv

# Certificat HTTPS du front, dans tls/ (hors de config/, que NetBox lit) :
# autosigné à défaut, à remplacer par celui de l'organisme (tls/serveur.crt
# et serveur.key, puis « docker compose restart acces »).
if [ ! -f tls/serveur.crt ]; then
    host="${AUSPEX_HOSTNAME:-$(hostname -f 2>/dev/null || hostname)}"
    # CN limité à 64 caractères (nom court) ; le nom complet va dans subjectAltName.
    cn=$(printf '%s' "${host%%.*}" | cut -c1-64)
    echo "Certificat HTTPS autosigné pour $host (tls/, à remplacer par le vôtre)"
    if ! err=$( umask 077
            openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 \
                -subj "/CN=$cn" -addext "subjectAltName=DNS:$host,DNS:localhost,IP:127.0.0.1" \
                -keyout tls/serveur.key -out tls/serveur.crt 2>&1 ); then
        echo "$err" >&2
        fail "création du certificat HTTPS impossible (openssl)"
    fi
    chmod 644 tls/serveur.crt 2>/dev/null || true
fi
# Clé lisible par le seul compte des services (le front ne tourne jamais en root).
chmod 700 tls
if [ "$(id -u)" -eq 0 ] && [ -n "$(env_get AUSPEX_UID)" ]; then
    chown -R "$(env_get AUSPEX_UID):$(env_get AUSPEX_GID)" tls
fi

say "Construction des images (Auspex, et NetBox avec le plugin Auspex)"
docker compose build auspex netbox reception acces

say "Démarrage de NetBox (le premier démarrage peut prendre plusieurs minutes)"
docker compose up -d postgres redis netbox

# NetBox est prêt quand son API répond, vu depuis le réseau Docker interne.
probe() {
    docker compose run --rm --no-deps -T --entrypoint python auspex -c \
        "import urllib.request,sys; urllib.request.urlopen('http://netbox:8080/login/', timeout=5); sys.exit(0)" \
        >/dev/null 2>&1
}
for i in $(seq 1 120); do
    probe && break
    [ "$i" -eq 120 ] && { docker compose logs --tail 50 netbox; fail "NetBox ne répond pas."; }
    sleep 5
done
echo "NetBox est prêt."

# Commande auspex exécutée avec le jeton ADMINISTRATEUR, dans un conteneur
# éphémère. Les jetons passent par l'environnement, jamais en argument.
as_admin() {
    NETBOX_TOKEN="$(env_get NETBOX_ADMIN_TOKEN)" LIBRARIAN_TOKEN="$(env_get LIBRARIAN_TOKEN)" \
        docker compose run --rm --no-deps -T -e NETBOX_TOKEN -e LIBRARIAN_TOKEN auspex "$@"
}

# Le jeton administrateur doit fonctionner. Sinon (NetBox déjà initialisé
# avant cette installation, par exemple), un nouveau jeton est demandé.
admin_token_ok() {
    NETBOX_TOKEN="$(env_get NETBOX_ADMIN_TOKEN)" docker compose run --rm --no-deps -T \
        -e NETBOX_TOKEN --entrypoint python auspex -c '
import os, urllib.request
req = urllib.request.Request("http://netbox:8080/api/users/users/?limit=1",
    headers={"Authorization": "Token " + os.environ["NETBOX_TOKEN"], "Accept": "application/json"})
urllib.request.urlopen(req, timeout=15)' >/dev/null 2>&1
}
if admin_token_ok; then
    echo "Jeton administrateur NetBox opérationnel."
else
    say "Création d'un jeton administrateur NetBox"
    token=$(NB_PASSWORD="$(env_get NETBOX_ADMIN_PASSWORD)" docker compose run --rm --no-deps -T \
        --entrypoint python -e NB_PASSWORD auspex -c '
import json, os, urllib.request
req = urllib.request.Request("http://netbox:8080/api/users/tokens/provision/",
    data=json.dumps({"username": "admin", "password": os.environ["NB_PASSWORD"],
                     "description": "Auspex : mise en place"}).encode(),
    headers={"Content-Type": "application/json", "Accept": "application/json"})
d = json.load(urllib.request.urlopen(req, timeout=30))
print(d.get("key") or d.get("token") or "")')
    [ -n "$token" ] || fail "impossible d'obtenir un jeton NetBox."
    sed -i "s/^NETBOX_ADMIN_TOKEN=.*/NETBOX_ADMIN_TOKEN=${token}/" .env
    admin_token_ok || fail "le jeton NetBox obtenu ne fonctionne pas."
fi

say "Mise en place dans NetBox : champs Auspex et compte de service Librarian"
as_admin netbox setup --apply || fail "mise en place dans NetBox impossible."

say "Démarrage d'Auspex (avec le seul jeton de Librarian)"
docker compose up -d auspex reception acces

say "Installation terminée"
cat <<EOF
  NetBox    : https://$(hostname -f 2>/dev/null || hostname):${AUSPEX_HTTPS_PORT:-443}
              (et http://127.0.0.1:${NETBOX_PORT:-8080} sur cette machine ; admin, mot de passe dans .env)
  Capteurs  : port ${AUSPEX_SENSOR_PORT:-2222} ; empreinte à donner aux capteurs :
              docker compose exec auspex auspex capteur empreinte
  Logs      : reçus des capteurs (ou déposés à la main) dans $(pwd)/logs
  Config    : $(pwd)/config/auspex.yaml  (zones, sorties SIEM, règles de flux)
  Suivi     : docker compose logs -f auspex
  Écarts    : docker compose exec auspex auspex findings
  Audit     : les écritures d'Auspex apparaissent dans l'historique NetBox au nom de « Librarian »
EOF
