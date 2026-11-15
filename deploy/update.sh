#!/usr/bin/env bash
# Mise à jour du central Auspex, avec sauvegarde et retour arrière automatique.
#
#   ./update.sh                         reconstruit et redémarre (même versions)
#   ./update.sh --netbox v4.4.5         change la version de NetBox
#                                       (--netbox v4.4 : retour à la version livrée)
#   ./update.sh --auspex v0.2.0         passe Auspex à un tag du dépôt
#
# Déroulé : sauvegarde (base NetBox, état Auspex, .env) → changement de
# versions → démarrage → contrôles de santé. Si un contrôle échoue, tout est
# remis comme avant : versions, code, base NetBox.
set -uo pipefail
cd "$(dirname "$0")"

NETBOX_TARGET=""
AUSPEX_TARGET=""
TIMEOUT="${AUSPEX_UPDATE_TIMEOUT:-900}"
while [ $# -gt 0 ]; do
    case "$1" in
        --netbox) NETBOX_TARGET="$2"; shift 2 ;;
        --auspex) AUSPEX_TARGET="$2"; shift 2 ;;
        -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Option inconnue : $1" >&2; exit 2 ;;
    esac
done

# Versions : caractères sûrs uniquement (elles sont écrites dans .env).
for v in "$NETBOX_TARGET" "$AUSPEX_TARGET"; do
    if [ -n "$v" ] && ! printf '%s' "$v" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'; then
        echo "Erreur : version « $v » invalide (lettres, chiffres, . _ - uniquement)" >&2
        exit 2
    fi
done

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
rand_hex() { ( set +o pipefail; LC_ALL=C tr -dc 'a-f0-9' </dev/urandom | head -c "$1" ); }
# Lecture de .env sans le charger dans le shell (voir install.sh).
env_get() { grep -E "^$1=" .env | head -1 | cut -d= -f2-; }
# Version de NetBox livrée avec Auspex (étiquette de l'image figée).
netbox_livree() { sed -n 's|^FROM netboxcommunity/netbox:\([^@]*\)@sha256:[0-9a-f]\{64\} AS netbox-livree$|\1|p' netbox/Dockerfile; }
[ -f .env ] || { echo "Erreur : .env absent, lancer d'abord ./install.sh" >&2; exit 2; }
CURRENT_NETBOX=$(env_get NETBOX_VERSION)

# Installation antérieure à Librarian : migration de .env AVANT la sauvegarde,
# pour qu'un retour arrière restaure un fichier compatible avec le compose.
if ! grep -q '^NETBOX_ADMIN_TOKEN=' .env && grep -q '^NETBOX_TOKEN=' .env; then
    sed -i 's/^NETBOX_TOKEN=/NETBOX_ADMIN_TOKEN=/' .env
fi
grep -q '^LIBRARIAN_TOKEN=' .env || echo "LIBRARIAN_TOKEN=$(rand_hex 40)" >> .env
grep -q '^AUSPEX_PROXY_SECRET=' .env || echo "AUSPEX_PROXY_SECRET=$(rand_hex 64)" >> .env

# Mise en place avec le jeton ADMINISTRATEUR (nouveaux champs d'une nouvelle
# version, compte Librarian) : Librarian n'a pas ces droits, et c'est voulu.
as_admin() {
    NETBOX_TOKEN="$(env_get NETBOX_ADMIN_TOKEN)" LIBRARIAN_TOKEN="$(env_get LIBRARIAN_TOKEN)" \
        docker compose run --rm --no-deps -T -e NETBOX_TOKEN -e LIBRARIAN_TOKEN auspex "$@"
}
wait_netbox() {
    local deadline=$(( $(date +%s) + TIMEOUT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        docker compose run --rm --no-deps -T --entrypoint python auspex -c \
            "import urllib.request; urllib.request.urlopen('http://netbox:8080/login/', timeout=5)" \
            >/dev/null 2>&1 && return 0
        sleep 10
    done
    return 1
}

# Tableau de bord (installations antérieures) : répertoire partagé avec NetBox.
mkdir -p tls config/tls data/state/tableau data/state/reception data/state/acces data/reception data/mises-a-jour
# Lancée en root : nouveaux répertoires rendus au compte des services (jamais root).
if [ "$(id -u)" -eq 0 ] && [ -n "$(env_get AUSPEX_UID)" ]; then
    chown "$(env_get AUSPEX_UID):$(env_get AUSPEX_GID)" data/state/tableau data/state/reception \
        data/state/acces data/reception data/mises-a-jour
fi
# Clé privée HTTPS hors de config/ (que NetBox lit) : ancien emplacement déplacé.
if [ -f config/tls/serveur.key ] && [ ! -f tls/serveur.key ]; then
    mv config/tls/serveur.key tls/serveur.key
    [ -f config/tls/serveur.crt ] && mv config/tls/serveur.crt tls/serveur.crt
    echo "Certificat HTTPS déplacé de config/tls/ vers tls/ (hors de portée de NetBox)"
fi
# Front HTTPS (nouveau) : certificat autosigné si l'installation n'en a pas encore.
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
        echo "Création du certificat HTTPS impossible : le front HTTPS ne démarrera pas" >&2
    fi
    chmod 644 tls/serveur.crt 2>/dev/null || true
fi
# Clé lisible par le seul compte des services (le front ne tourne jamais en root).
chmod 700 tls
if [ "$(id -u)" -eq 0 ] && [ -n "$(env_get AUSPEX_UID)" ]; then
    chown -R "$(env_get AUSPEX_UID):$(env_get AUSPEX_GID)" tls
fi

STAMP=$(date -u +%Y%m%d-%H%M%S)
BK="backups/$STAMP"
mkdir -p "$BK"
PREV_REF=$(git -C .. rev-parse HEAD 2>/dev/null || echo "")

# --- 1. Sauvegarde -----------------------------------------------------------
say "1/4 Sauvegarde dans deploy/$BK"
cp .env "$BK/env" && chmod 600 "$BK/env"
docker compose exec -T postgres pg_dump -U netbox -d netbox -Fc > "$BK/netbox.dump" \
    || { echo "Erreur : sauvegarde de la base NetBox impossible, mise à jour annulée." >&2; exit 1; }
[ -s "$BK/netbox.dump" ] || { echo "Erreur : sauvegarde NetBox vide, mise à jour annulée." >&2; exit 1; }
docker compose exec -T auspex auspex -c /etc/auspex/auspex.yaml backup \
    "/var/lib/auspex/backups/auspex-$STAMP.tar.gz" \
    || { echo "Erreur : sauvegarde Auspex impossible, mise à jour annulée." >&2; exit 1; }
echo "Base NetBox : $(du -h "$BK/netbox.dump" | cut -f1) — état Auspex : data/backups/auspex-$STAMP.tar.gz"

# Santé : NetBox répond ET Auspex a réussi un cycle commencé APRÈS $1. Sans
# cette date, le dernier cycle de l'ANCIENNE version suffirait à conclure.
healthy() {
    local since="$1"
    local deadline=$(( $(date +%s) + TIMEOUT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if docker compose exec -T auspex python -c \
              "import urllib.request; urllib.request.urlopen('http://netbox:8080/login/', timeout=5)" >/dev/null 2>&1 \
           && docker compose exec -T auspex auspex -c /etc/auspex/auspex.yaml health --since "$since" >/dev/null 2>&1; then
            return 0
        fi
        sleep 10
    done
    return 1
}

rollback() {
    say "Échec : retour à la version précédente"
    cp "$BK/env" .env
    if [ -n "$AUSPEX_TARGET" ] && [ -n "$PREV_REF" ]; then
        git -C .. checkout -q "$PREV_REF"
    fi
    docker compose stop netbox auspex >/dev/null 2>&1 || true
    echo "Restauration de la base NetBox…"
    # Restauration dans une base à part ; la base actuelle n'est remplacée que
    # si la restauration a entièrement réussi.
    if docker compose exec -T postgres sh -c 'dropdb -U netbox --if-exists netbox_rollback && \
            createdb -U netbox netbox_rollback' >/dev/null \
       && docker compose exec -T postgres pg_restore -U netbox -d netbox_rollback --no-owner \
            --exit-on-error < "$BK/netbox.dump"; then
        docker compose exec -T postgres sh -c 'psql -U netbox -d postgres -v ON_ERROR_STOP=1 -qc \
            "DROP DATABASE netbox" && psql -U netbox -d postgres -v ON_ERROR_STOP=1 -qc \
            "ALTER DATABASE netbox_rollback RENAME TO netbox"' \
            || echo "ATTENTION : bascule vers la base restaurée impossible. Sauvegarde : deploy/$BK/netbox.dump" >&2
    else
        echo "ATTENTION : restauration de la base impossible, base actuelle conservée telle quelle." >&2
        echo "Sauvegarde intacte : deploy/$BK/netbox.dump" >&2
    fi
    local since
    since=$(date -u +%Y-%m-%dT%H:%M:%S+00:00)
    docker compose build auspex netbox reception acces >/dev/null && docker compose up -d >/dev/null
    # La base restaurée peut ne pas encore contenir Librarian : mise en place.
    wait_netbox && as_admin netbox setup --apply >/dev/null \
        || echo "ATTENTION : mise en place NetBox impossible après retour arrière." >&2
    if healthy "$since"; then
        say "Mise à jour annulée : la version précédente fonctionne à nouveau."
    else
        say "ATTENTION : retour arrière effectué mais le central ne répond pas. Sauvegardes : deploy/$BK"
    fi
    exit 1
}

# --- 2. Changement de versions --------------------------------------------------
say "2/4 Versions"
if [ -n "$NETBOX_TARGET" ]; then
    sed -i "s/^NETBOX_VERSION=.*/NETBOX_VERSION=${NETBOX_TARGET}/" .env
    # Version livrée avec Auspex : image figée par empreinte. Autre version :
    # image prise à son étiquette (NETBOX_BASE), au choix de l'administrateur.
    sed -i '/^NETBOX_BASE=/d' .env
    if [ "$NETBOX_TARGET" != "$(netbox_livree)" ]; then
        echo "NETBOX_BASE=netboxcommunity/netbox:${NETBOX_TARGET}" >> .env
    fi
    echo "NetBox → $NETBOX_TARGET"
fi
if [ -n "$AUSPEX_TARGET" ]; then
    git -C .. fetch -q --tags origin && git -C .. checkout -q "$AUSPEX_TARGET" || rollback
    sed -i "s/^AUSPEX_VERSION=.*/AUSPEX_VERSION=${AUSPEX_TARGET}/" .env
    echo "Auspex → $AUSPEX_TARGET"
fi
grep -E '^(NETBOX|AUSPEX)_VERSION=' .env

# --- 3. Démarrage ---------------------------------------------------------------
say "3/4 Téléchargement, construction et démarrage"
STARTED=$(date -u +%Y-%m-%dT%H:%M:%S+00:00)
# Téléchargement seulement si la version change : un site sans accès à
# Internet doit pouvoir se mettre à jour avec les images déjà présentes.
if [ -n "$NETBOX_TARGET" ] && [ "$NETBOX_TARGET" != "$CURRENT_NETBOX" ]; then
    docker compose build --pull netbox || rollback
else
    docker compose build netbox || rollback   # plugin Auspex à jour, image de base locale
fi
docker compose build auspex reception acces || rollback
# Redémarrage d'Auspex dans tous les cas : la nouvelle version doit prouver
# qu'elle fonctionne par un cycle complet.
docker compose up -d --force-recreate auspex || rollback
docker compose up -d || rollback
wait_netbox || rollback
as_admin netbox setup --apply || rollback

# --- 4. Contrôles de santé ------------------------------------------------------
say "4/4 Contrôles de santé (jusqu'à $TIMEOUT s)"
healthy "$STARTED" || rollback
say "Mise à jour réussie."
grep -E '^(NETBOX|AUSPEX)_VERSION=' .env
