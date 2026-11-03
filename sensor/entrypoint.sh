#!/bin/sh
# Point d'entrée du capteur Auspex.
#
#   read FICHIER.pcap [...]   analyse des captures (logs dans /logs/<nom>/)
#   live INTERFACE            écoute continue d'une interface (SPAN ou TAP),
#                             avec envoi au central si AUSPEX_CENTRAL est défini
#   cle                       clé d'envoi du capteur (créée au besoin), à déclarer
#                             dans auspex.yaml du central (sensors[].key)
#   envoyer                   envoie une fois les logs de /logs au central
#   version                   versions de Zeek et des paquets installés
#
# Envoi : AUSPEX_CENTRAL=hôte[:port] (2222 par défaut) et
# AUSPEX_CENTRAL_EMPREINTE=SHA256:… (« auspex capteur empreinte » sur le central).
set -eu

DIR=/opt/auspex
CONF=/etc/auspex-capteur
KEY="$CONF/cle"
RETENTION_HOURS="${AUSPEX_SENSOR_RETENTION_HOURS:-48}"
INTERVAL="${AUSPEX_ENVOI_SECONDES:-60}"

log() { printf '{"time":"%s","event":"%s"%s}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "${2:+,$2}" >&2; }

ensure_key() {
    [ -f "$KEY" ] && return 0
    mkdir -p "$CONF"
    ssh-keygen -q -t ed25519 -N '' -C "auspex-capteur@$(hostname)" -f "$KEY"
    chmod 600 "$KEY"
}

# Vérifie l'empreinte du central AVANT tout envoi : un faux central ne reçoit rien.
pin_central() {
    : "${AUSPEX_CENTRAL:?AUSPEX_CENTRAL non défini (hôte[:port] du central)}"
    : "${AUSPEX_CENTRAL_EMPREINTE:?AUSPEX_CENTRAL_EMPREINTE non défini (auspex capteur empreinte)}"
    case "$AUSPEX_CENTRAL" in
        \[*\]:*) HOST="${AUSPEX_CENTRAL%%]:*}"; HOST="${HOST#[}"; PORT="${AUSPEX_CENTRAL##*]:}" ;;
        \[*\])   HOST="${AUSPEX_CENTRAL#[}"; HOST="${HOST%]}"; PORT=2222 ;;
        *:*:*)   HOST="$AUSPEX_CENTRAL"; PORT=2222 ;;
        *:*)     HOST="${AUSPEX_CENTRAL%:*}"; PORT="${AUSPEX_CENTRAL##*:}" ;;
        *)       HOST="$AUSPEX_CENTRAL"; PORT=2222 ;;
    esac
    KNOWN=$(mktemp)
    ssh-keyscan -T 10 -t ed25519 -p "$PORT" "$HOST" > "$KNOWN" 2>/dev/null || true
    seen=$(ssh-keygen -l -f "$KNOWN" 2>/dev/null | awk '{print $2}' | head -1)
    if [ -z "$seen" ]; then
        log envoi_central_injoignable "\"central\":\"$AUSPEX_CENTRAL\""
        rm -f "$KNOWN"; return 1
    fi
    if [ "$seen" != "$AUSPEX_CENTRAL_EMPREINTE" ]; then
        log envoi_empreinte_differente "\"central\":\"$AUSPEX_CENTRAL\",\"attendue\":\"$AUSPEX_CENTRAL_EMPREINTE\",\"recue\":\"$seen\""
        rm -f "$KNOWN"; return 1
    fi
}

ship() {
    ensure_key
    pin_central || return 1
    case "$HOST" in *:*) RHOST="[$HOST]" ;; *) RHOST="$HOST" ;; esac
    start=$(date +%s)
    if rsync -rt --chmod=D755,F644 --timeout=60 \
            --include='*/' --include='*.log' --include='*.log.gz' --include='/auspex-etat.json' --exclude='*' --prune-empty-dirs \
            -e "ssh -i $KEY -p $PORT -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KNOWN -o HostKeyAlgorithms=ssh-ed25519 -o ConnectTimeout=15 -o ServerAliveInterval=15 -o LogLevel=ERROR" \
            /logs/ "capteur@$RHOST:" ; then
        date -u +%Y-%m-%dT%H:%M:%SZ > /logs/.dernier-envoi
        log envoi_ok "\"secondes\":$(( $(date +%s) - start ))"
        rm -f "$KNOWN"; return 0
    fi
    log envoi_echec "\"central\":\"$AUSPEX_CENTRAL\""
    rm -f "$KNOWN"; return 1
}

usage() {
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
}

case "${1:-help}" in
    read)
        shift
        [ "$#" -ge 1 ] || { echo "Erreur : indiquer au moins un fichier pcap" >&2; exit 2; }
        for pcap in "$@"; do
            name=$(basename "$pcap"); name="${name%.*}"
            mkdir -p "/logs/$name"
            cd "/logs/$name"
            zeek -C -r "$pcap" "$DIR/auspex.zeek"
            echo "$pcap → /logs/$name ($(ls -1 | wc -l) fichiers de log)"
        done
        ;;
    live)
        iface="${2:-}"
        [ -n "$iface" ] || { echo "Erreur : indiquer l'interface d'écoute" >&2; exit 2; }
        # Purge des logs plus anciens que la rétention, toutes les heures.
        ( while true; do
              find /logs -type f -mmin +$((RETENTION_HOURS * 60)) -delete 2>/dev/null || true
              sleep 3600
          done ) &
        if [ -n "${AUSPEX_CENTRAL:-}" ]; then
            ensure_key
            ( while true; do sleep "$INTERVAL"; ship || true; done ) &
        else
            log envoi_desactive "\"raison\":\"AUSPEX_CENTRAL non défini\""
        fi
        cd /logs
        exec zeek -C -i "$iface" "$DIR/live.zeek"
        ;;
    cle)
        ensure_key
        cat "$KEY.pub"
        ssh-keygen -l -f "$KEY.pub" >&2
        ;;
    envoyer)
        ship
        ;;
    version)
        zeek --version
        zkg list installed 2>/dev/null || true
        [ -s /opt/icsnpp-absents ] && echo "Parsers ICSNPP absents : $(tr '\n' ' ' < /opt/icsnpp-absents)" || true
        ;;
    help|-h|--help)
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
