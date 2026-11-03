# Bibliothèque commune de l'appliance capteur Auspex (bash).
#
# capteur.conf est lu ligne à ligne et validé clé par clé : il n'est jamais
# exécuté (« source »), une valeur ne peut donc pas injecter de commande.

DATA=/var/lib/auspex-capteur
CONF="$DATA/config/capteur.conf"
RUN=/run/auspex
SEED_LABEL=AUSPEX-CONF
DATA_LABEL=AUSPEX-DATA

msg() {
    echo "auspex: $*"
    echo "auspex: $*" > /dev/kmsg 2>/dev/null || true
}

declare -A C=()
KEYS="NOM ADMIN_INTERFACE ADMIN_ADRESSE ADMIN_PASSERELLE DNS NTP ECOUTE_INTERFACE CENTRAL CENTRAL_EMPREINTE MAJ_CLE MAJ_FREQUENCE MAJ_ESSAI"

_ip4='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}'
_iface='(mac:[0-9a-f]{2}(:[0-9a-f]{2}){5}|[a-z][a-z0-9]{0,14})'

valid() {  # valid CLÉ VALEUR
    local k="$1" v="$2"
    case "$k" in
        NOM)               [[ "$v" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] ;;
        ADMIN_INTERFACE)   [[ "$v" =~ ^(auto|$_iface)$ ]] ;;
        ECOUTE_INTERFACE)  [[ "$v" =~ ^$_iface$ ]] ;;
        ADMIN_ADRESSE)     [[ "$v" =~ ^(dhcp|$_ip4/([89]|[12][0-9]|3[0-2]))$ ]] ;;
        ADMIN_PASSERELLE)  [[ -z "$v" || "$v" =~ ^$_ip4$ ]] ;;
        DNS)               [[ -z "$v" || "$v" =~ ^$_ip4([ ,]$_ip4){0,2}$ ]] ;;
        NTP)               [[ -z "$v" || "$v" =~ ^[A-Za-z0-9.-]{1,253}([ ,][A-Za-z0-9.-]{1,253}){0,3}$ ]] ;;
        CENTRAL)           [[ "$v" =~ ^[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$ ]] ;;
        CENTRAL_EMPREINTE) [[ "$v" =~ ^SHA256:[A-Za-z0-9+/]{43}$ ]] ;;
        # Clé publique Ed25519 des mises à jour (SubjectPublicKeyInfo en base64)
        MAJ_CLE)           [[ -z "$v" || "$v" =~ ^MCowBQYDK2VwAyEA[A-Za-z0-9+/]{43}=$ ]] ;;
        MAJ_FREQUENCE)     [[ "$v" =~ ^[1-9][0-9]{0,3}$ ]] && (( 10#$v <= 1440 )) ;;     # minutes
        MAJ_ESSAI)         [[ "$v" =~ ^[1-9][0-9]{1,3}$ ]] && (( 10#$v >= 30 && 10#$v <= 3600 )) ;;  # secondes
        *) return 1 ;;
    esac
}

# load_conf FICHIER : remplit C[...] ; renvoie 1 et affiche les problèmes sinon.
load_conf() {
    local file="${1:-$CONF}" line k v n=0 bad=0
    C=()
    [ -f "$file" ] || return 1
    while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1))
        line="${line%$'\r'}"
        [[ -z "${line// }" || "$line" =~ ^[[:space:]]*# ]] && continue
        if [[ ! "$line" =~ ^([A-Z_]+)=(.*)$ ]]; then
            msg "capteur.conf ligne $n : forme CLÉ=valeur attendue"; bad=1; continue
        fi
        k="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]}"
        v="${v#\"}"; v="${v%\"}"
        if [[ " $KEYS " != *" $k "* ]]; then msg "capteur.conf ligne $n : clé inconnue $k"; bad=1; continue; fi
        if ! valid "$k" "$v"; then msg "capteur.conf ligne $n : valeur invalide pour $k"; bad=1; continue; fi
        C[$k]="$v"
    done < "$file"
    for k in NOM ECOUTE_INTERFACE CENTRAL CENTRAL_EMPREINTE; do
        [ -n "${C[$k]:-}" ] || { msg "capteur.conf : $k manquant"; bad=1; }
    done
    : "${C[ADMIN_INTERFACE]:=auto}" "${C[ADMIN_ADRESSE]:=dhcp}"
    if [[ "${C[ADMIN_ADRESSE]}" != dhcp && -z "${C[ADMIN_PASSERELLE]:-}" ]]; then
        msg "capteur.conf : ADMIN_PASSERELLE nécessaire avec une adresse fixe"; bad=1
    fi
    if [[ ! "${C[CENTRAL]%%:*}" =~ ^$_ip4$ && -z "${C[DNS]:-}" ]]; then
        msg "capteur.conf : CENTRAL est un nom : renseigner DNS (ou donner l'adresse IP du central)"; bad=1
    fi
    return $bad
}

# resolve_iface SPEC [EXCLURE] : nom d'interface (mac:…, nom, ou auto = première Ethernet)
resolve_iface() {
    local spec="$1" exclude="${2:-}" i
    case "$spec" in
        mac:*)
            for i in /sys/class/net/*; do
                [ "$(cat "$i/address" 2>/dev/null)" = "${spec#mac:}" ] && { basename "$i"; return 0; }
            done ;;
        auto)
            for i in /sys/class/net/*; do
                i=$(basename "$i")
                [ "$i" = lo ] || [ "$i" = "$exclude" ] && continue
                [ -e "/sys/class/net/$i/device" ] && { echo "$i"; return 0; }
            done ;;
        *)
            [ -e "/sys/class/net/$spec" ] && { echo "$spec"; return 0; } ;;
    esac
    return 1
}

central_host() { echo "${C[CENTRAL]%%:*}"; }
central_port() { local p="${C[CENTRAL]#*:}"; [ "$p" = "${C[CENTRAL]}" ] && p=2222; echo "$p"; }
