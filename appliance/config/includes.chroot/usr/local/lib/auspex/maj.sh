# Mises à jour signées de l'image d'analyse du capteur (bash, après lib.sh).
#
# L'image d'analyse (Zeek, ICSNPP, scripts) est un squashfs publié par le
# central, avec un manifeste signé (Ed25519) par la clé de mises à jour de
# l'organisation (MAJ_CLE de capteur.conf). Deux emplacements sur le disque de
# données (a, b) plus l'image d'usine de l'ISO : la nouvelle version s'installe
# dans l'emplacement libre, est mise à l'essai, puis validée ou abandonnée
# (retour automatique à la précédente).
#
# Manifeste (texte, une valeur par ligne, signé tel quel) :
#   format=auspex-maj-capteur/1
#   version=0.9.1
#   sha256=<64 hexadécimaux>
#   taille=<octets>
#   publie_le=2026-11-01T12:00:00Z
#
# Rien n'est exécuté depuis le manifeste ni depuis l'état : lecture clé par clé.

MAJ="${MAJ:-$DATA/maj}"
USINE="${USINE:-/opt/auspex-sensor}"
USINE_VERSION="${USINE_VERSION:-/etc/auspex-version}"
MAJ_FORMAT="auspex-maj-capteur/1"
MAJ_TAILLE_MAX=$((2 * 1024 * 1024 * 1024))

declare -A M=()       # manifeste lu
declare -A E=()       # état des emplacements

usine_version() { tr -dc '0-9.' < "$USINE_VERSION" 2>/dev/null || echo 0; }

# version_gt A B : A strictement plus récente que B
version_gt() {
    [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}

# maj_pem CLÉ FICHIER : clé publique de capteur.conf → PEM
maj_pem() {
    [[ "$1" =~ ^MCowBQYDK2VwAyEA[A-Za-z0-9+/]{43}=$ ]] || return 1
    printf -- '-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n' "$1" > "$2"
}

# maj_verifier DOSSIER PEM [image] : signature du manifeste (et image si demandé).
# Remplit M[...] ; renvoie 1 et MAJ_RAISON sinon.
maj_verifier() {
    local dir="$1" pem="$2" with_image="${3:-}" line k v size sum
    M=(); MAJ_RAISON=""
    if [ ! -f "$dir/manifeste" ] || [ ! -f "$dir/manifeste.sig" ]; then
        MAJ_RAISON="manifeste ou signature absents"; return 1
    fi
    if [ "$(stat -c %s "$dir/manifeste")" -gt 4096 ] || [ "$(stat -c %s "$dir/manifeste.sig")" -ne 64 ]; then
        MAJ_RAISON="manifeste ou signature de taille anormale"; return 1
    fi
    if ! openssl pkeyutl -verify -pubin -inkey "$pem" -rawin -in "$dir/manifeste" \
            -sigfile "$dir/manifeste.sig" >/dev/null 2>&1; then
        MAJ_RAISON="signature invalide (clé de mises à jour différente ou manifeste modifié)"; return 1
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        [[ "$line" =~ ^([a-z0-9_]+)=([A-Za-z0-9.:/_+-]{1,128})$ ]] || { MAJ_RAISON="manifeste mal formé"; return 1; }
        k="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]}"
        case "$k" in format|version|sha256|taille|publie_le) M[$k]="$v" ;; esac
    done < "$dir/manifeste"
    if [ "${M[format]:-}" != "$MAJ_FORMAT" ]; then MAJ_RAISON="format de manifeste inconnu"; return 1; fi
    if [[ ! "${M[version]:-}" =~ ^[0-9]{1,6}(\.[0-9]{1,6}){1,4}$ ]]; then MAJ_RAISON="version invalide"; return 1; fi
    if [[ ! "${M[sha256]:-}" =~ ^[0-9a-f]{64}$ ]]; then MAJ_RAISON="empreinte invalide"; return 1; fi
    if [[ ! "${M[taille]:-}" =~ ^[1-9][0-9]{0,11}$ ]] || (( M[taille] > MAJ_TAILLE_MAX )); then
        MAJ_RAISON="taille invalide"; return 1
    fi
    [ -n "$with_image" ] || return 0
    if [ ! -f "$dir/image.squashfs" ] || [ -L "$dir/image.squashfs" ]; then MAJ_RAISON="image absente"; return 1; fi
    size=$(stat -c %s "$dir/image.squashfs")
    if [ "$size" != "${M[taille]}" ]; then MAJ_RAISON="taille de l'image différente du manifeste"; return 1; fi
    sum=$(sha256sum "$dir/image.squashfs" | cut -d' ' -f1)
    if [ "$sum" != "${M[sha256]}" ]; then MAJ_RAISON="empreinte de l'image différente du manifeste"; return 1; fi
    return 0
}

# État : actif (usine|a|b), precedent, essai (0|1), refusees (versions abandonnées)
etat_lire() {
    local line
    E=([actif]=usine [precedent]=usine [essai]=0 [refusees]="")
    [ -f "$MAJ/etat" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            actif=usine|actif=a|actif=b) E[actif]="${line#*=}" ;;
            precedent=usine|precedent=a|precedent=b) E[precedent]="${line#*=}" ;;
            essai=0|essai=1) E[essai]="${line#*=}" ;;
            refusees=*) [[ "${line#*=}" =~ ^[0-9.\ ]{0,400}$ ]] && E[refusees]="${line#*=}" ;;
        esac
    done < "$MAJ/etat"
}

etat_ecrire() {
    mkdir -p "$MAJ"
    printf 'actif=%s\nprecedent=%s\nessai=%s\nrefusees=%s\n' \
        "${E[actif]}" "${E[precedent]}" "${E[essai]}" "${E[refusees]}" > "$MAJ/etat.tmp"
    sync -f "$MAJ/etat.tmp" 2>/dev/null || true
    mv -f "$MAJ/etat.tmp" "$MAJ/etat"
}

refusee() { [[ " ${E[refusees]} " == *" $1 "* ]]; }

refuser() {   # garde les 20 dernières versions abandonnées
    refusee "$1" && return 0
    E[refusees]=$(echo ${E[refusees]} "$1" | tr ' ' '\n' | tail -20 | tr '\n' ' ' | sed 's/ $//')
}

# Version d'un emplacement (manifeste déjà vérifié), ou celle de l'ISO
slot_version() {
    if [ "$1" = usine ]; then usine_version; return; fi
    sed -n 's/^version=\([0-9.]*\)$/\1/p' "$MAJ/$1/manifeste" 2>/dev/null | head -1
}

autre_slot() { [ "$1" = a ] && echo b || echo a; }
