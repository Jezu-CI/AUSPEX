#!/usr/bin/env bash
# Copie les empreintes d'une version vers le miroir hors GitHub (Codeberg).
#
#   tools/miroir-empreintes.sh DOSSIER VERSION     copie (VERSION : vX.Y.Z)
#   MIROIR_ESSAI=1 tools/miroir-empreintes.sh      vérifie seulement l'accès en écriture
#
# DOSSIER contient SHA256SUMS et SHA256SUMS.sigstore.json, dont la signature a
# déjà été vérifiée (tools/verifier-version.sh). Ils sont copiés dans
# VERSION/ du dépôt miroir. Si le compte GitHub du projet était compromis, la
# page de version et ses empreintes pourraient être modifiées ensemble : le
# miroir, hébergé ailleurs, permet de recouper.
#
# Une version déjà présente n'est jamais modifiée : identique, rien à faire ;
# différente, échec (une empreinte publiée ne change pas).
#
# Dépôt miroir : AUSPEX_MIROIR_GIT (défaut : Codeberg). Jeton d'écriture : la
# variable d'environnement CODEBERG_TOKEN (secret GitHub), transmis à git par
# GIT_ASKPASS : jamais en argument, dans l'URL ni dans la configuration git.
#
# Code de sortie 0 si la copie (ou l'essai) a réussi, 1 sinon.
set -euo pipefail

MIROIR_GIT="${AUSPEX_MIROIR_GIT:-https://codeberg.org/Jezu_CI/AUSPEX-empreintes.git}"
FICHIERS=(SHA256SUMS SHA256SUMS.sigstore.json)

echec() { echo "ÉCHEC : $*" >&2; exit 1; }

travail=$(mktemp -d)
trap 'rm -rf "$travail"' EXIT

# Jeton remis à git à la demande (identifiant ignoré par Codeberg).
if [ -n "${CODEBERG_TOKEN:-}" ]; then
  cat > "$travail/askpass" <<'EOF'
#!/bin/sh
case "$1" in Username*) echo auspex-publication ;; *) printf '%s\n' "$CODEBERG_TOKEN" ;; esac
EOF
  chmod 700 "$travail/askpass"
  export GIT_ASKPASS="$travail/askpass"
fi
export GIT_TERMINAL_PROMPT=0
git_() {
  git -C "$travail/miroir" -c user.name="Auspex (publication)" \
    -c user.email="auspex-publication@users.noreply.codeberg.org" -c commit.gpgsign=false "$@"
}

git clone -q "$MIROIR_GIT" "$travail/miroir" 2>/dev/null || echec "miroir inaccessible : $MIROIR_GIT"
# Dépôt encore vide : première branche nommée main.
git_ rev-parse -q --verify HEAD >/dev/null || git_ symbolic-ref HEAD refs/heads/main

if [ "${MIROIR_ESSAI:-0}" = 1 ]; then
  git_ commit -q --allow-empty -m "Essai d'accès (non envoyé)"
  git_ push -q --dry-run origin HEAD:refs/heads/main 2>/dev/null \
    || echec "pas d'accès en écriture au miroir (jeton CODEBERG_TOKEN absent, expiré ou sans droit d'écriture ?)"
  echo "Accès en écriture au miroir : OK ($MIROIR_GIT)"
  exit 0
fi

[ $# -eq 2 ] || echec "usage : $0 DOSSIER VERSION"
DOSSIER="$1"
VERSION="$2"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || echec "version attendue au format vX.Y.Z : $VERSION"
for f in "${FICHIERS[@]}"; do
  [ -f "$DOSSIER/$f" ] || echec "$f absent de $DOSSIER"
done

cible="$travail/miroir/$VERSION"
if [ -d "$cible" ]; then
  for f in "${FICHIERS[@]}"; do
    cmp -s "$DOSSIER/$f" "$cible/$f" || echec "$VERSION déjà présente dans le miroir avec un $f différent : rien n'est modifié"
  done
  echo "$VERSION déjà présente dans le miroir, identique : rien à faire."
  exit 0
fi

mkdir "$cible"
for f in "${FICHIERS[@]}"; do cp "$DOSSIER/$f" "$cible/"; done

if [ ! -f "$travail/miroir/README.md" ]; then
  cat > "$travail/miroir/README.md" <<'EOF'
# Auspex — miroir des empreintes

Copie, hors GitHub, des empreintes (`SHA256SUMS`) et de leur signature
Sigstore (`SHA256SUMS.sigstore.json`) de chaque version d'
[Auspex](https://github.com/Jezu-CI/AUSPEX), un dossier par version.

Si le compte GitHub du projet était compromis, la page de version et ses
empreintes pourraient être modifiées ensemble : comparer avec ce miroir
permet de le détecter. Les fichiers sont déposés automatiquement à la
publication de chaque version et ne sont jamais modifiés ensuite.

Vérifier une version téléchargée et la comparer au miroir :

```bash
tools/verifier-version.sh DOSSIER vX.Y.Z
```

Mode d'emploi : <https://jezu-ci.github.io/AUSPEX/telecharger/>
EOF
fi

git_ add -A
git_ commit -q -m "Empreintes de la version $VERSION"
git_ push -q origin HEAD:refs/heads/main 2>/dev/null \
  || echec "envoi vers le miroir refusé (jeton CODEBERG_TOKEN absent, expiré ou sans droit d'écriture ?)"
echo "Empreintes de $VERSION copiées dans le miroir ($MIROIR_GIT)."
