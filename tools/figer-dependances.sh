#!/usr/bin/env bash
# Régénère les dépendances Python figées (version exacte + empreinte SHA-256
# de chaque paquet) du dossier requirements/ :
#
#   execution.txt   dépendances du produit (image du central, CI)
#   dev.txt         produit + tests + SBOM (CI, publication)
#   sbom.txt        produit + outil SBOM seulement (inventaire du produit)
#   site.txt        construction du site
#   captures.txt    captures d'écran (Playwright)
#
#   tools/figer-dependances.sh            (depuis la racine du dépôt)
#
# Résolution faite sous Python 3.10, la plus ancienne version prise en charge :
# les versions retenues fonctionnent aussi sous 3.11 à 3.13 (chaque fichier
# liste les empreintes de toutes les variantes publiées de chaque paquet).
# Prérequis : Docker et un accès à PyPI. Installation ensuite par :
#   pip install --require-hashes -r requirements/<fichier>.txt
set -euo pipefail

IMAGE="python:3.10-slim@sha256:6ff506466f8b1e981719b468cc0023b8ef000b983cdec0eafe119d01f379e31d"
PIP_TOOLS="pip-tools==7.4.1"

cd "$(dirname "$0")/.."
docker run --rm --memory 1g -v "$PWD:/src" -w /src -u "$(id -u):$(id -g)" -e HOME=/tmp \
  -e CUSTOM_COMPILE_COMMAND="tools/figer-dependances.sh" -e PIP_TOOLS="$PIP_TOOLS" "$IMAGE" sh -euc '
python -m venv /tmp/v && . /tmp/v/bin/activate
pip install -q --disable-pip-version-check "$PIP_TOOLS"
c() { pip-compile -q --generate-hashes --allow-unsafe --strip-extras --no-emit-index-url "$@"; }
c -o requirements/execution.txt pyproject.toml
c --extra dev -o requirements/dev.txt pyproject.toml requirements/outils.in
c -o requirements/sbom.txt pyproject.toml requirements/outils.in
c -o requirements/site.txt requirements/site.in
c -o requirements/captures.txt requirements/captures.in
' 2>&1 | grep -v -i -E "setuptools|license|\*{10}|!!|corresp\(|^\s*$|See https|By 20|Please" || true
echo "Dépendances figées régénérées : requirements/*.txt"
