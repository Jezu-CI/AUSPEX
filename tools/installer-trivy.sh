#!/usr/bin/env bash
# Installe Trivy (analyse de vulnérabilités et de licences) dans DOSSIER, à une
# version figée par son empreinte SHA-256 :
#
#   tools/installer-trivy.sh DOSSIER
#
# Ni l'action GitHub trivy-action ni l'installateur setup-trivy ne sont
# utilisés : leurs étiquettes ont été détournées en mars 2026
# (CVE-2026-33634, GHSA-69fq-xp46-6x23), comme la version 0.69.4 de Trivy.
# La 0.69.3 est antérieure à l'incident : publication immuable sur GitHub,
# signée par le workflow de publication de Trivy le 3 mars 2026. Pour changer
# de version : nouvelle empreinte relevée dans trivy_X.Y.Z_checksums.txt de la
# publication officielle, après vérification de sa signature Sigstore.
set -euo pipefail

VERSION="0.69.3"
SHA256="1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75"
DOSSIER="${1:?usage : $0 DOSSIER}"

archive=$(mktemp)
trap 'rm -f "$archive"' EXIT
curl -sSfL -o "$archive" \
  "https://github.com/aquasecurity/trivy/releases/download/v${VERSION}/trivy_${VERSION}_Linux-64bit.tar.gz"
echo "${SHA256}  ${archive}" | sha256sum -c --quiet - || { echo "empreinte de Trivy invalide" >&2; exit 1; }
mkdir -p "$DOSSIER"
tar -xzf "$archive" -C "$DOSSIER" trivy
"$DOSSIER/trivy" --version | head -1
