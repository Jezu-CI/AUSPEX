#!/usr/bin/env bash
# Vérifie l'origine et l'intégrité des fichiers d'une version d'Auspex.
#
#   tools/verifier-version.sh [DOSSIER]      (défaut : dossier courant)
#
# Le DOSSIER contient SHA256SUMS, SHA256SUMS.sigstore.json et un ou plusieurs
# fichiers de la version (ceux qui manquent sont ignorés). Prérequis : cosign
# (https://docs.sigstore.dev/cosign/system_config/installation/) et sha256sum.
#
# 1. Origine : SHA256SUMS a été signé par le workflow de publication du dépôt
#    Jezu-CI/AUSPEX, depuis la branche main ou un tag de version (certificat
#    Sigstore émis pour l'identité GitHub Actions, inscrit au journal public
#    Rekor). Aucune clé à récupérer : l'identité du signataire est vérifiée.
# 2. Intégrité : chaque fichier présent correspond à son empreinte.
#
# Code de sortie 0 si tout est conforme, 1 sinon.
set -euo pipefail

DOSSIER="${1:-.}"
DEPOT="${AUSPEX_DEPOT:-Jezu-CI/AUSPEX}"
IDENTITE="^https://github\.com/${DEPOT//./\\.}/\.github/workflows/version\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$"
EMETTEUR="https://token.actions.githubusercontent.com"

echec() { echo "ÉCHEC : $*" >&2; exit 1; }

command -v cosign >/dev/null || echec "cosign introuvable (https://docs.sigstore.dev/cosign/system_config/installation/)"
cd "$DOSSIER"
[ -f SHA256SUMS ] || echec "SHA256SUMS absent de $DOSSIER"
[ -f SHA256SUMS.sigstore.json ] || echec "SHA256SUMS.sigstore.json absent de $DOSSIER (versions signées : 0.2.0 et suivantes)"

echo "1/2 Origine de SHA256SUMS (signature Sigstore, workflow de publication de $DEPOT)"
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp "$IDENTITE" \
  --certificate-oidc-issuer "$EMETTEUR" \
  SHA256SUMS >/dev/null 2>&1 || echec "signature de SHA256SUMS invalide ou d'un autre signataire"
echo "    signature valide"

echo "2/2 Intégrité des fichiers présents"
sha256sum -c --ignore-missing SHA256SUMS || echec "un fichier ne correspond pas à son empreinte"
echo "Version vérifiée : fichiers intègres, publiés par le workflow de $DEPOT."
