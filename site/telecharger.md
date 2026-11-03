---
title: Télécharger
---

# Télécharger Auspex

Les fichiers de chaque version sont publiés sur
**[la page de la dernière version](https://github.com/Jezu-CI/AUSPEX/releases/latest)**,
avec leurs empreintes et leurs signatures. Nouveautés : [notes de version](versions.md).

## Central (NetBox + Auspex)

Le central s'installe depuis le code source, sur une machine Linux avec
Docker et Docker Compose v2 (2 vCPU, 4 Go de RAM). Remplacer `vX.Y.Z` par
le numéro de la dernière version :

```bash
git clone --branch vX.Y.Z https://github.com/Jezu-CI/AUSPEX.git auspex
cd auspex/deploy
./install.sh
```

Suite : [Déployer le central](guide.md#déployer-le-central) ·
[Exploitation](documentation/04-exploitation.md).

## Appliance du capteur

| Fichier | Usage |
| --- | --- |
| `auspex-capteur-<version>.iso` | appliance du capteur (clé USB, CD, machine virtuelle) |
| `auspex-capteur-<version>.squashfs` | image de mise à jour de l'analyse, à publier par le central |
| `auspex-sbom.cdx.json` | inventaire logiciel (CycloneDX) |
| `SHA256SUMS` | empreintes des fichiers |
| `SHA256SUMS.sigstore.json` | signature des empreintes (Sigstore) |
| `auspex-provenance.sigstore.json` | provenance de chaque fichier (SLSA) |

Suite : [Appliance capteur](guide.md#appliance-capteur-iso) ·
[Capteurs, en détail](documentation/02-capteur.md).

Le capteur existe aussi en image Docker, à construire depuis le code
(`docker build -t auspex-sensor sensor`) : voir [Capteur](guide.md#capteur).

## Vérifier un fichier téléchargé

Chaque version est **signée avec [Sigstore](https://www.sigstore.dev/)** par le
workflow de publication du dépôt, sans clé à gérer ni à récupérer : le
certificat de signature est émis pour l'identité de ce workflow et inscrit au
journal public de transparence Rekor. Une **attestation de provenance**
([SLSA](https://slsa.dev/)) indique en plus le commit et le workflow qui ont
produit chaque fichier.

Télécharger, dans un même dossier, le fichier voulu, `SHA256SUMS` et
`SHA256SUMS.sigstore.json`, puis, avec [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) :

```bash
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/Jezu-CI/AUSPEX/\.github/workflows/version\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

La première commande prouve que la liste d'empreintes vient du projet ; la
seconde, que le fichier téléchargé correspond à son empreinte. Depuis le code
source, [`tools/verifier-version.sh`](https://github.com/Jezu-CI/AUSPEX/blob/main/tools/verifier-version.sh)
fait les deux.

Provenance d'un fichier, avec [GitHub CLI](https://cli.github.com/) :

```bash
gh attestation verify auspex-capteur-<version>.iso --repo Jezu-CI/AUSPEX \
  --signer-workflow Jezu-CI/AUSPEX/.github/workflows/version.yml
```

Chaque publication vérifie ces commandes sur les vrais fichiers, et vérifie
qu'un fichier, une liste d'empreintes ou une provenance altérés sont refusés.

## Prérequis

| Composant | Minimum |
| --- | --- |
| Central | Linux, Docker et Docker Compose v2, 2 vCPU, 4 Go de RAM |
| Capteur (appliance) | x86-64, 2 Go de RAM, deux cartes réseau (administration, écoute), un disque de données |
| Capteur (Docker) | Linux, Docker, une interface reliée à un port miroir ou un TAP |
