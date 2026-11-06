---
title: Déclarer les flux autorisés
description: "Écrire le tableau des flux autorisés d'Auspex dans Excel ou en CSV : chaque colonne expliquée, exemples, dates d'expiration et import des règles."
---

# Déclarer les flux autorisés

Auspex compare chaque communication observée à **votre liste des flux
autorisés**. Cette liste est un simple tableau, que vous pouvez tenir dans
Excel. C'est souvent la matrice de flux que vous avez déjà pour vos pare-feu.

## Le tableau, colonne par colonne

| Colonne | Ce qu'on y met | Exemples |
| --- | --- | --- |
| `id` | un identifiant unique, que vous choisissez | `C-001`, `PARE-FEU-42` |
| `source` | qui parle : un nom de zone, une adresse, une plage, ou `any` (n'importe qui) | `T1-serveurs`, `10.2.5.0/24` |
| `destination` | à qui | `T0-AD`, `172.16.2.10` |
| `protocole` | `tcp`, `udp` ou `any` | `tcp` |
| `port` | un port, une plage, une liste, ou `any` | `443`, `8000-8100`, `80;443` |
| `description` | pourquoi ce flux existe | `Kerberos`, `Maintenance automate` |
| `proprietaire` | qui en est responsable | `Équipe AD`, `Prestataire X` |
| `expire_le` | la date de fin, ou vide si la règle est permanente | `15/12/2026`, `2026-12-15` |

## Un exemple

| id | source | destination | protocole | port | description | proprietaire | expire_le |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C-001 | T1-serveurs | T0-AD | tcp | 88 | Kerberos | Équipe AD | |
| C-014 | ADMIN-bastion | OT-N2 | tcp | 22 | Maintenance automate | Prestataire X | 15/12/2026 |
| C-020 | 10.2.5.0/24 | any | udp | 53;123 | DNS et NTP | | |

- La première ligne autorise les serveurs à s'authentifier auprès de
  l'Active Directory.
- La deuxième autorise un prestataire à se connecter aux automates depuis le
  bastion, **jusqu'au 15 décembre**. Après cette date, s'il se connecte
  encore, Auspex lèvera l'écart « Règle expirée encore utilisée ».
- La troisième autorise une plage d'adresses à joindre n'importe quel
  serveur DNS ou de temps.

## Bonnes pratiques

- **Utilisez les noms de zones** plutôt que des adresses : la règle reste
  vraie quand une machine change d'adresse.
- **Datez les accès provisoires** : prestataires, dépannages, projets. C'est
  la meilleure protection contre les ouvertures oubliées.
- **Renseignez le propriétaire** : quand une règle pose question, vous savez
  à qui la poser.
- **Évitez `any` des deux côtés** : une règle `any → any` rend Auspex
  aveugle.
- Les communications **à l'intérieur d'une même zone** ne sont pas
  contrôlées par défaut. Votre administrateur peut l'activer si vous
  voulez aller jusqu'à la microsegmentation.

## Fichier Excel ou CSV

- **Excel (.xlsx)** : la première feuille, ou une feuille nommée `regles`.
  Les vraies dates Excel sont acceptées.
- **CSV** : séparateur virgule ou point-virgule, y compris un export Excel
  Windows.
- La première ligne doit contenir les noms des colonnes, exactement comme
  ci-dessus.

## Mettre à jour les règles

Déposez le fichier à l'emplacement prévu par votre administrateur (par
défaut `deploy/config/regles-flux.csv` sur le central). Il est relu à chaque
cycle : une règle ajoutée est prise en compte dans les 5 minutes, et les
écarts qu'elle couvre se ferment.

Pour voir l'effet d'un changement **avant** de l'appliquer :

```bash
docker compose exec auspex auspex rules import            # simulation : ajouts, modifications, suppressions
docker compose exec auspex auspex rules import --apply    # application
```

Et pour récupérer les règles en vigueur dans un fichier :

```bash
docker compose exec auspex auspex rules export /var/lib/auspex/regles-actuelles.csv
```

!!! warning "Un fichier invalide met l'analyse en pause"
    Une date mal écrite ou une zone inconnue rend le fichier invalide.
    Auspex suspend alors l'analyse plutôt que de signaler de faux écarts,
    et le widget « État du service » le montre. `auspex validate` dit quelle
    ligne corriger.
