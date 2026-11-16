---
title: Installer et mettre en route Auspex
description: "Installer Auspex pas à pas : git clone, ./install.sh, un assistant demande vos zones, plages d'adresses et SIEM ; puis flux autorisés, capteur et vérification."
---

# Installer et mettre en route Auspex

Compter une demi-journée pour un premier site, dont la plus grande partie à
rassembler les informations (plages d'adresses, matrice de flux). La partie
technique tient en quelques commandes.

## Ce qu'il vous faut

| Élément | Détail |
| --- | --- |
| Une machine pour le **central** | Linux avec Docker et Docker Compose v2, 2 processeurs, 4 Go de mémoire |
| Une machine pour chaque **capteur** | un PC x86-64 ou une machine virtuelle, 2 Go de mémoire, **deux cartes réseau** (une pour écouter, une pour joindre le central) |
| Un accès à une **copie du trafic** | un port miroir sur un commutateur, ou un TAP |
| La liste de vos **zones** | le nom et les plages d'adresses de chaque partie du réseau |
| Votre **matrice de flux** | qui a le droit de parler à qui ; un fichier Excel suffit |

!!! tip "Pas de matrice de flux ?"
    Ce n'est pas bloquant. Commencez avec un fichier de règles presque vide :
    Auspex vous montrera tous les flux observés comme des écarts, et ce sera
    votre point de départ pour écrire la matrice.

## Étape 1 : installer le central

Sur la machine du central :

```bash
git clone https://github.com/Jezu-CI/AUSPEX.git auspex
cd auspex/deploy
./install.sh
```

Le script fait tout seul le reste : il crée les mots de passe, prépare NetBox,
crée un certificat HTTPS provisoire et démarre les services. Pendant
l'installation, **un assistant vous pose quelques questions** (étape 2). À la
fin, le script affiche l'adresse de NetBox.

Le mot de passe du compte `admin` se trouve dans le fichier `deploy/.env`,
sur la ligne `NETBOX_ADMIN_PASSWORD`. Ce fichier contient tous les secrets
de l'installation : ne le copiez nulle part.

!!! warning "Le compte admin ne se connecte que depuis le central"
    Par sécurité, le compte `admin` n'est accepté au départ que depuis la
    machine du central elle-même. Pour vous connecter depuis votre poste,
    ajoutez son adresse dans `deploy/config/auspex.yaml`, rubrique
    `auth`, ligne `break_glass` : `allow: [10.0.10.5/32]` (votre adresse),
    puis relancez NetBox avec `docker compose up -d --force-recreate netbox`.

## Étape 2 : répondre à l'assistant

L'assistant demande, dans l'ordre :

1. **le nom de l'organisation ou du site**, affiché en tête des rapports
   d'audit ;
2. **vos zones**, une par une : leur type dans une liste (Tier 0 annuaire,
   serveurs, postes, administration, DMZ, niveaux industriels de Purdue…),
   un nom court proposé d'office, et leurs **plages d'adresses**
   (`10.0.0.0/24`, plusieurs séparées par des virgules) ;
3. **votre SIEM**, s'il y en a un : son adresse, le transport (TLS conseillé)
   et le format (CEF ou JSON) ;
4. **les référentiels d'audit** pour lesquels produire un rapport signé chaque
   mois (NIS2, DORA, IEC 62443, ISO 27001, ANSSI).

Chaque réponse est vérifiée au fur et à mesure : une plage mal écrite ou deux
zones qui se chevauchent sont signalées tout de suite. Un récapitulatif
s'affiche avant d'enregistrer. Le résultat est écrit dans
`deploy/config/auspex.yaml`, que vous pouvez modifier ensuite à tout moment
(Auspex le relit à chaque cycle). Le sens de chaque type de zone est expliqué
dans [Les notions](notions.md#zone).

!!! tip "Pas toutes les réponses sous la main ?"
    Répondez « n » à la première question : une configuration d'exemple est
    installée, à adapter plus tard dans `deploy/config/auspex.yaml` (rubrique
    `zones`, et `organisation:` pour le nom des rapports).

## Étape 3 : déclarer les flux autorisés

Remplissez `deploy/config/regles-flux.csv` (ou un fichier Excel), une ligne
par flux autorisé. Le format est expliqué dans
[Déclarer les flux autorisés](regles-de-flux.md).

## Étape 4 : vérifier la configuration

```bash
docker compose exec auspex auspex validate
docker compose exec auspex auspex plan
```

- `validate` liste **toutes** les erreurs d'un coup (une zone mal écrite,
  une date invalide dans les règles…).
- `plan` montre ce qui va changer : règles à importer, réglages à appliquer.

Tant que la configuration n'est pas correcte, Auspex **met l'analyse en
pause** : il préfère ne rien dire plutôt que de signaler de faux écarts.

## Étape 5 : brancher un capteur

Suivez [Installer un capteur](capteurs.md). Comptez une heure pour le
premier, quelques minutes pour les suivants.

## Étape 6 : vérifier que tout fonctionne

Après 5 à 10 minutes, connectez-vous à NetBox (voir [Se connecter](connexion.md)).
Sur la page d'accueil :

- le widget **État du service** indique « en service » et l'heure du dernier
  cycle ;
- le widget **Inventaire observé** commence à compter des actifs ;
- les premiers écarts apparaissent dans **Écarts ouverts**.

Si rien n'arrive, voir [Au quotidien et en cas de problème](quotidien.md#en-cas-de-problème).

!!! tip "Essayer sans réseau réel"
    Le dépôt contient un scénario de démonstration : 7 jours de trafic
    simulé d'un site IT et industriel, avec quatre problèmes cachés (un SSH
    de dépannage oublié, un poste qui administre un contrôleur de domaine,
    un serveur qui parle directement à un automate, un accès prestataire
    expiré). Voir le [démarrage rapide](../guide.md#démarrage-rapide-5-minutes).
