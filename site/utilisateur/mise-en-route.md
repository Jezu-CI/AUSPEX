---
title: Mettre Auspex en route
description: "Mettre Auspex en route pas à pas : installer le central, décrire les zones, importer les flux autorisés, brancher un capteur et vérifier que tout fonctionne."
---

# Mettre Auspex en route

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
crée un certificat HTTPS provisoire et démarre les services. À la fin, il
affiche l'adresse de NetBox.

Le mot de passe du compte `admin` se trouve dans le fichier `deploy/.env`,
sur la ligne `NETBOX_ADMIN_PASSWORD`. Ce fichier contient tous les secrets
de l'installation : ne le copiez nulle part.

!!! warning "Le compte admin ne se connecte que depuis le central"
    Par sécurité, le compte `admin` n'est accepté au départ que depuis la
    machine du central elle-même. Pour vous connecter depuis votre poste,
    ajoutez son adresse dans `deploy/config/auspex.yaml`, rubrique
    `auth`, ligne `break_glass` : `allow: [10.0.10.5/32]` (votre adresse),
    puis relancez NetBox avec `docker compose up -d --force-recreate netbox`.

## Étape 2 : décrire vos zones

Ouvrez `deploy/config/auspex.yaml` avec un éditeur de texte. La rubrique
`zones` contient des exemples à remplacer par vos vraies zones :

```yaml
zones:
  - { name: T0-AD,         class: tier0,     prefixes: [10.0.0.0/24] }
  - { name: T1-serveurs,   class: tier1,     prefixes: [10.1.0.0/16] }
  - { name: T2-postes,     class: tier2,     prefixes: [10.2.0.0/16] }
  - { name: ADMIN-bastion, class: admin,     prefixes: [10.9.0.0/24] }
  - { name: OT-DMZ,        class: purdue3.5, prefixes: [172.16.35.0/24] }
  - { name: OT-N2,         class: purdue2,   prefixes: [172.16.2.0/24] }
```

- `name` : un nom court, sans espace, que vous retrouverez partout.
- `class` : la sensibilité de la zone (voir [Les notions](notions.md#zone)).
  Valeurs possibles : `tier0`, `tier1`, `tier2`, `admin`, `dmz`, `other`,
  `purdue0` à `purdue5`, `purdue3.5`.
- `prefixes` : une ou plusieurs plages d'adresses. Une adresse appartient à
  la plage la plus précise qui la contient.

Profitez-en pour renseigner `organisation:` (le nom qui apparaîtra en tête
des rapports d'audit).

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
