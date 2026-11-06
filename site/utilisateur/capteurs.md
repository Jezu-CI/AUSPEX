---
title: Installer un capteur
description: "Installer un capteur Auspex pas à pas : où le brancher, démarrer l'appliance, la configurer à l'écran, la déclarer sur le central et vérifier que les données arrivent."
---

# Installer un capteur

Le capteur écoute une copie du trafic et l'envoie, résumé, au central. Il
n'a pas de compte utilisateur, pas d'accès à distance, et sa carte d'écoute
est rendue muette : rien ne peut sortir par elle.

## Où le brancher

Le capteur ne voit que le trafic qu'on lui copie. Choisissez des points de
passage :

- le **cœur de réseau** ou le commutateur qui relie les zones entre elles :
  c'est là que passent les flux entre zones, ceux qui comptent pour la
  segmentation ;
- dans l'atelier, le commutateur de la **supervision** (niveau 2) : il voit
  les échanges entre écrans, automates et stations d'ingénierie ;
- la **DMZ industrielle**, si vous en avez une.

Sur le commutateur, configurez un **port miroir** (SPAN) qui recopie le
trafic des ports ou des VLAN choisis. Ou installez un **TAP** sur un câble.
Votre équipe réseau ou l'intégrateur de l'atelier sait le faire.

## Ce qu'il vous faut

- un PC x86-64 ou une machine virtuelle, 2 Go de mémoire ;
- **deux cartes réseau** : une pour l'écoute (reliée au port miroir), une
  pour l'administration (qui joint le central sur le port 2222) ;
- un **disque de données vide** (256 Mo au minimum), qui gardera la
  configuration et les derniers journaux ;
- l'image `auspex-capteur-<version>.iso`, depuis la
  [page de téléchargement](../telecharger.md), copiée sur une clé USB (avec
  Rufus, Etcher ou balenaEtcher) ou montée dans la machine virtuelle.

## Étape 1 : préparer le central

Sur le central, notez son **empreinte** : c'est ce qui permettra au capteur
de vérifier qu'il parle au bon central, et pas à un imposteur.

```bash
cd auspex/deploy
docker compose exec auspex auspex capteur empreinte
```

Elle ressemble à `SHA256:k3J9…`.

## Étape 2 : démarrer et configurer le capteur

1. Démarrez la machine sur l'ISO.
2. Au premier démarrage, l'écran propose de configurer le capteur. Répondez
   « Oui », puis renseignez :
    - le **nom** du capteur (par exemple `capteur-atelier`) ;
    - l'**interface d'écoute** : celle reliée au port miroir. L'écran indique
      pour chaque carte si un câble est branché ;
    - l'**interface d'administration** : celle qui joint le central ;
    - son **adresse** : `dhcp`, ou une adresse fixe comme `10.9.0.20/24`
      avec sa passerelle ;
    - le **DNS** (seulement si vous donnez le central par son nom) et un
      serveur de **temps** (recommandé) ;
    - l'**adresse du central** et son **empreinte**, notée à l'étape 1.
3. L'écran affiche ensuite la **clé d'envoi** du capteur. Recopiez-la, ou
   exportez-la sur une clé USB nommée `AUSPEX-CONF` (menu « Exporter la clé
   sur clé USB »).

!!! tip "Plusieurs capteurs à installer ?"
    Préparez une clé USB nommée `AUSPEX-CONF` avec un fichier
    `capteur.conf` (modèle dans la
    [documentation technique](../documentation/05-configuration.md#capteurconf-appliance)).
    Le capteur la lit au démarrage : aucune saisie à l'écran.

## Étape 3 : déclarer le capteur sur le central

Ajoutez le capteur dans `deploy/config/auspex.yaml`, rubrique `sensors` :

```yaml
sensors:
  - name: capteur-atelier          # le même nom que sur le capteur
    zone: OT-N2                    # la zone où il écoute
    interface: eth1
    key: "ssh-ed25519 AAAA…"       # la clé d'envoi affichée par le capteur
    allow: [10.9.0.20]             # l'adresse d'administration du capteur
```

C'est pris en compte au cycle suivant, sans redémarrage.

## Étape 4 : vérifier

Sur l'écran du capteur, sans rien toucher :

| Ligne | Ce qu'il faut voir |
| --- | --- |
| Écoute | « aucune adresse, rien n'est émis » |
| Analyse (Zeek) | `active` |
| Dernier envoi | une heure récente (le capteur envoie toutes les minutes) |

Sur le central :

```bash
docker compose exec auspex auspex capteur liste
```

Le capteur apparaît avec l'heure de son dernier dépôt. Quelques minutes plus
tard, ses actifs arrivent dans le tableau de bord.

## Le menu du capteur

Appuyez sur **Entrée** devant l'écran d'état pour ouvrir le menu :
configurer, afficher la clé d'envoi, l'exporter sur clé USB, redémarrer,
éteindre. C'est tout : il n'y a rien d'autre à administrer sur le capteur.

## Les mises à jour

- **L'analyse** (ce qui reconnaît les équipements) se met à jour **par le
  réseau**, depuis le central, sans déplacement. Chaque version est signée
  par votre central : le capteur refuse tout le reste. Si une nouvelle
  version se comporte mal, le capteur revient tout seul à la précédente.
  La mise en place est décrite dans la
  [documentation technique](../documentation/02-capteur.md#mises-à-jour-signées-de-lanalyse-ab).
- **Le système** du capteur se met à jour en le redémarrant sur une ISO plus
  récente. La configuration et la clé, rangées sur le disque de données, sont
  conservées.

## Retirer un capteur

Supprimez-le de la rubrique `sensors` : sa clé est révoquée au cycle suivant
et il ne peut plus rien envoyer.

!!! info "Une alternative : le capteur en conteneur"
    Sur un serveur Linux déjà relié à un port miroir, le capteur existe aussi
    en image Docker. Voir la [documentation technique](../documentation/02-capteur.md).
