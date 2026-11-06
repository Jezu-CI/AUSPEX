---
title: L'inventaire dans NetBox
description: "Comment Auspex alimente l'inventaire NetBox : ce qu'il écrit, ce qu'il ne touche jamais, les adresses « Observé par Auspex » et les fiches à compléter pour NIS2 et DORA."
---

# L'inventaire dans NetBox

NetBox est l'outil où vos équipes tiennent l'inventaire : équipements,
machines virtuelles, adresses IP. Auspex y ajoute **ce qu'il observe**, sans
jamais effacer ce que vous avez saisi.

## Ce qu'Auspex écrit

- Sur chaque adresse IP qu'il a vue, des **champs « Auspex »** (en lecture
  seule dans l'interface) : système, type, fabricant, modèle, firmware,
  rôles, score de confiance, première et dernière observation.
- Une **étiquette `auspex`**, pour filtrer facilement.
- Pour une adresse inconnue de NetBox : une nouvelle adresse, avec la
  description **« Observé par Auspex »**, rattachée à rien. C'est à un humain
  de dire ce que c'est.

## Ce qu'Auspex ne touche jamais

La description, le statut, le rattachement à un équipement, et tous les
champs saisis à la main. Auspex ne supprime rien.

Toutes ses écritures apparaissent dans l'historique de NetBox au nom d'un
compte dédié, **Librarian**, qui n'a que les droits strictement nécessaires.
Vous savez toujours qui a écrit quoi.

## Le travail qui vous revient

### Traiter les adresses « Observé par Auspex »

Dans **IPAM → Adresses IP**, recherchez « Observé par Auspex » (la
description de ces adresses). Pour chacune :

1. regardez les champs Auspex : ils disent souvent de quoi il s'agit
   (« Automate Siemens », « Windows Server ») ;
2. retrouvez la machine et son propriétaire ;
3. rattachez l'adresse au bon équipement ou à la bonne machine virtuelle, ou
   créez-le.

Si personne ne reconnaît la machine, traitez-la comme un incident.

### Compléter les fiches

NIS2 et DORA demandent de connaître, pour chaque actif, son **propriétaire**,
son **niveau de protection**, sa **fonction métier** et sa **criticité**.
Auspex ajoute pour cela quatre champs à vos fiches d'équipement et de machine
virtuelle : **Propriétaire de l'actif** (ou le locataire NetBox, s'il est
renseigné), **Niveau de protection requis**, **Fonction métier supportée** et
**Criticité**. Il signale chaque fiche où l'une de ces informations manque
(écart « Fiche d'inventaire incomplète »). Complétez-les au fil de l'eau.

## Lire une identification

Chaque identification vient avec un **score de confiance** et la **liste
des indices** qui l'ont produite : un protocole industriel reconnu, un nom
annoncé, une façon particulière de répondre… Si une identification vous
semble fausse, ces indices disent pourquoi Auspex s'est trompé. Vous pouvez
les transmettre au projet pour améliorer les règles (voir
[Contribuer](https://github.com/Jezu-CI/AUSPEX/blob/main/CONTRIBUTING.md)).

Auspex reconnaît notamment les automates Siemens, les superviseurs Niagara,
les passerelles HART, les équipements Moxa, Hirschmann ou RUGGEDCOM, et
distingue les automates, les écrans opérateurs et les stations d'ingénierie.
