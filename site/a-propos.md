---
title: À propos d'Auspex
description: "Qui conçoit Auspex, pourquoi ce projet, comment il est développé (assistance d'une IA, tests automatisés) et sous quelle licence."
---

# À propos

## Le projet

Auspex est né d'un constat de terrain : dans les réseaux industriels comme dans
les systèmes d'information, on protège mal ce qu'on ne connaît pas. Les
inventaires déclarés vieillissent, les flux réels s'écartent des règles, et les
outils qui interrogent activement les équipements sont souvent proscrits en
environnement industriel.

Auspex part donc du principe inverse : **tout voir, ne rien émettre**. Il
observe le trafic, identifie les actifs, compare les flux réels aux règles de
segmentation et produit des preuves exploitables pour NIS2, DORA et
l'IEC 62443.

## L'auteur { #auteur }

Auspex est conçu par **Yann Mathon**, consultant en cybersécurité : réponse à
incident et investigation numérique, environnements Microsoft, modèle
d'administration en tiers et microsegmentation réseau. GitHub :
[Jezu-CI](https://github.com/Jezu-CI).

## Comment Auspex est développé

Yann Mathon n'est pas développeur de métier : il apporte le besoin, l'expertise
sécurité et les choix de conception ; le code est écrit avec l'assistance de
**Claude** (Anthropic). La qualité ne repose pas sur la confiance : chaque
modification est vérifiée automatiquement sur le vrai produit (vrai NetBox, vrai
navigateur, appliance démarrée en machine virtuelle, captures industrielles
réelles). Le détail est public : [preuves automatisées](documentation/06-preuves-ci.md).

## Licence

Auspex est un logiciel libre sous **licence GNU AGPL v3**, avec une mention
d'attribution à conserver (« Basé sur Auspex, projet conçu par Yann Mathon »).
Voir [LICENSE](https://github.com/Jezu-CI/AUSPEX/blob/main/LICENSE) et
[NOTICE](https://github.com/Jezu-CI/AUSPEX/blob/main/NOTICE).

## Contribuer, signaler

- Proposer une règle d'identification d'équipement ou signaler une anomalie :
  [issues du dépôt](https://github.com/Jezu-CI/AUSPEX/issues/new/choose).
- Signaler une vulnérabilité, en privé : [politique de sécurité](securite.md).
