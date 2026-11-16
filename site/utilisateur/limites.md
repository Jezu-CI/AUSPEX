---
title: Ce qu'Auspex voit, ce qu'il ne voit pas
description: "Les limites de la découverte passive d'Auspex : ce qu'un capteur qui écoute le réseau voit, ce qu'il ne peut pas voir, et comment en tenir compte dans un inventaire ou un audit."
---

# Ce qu'Auspex voit, ce qu'il ne voit pas

Auspex écoute une copie du trafic réseau (port miroir ou TAP) et n'émet
jamais rien. C'est ce qui le rend sûr sur un réseau industriel, et c'est
aussi ce qui fixe ses limites : **il ne connaît que ce qui passe devant ses
capteurs.** Cette page les décrit franchement, pour que l'inventaire et les
rapports d'audit soient lus pour ce qu'ils sont.

## Ce qu'Auspex voit

- **Les équipements qui communiquent** sur les liens écoutés : leur adresse
  IP, leur adresse MAC quand ils sont sur le même segment que le capteur,
  leurs noms quand ils les annoncent (DHCP, authentification NTLM).
- **Ce que leurs échanges révèlent d'eux** : système et version, fabricant,
  modèle, firmware, rôle (automate, IHM, contrôleur de domaine…), d'après
  les en-têtes des protocoles (HTTP, SSH, SMB, TLS, SNMP, EtherNet/IP,
  S7comm, Modbus, BACnet…). Chaque information porte un score de confiance
  et la liste des indices qui l'ont produite.
- **Les flux** entre ces équipements : qui parle à qui, sur quel port et
  quel protocole, depuis quand, et s'ils respectent les règles déclarées.

Auspex ne lit que des **métadonnées** de trafic : il n'enregistre pas le
contenu des échanges (voir [Données traitées](../documentation/07-donnees-traitees.md)).

## Ce qu'Auspex ne voit pas

| Situation | Pourquoi | Ce qu'il faut faire |
| --- | --- | --- |
| Un équipement **éteint ou silencieux** | rien ne passe sur le réseau, il n'y a rien à observer | le garder dans l'inventaire déclaré de NetBox ; Auspex signale « déclaré, jamais vu » |
| Un flux qui **ne passe pas par un lien écouté** | deux machines branchées sur le même commutateur se parlent sans que le trafic remonte jusqu'au capteur | placer le port miroir au bon endroit (cœur de réseau, passage entre zones), ajouter un capteur par site ou par zone sensible |
| Une **zone sans capteur** | aucune copie du trafic n'en sort | le rapport d'audit liste les capteurs et la zone que chacun écoute, et rappelle qu'un réseau non couvert n'y apparaît pas : vérifier que chaque zone sensible a son capteur |
| Le **contenu chiffré** (TLS, SSH, RDP, VPN…) | le chiffrement protège le contenu, ce qui est voulu | Auspex voit quand même qui parle à qui et, souvent, le certificat ou la version du logiciel annoncée en clair à l'ouverture |
| Des machines **derrière une traduction d'adresses (NAT)** ou un proxy | elles partagent une seule adresse vue du capteur | les écouter avant la traduction, ou les déclarer dans NetBox |
| Un équipement qui **n'annonce rien d'identifiable** | sans en-tête ni bannière, il n'y a pas d'indice | il apparaît comme « non identifié » avec ses flux ; à compléter dans NetBox |
| Les **adresses publiques** | Auspex inventorie les zones déclarées et les adresses privées, pas Internet | les flux vers Internet restent visibles et contrôlés par les règles |
| Les **vulnérabilités** (CVE) | Auspex identifie le firmware et les versions, il ne les compare pas à une base de vulnérabilités | exporter l'inventaire (versions, firmwares) vers l'outil de gestion des vulnérabilités |
| Le trafic **perdu par le port miroir** quand il est saturé | un commutateur chargé peut abandonner une partie de la copie | dimensionner le miroir ou passer à un TAP sur les liens les plus chargés |

## Ce qu'il faut en retenir

- **L'inventaire observé complète l'inventaire déclaré, il ne le remplace
  pas.** C'est pourquoi Auspex écrit les deux côte à côte dans NetBox, avec
  les écarts entre les deux.
- **Une identification est une déduction**, pas une certitude : le score de
  confiance et les indices permettent de juger. En cas de doute, la fiche
  déclarée dans NetBox fait foi.
- **Auspex détecte, il ne bloque pas.** Un flux interdit est signalé et peut
  partir en alerte vers le SIEM ; le bloquer reste le rôle du pare-feu.
- **Auspex aide à démontrer la conformité, il ne la garantit pas.** Les
  rapports d'audit prouvent ce qui a été observé sur la période et la
  couverture des capteurs ; ils ne disent rien de ce qui n'est pas passé
  devant eux.
