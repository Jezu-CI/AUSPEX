---
title: Les notions à connaître
description: "Les notions d'Auspex expliquées simplement : actif, zone, tier, niveaux Purdue, flux, règle de flux, écart, capteur passif, inventaire observé et déclaré."
---

# Les notions à connaître

Une dizaine de mots suffisent pour comprendre tout Auspex.

## Actif

Tout ce qui a une adresse sur le réseau : un poste, un serveur, une
imprimante, un automate, un écran de supervision, un commutateur… Auspex
découvre les actifs **parce qu'ils communiquent**. Un équipement éteint, ou
qui ne parle jamais sur les liens écoutés, reste invisible.

## Zone

Un morceau de votre réseau, défini par ses plages d'adresses. Par exemple
« les postes de travail » (10.2.0.0/16) ou « l'atelier, ligne 2 »
(172.16.2.0/24). Chaque zone reçoit une **classe** qui dit à quel point elle
est sensible.

### Les classes de l'informatique de gestion (modèle en tiers)

Le modèle en tiers, recommandé par l'ANSSI, range les machines selon ce
qu'elles contrôlent. Plus le chiffre est bas, plus c'est sensible.

| Classe | Ce qu'on y trouve |
| --- | --- |
| **Tier 0** | ce qui contrôle tout le reste : contrôleurs de domaine Active Directory, PKI |
| **Administration** | les postes et bastions d'où l'on administre |
| **Tier 1** | les serveurs et applications métier |
| **Tier 2** | les postes de travail des utilisateurs |
| **DMZ** | les services exposés vers l'extérieur |

La règle d'or : **on n'administre jamais une zone sensible depuis une zone
qui l'est moins.** Un poste utilisateur (tier 2) qui ouvre un bureau à
distance sur un contrôleur de domaine (tier 0) est un signal d'alarme.

### Les classes du réseau industriel (niveaux Purdue)

Le modèle Purdue découpe une usine en étages, du capteur physique jusqu'à
l'informatique de l'entreprise.

| Niveau | Ce qu'on y trouve |
| --- | --- |
| 0 | capteurs et actionneurs |
| 1 | automates |
| 2 | supervision, écrans opérateurs (IHM) |
| 3 | gestion de la production, historiens |
| 3,5 | **DMZ industrielle** : le sas entre l'usine et le reste |
| 4 et 5 | informatique de l'entreprise |

La règle d'or : **l'informatique de gestion ne parle jamais directement aux
automates.** Tout passe par la DMZ industrielle.

## Flux

Une communication entre deux actifs : qui parle à qui, par quel protocole et
sur quel port. Par exemple « le poste 10.2.1.13 ouvre un bureau à distance
(RDP, port 3389) sur le serveur 10.0.0.5 ». Auspex regroupe les connexions
répétées en un seul flux.

## Règle de flux

Une ligne de votre tableau des flux autorisés : « la zone A a le droit de
parler à la zone B, sur tel port, pour telle raison, jusqu'à telle date ».
C'est la matrice de flux que vous avez peut-être déjà pour vos pare-feu.
Voir [Déclarer les flux autorisés](regles-de-flux.md).

## Écart

Tout ce qu'Auspex observe et qui ne correspond pas à ce qui est déclaré : un
flux sans règle, une règle expirée encore utilisée, un équipement absent de
l'inventaire… Chaque écart a une **gravité** (critique, élevée, moyenne,
faible) et des **références réglementaires** (NIS2, DORA…). Voir
[Comprendre et traiter les écarts](ecarts.md).

## Capteur passif

Le boîtier qui écoute. On le branche sur un **port miroir** (un port du
commutateur qui reçoit une copie du trafic, aussi appelé SPAN) ou sur un
**TAP** (un petit boîtier qui duplique le trafic d'un câble). Le capteur
n'envoie jamais rien sur ce réseau : ni requête, ni réponse, ni même une
annonce d'adresse.

## Inventaire observé et inventaire déclaré

- L'**inventaire déclaré** est ce que vos équipes ont saisi dans NetBox :
  « ce serveur existe, il appartient à telle équipe, il tourne sous
  Windows ».
- L'**inventaire observé** est ce qu'Auspex voit sur le réseau.

Auspex met les deux côte à côte et signale les différences : un automate
présent sur le réseau mais inconnu de l'inventaire, un serveur déclaré mais
jamais vu, un système différent de celui annoncé.

## Score de confiance

Pour identifier un actif, Auspex rassemble des indices : la façon dont il
parle, le protocole industriel qu'il utilise, le nom qu'il annonce… Chaque
indice ajoute du poids. Le score de confiance dit à quel point
l'identification est sûre, et la **liste des indices** permet de vérifier
pourquoi Auspex pense ce qu'il pense.

## Cycle

Toutes les 5 minutes, le central lit les nouveaux journaux des capteurs,
met l'inventaire à jour, recalcule les écarts et envoie les alertes. C'est
un cycle. Le tableau de bord indique l'heure du dernier.
