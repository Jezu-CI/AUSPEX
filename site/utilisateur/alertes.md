---
title: Recevoir les alertes d'Auspex
description: "Envoyer les écarts d'Auspex vers un SIEM ou un outil de supervision : syslog, webhook HTTPS ou fichier, filtrage par gravité et test des envois."
---

# Recevoir les alertes

Chaque écart peut partir en **alerte** vers l'outil qui surveille déjà votre
sécurité : un SIEM (Splunk, Elastic, Sentinel, QRadar, Wazuh…), un outil de
supervision ou un simple fichier.

## Ce que vous recevez

- **Une alerte à l'ouverture** d'un écart, une autre quand il change de
  gravité, une dernière quand il se ferme.
- **Le même identifiant** du début à la fin : votre SIEM peut suivre un
  écart comme un ticket, sans rafale de doublons.
- Le détail utile : les deux machines, leurs zones, le port, la gravité et
  les références réglementaires.

## Les façons de les recevoir

| Sortie | Pour qui |
| --- | --- |
| **syslog** (UDP, TCP ou TLS chiffré), au format CEF ou JSON | la plupart des SIEM |
| **webhook** HTTPS, en JSON | un outil de ticketing, une messagerie d'équipe, une automatisation |
| **fichier** JSONL | un agent de collecte déjà présent sur le central |

Votre administrateur les déclare dans `auspex.yaml`, rubrique `alerts`. Par
exemple, pour n'envoyer au SIEM que les écarts de gravité élevée ou
critique, en syslog chiffré :

```yaml
alerts:
  outputs:
    - { type: syslog, url: "tls://siem.ville.local:6514", format: cef, min_severity: high }
```

## Si le SIEM est injoignable

Rien n'est perdu. Les alertes attendent sur le disque du central et
repartent au cycle suivant. Le widget **État du service** affiche le nombre
d'envois en attente ou en échec.

## Tester

```bash
docker compose exec auspex auspex alerts test
```

envoie une alerte factice à chaque sortie déclarée. Vérifiez qu'elle arrive
dans votre SIEM avant de compter dessus.

Le détail de chaque réglage (formats, certificats, jeton du webhook) est dans
la [documentation technique](../documentation/05-configuration.md#sorties-siem).
