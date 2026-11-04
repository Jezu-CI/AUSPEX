# 9. Référence de configuration

`auspex validate` liste **tous** les problèmes d'un coup ; `auspex plan`
montre ce qu'un changement implique. Les chemins relatifs (règles, `ca_file`,
métadonnées, autorités) sont relatifs au dossier de `auspex.yaml`
(`deploy/config/`). **Aucun secret** n'est accepté dans `auspex.yaml`.

Exemple complet : [`examples/auspex.yaml.example`](../examples/auspex.yaml.example).

## `auspex.yaml`

### Général

| Clé | Défaut | Valeurs |
| --- | --- | --- |
| `version` | — | `1` |
| `channel` | `stable` | `stable`, `edge`, `offline` (site isolé) |
| `organisation` | — | nom affiché dans les exports d'audit (≤ 120 caractères) |
| `state_dir` | `state` | données d'exécution |
| `retention_days` | `180` | conservation des observations (entier ≥ 1) |
| `fingerprint_rules` | — | fichiers ou dossiers de règles d'identification supplémentaires |
| `modules` | `[]` | `github.com/org/depot@version` (version épinglée, une seule fois chacun) |

### `zones`

Liste de `{name, class, prefixes}`. `class` : `tier0`, `tier1`, `tier2`,
`admin`, `dmz`, `other`, `purdue0` … `purdue5`, `purdue3.5`. Noms uniques,
au moins un préfixe ; une adresse appartient au préfixe le plus spécifique.

### `sensors`

| Clé | Rôle |
| --- | --- |
| `name` | nom unique ; avec `key` : minuscules, chiffres, tirets (dossier `logs/<name>/`) |
| `zone` | zone déclarée où écoute le capteur (sert au rapprochement « silencieux ») |
| `interface` | interface d'écoute (documentaire) |
| `mode` | `passive` (défaut) ; `active-light` refusé en zone OT |
| `key` | clé publique `ssh-ed25519` d'envoi ; unique par capteur |
| `allow` | adresses ou plages d'origine acceptées (`0.0.0.0/0` refusé ; sans `key`, sans effet) |

### `flow_rules`

`file` : fichier `.csv` ou `.xlsx` ([format](../README.md#format-des-règles-de-flux)).

### `alerts`

| Clé | Défaut | Rôle |
| --- | --- | --- |
| `persistent_after_days` | `3` | un flux non déclaré devient persistant |
| `unused_rule_after_days` | `90` | fenêtre minimale avant de signaler une règle inutilisée |
| `check_intra_zone` | `false` | exiger aussi des règles à l'intérieur des zones |
| `scan` | — | alerte « balayage du réseau », voir ci-dessous |
| `outputs[]` | — | sorties SIEM, voir ci-dessous |

#### Balayages du réseau (`alerts.scan`)

Une machine qui tente de joindre de nombreuses cibles (adresse et port)
**refusées ou sans réponse** déclenche une alerte « Balayage du réseau » :
une seule par machine, ouverte pendant le balayage, mise à jour si la gravité
change, résolue d'elle-même quand le balayage cesse (plus de tentative dans la
fenêtre). Le message indique le nombre de cibles et de machines visées, les
zones et les ports les plus visés.

| Clé | Défaut | Rôle |
| --- | --- | --- |
| `enabled` | `true` | `false` : aucune alerte de balayage |
| `min_targets` | `100` | nombre de cibles distinctes à partir duquel on parle de balayage (même seuil que le rôle « Balayage de ports » de l'inventaire) |
| `window_hours` | `24` | seules les tentatives de cette fenêtre comptent |
| `severity` | `high` | gravité ; relevée d'un cran si le tier 0 ou l'atelier (Purdue 0 à 2) est visé : un balayage peut suffire à arrêter un automate |
| `allowed` | `[]` | IP ou préfixes CIDR des scanners autorisés (scanner de vulnérabilités) : aucune alerte |

```yaml
alerts:
  scan:
    allowed: [10.9.0.20/32]   # scanner de vulnérabilités de l'équipe sécurité
```

Limites : seuls les balayages TCP sont détectés (tentatives refusées, `REJ`,
ou sans réponse, `S0`) ; un balayage UDP ou ICMP, ou un balayage lent étalé
au-delà de la fenêtre, ne déclenche pas l'alerte.

Sortie : `type` (`syslog`, `webhook`, `file`), `url`
(`udp://`, `tcp://`, `tls://` pour syslog ; `https://` obligatoire pour
webhook), `format` (`cef` par défaut pour syslog, `json`), `min_severity`
(`info` … `critical`), `token_env` (variable qui porte le jeton du webhook),
`path` (fichier JSONL), `ca_file`.

#### Sorties SIEM

| Type | Transport | Format |
| --- | --- | --- |
| `syslog` | `udp://`, `tcp://`, `tls://` (certificat vérifié, `ca_file` facultatif) | RFC 5424, charge CEF ou JSON |
| `webhook` | HTTPS uniquement, jeton par variable d'environnement (`token_env`) | JSON |
| `file` | fichier local | JSONL |

- Événement normalisé, aligné sur OCSF (`severity_id` 1 à 5) ; gravités
  converties pour syslog (2 à 6) et CEF (1 à 10).
- Filtre `min_severity` par sortie.
- **File d'attente sur disque** (`state/outbox/`) : un envoi en échec est
  conservé et réexpédié au cycle suivant, sans perte ; code de sortie 3 et
  compteur visible dans le widget « État du service ».
- `auspex alerts test` envoie un événement factice à chaque sortie.

### `netbox`

| Clé | Défaut | Rôle |
| --- | --- | --- |
| `url` | — | HTTPS obligatoire (HTTP seulement pour un nom interne sans point avec `allow_http_internal: true`) |
| `token_env` | `NETBOX_TOKEN` | variable qui porte le jeton (`token` refusé) |
| `silent_after_days` | `30` | seuil de l'écart « actif silencieux » |
| `ca_file` | — | autorité interne |

### `access`

| Clé | Défaut | Rôle |
| --- | --- | --- |
| `default` | `deny_if_unlisted` | ou `allow_if_unlisted` |
| `trusted_proxies` | `[]` | reverse proxys dont on croit `X-Forwarded-For` (`0.0.0.0/0` refusé) |
| `trusted_hosts[]` | `[]` | `{user: … , allow: […]}` ou `{group: …, allow: […]}`, exactement un des deux |

### `auth`

Dès que `auth` est présent, `break_glass` est **obligatoire**.

| Clé | Rôle |
| --- | --- |
| `primary` | `ldaps`, `oidc`, `saml`, ou absent (comptes locaux) ; un bloc renseigné sans être `primary` est refusé |
| `break_glass` | `{user, mfa: totp|webauthn, allow: [...]}` |
| `mfa.methods` | parmi `totp`, `email`, `webauthn` (défaut `[totp]`) |
| `mfa.email` | `smtp_server`, `port` (587 / 465), `security` (`starttls`, `tls`, `none`), `from`, `username`, `ca_file` ; mot de passe : `AUSPEX_SMTP_PASSWORD` |
| `mfa.webauthn` | `domaine` (nom, pas une IP), `adresse` (origine HTTPS exacte, dont le nom finit par `domaine`), `exiger_code` (booléen) |
| `ldaps` | `servers` (ou `server`), `start_tls`, `bind_dn`, `user_search_base`, `user_attribute` (`sAMAccountName`), `group_search_base`, `group_type` (`active_directory`, `group_of_names`, `posix`), `require_group`, `superuser_group`, `attributes`, `ca_file` ; mot de passe : `AUSPEX_LDAP_BIND_PASSWORD` |
| `oidc` | `issuer` (https://), `client_id`, `label`, `scopes`, `groups_claim` (`groups`), `require_group`, `superuser_group`, `ca_file` ; secret : `AUSPEX_OIDC_CLIENT_SECRET` |
| `saml` | `sp_entity_id`, `idp_metadata` (fichier), `label`, `attributes` (`permanent_id`, `username` obligatoires, `email`…), `groups_attribute`, `require_group`, `superuser_group`, `contact` |
| `carte` | `adresse` (https://…:8443), `autorites` (PEM, AC uniquement), `revocation` (PEM de LCR), `identifiant` (`upn`, `upn_court`, `email`, `cn`), `creer_comptes` (booléen) |

### `audit`

| Clé | Défaut | Rôle |
| --- | --- | --- |
| `referentiels` | `[]` | `nis2`, `dora`, `iec62443`, `iso27001`, `anssi` (exports automatiques) |
| `frequence` | `mensuelle` | `quotidienne`, `hebdomadaire`, `mensuelle` |
| `periode_jours` | selon la fréquence (1, 7, 30) | 1 à 3660 |
| `conserver` | `24` | exports gardés par référentiel |

## `.env` (central)

Généré par `install.sh`, droits 600. Ne jamais le versionner.

| Variable | Rôle |
| --- | --- |
| `NETBOX_VERSION`, `AUSPEX_VERSION` | versions déployées (changées par `update.sh`) |
| `AUSPEX_UID`, `AUSPEX_GID` | compte des services (jamais 0) |
| `DB_PASSWORD`, `NETBOX_SECRET_KEY` | base et clé secrète de NetBox |
| `NETBOX_ADMIN_PASSWORD`, `NETBOX_ADMIN_TOKEN`, `NETBOX_ADMIN_EMAIL` | administrateur local de NetBox |
| `LIBRARIAN_TOKEN` | jeton du compte de service, seul transmis à Auspex |
| `AUSPEX_PROXY_SECRET` | secret partagé front ↔ NetBox (64 hexadécimaux) |
| `AUSPEX_LDAP_BIND_PASSWORD`, `AUSPEX_OIDC_CLIENT_SECRET`, `AUSPEX_SMTP_PASSWORD` | secrets des connexions, donnés à NetBox seul |
| `AUSPEX_INTERVAL` | intervalle du cycle, en secondes (300) |
| `AUSPEX_HTTPS_BIND`, `AUSPEX_HTTPS_PORT`, `AUSPEX_CARTE_PORT` | front HTTPS (`0.0.0.0`, 443, 8443) |
| `AUSPEX_SENSOR_BIND`, `AUSPEX_SENSOR_PORT` | réception des capteurs (`0.0.0.0`, 2222) |
| `NETBOX_BIND`, `NETBOX_PORT` | accès HTTP direct à NetBox (`127.0.0.1`, 8080) |
| `AUSPEX_LOGS_DIR`, `AUSPEX_LOGS_RETENTION_DAYS` | dossier des logs reçus (`./logs`), purge (30 jours) |
| `AUSPEX_INTERNAL_SUBNET`, `AUSPEX_FRONT_IP` | réseau interne (172.31.250.0/24), adresse fixe du front |

## `capteur.conf` (appliance)

Lu clé par clé, jamais exécuté ; une clé inconnue ou une valeur invalide
rend la configuration invalide (le capteur n'écoute ni n'envoie rien).

| Clé | Obligatoire | Valeurs |
| --- | --- | --- |
| `NOM` | oui | minuscules, chiffres, tirets (≤ 63) |
| `ECOUTE_INTERFACE` | oui | `mac:aa:bb:…` ou nom d'interface |
| `CENTRAL` | oui | adresse IP ou nom, `:port` facultatif (2222) |
| `CENTRAL_EMPREINTE` | oui | `SHA256:…` (`auspex capteur empreinte`) |
| `ADMIN_INTERFACE` | non (`auto`) | `auto`, `mac:…` ou nom ; doit différer de l'écoute |
| `ADMIN_ADRESSE` | non (`dhcp`) | `dhcp` ou `a.b.c.d/nn` (avec `ADMIN_PASSERELLE`) |
| `ADMIN_PASSERELLE` | si adresse fixe | adresse IPv4 |
| `DNS` | si `CENTRAL` est un nom | jusqu'à 3 adresses IPv4 |
| `NTP` | non | jusqu'à 4 noms ou adresses |
| `MAJ_CLE` | non | `MCowBQYDK2VwAyEA…=` (`auspex capteur cle-maj`) ; absente = pas de mises à jour |
| `MAJ_FREQUENCE` | non (360) | minutes entre deux vérifications, 1 à 1440 |
| `MAJ_ESSAI` | non (300) | secondes d'essai d'une nouvelle version, 30 à 3600 |

## Variables du capteur Docker

| Variable | Rôle |
| --- | --- |
| `AUSPEX_CENTRAL` | `hôte[:port]` du central (active l'envoi) |
| `AUSPEX_CENTRAL_EMPREINTE` | empreinte épinglée de la clé d'hôte du central |
| `AUSPEX_SENSOR_RETENTION_HOURS` | purge locale des logs, en heures (48) |
| `AUSPEX_ENVOI_SECONDES` | intervalle d'envoi (60) |
