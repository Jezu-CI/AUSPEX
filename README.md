# Auspex

[![CI](https://github.com/Jezu-CI/AUSPEX/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Jezu-CI/AUSPEX/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Jezu-CI/AUSPEX/badge)](https://scorecard.dev/viewer/?uri=github.com/Jezu-CI/AUSPEX)
[![Captures réelles](https://github.com/Jezu-CI/AUSPEX/actions/workflows/captures-reelles.yml/badge.svg?branch=main)](https://github.com/Jezu-CI/AUSPEX/actions/workflows/captures-reelles.yml)
[![Version](https://img.shields.io/github/v/release/Jezu-CI/AUSPEX?label=version)](https://github.com/Jezu-CI/AUSPEX/releases/latest)
[![Licence AGPL v3](https://img.shields.io/badge/licence-AGPL%20v3-blue)](LICENSE)
[![Site](https://img.shields.io/badge/site-jezu--ci.github.io%2FAUSPEX-12805a)](https://jezu-ci.github.io/AUSPEX/)

*CMDB open source passive IT/OT — v0.1 « Silence Before Dawn »*

**Site du projet : [jezu-ci.github.io/AUSPEX](https://jezu-ci.github.io/AUSPEX/)** — documentation, captures d'écran, téléchargement.

À Rome, l'auspex lisait les présages en observant le vol des oiseaux, sans
jamais intervenir. C'est le principe de l'outil : tout voir, ne rien émettre.

Auspex est une **CMDB open source** qui se remplit en écoutant le réseau :
inventaire des actifs et contrôle de la segmentation réseau **par écoute
passive**, sans agent, sans compte de service, sans émettre un seul paquet
sur les réseaux surveillés. Conçu pour les environnements IT et industriels
(OT), et pour produire les preuves attendues par NIS2, DORA et l'IEC 62443.

*Aucun flux non déclaré n'échappe au regard de l'Auspex. Pour l'Empereur.*

> **État du projet : v0.1, déployable.** Central complet (NetBox + Auspex en
> docker compose), capteur Docker et appliance ISO, identification IT/OT,
> conformité des flux, alertes SIEM, tableau de bord et carte, exports d'audit
> signés, authentification forte (MFA, clé de sécurité, carte à puce, LDAPS,
> OIDC, SAML). Chaque fonctionnalité est prouvée en CI sur le vrai produit :
> vrai Zeek, vrai NetBox, vrai navigateur, appliance démarrée en machine
> virtuelle, captures industrielles réelles (voir
> [docs/06-preuves-ci.md](docs/06-preuves-ci.md) et le
> [journal des versions](CHANGELOG.md)).

> **Documentation** (authentification, capteurs, exports d'audit,
> exploitation, référence de configuration, preuves) : [`docs/`](docs/README.md).

## Ce que fait la version actuelle

À partir de logs Zeek (JSON ou TSV, compressés ou non) :

- **Inventaire identifié** : famille et version d'OS, type d'équipement,
  fabricant, modèle, firmware, rôles (contrôleur de domaine, DNS, automate,
  maître Modbus...), chacun avec un **score de confiance** et la **liste des
  indices** qui l'ont produit.
- **Conformité des flux** : chaque flux entre zones est comparé aux règles
  déclarées dans un fichier **CSV ou XLSX**. Écarts détectés :

  | Écart | Exemple |
  | --- | --- |
  | Nouveau flux non déclaré | RDP d'un poste vers un serveur |
  | Flux non déclaré persistant | SSH ouvert pour un dépannage, jamais refermé |
  | Règle expirée encore utilisée | accès prestataire au-delà de la date prévue |
  | Règle jamais utilisée | règle candidate au nettoyage |
  | Administration depuis un tier moins sensible | poste T2 en RDP sur un contrôleur de domaine T0 |
  | Flux IT vers OT sans DMZ industrielle | serveur qui interroge un automate en direct |
  | Balayage du réseau | poste compromis qui balaie l'atelier (une alerte par machine, résolue quand le balayage cesse) |

- **Alertes SIEM** : syslog RFC 5424 (UDP, TCP, TLS avec vérification du
  certificat) en CEF ou JSON, webhook HTTPS, fichier JSONL. Une alerte garde
  le même identifiant de l'ouverture à la résolution : pas de rafale de
  doublons. File d'attente sur disque si le SIEM est injoignable.
- **Références réglementaires** sur chaque écart (NIS2 / règlement
  2024/2690, IEC 62443, ISO 27001, modèle en tiers ANSSI).
- **Rôles industriels** : automates, IHM et stations d'ingénierie distingués
  (S7, Modbus, Omron), routeurs BACnet, machines qui balaient le réseau.

Et autour : capteur passif (Docker ou appliance ISO durcie, mises à jour
signées), synchronisation avec NetBox, tableau de bord et carte interactive,
exports d'audit signés (NIS2, DORA, IEC 62443, ISO 27001, ANSSI).

## Déployer le central

Prérequis : une machine Linux avec Docker et Docker Compose v2. Cible de
ressources : 2 vCPU, 4 Go de RAM.

```bash
git clone https://github.com/Jezu-CI/AUSPEX.git auspex && cd auspex/deploy
./install.sh
```

Le script génère les secrets (`.env`, droits 600), une configuration de
départ, démarre NetBox, PostgreSQL, Redis et Auspex, et fournit à Auspex un
jeton d'API NetBox. Ensuite :

1. adapter `deploy/config/auspex.yaml` (zones, sorties SIEM) et
   `deploy/config/regles-flux.csv` ;
2. déposer les logs des capteurs dans `deploy/logs/` ;
3. suivre le service : `docker compose logs -f auspex`.

Le service analyse les nouveaux logs, met NetBox à jour et envoie les alertes
toutes les 5 minutes. Il relit sa configuration à chaque cycle et applique
`auspex.yaml` (une règle ajoutée au fichier est prise en compte au cycle
suivant). Tant que le déploiement n'est pas conforme (NetBox pas encore
démarré, jeton absent, fichier de règles invalide), **l'analyse est suspendue
et aucune alerte n'est émise** : jamais d'écarts calculés sans les règles de
flux. La cause est visible avec `docker compose exec auspex auspex health`.

**Compte de service « Librarian »** — Auspex n'écrit pas dans NetBox en
administrateur, mais avec un compte dédié aux droits minimaux, créé et
maintenu par l'installation :

| Librarian peut | Librarian ne peut pas |
| --- | --- |
| lire adresses IP, équipements, VM, champs et étiquettes | toucher aux équipements, VM, sites… |
| créer une adresse IP, uniquement marquée « Observé par Auspex » | supprimer quoi que ce soit |
| modifier une adresse IP pour l'enrichir | créer des champs, des utilisateurs, des jetons |

NetBox ne permettant pas de droits champ par champ, c'est la limite la plus
fine possible. Le conteneur Auspex ne reçoit **que** le jeton de Librarian ; le
jeton administrateur reste dans `.env` et ne sert qu'à la mise en place
(installation et mise à jour). Toutes les écritures d'Auspex apparaissent
dans l'historique de NetBox au nom de Librarian. Une permission élargie à la
main, ou un Librarian promu administrateur, est remis en ordre à la mise à
jour suivante. La CI vérifie chaque interdiction sur un vrai NetBox.

Les jetons sont générés aléatoirement à l'installation : le jeton
administrateur par défaut de l'image NetBox, connu publiquement, n'est jamais
créé (la CI vérifie qu'il est refusé).

**Mise à jour** — `./update.sh` (ou `./update.sh --netbox v4.4.5`,
`./update.sh --auspex v0.2.0`) sauvegarde la base NetBox, l'état d'Auspex et
`.env`, change les versions, redémarre, puis contrôle la santé du central. Si
un contrôle échoue, tout est remis comme avant, base NetBox comprise. La CI
vérifie ce retour arrière à chaque modification, en forçant une mise à jour
vers une version inexistante.

**Durcissement** — le conteneur Auspex tourne sans privilèges, sur un système
de fichiers en lecture seule, et lit les logs des capteurs en lecture seule.
NetBox est publié par le front HTTPS d'Auspex (voir plus bas) ; en HTTP, il
n'écoute que sur la machine du central.

**Restriction des connexions par IP source (trusted hosts)** — un plugin
NetBox fourni avec le central vérifie, avant toute action, l'adresse d'où
vient chaque connexion authentifiée (session de l'interface comme jeton
d'API). Exemple : `user1` n'est accepté que depuis 10.10.1.2 et 172.16.20.2.

```yaml
access:
  default: deny_if_unlisted        # utilisateur sans règle : refusé
  trusted_proxies: [192.0.2.10]    # votre reverse proxy TLS, s'il y en a un
  trusted_hosts:
    - user: user1
      allow: [10.10.1.2/32, 172.16.20.2/32]
    - group: admins-t0
      allow: [10.0.10.0/28]
auth:
  break_glass: {user: admin, mfa: totp, allow: [10.0.10.5/32]}
```

| Compte | Accepté depuis |
| --- | --- |
| Utilisateurs et groupes | les adresses de leurs règles ; sans règle, la politique par défaut |
| Brise-glace (`admin`) | la machine du central, et les adresses de `allow` |
| Librarian | uniquement le réseau interne du central : un jeton volé ne sert à rien ailleurs |

- L'en-tête `X-Forwarded-For` n'est cru que s'il vient d'un proxy déclaré
  dans `trusted_proxies`. Sinon il est ignoré, car n'importe qui peut
  l'écrire. Un `0.0.0.0/0` est refusé à la validation.
- Une connexion refusée reçoit un HTTP 403, sa session est fermée, et
  l'événement `auspex_access_denied` est journalisé (en JSON, prêt pour le
  SIEM).
- Les modifications de `auspex.yaml` sont prises en compte sans redémarrage.
  Si le fichier devient invalide, NetBox se **verrouille** : seul l'administrateur
  local reste accepté, depuis la machine du central, le temps de corriger.
- La CI vérifie chaque cas sur le central complet, y compris une usurpation
  d'adresse par en-tête depuis un conteneur du central.

**Double authentification (MFA)** — toute connexion à l'interface qui ne
passe pas par un fournisseur d'identité ou une carte à puce (comptes locaux,
brise-glace compris, et LDAPS) exige une clé de sécurité (voir plus bas) ou
un code à usage unique (TOTP), lu dans n'importe quelle
application d'authentification (Aegis, FreeOTP, Google ou Microsoft
Authenticator…). Avec OIDC ou SAML, c'est la MFA du fournisseur qui s'applique.

- Première connexion : on scanne un QR code (ou on saisit la clé) dans
  l'application, on confirme par un premier code. 10 **codes de secours** à
  usage unique sont alors montrés, une seule fois.
- **Sans téléphone professionnel** : l'application peut tourner sur le poste
  (KeePassXC gère les codes TOTP), ou, si `email` est activé, le code est
  envoyé par e-mail (8 chiffres, valable 10 minutes, un envoi par minute et
  5 par heure au plus). L'e-mail indique l'adresse du poste qui se connecte.
  Moins robuste qu'une application (qui lit la messagerie passe la MFA) ; il
  n'est jamais proposé au brise-glace, qui doit fonctionner même quand la
  messagerie est en panne.
- Tant que le code n'est pas saisi, rien n'est accessible, API comprise.
- Un code ne sert qu'une fois. Après 5 erreurs, le compte est verrouillé
  5 minutes, puis 10, 20… jusqu'à 24 h tant qu'aucune connexion ne réussit.
- Les jetons d'API (Auspex, scripts) ne sont pas concernés : ils sont limités
  par les trusted hosts.
- Chaque événement est journalisé (`auspex_mfa_ok`, `auspex_mfa_failed`,
  `auspex_mfa_locked`…), sans jamais de secret ni de code.

```yaml
auth:
  mfa:
    methods: [totp, email]        # chacun choisit à sa première connexion
    email:
      smtp_server: smtp.exemple.fr
      port: 587
      security: starttls          # certificat du serveur toujours vérifié
      from: auspex@exemple.fr
      ca_file: ca-interne.pem     # facultatif : autorité de certification interne
```

Le mot de passe SMTP éventuel va dans `.env` (`AUSPEX_SMTP_PASSWORD=...`),
jamais dans `auspex.yaml`. L'adresse utilisée est celle du compte NetBox
(renseignée par l'administrateur, ou par l'annuaire pour LDAPS).

Téléphone perdu, ou compte verrouillé, côté administrateur :

```bash
cd deploy
docker compose exec netbox /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py auspex_mfa status
docker compose exec netbox /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py auspex_mfa unlock user1
docker compose exec netbox /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py auspex_mfa reset user1
```

Chaque commande affiche son événement (`auspex_mfa_unlock`, `auspex_mfa_reset`)
au même format JSON, à conserver dans le journal d'administration.

La CI rejoue un parcours complet sur le central : inscription, connexion,
rejeu refusé, code de secours, verrouillage, réinitialisation, et le même
parcours par e-mail avec un vrai serveur de messagerie de test.

**Clé de sécurité (WebAuthn)** — clé USB FIDO2 (YubiKey, SoloKey…), Windows
Hello ou l'empreinte d'un portable : la méthode la plus sûre, proposée en
premier quand elle est activée. Le navigateur lie la clé au domaine d'Auspex :
elle ne répond pas sur un site d'hameçonnage, même parfaitement imité.

```yaml
auth:
  break_glass: { user: admin, mfa: webauthn }   # facultatif : brise-glace par clé
  mfa:
    methods: [webauthn, totp]
    webauthn:
      domaine: auspex.ville.fr
      adresse: https://auspex.ville.fr          # adresse exacte de NetBox (HTTPS)
      exiger_code: false                        # true : code PIN ou biométrie exigés
```

- Inscription d'une clé à la première connexion, codes de secours comme pour
  TOTP ; la page **Mes clés de sécurité** (`/plugins/auspex/mfa/cles/`) permet
  d'inscrire une **clé de secours**, à ranger à part, et de retirer une clé
  perdue (jamais la dernière).
- Seule la clé publique est conservée. Une clé clonée est détectée (compteur
  de signatures), une réponse rejouée est refusée (défi à usage unique).
- `auspex_mfa reset` révoque aussi les clés de l'utilisateur.
- La CI inscrit et utilise une clé virtuelle (protocole CTAP2) avec un vrai
  navigateur sur le vrai NetBox.

**Front HTTPS** — le central publie NetBox en HTTPS (service `acces`, nginx
sans privilèges). L'installation crée un certificat autosigné : le remplacer
par celui de l'organisme (`tls/serveur.crt` et `serveur.key`, hors de `config/` :
NetBox ne voit jamais la clé privée), puis
`docker compose restart acces`. Ports : `AUSPEX_HTTPS_PORT` (443) et
`AUSPEX_CARTE_PORT` (8443) dans `.env`. NetBox reste joignable en HTTP sur
la machine du central seulement (`127.0.0.1:8080`).

**Carte à puce** — connexion par certificat client (cartes d'agent, cartes
d'ouverture de session Windows…), sur un port dédié du front : le site
principal ne déclenche jamais de fenêtre de choix de certificat.

```yaml
auth:
  carte:
    adresse: https://auspex.ville.fr:8443   # port carte du front
    autorites: tls/cartes-ac.pem            # AC émettrices des cartes (PEM)
    revocation: tls/cartes-lcr.pem          # liste de révocation (PEM), recommandée
    identifiant: upn_court                  # upn | upn_court | email | cn → compte NetBox
    creer_comptes: false                    # true : compte créé sans droits au premier passage
```

- Le front vérifie la chaîne jusqu'aux autorités déclarées, la révocation et
  la possession de la carte (donc de son code PIN) ; NetBox ne reçoit
  l'identité que du front (secret partagé `AUSPEX_PROXY_SECRET`, créé à
  l'installation) : des en-têtes forgés envoyés directement à NetBox sont
  refusés.
- La carte vaut double authentification. Le compte d'administration local et
  le brise-glace ne se connectent **jamais** par carte.
- Le compte est retrouvé sans tenir compte de la casse (refus si deux comptes
  ne diffèrent que par elle) ; les trusted hosts s'appliquent comme pour
  toute connexion.
- La liste de révocation doit être tenue à jour : `auspex plan` prévient
  7 jours avant son échéance ; périmée, elle fait refuser **toutes** les cartes.
- Bouton « Connexion par carte à puce » sur la page de connexion ; chaque
  connexion et chaque refus est journalisé (`auspex_carte_ok`,
  `auspex_carte_refused`, avec le sujet et le numéro de série de la carte).
- La CI construit une PKI de test et se connecte à travers le vrai front :
  carte valide, carte révoquée, autorité inconnue, sans carte, sans compte,
  carte au nom de l'administrateur, en-têtes forgés.

**Connexion par l'annuaire (LDAPS)** — Active Directory ou OpenLDAP, décrit
dans `auspex.yaml` :

```yaml
auth:
  primary: ldaps
  ldaps:
    servers: [ldaps://dc01.ville.local, ldaps://dc02.ville.local]
    bind_dn: "CN=svc-auspex,OU=Services,DC=ville,DC=local"
    user_search_base: "OU=Utilisateurs,DC=ville,DC=local"
    user_attribute: sAMAccountName          # uid pour OpenLDAP
    group_search_base: "OU=Groupes,DC=ville,DC=local"
    group_type: active_directory            # groupes imbriqués ; group_of_names, posix
    require_group: "CN=Auspex-Utilisateurs,OU=Groupes,DC=ville,DC=local"
    ca_file: ca-ad.pem                      # autorité interne, à côté de auspex.yaml
  break_glass: {user: admin, mfa: totp}
```

- Mot de passe du compte de lecture dans `.env` : `AUSPEX_LDAP_BIND_PASSWORD=...`,
  donné à NetBox seul.
- Toujours chiffré : `ldaps://`, ou `ldap://` avec `start_tls: true`. Un
  `ldap://` en clair est refusé à la validation, et la vérification du
  certificat ne se désactive pas.
- Les groupes de l'annuaire sont recopiés dans NetBox : on leur donne des
  droits, et on peut écrire des règles trusted hosts par groupe.
- Nom, prénom et e-mail viennent de l'annuaire (l'e-mail sert à la MFA par
  e-mail).
- La MFA reste exigée : l'annuaire ne fournit que le mot de passe.
- Dès qu'une méthode principale est choisie, seuls le brise-glace et
  l'administrateur local peuvent encore se connecter avec un compte local de
  NetBox : un compte local oublié est refusé.
- Après une modification de la section `auth` : `docker compose up -d
  --force-recreate netbox`.

La CI monte un vrai annuaire OpenLDAP en LDAPS et vérifie la connexion, le
groupe exigé, la recopie des groupes, la MFA, le refus des comptes locaux, et
le refus d'un annuaire dont le certificat n'est pas reconnu.

**Connexion unique (OIDC)** — Entra ID (Azure), Google, AWS Cognito,
Keycloak… : un bouton sur la page de connexion de NetBox.

```yaml
auth:
  primary: oidc
  oidc:
    issuer: https://login.microsoftonline.com/<tenant>/v2.0
    # Google : https://accounts.google.com
    # AWS Cognito : https://cognito-idp.<région>.amazonaws.com/<pool>
    # Keycloak : https://sso.ville.local/realms/<royaume>
    client_id: auspex-netbox
    label: Microsoft                 # texte du bouton
    groups_claim: groups             # champ qui porte les groupes
    require_group: auspex-utilisateurs
    superuser_group: auspex-admins   # facultatif
    ca_file: ca-interne.pem          # facultatif : autorité interne
  break_glass: {user: admin, mfa: totp}
```

- Secret du client dans `.env` : `AUSPEX_OIDC_CLIENT_SECRET=...`, donné à
  NetBox seul. Adresse de retour à déclarer chez le fournisseur :
  `https://<votre NetBox>/oauth/complete/oidc/`.
- Le fournisseur est toujours joint en HTTPS, certificat vérifié.
- Hors du groupe exigé : refusé avant toute création de compte. Les groupes
  envoyés sont recopiés dans NetBox à chaque connexion ; administrateur
  NetBox seulement via `superuser_group`. Jamais de rattachement d'un compte
  existant par l'adresse e-mail.
- La MFA est celle du fournisseur : Auspex ne redemande pas de code.
- Entra ID envoie par défaut les identifiants des groupes, pas leurs noms :
  utiliser ces identifiants dans `require_group`, ou configurer l'envoi des
  noms dans Entra.

La CI monte un vrai Keycloak en HTTPS et rejoue la connexion complète comme un
navigateur, dont le refus hors du groupe et le refus d'un fournisseur dont le
certificat n'est pas reconnu.

**Connexion unique (SAML 2.0)** — ADFS, Entra ID, Keycloak… : on donne le
fichier de métadonnées exporté du fournisseur, Auspex y lit son identifiant,
son adresse et son certificat de signature.

```yaml
auth:
  primary: saml
  saml:
    sp_entity_id: https://netbox.ville.local      # identifiant de NetBox chez le fournisseur
    idp_metadata: adfs-metadata.xml              # à côté de auspex.yaml
    label: ADFS
    attributes:                                  # noms des attributs envoyés par le fournisseur
      permanent_id: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn
      username: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn
      email: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
    groups_attribute: http://schemas.microsoft.com/ws/2008/06/identity/claims/groups
    require_group: auspex-utilisateurs
  break_glass: {user: admin, mfa: totp}
```

- Adresse de retour à déclarer chez le fournisseur :
  `https://<votre NetBox>/oauth/complete/saml/`.
- Toute assertion doit être signée par le certificat des métadonnées
  (algorithmes obsolètes refusés) ; l'adresse du fournisseur doit être en
  https://. Mêmes règles que l'OIDC pour les groupes, le groupe exigé et
  l'administration.

La CI rejoue la connexion SAML complète avec Keycloak, dont le refus d'une
assertion modifiée (un utilisateur qui se fait passer pour l'administrateur) et
d'un fournisseur dont le certificat ne correspond pas aux métadonnées.

**Tableau de bord** — Auspex s'intègre au tableau de bord de NetBox, que
chaque utilisateur personnalise lui-même (ajouter, retirer, déplacer,
redimensionner les widgets ; mode sombre compris). Quatre widgets :

| Widget | Contenu | Réglages |
| --- | --- | --- |
| Écarts ouverts | compteurs par gravité, écarts du plus grave au plus ancien | gravité minimale, flux ou inventaire, nombre de lignes |
| État du service | dernier cycle, erreurs, envois SIEM en échec ou en attente, règles expirées ou qui expirent | — |
| Inventaire observé | actifs, nouveaux (24 h), silencieux (7 j), non identifiés, répartition | par type, par système, par zone |
| Matrice des zones | flux observés entre zones et écarts associés (microsegmentation) | — |

Les nouveaux utilisateurs reçoivent ce tableau par défaut. La page **Écarts de
conformité** (menu Plugins de NetBox) liste tous les écarts, avec filtres par
gravité, origine, zone et recherche libre.

- Le service écrit à chaque cycle un instantané dans `data/state/tableau/` : c'est le
  seul répertoire de données d'Auspex que NetBox lit, en lecture seule.
- Données réservées aux comptes qui peuvent lire l'inventaire.
- Si le service ne met plus les données à jour, les widgets l'affichent.

**Carte interactive** — la page **Carte des actifs** (menu Plugins) dessine les
zones, les actifs observés et les flux entre eux :

- zones de gestion (tiers 0, administration, 1, 2, DMZ) à gauche, zones
  industrielles (niveaux Purdue 5 à 0) à droite : un flux qui traverse la
  page est un flux IT ↔ OT ;
- couleur de l'actif selon son type, cercle rouge s'il est concerné par un
  écart, pâle s'il est silencieux depuis 7 jours ;
- flux agrégés par couple d'actifs (ports, nombre de connexions), en rouge
  quand ils sont en écart ;
- clic sur un actif : identification, écarts et liste de ses flux ; clic sur
  un flux : ports, volume, écart ;
- filtre « Écarts seulement », recherche par adresse IP ou nom d'hôte, zoom
  et déplacement à la souris, mode sombre.

Le service écrit la carte dans `data/state/tableau/carte.json` (1 500 actifs
et 4 000 flux au plus, les plus en écart d'abord). Mêmes droits que le
tableau de bord. Les noms d'hôte et autres valeurs vues sur le réseau sont
affichés comme du texte, jamais interprétés.

**Exports d'audit signés** — une archive par référentiel, pour un auditeur ou
un dossier de conformité :

| Référentiel | Exigences couvertes par les preuves d'Auspex |
| --- | --- |
| NIS2 (règlement d'exécution 2024/2690) | §6.8 segmentation, §6.7 sécurité des réseaux, §12.4 inventaire, §3.2 surveillance |
| DORA (règlement 2022/2554, RTS 2024/1774) | art. 13 a) b) c) h) (segmentation, flux documentés, réseau d'administration, règles de filtrage), art. 8 inventaire |
| IEC 62443-3-3 | SR 5.1, SR 5.2, SR 6.2, SR 7.8 |
| ISO/IEC 27001:2022 | A.8.22, A.8.20, A.5.9, A.8.16 |
| ANSSI | administration en tiers, cloisonnement et filtrage, systèmes industriels, cartographie |

Chaque archive contient un **rapport** lisible et imprimable (constat par
exigence : écarts ouverts, sans écart observé, preuve fournie, non évalué),
les **preuves** en CSV et JSON (écarts de la période avec leurs dates,
inventaire, règles, flux entre zones et leur couverture par les règles) et un
**manifeste signé** (Ed25519) qui liste l'empreinte de chaque fichier et
celle de l'export précédent.

- Le rapport dit, pour chaque exigence, ce qu'Auspex prouve et ce qui reste à
  évaluer hors d'Auspex (procédures, revues) : il ne prétend pas à plus.
- Une exigence est « non évaluée » quand la donnée manque (inventaire sans
  rapprochement NetBox, aucune règle de flux chargée).
- L'auditeur vérifie l'archive **sans Auspex** (`openssl`, `sha256sum` ; mode
  d'emploi dans `VERIFIER.txt`), après avoir comparé l'empreinte de la clé à
  celle que vous lui communiquez (`auspex audit cle`, ou la page NetBox).
- Production automatique avec la section `audit` de `auspex.yaml`
  (`referentiels`, `frequence`), ou à la demande. Les exports apparaissent
  dans NetBox, page **Exports d'audit** (téléchargements journalisés).
- La clé privée reste dans `data/state/cles/` (droits 600), hors de portée de
  NetBox ; elle est incluse dans les sauvegardes, qui sont donc à protéger.
- Les valeurs vues sur le réseau (noms d'hôte…) sont neutralisées dans les
  CSV (pas de formule de tableur) et le rapport ne contient aucun script.

## Démarrage rapide (5 minutes)

Prérequis : Python 3.10 ou plus récent.

```bash
git clone https://github.com/Jezu-CI/AUSPEX.git auspex && cd auspex
pip install -e .

cd examples/demo
python generate_logs.py logs        # 7 jours de logs Zeek simulés (site IT/OT)
auspex validate                       # vérifie auspex.yaml
auspex rules import                   # simulation de l'import des règles de flux
auspex rules import --apply           # import réel
auspex analyze --logs logs --now logs # analyse
auspex findings                       # écarts ouverts
auspex assets                         # inventaire identifié
```

Le scénario de démonstration contient volontairement : un SSH de dépannage
oublié, un RDP d'un poste vers le contrôleur de domaine, un serveur qui
interroge un automate en Modbus sans passer par la DMZ, et un accès
prestataire couvert par une règle expirée. Les quatre sont détectés ; le
trafic Active Directory normal ne déclenche rien.

## Capteur

Le capteur est une image Docker : Zeek, les parsers industriels ICSNPP de la
CISA (EtherNet/IP-CIP, S7comm, Modbus, DNP3, BACnet, OPC UA, FINS, HART-IP,
GE-SRTP, PROFINET). Il ne fait qu'écouter.

```bash
docker build -t auspex-sensor sensor

# Analyser des captures existantes (réseau coupé, système en lecture seule)
docker run --rm --network none --read-only --tmpfs /tmp \
  -v "$PWD/pcap:/pcap:ro" -v "$PWD/logs:/logs" auspex-sensor read /pcap/site.pcap
auspex analyze --logs logs/site

# Écouter en continu un port SPAN ou un TAP (interface sans adresse IP)
docker run -d --name auspex-sensor --network host --cap-drop ALL \
  --cap-add NET_RAW --cap-add NET_ADMIN -v /var/lib/auspex/logs:/logs \
  auspex-sensor live eth1
```

En écoute continue, les logs tournent toutes les heures et sont purgés après
48 h (`AUSPEX_SENSOR_RETENTION_HOURS`).

**Envoi au central.** Le capteur pousse ses logs toutes les minutes (SSH +
rsync, port 2222 du central) ; il n'ouvre aucun port. Inscription en trois
étapes :

```bash
# 1. Sur le capteur : sa clé d'envoi (créée au premier appel)
docker run --rm -v /etc/auspex-capteur:/etc/auspex-capteur auspex-sensor cle

# 2. Sur le central : déclarer le capteur dans config/auspex.yaml
#      sensors:
#        - { name: capteur-ot, zone: OT-N2, interface: eth1,
#            key: "ssh-ed25519 AAAA…", allow: [10.9.0.20] }
#    (pris en compte au cycle suivant), puis relever l'empreinte du central :
docker compose exec auspex auspex capteur empreinte

# 3. Sur le capteur : écoute avec envoi
docker run -d --name auspex-sensor --network host --cap-drop ALL \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v /etc/auspex-capteur:/etc/auspex-capteur -v /var/lib/auspex/logs:/logs \
  -e AUSPEX_CENTRAL=central.exemple.fr -e AUSPEX_CENTRAL_EMPREINTE=SHA256:… \
  auspex-sensor live eth1
```

- Le capteur vérifie l'empreinte du central avant tout envoi : un faux
  central ne reçoit rien.
- Côté central, chaque clé ne peut qu'**écrire** dans le dossier de son
  capteur (`logs/<nom>/`) : ni lecture des logs, ni suppression, ni shell,
  ni redirection de port (seule lecture possible : la publication signée
  des mises à jour, en lecture seule) ; `allow` limite les adresses d'origine. Le service de
  réception tourne sans privilèges, système en lecture seule.
- Retirer un capteur de `auspex.yaml` révoque sa clé au cycle suivant.
- `auspex capteur liste` : capteurs autorisés et dernier dépôt reçu. Les logs
  reçus sont purgés après 30 jours (`AUSPEX_LOGS_RETENTION_DAYS`).
- Limite connue : un capteur compromis peut déposer de faux logs dans son
  propre dossier (et remplir le disque) ; c'est pourquoi chaque capteur a sa
  clé, révocable seule, et que l'adresse d'origine est contrôlée. Pour tester sans lab,
`python tools/pcapgen.py lab.pcap` fabrique une capture IT/OT réaliste : c'est
elle que la CI fait lire au vrai Zeek à chaque modification.

## Appliance capteur (ISO)

Pour un boîtier ou une machine virtuelle dédiée, une image prête à démarrer
(clé USB, CD, VM) : Debian 12 minimal + le capteur ci-dessus.

- **Système en lecture seule** (image live) ; seuls la clé, la configuration
  et les logs récents sont conservés, sur un disque de données (formaté au
  premier démarrage s'il est **entièrement vide**, jamais sinon).
- **Interface d'écoute muette** : ni adresse, ni ARP, ni IPv6, et un pare-feu
  qui jette toute trame sortante sur cette interface.
- **Interface d'administration** : sorties vers le central (port 2222), les
  DNS et NTP déclarés, DHCP ; rien d'autre, aucune entrée.
- **Aucun compte** : pas de serveur SSH, pas de connexion à la console ;
  l'écran affiche l'état du capteur et un menu de configuration.
- Configuration au premier démarrage, à l'écran, ou par une clé USB étiquetée
  `AUSPEX-CONF` contenant `capteur.conf` (et, pour un déploiement en série,
  la clé d'envoi `cle` / `cle.pub`) :

```ini
NOM=capteur-ot
ADMIN_INTERFACE=mac:52:54:00:a0:00:01   # ou un nom (eno1), ou auto
ADMIN_ADRESSE=dhcp                      # ou 10.9.0.20/24 avec ADMIN_PASSERELLE
DNS=                                    # nécessaire si CENTRAL est un nom
NTP=10.9.0.53
ECOUTE_INTERFACE=mac:52:54:00:a0:00:02
CENTRAL=10.9.0.10:2222
CENTRAL_EMPREINTE=SHA256:…              # auspex capteur empreinte, sur le central
MAJ_CLE=MCowBQYDK2VwAyEA…               # auspex capteur cle-maj (facultatif : mises à jour)
MAJ_FREQUENCE=360                       # minutes entre deux vérifications (défaut 360)
MAJ_ESSAI=300                           # secondes d'essai d'une nouvelle version (défaut 300)
```

### Mises à jour signées de l'analyse

L'analyse (Zeek, ICSNPP, scripts Auspex : ce qui évolue le plus souvent)
se met à jour **par le réseau**, sans déplacement sur site ; le système de
l'appliance (noyau, pare-feu) se met à jour en démarrant une nouvelle ISO.

```bash
# Sur le central, une fois : la ligne MAJ_CLE à mettre dans capteur.conf
docker compose exec auspex auspex capteur cle-maj
# À chaque version : l'image produite avec l'ISO (auspex-capteur-<version>.squashfs)
mkdir -p data/depot-maj && cp auspex-capteur-0.2.0.squashfs data/depot-maj/
docker compose exec auspex auspex capteur publier /var/lib/auspex/depot-maj/auspex-capteur-0.2.0.squashfs
docker compose exec auspex auspex capteur liste      # version d'analyse de chaque capteur
```

- **Signée par votre organisation** : clé Ed25519 du central (distincte de
  celle des audits), dont chaque capteur ne connaît que la partie publique.
  Une image ou un manifeste modifié, une autre clé : refusé.
- **Récupérée par le canal existant** : même connexion SSH que l'envoi des
  logs (clé d'hôte épinglée), en lecture seule ; aucune nouvelle ouverture de
  flux. Reprise après coupure, et seules les différences transitent.
- **A/B avec retour automatique** : la nouvelle version s'installe dans
  l'emplacement libre du disque de données, puis tourne à l'essai ; si
  l'analyse redémarre ou s'arrête pendant l'essai (ou si le capteur redémarre
  avant la fin), retour à la version précédente, et la version est écartée.
- **Jamais de retour en arrière imposé** : une version publiée doit être plus
  récente que celle du capteur ; une ISO plus récente l'emporte sur les
  emplacements.
- Revérifiée (signature et empreinte) à chaque démarrage ; montée en lecture
  seule ; état (`analyse`, dernière mise à jour) visible du central.

La CI construit l'ISO, la démarre en machine virtuelle avec du trafic rejoué
sur l'interface d'écoute et vérifie que les logs arrivent au central, qu'**aucune
trame** ne sort par l'écoute et que l'administration n'émet rien d'autre que
DHCP et l'envoi au central. Elle y publie ensuite des mises à jour : manifeste
falsifié refusé, version suivante installée et validée, version défaillante
abandonnée avec retour automatique. L'ISO et l'image de mise à jour sont
disponibles dans les artefacts de la CI.

## Synchronisation avec NetBox

Auspex écrit l'inventaire **observé** dans NetBox, à côté de l'inventaire
**déclaré** par les équipes, et signale les écarts entre les deux.

```bash
export NETBOX_TOKEN=…            # jamais dans auspex.yaml
auspex netbox setup --apply      # crée les champs « Auspex » (une seule fois)
auspex netbox sync               # simulation : ce qui serait écrit, écarts trouvés
auspex netbox sync --apply       # écriture et alertes
```

- Auspex n'écrit que dans ses propres champs (`auspex_…`, en lecture seule
  dans l'interface) et pose l'étiquette `auspex`. Description, statut,
  rattachement et champs saisis à la main ne sont jamais modifiés.
- Une adresse observée absente de NetBox est créée, marquée « Observé par
  Auspex », sans être rattachée : c'est à un humain de dire ce qu'elle est.
- Écarts détectés :

  | Écart | Exemple |
  | --- | --- |
  | Actif inconnu | un poste ou un automate actif sur le réseau, absent de la CMDB |
  | Actif silencieux | un serveur déclaré actif dans une zone écoutée, jamais vu |
  | Identification divergente | déclaré « Windows Server », observé Ubuntu |
  | Fiche incomplète | propriétaire, niveau de protection, fonction métier ou criticité manquants (NIS2 §12.4, DORA art. 8) |

- Fonctionne avec les équipements et les machines virtuelles, et avec les
  jetons NetBox v1 et v2. Testé à chaque modification contre un vrai NetBox 4.4.

## État voulu : `auspex plan` et `auspex apply`

`auspex.yaml` décrit l'état voulu. `auspex plan` montre ce qui changerait :
modules à installer ou retirer, règles de flux à importer, champs à créer dans
NetBox. `auspex apply` l'applique. Si le plan contient la moindre erreur,
`apply` ne touche à rien. Relancer `apply` sur un déploiement conforme ne fait
rien : `auspex.yaml` et le fichier de règles peuvent vivre dans un dépôt Git,
et chaque fusion se termine par `auspex apply`.

## Modules communautaires

Chacun peut publier un module dans son propre dépôt GitHub ; on l'installe en
une ligne, avec une version épinglée :

```yaml
modules:
  - github.com/exemple/auspex-rules-schneider@v0.4.1
```

| Type | Contenu |
| --- | --- |
| `rules` | règles d'identification (YAML), préfixes MAC, alias |
| `references` | correspondances entre écarts et un référentiel sectoriel |

Garde-fous :

- **données uniquement** : un module contenant un script ou un exécutable est
  refusé (les modules de code viendront avec un bac à sable) ;
- **verrouillage** : `auspex.lock` retient le commit de chaque version ; si un
  tag est déplacé vers un autre contenu, l'installation est refusée ;
- **intégrité** : l'empreinte du module est vérifiée à chaque chargement.

Pour écrire un module : copier [`templates/module-rules`](templates/module-rules)
et vérifier avec `auspex module check`.

## Commandes

| Commande | Rôle |
| --- | --- |
| `auspex validate` | vérifie `auspex.yaml` et liste **tous** les problèmes d'un coup |
| `auspex plan` / `auspex apply` | montre / applique ce qui sépare le déploiement de `auspex.yaml` |
| `auspex daemon --logs RÉP` | service : analyse, NetBox et alertes en continu (`--once` : un cycle) |
| `auspex health` | état du service (vérification de santé Docker) |
| `auspex backup [FICHIER]` | sauvegarde l'état et la configuration, avec empreintes |
| `auspex restore FICHIER [--check]` | vérifie ou restaure une sauvegarde |
| `auspex module list` / `module check` | modules installés / vérifier un module à publier |
| `auspex rules import [FICHIER]` | simule l'import CSV/XLSX : ajouts, modifications, suppressions |
| `auspex rules import --apply` | applique l'import (idempotent : réimporter ne change rien) |
| `auspex rules export FICHIER` | exporte les règles actives en CSV |
| `auspex analyze --logs RÉP` | ingère les **nouveaux** logs, identifie, évalue, envoie les alertes |
| `auspex assets [--zone Z] [--json]` | inventaire identifié |
| `auspex findings [--min-severity high]` | écarts ouverts |
| `auspex alerts test` | envoie une alerte factice à chaque sortie configurée |
| `auspex netbox setup [--apply]` | crée les champs Auspex dans NetBox |
| `auspex netbox sync [--apply]` | écrit l'inventaire observé et rapproche du déclaré |
| `auspex audit export RÉFÉRENTIEL` | export d'audit signé : `nis2`, `dora`, `iec62443`, `iso27001`, `anssi` (`--jours`, `--fin`) |
| `auspex audit verify ARCHIVE` | vérifie un export (signature, empreintes, fichiers ajoutés) ; code 1 si altéré |
| `auspex audit cle` / `audit list` | empreinte de la clé de signature / exports produits |
| `auspex capteur empreinte` | empreinte du central, à saisir sur chaque capteur |
| `auspex capteur liste` | capteurs déclarés, autorisés, dernier dépôt reçu, version d'analyse |
| `auspex capteur cle-maj` | clé de mises à jour : ligne `MAJ_CLE` pour `capteur.conf` |
| `auspex capteur publier IMAGE` | signe et publie une image d'analyse pour les capteurs (`--version`, `--force`) |

Codes de sortie : `0` succès, `1` configuration ou fichier invalide, `2`
argument manquant, `3` échec d'envoi vers le SIEM (les alertes sont conservées),
`4` erreur NetBox, `5` module refusé, `6` sauvegarde invalide.

Relancer une analyse sur les mêmes logs ne compte rien deux fois : Auspex
retient jusqu'où chaque fichier a été lu, y compris quand Zeek le renomme à la
rotation ou qu'il est compressé et copié sur le central.

## Configuration

Tout un déploiement est décrit par un seul fichier `auspex.yaml`. Exemple
commenté : [`examples/auspex.yaml.example`](examples/auspex.yaml.example).
Aucun secret n'y est accepté : les jetons passent par des variables
d'environnement.

## Format des règles de flux

```csv
id,source,destination,protocole,port,description,proprietaire,expire_le
C-001,T1-serveurs,T0-AD,tcp,88,Kerberos,Equipe AD,
C-014,ADMIN-bastion,OT-N2,tcp,22,Maintenance automate,Prestataire X,15/12/2026
C-020,10.2.5.0/24,any,udp,53;123,DNS et NTP,,
```

- Source et destination : nom de zone, IP, préfixe CIDR ou `any`.
- Port : `443`, `8000-8100`, `80;443` ou `any`.
- `expire_le` : `AAAA-MM-JJ` ou `JJ/MM/AAAA`, vide si permanente.
- XLSX : première feuille (ou feuille nommée `regles`), vraies dates Excel acceptées.
- CSV : séparateur `,` ou `;`, UTF-8 ou export Excel Windows.

## Règles d'identification

Les règles sont des **données** (`rules/*.yaml`), pas du code. Chaque règle
lit un type de log Zeek, teste quelques champs et vote pour un attribut avec
un poids. Une règle ne vote qu'une fois par actif, quel que soit le volume de
trafic, et les indices concordants se cumulent.

Elles sont confrontées à chaque modification à des **captures industrielles
réelles** (lab 4SICS 2015, S7, Modbus, DNP3, EtherNet/IP, BACnet, IEC 104,
FINS, HART-IP, Niagara) lues par le vrai capteur : automate Siemens S7-1200
identifié par sa référence et son firmware, superviseurs NiagaraAX, passerelle
HART Rosemount, équipements Moxa, Hirschmann, RUGGEDCOM, Digi ; IHM et stations
d'ingénierie distinguées ; machines qui balaient le réseau signalées (au lieu
de passer pour des maîtres DNP3). Voir
[CONTRIBUTING.md](CONTRIBUTING.md) pour en écrire.

## Architecture du dépôt

```
src/auspex/
  config.py        validation de auspex.yaml
  zones.py         IP → zone (préfixe le plus spécifique)
  zeek.py          lecture des logs Zeek, agrégation des flux
  flowrules.py     import CSV/XLSX, simulation, export
  compliance.py    écarts aux règles et au modèle d'architecture
  fingerprint/     moteur d'identification passive
  state.py         persistance : flux, inventaire, alertes, registre d'ingestion
  outputs/         sorties SIEM (syslog, webhook, fichier)
  netbox.py        synchronisation observé / déclaré
  modules.py       modules communautaires, verrouillage, intégrité
  deploy.py        plan / apply
  backup.py        sauvegarde et restauration
  access.py        trusted hosts : décision par utilisateur, groupe et IP source
  mfa.py           double authentification : TOTP (RFC 6238), e-mail, codes de secours
  qrcode.py        QR codes sans dépendance (inscription à la MFA)
  dashboard.py     instantané pour le tableau de bord (widgets NetBox)
  netbox_auth.py   méthode de connexion (LDAPS, OIDC, SAML, carte) → réglages NetBox
  webauthn.py      clés de sécurité (CBOR/COSE, vérifications WebAuthn)
  carte.py         carte à puce : identité tirée du certificat client
  audit.py         exports d'audit signés
  reception.py     capteurs : clés autorisées, réception
  maj.py           mises à jour signées de l'analyse des capteurs
  cli.py           commande `auspex`
netbox-plugin/     plugin NetBox (trusted hosts, MFA, connexion unique, carte à puce, tableau de bord, carte, audits)
rules/             règles d'identification IT, OT et préfixes MAC
sensor/            image du capteur (Zeek + ICSNPP)
appliance/         ISO du capteur (live-build), configuration durcie
deploy/            central : docker compose, install.sh, update.sh
templates/         gabarit de module communautaire
tools/             générateur de captures, diagnostic CI
examples/          configuration commentée et scénario de démonstration
tests/             tests unitaires, de bout en bout et d'intégration
docs/              documentation (exploitation, configuration, preuves)
```

## Feuille de route

| Jalon | Contenu | État |
| --- | --- | --- |
| Cœur | analyse, fingerprinting, conformité, import CSV/XLSX, alertes SIEM, CLI | **fait** |
| J1 | image capteur (Zeek + ICSNPP), rejeu de pcaps en CI | **fait** (JA4+ retiré : licence FoxIO incompatible avec un usage monétisé) |
| J2–J3 | enrichissement des règles IT et OT à partir de captures réelles | **fait** (captures publiques ; à compléter par des captures de terrain) |
| J4 | écriture dans NetBox (observé / déclaré), champs NIS2 / DORA | **fait** |
| J6 | `plan / apply`, service continu, docker compose, mise à jour avec retour arrière, modules, sauvegardes | **fait** |
| J7 | plugin NetBox : trusted hosts, MFA, LDAPS / OIDC / SAML, tableau de bord, carte interactive | **fait** |
| J8 | exports d'audit signés par référentiel (NIS2, DORA, IEC 62443, ISO 27001, ANSSI) | **fait** |
| J9 | ISO durcie du capteur, envoi des logs au central, WebAuthn, carte à puce, mises à jour signées | **fait** |
| v0.2 | signature des versions (Sigstore), alertes SIEM sur les balayages, captures de terrain, OpenSSF Scorecard, miroir des empreintes | [en cours](https://github.com/Jezu-CI/AUSPEX/milestone/1) |

## Noms de version

Chaque version porte un nom de code :

| Version | Nom de code |
| --- | --- |
| 0.1 | Silence Before Dawn |

## Licence

[GNU AGPL v3](LICENSE), avec un terme additionnel d'attribution ([NOTICE](NOTICE)).

En clair : vous pouvez utiliser Auspex librement, y compris en entreprise, le
modifier et le redistribuer. En échange, toute version modifiée mise à
disposition d'autres personnes, **y compris comme service en ligne**, doit
publier son code source sous la même licence, et conserver la mention
« Basé sur Auspex, projet conçu par Yann Mathon ».

Projet conçu par Yann Mathon ; code développé avec l'assistance de Claude
(Anthropic). Les versions jusqu'à la 0.1.0 incluse ont été publiées sous
licence Apache 2.0.
