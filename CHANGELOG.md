# Journal des versions

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) ;
versions selon [SemVer](https://semver.org/lang/fr/). Liens absolus : ces notes
sont reprises telles quelles sur la page de chaque version GitHub.

## [0.3.0] — en préparation

### Sécurité

- **Images de base à jour** : Python 3.12 (central) et Debian bookworm (réception) sur leurs dernières empreintes ; image du capteur allégée des outils de construction (compilateur, cmake, git, en-têtes) et de GitPython une fois les parsers compilés. Le détail de l'analyse de chaque image est aussi écrit dans le journal du contrôle.
- **Images PostgreSQL et Valkey du central figées par empreinte** (`deploy/docker-compose.yml`), suivies par Dependabot ; la CI teste NetBox avec la même base de données que celle livrée.
- **Analyse des vulnérabilités et des licences** (workflow « Vulnérabilités et licences », à chaque changement de dépendances et chaque semaine) : Trivy, installé à une version figée par son empreinte (pas d'action GitHub tierce : `trivy-action` et `setup-trivy` ont été détournées en mars 2026, CVE-2026-33634). Paquets Python du produit : vulnérabilité corrigée de gravité moyenne ou plus, ou licence incompatible avec l'AGPL v3 (liste explicite, `tools/verifier-licences.py`) → échec. Images livrées : vulnérabilités hautes et critiques publiées dans l'onglet Security.
- **Image NetBox du central figée par empreinte**, comme toutes les autres images : la version livrée avec Auspex ne peut plus changer à l'insu du projet ; Dependabot propose chaque nouvelle empreinte, vérifiée par la CI ([#4](https://github.com/Jezu-CI/AUSPEX/issues/4)). Une autre version choisie avec `update.sh --netbox` reste possible, prise à son étiquette ; `--netbox` suivi de la version livrée y revient.

- **NetBox 4.7** (4.4 n'est plus maintenu : une centaine de vulnérabilités connues dans son image, signalées dans l'onglet Security). Changements pour Auspex :
  - serveur web de l'image : Granian remplace NGINX Unit. Son point d'entrée remplaçait l'adresse source par l'en-tête X-Forwarded-For pour toute machine des plages privées, ce qui aurait permis d'usurper l'adresse d'un poste autorisé : il est remplacé par un point d'entrée sans cette réécriture, et la construction de l'image échoue si l'image change de forme ;
  - jetons d'API v2 (`nbt_CLÉ.SECRET`) : NetBox n'en garde qu'une empreinte, calculée avec un nouveau secret de `.env` (`API_TOKEN_PEPPER`, ajouté par `update.sh`). L'API ne permet plus d'imposer la valeur d'un jeton : ceux de l'administrateur et de Librarian sont posés dans NetBox par le plugin (`manage.py auspex_jeton`, valeur lue sur l'entrée standard). L'image ne crée plus aucun jeton. Les jetons v1 d'une installation antérieure restent valables ;
  - contrôle des adresses autorisées (trusted hosts) : les jetons sont identifiés comme NetBox 4.7 les identifie (v2 et v1) ; un jeton inconnu est refusé par le plugin lui-même, sans attendre NetBox ;
  - connexion unique (OIDC, SAML) : elle ne démarre plus que par le bouton de la page de connexion (requête POST protégée contre la falsification) ; NetBox joint lui-même le fournisseur SAML, le complément que faisait le plugin est retiré ;
  - autorité de certification interne (OIDC, serveur de messagerie) : vérification stricte des certificats (Python 3.14 de l'image) ; une autorité sans extensions `basicConstraints` et `keyUsage` est refusée (contrôle donné dans le guide) ;
  - codes MFA par e-mail : envoi direct en SMTP (bibliothèque standard), Django 6.1 n'acceptant plus de moteur d'envoi propre à un plugin ; certificat du serveur toujours vérifié, TLS 1.2 au moins.

  `./update.sh` fait passer une installation sur la version livrée précédente (4.4) à la 4.7, avec sauvegarde et retour arrière automatique comme toute mise à jour.

### Ajouté

- **Capteur raccordé par un code** : `auspex capteur inviter NOM --zone Z` affiche un code à usage unique (1 h) ; sur le capteur Docker, `rejoindre CENTRAL CODE` vérifie la clé du central contre le code (un faux central est refusé), s'inscrit, et retient l'adresse et l'empreinte du central. Le central n'autorise la clé dérivée du code que pour déposer la clé du capteur, une fois, avant l'expiration ; il ne garde jamais le code. Capteurs ainsi raccordés dans `data/state/capteurs.yaml` (auspex.yaml n'est jamais modifié), retrait par `auspex capteur retirer`. Appliance ISO : raccordement par adresse et empreinte, comme avant.
- **Assistant d'installation** : à la première installation, `./install.sh` demande le nom de l'organisation, les zones et leurs plages d'adresses, le SIEM éventuel (syslog TLS, TCP ou UDP, CEF ou JSON) et les référentiels d'audit, vérifie chaque saisie (plage invalide, zones qui se chevauchent) et écrit `config/auspex.yaml` en gardant les commentaires du modèle. Aucune question hors d'un terminal (CI, script) ; `AUSPEX_REPONSES=reponses.json` pour une installation automatisée. Commande sous-jacente : `auspex init`.
- **README recentré** (présentation, installation en trois lignes, démonstration, documentation) ; le détail du déploiement, de la sécurité des accès, du capteur, des commandes et des formats passe dans `GUIDE.md`, publié sur le site comme avant (page Guide, mêmes ancres). Page « Installer et mettre en route » du guide utilisateur mise à jour, bouton « Installer » sur l'accueil du site.
- **Ce qu'Auspex voit, ce qu'il ne voit pas** : page du guide utilisateur, section du README, question de la FAQ et page anglaise. Limites de l'écoute passive (équipement silencieux, flux hors des liens écoutés, zone sans capteur, contenu chiffré, NAT, vulnérabilités non comparées, détection sans blocage) et parade pour chacune ; les exports d'audit aident à démontrer la conformité sur le périmètre écouté, sans la garantir.
- Composants tiers : section « Site, visuels et interface » (thème du site, icônes Material Design et Font Awesome avec leur licence et l'attribution due, aucune police tierce, logos de l'auteur).
- Feuille de route v0.3 : accessibilité, avec un état des lieux des contrastes (WCAG AA) dans [#35](https://github.com/Jezu-CI/AUSPEX/issues/35).
- **Effacement d'un actif sur demande** (RGPD) : `auspex oublier IP… [--apply]`, simulation par défaut. Retire l'adresse de la fiche d'actif, des flux, des écarts et alertes, des envois au SIEM en attente, du tableau de bord et de la carte ; indique ce qui reste à faire hors d'Auspex (NetBox, alertes déjà livrées) et ce qui est conservé par conception (exports signés, sauvegardes, journaux bruts jusqu'à leur purge). Verrou partagé avec le cycle du service : un cycle en cours ne réécrit pas ce qui vient d'être effacé.
- **Page « Données traitées »** pour le DPO (documentation 7) : chaque donnée, sa finalité, son emplacement et sa durée de conservation, y compris le contenu des journaux bruts Zeek.

### Changé

- Fichier de provenance des versions renommé `auspex-provenance.intoto.jsonl` (même contenu, sur une ligne) : extension reconnue comme provenance SLSA, notamment par OpenSSF Scorecard ([#4](https://github.com/Jezu-CI/AUSPEX/issues/4)). La 0.2.0 garde `auspex-provenance.sigstore.json`.

### Corrigé

- Les **alertes résolues** n'étaient jamais purgées : elles le sont désormais après `retention_days`, comme les actifs et les flux.
- Les **journaux des conteneurs** du central n'étaient pas bornés (ils contiennent les événements de connexion) : rotation à 5 fichiers de 10 Mo par service.
- Publication d'une version : publier le brouillon crée le tag, qui relançait tout le workflow (vingt minutes de construction) pour finir en échec sur une version déjà publiée. La version publiée est désormais reconnue d'emblée et le reste ignoré.

## [0.2.0] « Lantern in the Void » — 2026-11-14

### Sécurité

- **Codes de secours de la double authentification** : empreintes **scrypt** avec un sel propre à chaque code, au lieu de SHA-256 sans sel. Un vol de la base de données ne permet plus de retrouver les codes par recherche exhaustive. Les codes distribués avant la 0.2.0 restent valables jusqu'à leur utilisation.
- **Analyse de code (linter)** : ruff vérifie à chaque modification les erreurs probables et pièges courants (règles dans `pyproject.toml`) ; corrections des points relevés (exceptions qui masquaient leur cause, fermetures sur une variable de boucle, imports inutiles).
- **Fuzzing des analyseurs** (`fuzz/`, workflow hebdomadaire, Atheris si installé) : manifeste de mise à jour, journaux des capteurs, fichier des règles de flux, configuration. Il a révélé et fait corriger des plantages sur données abîmées ou forgées : manifeste non ASCII, en-têtes de journal Zeek incomplets, horodatages hors limites, champs du mauvais type, horodatages sans fuseau mêlés aux autres, fichier de règles hors encodage ou avec caractère nul, port « inf », configuration non UTF-8 ou de structure inattendue. Un journal envoyé par un capteur compromis ne peut plus interrompre le cycle d'analyse. Chaque cas est un test de non-régression.
- **Fuzzing étendu à toutes les données venues de l'extérieur** ([#9](https://github.com/Jezu-CI/AUSPEX/issues/9)) : journaux compressés (gzip, archives tronquées), classeur Excel des règles, moteur d'identification (règles réelles sur des journaux forgés), clé publique d'un capteur, archive de sauvegarde à restaurer, réponses de l'API NetBox. Bornes vérifiées : 10 s par entrée (et 2 Go de mémoire avec Atheris). Corrigé : archive gzip ou classeur Excel abîmés (`zlib.error`), champs de journal du mauvais type dans l'identification (protocole numérique, état de connexion en liste, adresse MAC non textuelle), manifeste de sauvegarde illisible ou de structure inattendue, réponse NetBox illisible ou de forme inattendue (désormais vérifiée avant usage), lien de pagination NetBox mal formé ou **sans fin** (le cycle pouvait boucler indéfiniment). Mémoire bornée : une ligne de journal de plus de 1 Mo est ignorée sans être lue entière (une archive piégée de 200 Ko faisait monter la mémoire à plus de 400 Mo, 19 Mo désormais) ; un fichier de règles est limité à 20 000 lignes.

### Changé

- **Licence : GNU AGPL v3**, avec un terme additionnel d'attribution
  ([NOTICE](https://github.com/Jezu-CI/AUSPEX/blob/main/NOTICE)) : toute version modifiée mise à disposition, y compris
  comme service en ligne, publie son code et conserve la mention « Basé sur
  Auspex, projet conçu par Yann Mathon ». La mention figure dans le widget
  « État du service » et la page des écarts. Les versions jusqu'à la 0.1.0
  incluse restent sous Apache 2.0.
- Documentation publique recentrée sur l'utilisation : authentification,
  capteurs, exports d'audit, exploitation, configuration (sorties SIEM
  comprises), preuves automatisées ; limites connues dans SECURITY.md.
- Modèle de module (`templates/module-rules`) déclaré compatible avec Auspex 0.2 (`>=0.2,<0.3`) : un module écrit pour la 0.1 doit élargir sa plage `auspex:` après vérification.

### Ajouté

- **Versions signées** ([#1](https://github.com/Jezu-CI/AUSPEX/issues/1)) : signature Sigstore sans clé de `SHA256SUMS` (identité du workflow de publication, journal public Rekor) et attestation de provenance SLSA de chaque fichier. Vérification en une commande (`tools/verifier-version.sh`, ou `cosign verify-blob` et `gh attestation verify`), éprouvée à chaque publication, contre-épreuves comprises (fichier, empreintes ou provenance altérés refusés).
- **Alerte SIEM « Balayage du réseau »** ([#2](https://github.com/Jezu-CI/AUSPEX/issues/2)) : une machine qui tente de joindre au moins 100 cibles (adresse et port) refusées ou sans réponse en 24 h déclenche une alerte, une seule par machine, résolue d'elle-même quand le balayage cesse. Gravité élevée, critique si le tier 0 ou l'atelier est visé ; seuil, fenêtre, gravité et scanners autorisés réglables (`alerts.scan`). Rattachée aux contrôles de surveillance des exports d'audit (NIS2 §3.2, IEC 62443 SR 6.2, ISO 27001 A.8.16). Prouvée avec le vrai Zeek sur une capture de balayage, et dans le scénario de démonstration.
- **OpenSSF Scorecard** ([#4](https://github.com/Jezu-CI/AUSPEX/issues/4)) : bonnes pratiques de sécurité du dépôt mesurées chaque semaine et à chaque modification, résultats publiés (badge du README) et dans l'onglet Security. Dans la foulée : toutes les actions GitHub épinglées sur un commit et les images de base sur leur empreinte, dépendances Python figées avec empreintes (`requirements/`, image du central comprise : chaque installation vérifie l'empreinte de chaque paquet, outils de construction et de régénération compris ; `tools/figer-dependances.sh` pour les régénérer), Dependabot pour tenir le tout à jour (une demande groupée par semaine), permissions des workflows en lecture seule par défaut (écriture accordée au seul job qui en a besoin), analyse de code CodeQL (Python, JavaScript, workflows).
- **Miroir des empreintes hors GitHub** ([#5](https://github.com/Jezu-CI/AUSPEX/issues/5)) : à la publication de chaque version, `SHA256SUMS` et sa signature, vérifiés au préalable, sont copiés dans [codeberg.org/Jezu_CI/AUSPEX-empreintes](https://codeberg.org/Jezu_CI/AUSPEX-empreintes) (un dossier par version, jamais modifié ensuite), puis relus et comparés. `tools/verifier-version.sh DOSSIER vX.Y.Z` compare en plus avec ce miroir, pour recouper si le compte GitHub du projet était compromis.
- **Référencement du site** (moteurs de recherche et moteurs de réponse IA) : description précise et titre explicite pour chaque page, aperçus de partage (Open Graph, cartes sociales) avec l'image du projet, données structurées schema.org (logiciel, auteur, site, questions fréquentes), page **Questions fréquentes**, page **À propos**, résumé **en anglais** (liens hreflang), fichier `llms.txt` pour les assistants IA, images chargées à la demande.
- **Site respectueux de la vie privée** : aucun cookie, aucune mesure d'audience, aucune ressource tierce (polices du système au lieu de Google Fonts, schémas pré-rendus en images au lieu d'un script externe, plus d'appel à l'API GitHub depuis le navigateur) ; la publication du site échoue si une page charge une ressource depuis un autre domaine. Pages **Mentions légales** et **Confidentialité**, liées en pied de page.
- **Vidéo de démonstration** de deux minutes sur l'accueil du site, filmée automatiquement par la CI sur un vrai central (workflow à la demande), hébergée sur le site sans service tiers.
- **Guide utilisateur** (13 pages en langage simple) intégré au site, et **choix du public** dès l'accueil : « utiliser Auspex » ou « la technique » ; les pages techniques renvoient vers le guide utilisateur.


### Limites connues

- Règles toujours étalonnées sur des captures publiques : captures de terrain
  reportées en v0.3 ([#3](https://github.com/Jezu-CI/AUSPEX/issues/3)).


## [0.1.0] « Silence Before Dawn » — 2026-11-02

Première version publiable : central complet, capteur, appliance et
intégration NetBox, prouvés à chaque modification sur le vrai produit
(voir [docs/06-preuves-ci.md](https://github.com/Jezu-CI/AUSPEX/blob/main/docs/06-preuves-ci.md)).

### Analyse et conformité
- Lecture des logs Zeek (JSON, TSV, gzip), agrégation en flux, registre
  d'ingestion (aucun double comptage, rotation et copie gérées).
- Conformité des flux aux règles déclarées (CSV / XLSX) : nouveau flux non
  déclaré, flux non déclaré persistant, règle expirée encore utilisée, règle
  jamais utilisée ; violations d'architecture : administration depuis un tier
  moins sensible, flux IT vers OT sans DMZ industrielle.
- Références réglementaires sur chaque écart (NIS2 2024/2690, IEC 62443,
  ISO 27001, ANSSI), identifiants d'alerte stables.
- Alertes SIEM : syslog RFC 5424 (UDP, TCP, TLS vérifié) en CEF ou JSON,
  webhook HTTPS, fichier JSONL ; file d'attente sur disque.

### Identification passive
- Moteur de votes explicable (règles en données, OU bruité, confiance,
  indices), conditions numériques et règles d'agrégat.
- 102 règles IT et OT confrontées à 24 captures industrielles publiques et
  au lab 4SICS 2015 (66 identifications attendues, faux positifs compris) :
  S7comm / S7comm-plus (automate, IHM, station d'ingénierie), Modbus, DNP3,
  EtherNet/IP-CIP, BACnet (fabricant, modèle, firmware, routeurs), IEC 104,
  Omron FINS, HART-IP, Niagara ; bannières et certificats d'équipements
  (Moxa, Hirschmann, RUGGEDCOM, Digi, Siemens, Schneider), sysDescr SNMP,
  User-Agent, en-têtes Server, noms NTLM / DHCP ; balayages signalés.

### Capteur et appliance
- Image du capteur : Zeek, parsers ICSNPP (EtherNet/IP, S7comm, Modbus, DNP3,
  BACnet, OPC UA, FINS, HART-IP, GE-SRTP, PROFINET). JA4+ n'est pas embarqué :
  sa licence (FoxIO License 1.1) interdit l'usage monétisé sans licence OEM.
- Envoi au central par SSH + rsync (empreinte du central épinglée, écriture
  seule, une clé par capteur, révocation au cycle suivant).
- Appliance ISO (Debian 12) : système en lecture seule, interface d'écoute
  muette (aucune trame émise, prouvé en VM), aucun compte, configuration par
  clé USB `AUSPEX-CONF`.
- Mises à jour signées de l'analyse (Ed25519, A/B, essai et retour
  automatique, jamais de retour en arrière imposé).

### Central et NetBox
- Installation en une commande (docker compose), mise à jour avec retour
  arrière automatique (base NetBox comprise), sauvegardes vérifiées.
- Compte de service Librarian aux droits minimaux ; inventaire observé à côté
  du déclaré, écarts d'inventaire (inconnu, silencieux, divergent, incomplet).
- `auspex plan` / `apply`, modules communautaires verrouillés et vérifiés.
- Plugin NetBox : restriction par adresse source (trusted hosts), double
  authentification (TOTP, e-mail, clé de sécurité WebAuthn), LDAPS, OIDC,
  SAML, carte à puce (front HTTPS, port dédié), tableau de bord, carte
  interactive, page des écarts.
- Exports d'audit signés par référentiel (NIS2, DORA, IEC 62443, ISO 27001,
  ANSSI), vérifiables sans Auspex.

### Documentation
- Guide d'utilisation ([README](https://github.com/Jezu-CI/AUSPEX/blob/main/README.md)) et documentation technique
  ([docs/](https://github.com/Jezu-CI/AUSPEX/blob/main/docs/README.md)).

### Limites connues
- Règles étalonnées sur des captures publiques : à compléter par des captures
  de terrain ; pas d'empreintes TLS (JA4) en v0.1.
- Un capteur compromis peut déposer de faux logs dans son propre dossier.
- Signature des mises à jour du capteur = clé de l'organisation (pas encore
  de signature des versions du projet).
