# Journal des versions

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) ;
versions selon [SemVer](https://semver.org/lang/fr/). Liens absolus : ces notes
sont reprises telles quelles sur la page de chaque version GitHub.

## [0.2.0] — en préparation

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

### Ajouté

- **Versions signées** ([#1](https://github.com/Jezu-CI/AUSPEX/issues/1)) : signature Sigstore sans clé de `SHA256SUMS` (identité du workflow de publication, journal public Rekor) et attestation de provenance SLSA de chaque fichier. Vérification en une commande (`tools/verifier-version.sh`, ou `cosign verify-blob` et `gh attestation verify`), éprouvée à chaque publication, contre-épreuves comprises (fichier, empreintes ou provenance altérés refusés).
- **Alerte SIEM « Balayage du réseau »** ([#2](https://github.com/Jezu-CI/AUSPEX/issues/2)) : une machine qui tente de joindre au moins 100 cibles (adresse et port) refusées ou sans réponse en 24 h déclenche une alerte, une seule par machine, résolue d'elle-même quand le balayage cesse. Gravité élevée, critique si le tier 0 ou l'atelier est visé ; seuil, fenêtre, gravité et scanners autorisés réglables (`alerts.scan`). Rattachée aux contrôles de surveillance des exports d'audit (NIS2 §3.2, IEC 62443 SR 6.2, ISO 27001 A.8.16). Prouvée avec le vrai Zeek sur une capture de balayage, et dans le scénario de démonstration.
- **OpenSSF Scorecard** ([#4](https://github.com/Jezu-CI/AUSPEX/issues/4)) : bonnes pratiques de sécurité du dépôt mesurées chaque semaine et à chaque modification, résultats publiés (badge du README) et dans l'onglet Security. Dans la foulée : toutes les actions GitHub épinglées sur un commit et les images de base sur leur empreinte, dépendances Python figées avec empreintes (`requirements/`, image du central comprise : chaque installation vérifie l'empreinte de chaque paquet, outils de construction et de régénération compris ; `tools/figer-dependances.sh` pour les régénérer), Dependabot pour tenir le tout à jour (une demande groupée par semaine), permissions des workflows en lecture seule par défaut (écriture accordée au seul job qui en a besoin), analyse de code CodeQL (Python, JavaScript, workflows).
- **Miroir des empreintes hors GitHub** ([#5](https://github.com/Jezu-CI/AUSPEX/issues/5)) : à la publication de chaque version, `SHA256SUMS` et sa signature, vérifiés au préalable, sont copiés dans [codeberg.org/Jezu_CI/AUSPEX-empreintes](https://codeberg.org/Jezu_CI/AUSPEX-empreintes) (un dossier par version, jamais modifié ensuite), puis relus et comparés. `tools/verifier-version.sh DOSSIER vX.Y.Z` compare en plus avec ce miroir, pour recouper si le compte GitHub du projet était compromis.
- **Référencement du site** (moteurs de recherche et moteurs de réponse IA) : description précise et titre explicite pour chaque page, aperçus de partage (Open Graph, cartes sociales) avec l'image du projet, données structurées schema.org (logiciel, auteur, site, questions fréquentes), page **Questions fréquentes**, page **À propos**, résumé **en anglais** (liens hreflang), fichier `llms.txt` pour les assistants IA, images chargées à la demande.
- **Site respectueux de la vie privée** : aucun cookie, aucune mesure d'audience, aucune ressource tierce (polices du système au lieu de Google Fonts, schémas pré-rendus en images au lieu d'un script externe, plus d'appel à l'API GitHub depuis le navigateur) ; la publication du site échoue si une page charge une ressource depuis un autre domaine. Pages **Mentions légales** et **Confidentialité**, liées en pied de page.
- **Guide utilisateur** (13 pages en langage simple) intégré au site, et **choix du public** dès l'accueil : « utiliser Auspex » ou « la technique » ; les pages techniques renvoient vers le guide utilisateur.


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
