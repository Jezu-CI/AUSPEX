# 10. Preuves automatisées

Chaque modification poussée sur le dépôt déclenche la CI
(`.github/workflows/ci.yml`). Au-delà des tests unitaires, elle **déploie et
attaque** le vrai produit : vrai Zeek, vrai NetBox, vrai annuaire, vrai
fournisseur d'identité, vrai navigateur, vraie machine virtuelle. Les scripts
de preuve sont dans `tools/ci_*.py` ; chacun affiche une ligne par
vérification et une synthèse `n/n vérifications réussies` (annotation
GitHub).

## Tâches

| Tâche | Ce qui est prouvé |
| --- | --- |
| Tests (Python 3.10 à 3.13) | tests unitaires et de bout en bout, dont les tests du plugin sous Django (harnais sans NetBox) |
| Scénario de démonstration | 7 jours de logs IT/OT simulés : les 4 écarts plantés sont trouvés, le trafic Active Directory normal ne déclenche rien ; règles d'identification livrées valides |
| SBOM | inventaire logiciel (CycloneDX) publié |
| Capteur (Zeek réel) | l'image construite lit une capture IT/OT réaliste (`tools/pcapgen.py`), réseau coupé, système en lecture seule ; les logs produits sont analysés |
| NetBox réel | synchronisation contre un vrai NetBox 4.4 : champs, créations, écarts d'inventaire, jetons v1 et v2 |
| Central | installation complète en docker compose, puis les preuves ci-dessous, puis mise à jour et retour arrière |
| Appliance | ISO construite, démarrée en VM (QEMU, KVM si disponible), trafic rejoué, captures des deux interfaces, mises à jour signées |

## Central : étapes de preuve

| Étape | Script | Vérifie notamment |
| --- | --- | --- |
| Installation en une commande, premier cycle | `install.sh` | santé, écarts détectés, inventaire écrit dans NetBox |
| Jeton public refusé | — | le jeton administrateur par défaut de l'image NetBox n'existe pas |
| Librarian | — | chaque interdiction (supprimer, toucher un équipement, créer un champ ou un jeton…), remise en ordre après élargissement manuel |
| Trusted hosts | `ci_trusted_hosts.py` | utilisateur refusé hors de ses adresses, usurpation par en-tête depuis un conteneur, verrouillage sur configuration invalide |
| MFA | `ci_mfa.py` | inscription, connexion, rejeu refusé, code de secours, verrouillage, réinitialisation ; même parcours par e-mail avec un vrai serveur de messagerie de test |
| LDAPS | `ci_ldap.py` | vrai OpenLDAP en LDAPS : connexion, groupe exigé, recopie des groupes, MFA, refus des comptes locaux, refus d'un certificat inconnu |
| OIDC | `ci_oidc.py` | vrai Keycloak en HTTPS : parcours navigateur complet, refus hors groupe, refus d'un certificat inconnu |
| SAML | `ci_saml.py` | même Keycloak : assertion modifiée (usurpation de l'administrateur) refusée, certificat différent des métadonnées refusé |
| Tableau de bord, carte | `ci_dashboard.py` | instantané du vrai service, widgets rendus, tableau par défaut, page des écarts, carte |
| Exports d'audit | `ci_audit.py` | export périodique du service, téléchargement par session, vérification **sans Auspex** (openssl, sha256sum) puis `audit verify`, altérations détectées, clé privée hors de portée de NetBox |
| Capteur → central | `ci_capteur.py` | vrai capteur, empreinte vérifiée ; attaques : faux central, clé inconnue, bonne clé depuis une mauvaise adresse, lecture des logs reçus par tous les chemins (seule la publication des mises à jour est servie), évasion du dossier, commande arbitraire, suppression, révocation |
| WebAuthn | `ci_webauthn.py` | Chromium + clé virtuelle CTAP2 sur le vrai NetBox : inscription, connexion par clé, compteur, seconde clé, refus sans clé, code de secours, révocation par `reset` |
| Carte à puce | `ci_carte.py` | PKI de test (openssl) à travers le vrai front : carte valide (session sans MFA), révoquée, autre autorité, sans carte, sans compte, au nom de l'administrateur ; en-têtes forgés directement sur NetBox et par le site principal ; journaux |
| Conteneur durci | — | compte non root, système de fichiers en lecture seule, logs des capteurs en lecture seule ; (étape Librarian) jeton administrateur absent du conteneur Auspex |
| Mise à jour (mêmes versions) | `update.sh` | sauvegarde, redémarrage, santé |
| Mise à jour ratée | `update.sh --auspex <inexistante>` | retour arrière automatique complet, base NetBox comprise |

## Appliance : étapes de preuve (`ci_appliance.py`)

1. Disque de données vide formaté au premier démarrage (et seulement lui).
2. Configuration et clé importées du support `AUSPEX-CONF`.
3. Pare-feu, réseau, analyse démarrés ; image d'usine de l'ISO active.
4. Trafic IT/OT rejoué sur l'écoute : logs reçus et analysés par le
   central, automate présent dans l'inventaire.
5. **Mises à jour signées** : manifeste falsifié refusé (rien d'installé) ;
   version suivante téléchargée, installée dans l'emplacement `a`, validée
   après l'essai ; version signée mais défaillante installée dans `b`,
   abandonnée, **retour automatique** sur `a`, jamais retentée ; état reçu
   par le central, logs toujours reçus après le retour arrière.
6. Captures des deux interfaces pendant tout l'essai : **aucune trame
   émise** sur l'écoute ; sur l'administration, rien d'autre que DHCP, ARP
   et le central.
7. Aucune invite de connexion sur la console série.

## Captures réelles

Workflow distinct (`.github/workflows/captures-reelles.yml`), à chaque
modification des règles, du moteur ou du capteur, et chaque semaine :

1. **Téléchargement vérifié** : 24 captures industrielles publiques et les
   logs Zeek d'origine du lab 4SICS 2015 (dépôt automayt/ICS-pcap, épinglé
   par commit, chaque fichier vérifié par SHA-256 ; `tools/captures-reelles.yaml`).
   Elles ne sont pas redistribuées dans le dépôt d'Auspex.
2. **Vrai capteur** : chaque capture est lue par l'image du capteur (Zeek 9
   + ICSNPP), réseau coupé, système en lecture seule.
3. **Relevé** : pour chaque capture, les logs produits, leurs champs et les
   valeurs observées (ce qui sert à écrire les règles, plutôt que de mémoire).
4. **Identifications attendues** (`tools/captures-reelles-attendus.yaml`) :
   ce que l'équipement dit de lui-même (sysDescr SNMP, certificat, I-Am
   BACnet, propriétés…), les rôles établis par le protocole, et les **faux
   positifs** corrigés à ne pas réintroduire (balayeurs pris pour des maîtres
   DNP3, adresses de diffusion prises pour des équipements). Un attendu
   manquant fait échouer la CI.

Protocoles couverts : S7comm, S7comm-plus, Modbus, DNP3, EtherNet/IP-CIP,
BACnet, IEC 60870-5-104, Omron FINS, HART-IP, Niagara Fox, SAIA S-Bus, plus le
trafic IT du lab 4SICS (HTTP, SSH, TLS, SNMP, DNS, NTLM).

## Lire un résultat

- Annotations de la page du run : `::notice` (synthèse par preuve),
  `::error` (vérification échouée, exception).
- Journaux complets de chaque tâche ; pour l'appliance, artefact
  `appliance-diagnostic` (console série, captures pcap) et
  `auspex-capteur-iso` (ISO et image de mise à jour, 7 jours).
