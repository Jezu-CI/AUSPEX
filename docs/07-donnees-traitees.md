# Données traitées (RGPD)

Cette page s'adresse au délégué à la protection des données (DPO) et au
responsable de la sécurité de l'organisation qui installe Auspex. Elle décrit
chaque donnée collectée, sa finalité, son emplacement, sa durée de
conservation, et les moyens de la limiter ou de l'effacer. Elle sert de base à
la fiche du registre des traitements ; elle ne remplace pas l'analyse propre à
chaque organisation.

## Qui est responsable

Auspex est un logiciel installé et exploité par l'organisation, sur ses
propres machines. **L'organisation est responsable du traitement.** Le projet
Auspex ne reçoit aucune donnée : pas de télémétrie, pas de compte en ligne,
aucune connexion sortante hors celles que l'organisation configure (capteurs
vers le central, central vers NetBox, le SIEM et l'annuaire).

**Finalité** : sécurité du système d'information. Inventaire des équipements
présents sur le réseau, contrôle de la segmentation (flux autorisés entre
zones), détection d'écarts et preuves d'audit (NIS2, DORA, IEC 62443). Base
légale à déterminer par l'organisation (obligation légale pour une entité
soumise à NIS2 ou DORA, intérêt légitime sinon).

**Personnes concernées** : les données décrivent d'abord des **équipements**.
Elles deviennent personnelles lorsqu'un équipement est rattaché à une
personne (poste de travail, téléphone, nom de machine portant un nom), et pour
les comptes des utilisateurs d'Auspex.

## Ce qu'Auspex ne collecte jamais

- Le **contenu** des échanges : ni fichiers, ni courriels, ni pages web, ni
  captures de paquets. Le capteur n'enregistre que des métadonnées (Zeek).
- Les **mots de passe** circulant sur le réseau.
- Aucune donnée n'est demandée aux équipements surveillés : le capteur
  n'émet rien.

## Données, finalité et conservation

| Donnée | Exemple | Finalité | Où | Conservation |
| --- | --- | --- | --- | --- |
| **Journaux bruts Zeek** (métadonnées de trafic) | voir ci-dessous | matière première de l'analyse | capteur, puis central (`logs/`) | **48 h** sur le capteur (`AUSPEX_SENSOR_RETENTION_HOURS`), **30 jours** sur le central (`AUSPEX_LOGS_RETENTION_DAYS`) |
| Fiche d'actif | adresse IP, adresses MAC, noms de machine (DHCP, NTLM), système, fabricant, modèle, firmware, rôle, première et dernière apparition | inventaire | central (`state/assets.json`), NetBox | **180 jours** après la dernière apparition (`retention_days`) ; dans NetBox, jusqu'à suppression par un administrateur |
| Flux | adresse source et destination, protocole, port, dates, volumes | contrôle de la segmentation | central (`state/flows.json`) | **180 jours** après le dernier échange (`retention_days`) |
| Écarts et alertes | flux non autorisé entre deux adresses, date | détection | central (`state/alerts.json`), SIEM | ouverts : tant qu'ils durent ; résolus : **180 jours** (`retention_days`) ; dans le SIEM : politique du SIEM |
| Exports d'audit signés | inventaire, flux et écarts de la période | preuve de conformité | central (`state/audits/`) | les **24** derniers par référentiel (`audit.conserver`) ; copies remises aux auditeurs : politique de l'organisation |
| Comptes des utilisateurs d'Auspex | identifiant, nom, adresse e-mail (MFA par e-mail, SSO), groupes | contrôle d'accès | NetBox (base PostgreSQL) | durée du compte |
| Facteurs d'authentification | secret TOTP, clés de sécurité (clé publique), empreintes des codes de secours | double authentification | NetBox | durée du compte ; jamais de code ni de mot de passe en clair |
| Journaux de connexion | identifiant, adresse IP du poste, événement (connexion, MFA, échec) | traçabilité, détection d'intrusion | journaux des conteneurs, SIEM si configuré | rotation : **5 fichiers de 10 Mo** par service ; dans le SIEM : politique du SIEM |
| Sauvegardes | copie de l'état et de la configuration | reprise après incident | emplacement choisi par l'exploitant | politique de l'organisation |

Toutes les durées signalées par un nom de paramètre sont réglables
([Référence de configuration](05-configuration.md)). Une durée plus courte
réduit d'autant l'historique (un flux « persistant » se juge sur plusieurs
jours).

### Contenu des journaux bruts Zeek

Le capteur écrit les journaux standards de Zeek et ceux des protocoles
industriels. Auspex n'en exploite qu'une partie (connexions, DHCP, NTLM,
HTTP, SSH, TLS, SNMP et protocoles industriels), mais les journaux bruts
contiennent davantage, dont des données personnelles possibles :

- noms de domaine demandés (`dns.log`), hôtes, adresses web et navigateurs
  (`http.log`), noms de serveurs TLS et certificats (`ssl.log`, `x509.log`) ;
- noms d'utilisateur transmis en clair ou dans les en-têtes de protocoles
  (`ntlm.log`, `kerberos.log`, `ftp.log`, `rdp.log`) ;
- expéditeurs, destinataires et objets des courriels non chiffrés
  (`smtp.log`), noms de fichiers échangés (`files.log`, `smb_files.log`).

Ces journaux ne quittent pas l'infrastructure de l'organisation, restent
**48 heures** sur le capteur et **30 jours** sur le central, et ne sont lus
que par Auspex. Réduire leur contenu aux seuls journaux exploités est prévu
pour la v0.3 ([#38](https://github.com/Jezu-CI/AUSPEX/issues/38)).

## Effacer un actif sur demande

Pour un équipement retiré, ou à la demande d'une personne :

```bash
docker compose exec auspex auspex oublier 10.2.1.13            # simulation : ce qui serait effacé
docker compose exec auspex auspex oublier 10.2.1.13 --apply    # effacement
```

La commande retire l'adresse de la fiche d'actif, des flux, des écarts et
alertes, des alertes en attente d'envoi au SIEM, du tableau de bord et de la
carte. Elle attend la fin d'un cycle d'analyse en cours. Elle indique ensuite
ce qu'elle ne peut pas modifier :

- **NetBox** : le compte de service d'Auspex n'a aucun droit de suppression.
  Supprimer l'adresse IP avec un compte administrateur (IPAM → Adresses IP).
- **Alertes déjà livrées** (SIEM, webhook, fichier de sortie) : à effacer dans
  ces outils.
- **Exports d'audit signés et sauvegardes** : preuves scellées ; leur durée de
  conservation est celle de la politique d'archivage de l'organisation.
- **Journaux bruts** : effacés automatiquement au terme de leur durée de
  conservation.

Un équipement encore actif sur le réseau réapparaît au cycle suivant :
l'effacement vaut pour un équipement retiré, ou pour corriger une donnée.

## Sécurité des données

Chiffrement des échanges (capteurs vers central en SSH, interface en HTTPS,
SIEM en TLS vérifié), double authentification obligatoire, comptes et droits
minimaux, exports signés. Détail : [Sécurité](../SECURITY.md) et
[Authentification et accès](01-authentification.md).
