# Politique de sécurité

Ce projet manipule une carte détaillée des systèmes d'information de ses
utilisateurs. Les vulnérabilités sont traitées en priorité.

## Signaler une vulnérabilité

Ne pas ouvrir d'issue publique. Utiliser le signalement privé de GitHub
(onglet **Security → Report a vulnerability**) en indiquant :

- la version concernée ;
- le composant (capteur, central, plugin NetBox, module) ;
- un scénario de reproduction ;
- l'impact estimé.

Délais visés : accusé de réception sous 3 jours ouvrés, évaluation sous
10 jours, correctif selon la gravité. La divulgation est coordonnée avec la
personne qui signale.

## Versions maintenues

Seule la dernière version mineure reçoit des correctifs de sécurité tant que
le projet est en 0.x.

## Engagements de conception

- Les capteurs n'émettent aucun paquet sur les réseaux surveillés.
- Aucun identifiant d'accès aux actifs n'est demandé ni stocké.
- Les connexions partent toujours du capteur vers le central, et du central vers le SIEM.
- Aucun secret dans `auspex.yaml` : la validation refuse un champ `token`.
- Les sorties TLS vérifient toujours le certificat du destinataire.
- Auspex écrit dans NetBox avec le compte de service « Librarian » : lecture,
  création d'adresses IP marquées, enrichissement d'adresses IP, et rien
  d'autre (aucune suppression, aucune administration). Le jeton administrateur
  n'est jamais transmis au service.
- Toute connexion authentifiée à NetBox est filtrée par adresse source
  (trusted hosts). Le serveur web de l'image NetBox d'origine remplace
  l'adresse de connexion par l'en-tête `X-Forwarded-For` reçu des réseaux
  privés, ce qui permettrait d'usurper l'adresse d'un poste autorisé : le
  central supprime ce comportement, et seul un proxy déclaré peut fournir
  cet en-tête. Configuration invalide = verrouillage, jamais ouverture.
- Double authentification (TOTP) obligatoire pour toute connexion à
  l'interface hors fournisseur d'identité, sans option pour la désactiver.
  Mécanisme d'authentification inconnu = MFA exigée. Anti-rejeu, verrouillage
  progressif, codes de secours conservés uniquement sous forme d'empreinte.
  Limite connue : la première inscription se fait après le mot de passe seul
  (comme tout TOTP) ; elle est journalisée, et une fois inscrit, un compte ne
  peut changer d'appareil que par une réinitialisation administrateur.
- MFA par e-mail (option) : codes de 8 chiffres à usage unique, conservés
  sous forme d'empreinte, valables 10 minutes, 5 essais par code, envois
  limités par utilisateur ; certificat SMTP vérifié (TLS 1.2 minimum) ; jamais
  pour le brise-glace. Facteur plus faible que TOTP : à réserver aux équipes
  qui ne peuvent pas utiliser d'application.
- Annuaire (LDAPS) : jamais de mot de passe en clair sur le réseau (ldap://
  sans StartTLS refusé), certificat toujours vérifié (aucune option pour le
  désactiver), TLS 1.2 minimum. Avec une méthode principale, les comptes
  locaux autres que le brise-glace sont refusés.
- Connexion unique (OIDC) : fournisseur en HTTPS, certificat toujours vérifié,
  secret hors de auspex.yaml, refus hors du groupe exigé avant toute création
  de compte, aucun rattachement de compte par l'adresse e-mail, droits
  d'administration uniquement par un groupe désigné.
- Connexion unique (SAML) : assertions signées obligatoires, vérifiées avec le
  certificat des métadonnées du fournisseur, algorithmes obsolètes refusés,
  métadonnées sans DTD ni entités, mêmes règles de groupes que l'OIDC.
- Clé de sécurité (WebAuthn) : implémentation vérifiée par la CI avec un vrai
  navigateur ; origine et domaine exacts, défi à usage unique (5 minutes),
  présence de l'utilisateur exigée, clé clonée détectée (compteur), seule la
  clé publique conservée.
- Carte à puce : la chaîne, la révocation et la possession de la carte sont
  vérifiées par le front HTTPS, sur un port dédié ; NetBox ne croit que le
  front (secret partagé, en-têtes effacés sur le site principal) ;
  administrateur local et brise-glace jamais par carte.
- La clé privée HTTPS n'est lisible que par le front (hors du répertoire de
  configuration lu par NetBox) ; les clés de signature (audits, mises à jour
  des capteurs) ne sont lisibles que par le service Auspex.
- Exports d'audit signés (Ed25519), chaînés, vérifiables sans Auspex.
- Appliance capteur : aucun compte ni serveur SSH, système en lecture seule,
  interface d'écoute muette par pare-feu, configuration jamais exécutée.
  Mises à jour de l'analyse signées par l'organisation, revérifiées à chaque
  démarrage, sans retour en arrière imposé, abandonnées automatiquement en
  cas d'échec.
- Versions publiées signées (Sigstore, sans clé) avec provenance SLSA ; la
  liste d'empreintes et sa signature sont aussi copiées, à chaque
  publication, dans un miroir hors GitHub
  ([codeberg.org/Jezu_CI/AUSPEX-empreintes](https://codeberg.org/Jezu_CI/AUSPEX-empreintes)),
  jamais modifié ensuite, pour recouper si le compte GitHub du projet était
  compromis. Mode d'emploi : [Télécharger → Vérifier](https://jezu-ci.github.io/AUSPEX/telecharger/#v%C3%A9rifier-un-fichier-t%C3%A9l%C3%A9charg%C3%A9).

## Limites connues

- **Capteur compromis** : il peut déposer de faux logs dans son propre
  dossier (et remplir le disque du central). Atténuation : une clé par
  capteur, révocable seule, adresse d'origine contrôlée, dossier cloisonné,
  purge à 30 jours.
- **Clé de confiance des mises à jour** stockée sur le disque de données du
  capteur : un accès physique permet de la remplacer avec l'image.
- **Signature des mises à jour = signature de l'organisation**, pas du
  projet : vérifier l'empreinte de l'image publiée par le projet avant de
  la publier sur le central.
- **Code MFA par e-mail** : moins robuste qu'une application ou une clé
  (qui lit la messagerie passe la MFA) ; jamais proposé au brise-glace.
- **LCR des cartes à puce** : elle doit être tenue à jour ; périmée, toutes
  les cartes sont refusées (préféré à l'acceptation de cartes révoquées).
- **Secrets TOTP en base** : la sauvegarde de la base NetBox est sensible.
- **Intra-zone** : par défaut, seuls les flux **entre** zones sont comparés
  aux règles (`check_intra_zone: true` pour aller plus loin).
