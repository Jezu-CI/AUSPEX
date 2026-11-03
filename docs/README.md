# Documentation d'Auspex

Le [README](../README.md) explique **comment installer et utiliser** Auspex.
Ces pages détaillent ce dont ont besoin les équipes qui le déploient,
l'exploitent ou l'auditent : accès et authentification, capteurs, exports
d'audit, exploitation courante, configuration complète, et ce que la CI
prouve à chaque modification.

| Page | Contenu |
| --- | --- |
| [1. Authentification et accès](01-authentification.md) | trusted hosts, MFA (TOTP, e-mail, WebAuthn), LDAPS, OIDC, SAML, carte à puce, brise-glace |
| [2. Capteurs](02-capteur.md) | image d'analyse, envoi au central, appliance ISO, mises à jour signées A/B |
| [3. Exports d'audit](03-audits.md) | contenu, format, signature, chaînage, vérification sans Auspex |
| [4. Exploitation](04-exploitation.md) | installation, mise à jour et retour arrière, sauvegardes, santé, journaux, dépannage |
| [5. Référence de configuration](05-configuration.md) | `auspex.yaml`, `.env`, `capteur.conf` : chaque clé, sorties SIEM |
| [6. Preuves automatisées](06-preuves-ci.md) | ce que la CI vérifie à chaque modification, et comment |

Engagements et limites de sécurité : [SECURITY.md](../SECURITY.md).

Conventions : les noms de fichiers sont relatifs au dossier `deploy/` du
central sauf mention contraire ; « le service » désigne le conteneur
`auspex` (analyse en continu) ; « NetBox » désigne le conteneur `netbox` et
son plugin `netbox_auspex`.
