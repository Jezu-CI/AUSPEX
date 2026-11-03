# netbox-auspex

Plugin NetBox d'[Auspex](../README.md). Il est installé automatiquement dans
l'image NetBox du central (`deploy/netbox/Dockerfile`) et lit la section
`access` de `auspex.yaml`.

Fonctions :

- **restriction des connexions par IP source** (trusted hosts), appliquée
  avant toute action, à l'interface comme à l'API. Logique : `auspex.access` ;
- **double authentification TOTP** des comptes locaux et LDAPS (pages
  `/plugins/auspex/mfa/`, table `netbox_auspex_totpdevice`, commande
  `manage.py auspex_mfa`). Logique : `auspex.mfa`.

Les deux logiques sont testées sans NetBox ; le plugin les applique. Ses
propres tests (`tests/plugin/`) tournent sur un vrai Django.

Compatibilité : NetBox 4.4.
