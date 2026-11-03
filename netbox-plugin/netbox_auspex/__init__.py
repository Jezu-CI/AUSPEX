"""Plugin NetBox d'Auspex.

- Restriction des connexions par IP source (« trusted hosts »), appliquée à
  chaque requête authentifiée, AVANT toute action, qu'elle vienne de
  l'interface (session) ou de l'API (jeton). Décision : auspex.access.
- Double authentification (TOTP) des connexions qui ne passent pas par un
  fournisseur d'identité : comptes locaux (dont le brise-glace) et LDAPS.
  Logique : auspex.mfa.
- Tableau de bord : widgets (écarts, état du service, inventaire, matrice des
  zones) et page « Écarts de conformité », à partir de l'instantané écrit par
  le service Auspex.

Les deux cœurs sont testés indépendamment de NetBox.
"""

import logging
import sys

from netbox.plugins import PluginConfig


class AuspexConfig(PluginConfig):
    name = "netbox_auspex"
    verbose_name = "Auspex"
    description = "CMDB passive IT/OT : restriction par IP source, double authentification"
    version = "0.1.0"
    author = "Yann Mathon"
    base_url = "auspex"
    min_version = "4.4.0"
    max_version = "4.4.99"
    default_auto_field = "django.db.models.BigAutoField"
    # Ordre : l'adresse source d'abord (refus immédiat), puis la MFA.
    middleware = ["netbox_auspex.middleware.TrustedHostsMiddleware",
                  "netbox_auspex.mfa.MFARequiredMiddleware"]
    default_settings = {
        "config_path": "/etc/auspex/auspex.yaml",
        "internal_subnet": None,
        "email_backend": "netbox_auspex.mfa.VerifiedSMTPBackend",
        # Instantané du tableau de bord écrit par le service Auspex (lecture seule)
        "dashboard_path": "/var/lib/auspex-tableau/dashboard.json",
        # Adresse du port carte du front (auth.carte) : bouton de la page de connexion
        "carte_url": None,
    }

    def ready(self):
        super().ready()
        # Widgets du tableau de bord : enregistrés à l'import du module.
        from . import widgets  # noqa: F401
        # Bouton « Connexion par carte à puce » (gabarit login.html : settings.AUSPEX_CARTE_URL).
        # NetBox ne recopie pas les réglages inconnus de configuration.py : publié ici.
        from django.conf import settings
        try:
            from netbox.plugins.utils import get_plugin_config
        except ImportError:  # pragma: no cover - selon la version de NetBox
            from extras.plugins.utils import get_plugin_config
        settings.AUSPEX_CARTE_URL = get_plugin_config("netbox_auspex", "carte_url") or ""
        # Événements de sécurité (JSON) sur la sortie d'erreur du conteneur,
        # donc dans `docker compose logs` et vers le SIEM. Sans cela, les
        # événements de niveau INFO (connexions réussies) seraient perdus.
        logger = logging.getLogger("netbox_auspex")
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(logging.Formatter("%(message)s"))
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.propagate = False


config = AuspexConfig
