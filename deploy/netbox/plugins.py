# Configuration des plugins NetBox pour le central Auspex (chargée par l'image
# NetBox officielle depuis /etc/netbox/config/).
import os

PLUGINS = ["netbox_auspex"]

PLUGINS_CONFIG = {
    "netbox_auspex": {
        # auspex.yaml monté en lecture seule : section « access ».
        "config_path": os.environ.get("AUSPEX_CONFIG", "/etc/auspex/auspex.yaml"),
        # Réseau Docker interne du central : le seul d'où Librarian est accepté.
        "internal_subnet": os.environ.get("AUSPEX_INTERNAL_SUBNET"),
    },
}

# Méthode de connexion principale, d'après auspex.yaml (section auth). Le
# backend local reste toujours actif pour le brise-glace. Écrit dans la
# variable ET dans l'environnement : quel que soit l'ordre de lecture des
# fichiers de configuration de l'image, la valeur d'Auspex l'emporte.
try:
    from auspex.config import load_config as _load
    from auspex.netbox_auth import auth_backends as _auth_backends
    from auspex.netbox_auth import social_settings as _social_settings

    _access = _load(PLUGINS_CONFIG["netbox_auspex"]["config_path"]).access
    _backends = _auth_backends(_access)
    REMOTE_AUTH_BACKEND = _backends if len(_backends) > 1 else _backends[0]
    # Carte à puce : bouton sur la page de connexion, vers le port carte du front HTTPS.
    # NetBox ne recopie pas dans ses réglages les noms qu'il ne connaît pas (relevé en CI) :
    # l'adresse passe par la configuration du plugin, qui la publie au démarrage.
    if _access.card is not None:
        PLUGINS_CONFIG["netbox_auspex"]["carte_url"] = _access.card.address + "/plugins/auspex/carte-a-puce/"
    # OIDC : réglages SOCIAL_AUTH_* (secret du client lu dans l'environnement).
    globals().update(_social_settings(_access, os.environ))
except Exception:  # configuration invalide : comptes locaux seulement, le plugin verrouille
    REMOTE_AUTH_BACKEND = "netbox.authentication.RemoteUserBackend"
# L'image lit cette variable comme une liste séparée par des espaces.
os.environ["REMOTE_AUTH_BACKEND"] = (" ".join(REMOTE_AUTH_BACKEND) if isinstance(REMOTE_AUTH_BACKEND, list)
                                     else REMOTE_AUTH_BACKEND)

# Tableau de bord proposé aux nouveaux utilisateurs (chacun le réorganise
# ensuite à sa guise : ajout, retrait, déplacement, taille des widgets).
DEFAULT_DASHBOARD = [
    {"widget": "netbox_auspex.FindingsWidget", "width": 8, "height": 5, "title": "Auspex — Écarts ouverts",
     "config": {"max_items": 7}},
    {"widget": "netbox_auspex.ServiceWidget", "width": 4, "height": 3, "title": "Auspex — État du service"},
    {"widget": "netbox_auspex.InventoryWidget", "width": 4, "height": 4, "title": "Auspex — Inventaire observé"},
    {"widget": "netbox_auspex.ZoneMatrixWidget", "width": 8, "height": 4, "title": "Auspex — Matrice des zones"},
]
