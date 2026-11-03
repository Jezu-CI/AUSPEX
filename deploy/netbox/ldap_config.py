# Configuration LDAP de NetBox, produite à partir de la section auth.ldaps
# d'auspex.yaml (et non de variables d'environnement). NetBox lit ce module
# quand l'annuaire est la méthode de connexion principale.
#
# Sécurité : certificat du serveur toujours vérifié (TLS 1.2 minimum), aucun
# moyen de le désactiver ; mot de passe du compte de lecture dans
# AUSPEX_LDAP_BIND_PASSWORD (fichier .env), jamais dans auspex.yaml.
import json
import logging
import os

_logger = logging.getLogger("netbox_auspex")
_plan = None
try:
    from auspex.config import load_config
    from auspex.netbox_auth import ldap_plan

    _plan = ldap_plan(load_config(os.environ.get("AUSPEX_CONFIG", "/etc/auspex/auspex.yaml")).access)
except Exception as _exc:  # configuration invalide : pas d'annuaire (le plugin verrouille l'accès)
    _logger.error(json.dumps({"event": "auspex_ldap_config_error", "error": str(_exc)}, ensure_ascii=False))

if _plan:
    import ldap
    from django_auth_ldap import config as _dal

    AUTH_LDAP_SERVER_URI = _plan["server_uri"]
    AUTH_LDAP_START_TLS = _plan["start_tls"]
    AUTH_LDAP_BIND_DN = _plan["bind_dn"]
    AUTH_LDAP_BIND_PASSWORD = os.environ.get(_plan["bind_password_env"], "")
    _options = {
        ldap.OPT_REFERRALS: 0,                               # Active Directory
        ldap.OPT_NETWORK_TIMEOUT: 10,
        ldap.OPT_X_TLS_REQUIRE_CERT: ldap.OPT_X_TLS_DEMAND,  # certificat exigé et vérifié
    }
    if hasattr(ldap, "OPT_X_TLS_PROTOCOL_TLS1_2"):  # selon la version de python-ldap
        _options[ldap.OPT_X_TLS_PROTOCOL_MIN] = ldap.OPT_X_TLS_PROTOCOL_TLS1_2
    if _plan["ca_file"]:
        _options[ldap.OPT_X_TLS_CACERTFILE] = _plan["ca_file"]
        LDAP_CA_CERT_FILE = _plan["ca_file"]
    _options[ldap.OPT_X_TLS_NEWCTX] = 0  # en dernier : applique les options TLS ci-dessus
    AUTH_LDAP_CONNECTION_OPTIONS = _options

    _base, _filter = _plan["user_search"]
    AUTH_LDAP_USER_SEARCH = _dal.LDAPSearch(_base, ldap.SCOPE_SUBTREE, _filter)
    AUTH_LDAP_USER_ATTR_MAP = _plan["user_attr_map"]
    AUTH_LDAP_ALWAYS_UPDATE_USER = True
    if _plan["group_search"]:
        _gbase, _gfilter = _plan["group_search"]
        AUTH_LDAP_GROUP_SEARCH = _dal.LDAPSearch(_gbase, ldap.SCOPE_SUBTREE, _gfilter)
        AUTH_LDAP_GROUP_TYPE = getattr(_dal, _plan["group_type"])()
        AUTH_LDAP_MIRROR_GROUPS = True      # groupes visibles dans NetBox (droits, trusted hosts)
        AUTH_LDAP_FIND_GROUP_PERMS = True
        AUTH_LDAP_CACHE_TIMEOUT = 3600
    if _plan["require_group"]:
        AUTH_LDAP_REQUIRE_GROUP = _plan["require_group"]
    if _plan["superuser_group"]:
        AUTH_LDAP_USER_FLAGS_BY_GROUP = {"is_superuser": _plan["superuser_group"]}
