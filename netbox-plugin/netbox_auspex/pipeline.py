"""Étapes Auspex de la chaîne de connexion SSO (OIDC ou SAML) de NetBox.

- require_group : refuse, AVANT toute création de compte, quiconque n'est pas
  dans le groupe exigé (auth.oidc / auth.saml : require_group).
- sync_groups : recopie les groupes envoyés par le fournisseur dans NetBox
  (droits et règles trusted hosts par groupe) ; administrateur NetBox si
  membre de superuser_group, et seulement dans ce cas.
"""

from __future__ import annotations

import json
import logging

logger = logging.getLogger("netbox_auspex")

try:
    from social_core.exceptions import AuthForbidden
except ImportError:  # pragma: no cover
    from django.core.exceptions import PermissionDenied as AuthForbidden


def _oidc():
    """Fournisseur actif (OIDC ou SAML) : groups_claim, require_group, superuser_group."""
    from auspex.netbox_auth import sso_config

    from .mfa import _access
    return sso_config(_access())


def claims(backend, response) -> dict:
    """OIDC : champs du jeton d'identité + réponse du fournisseur.
    SAML : attributs de l'assertion (response["attributes"])."""
    out = {}
    id_token = getattr(backend, "id_token", None)
    if isinstance(id_token, dict):
        out.update(id_token)
    if isinstance(response, dict):
        out.update(response)
        if isinstance(response.get("attributes"), dict):
            out.update(response["attributes"])
    return out


def groups_of(backend, response, claim: str) -> list[str]:
    value = claims(backend, response).get(claim) or []
    if isinstance(value, str):
        value = [value]
    # Chemins Keycloak (/groupe/sous-groupe) : on garde le dernier élément.
    return sorted({str(g).rstrip("/").rsplit("/", 1)[-1] for g in value if str(g).strip("/")})


def require_group(backend, details=None, response=None, *args, **kwargs):
    cfg = _oidc()
    if cfg is None:
        # Configuration illisible : aucune connexion SSO (le plugin verrouille déjà).
        raise AuthForbidden(backend)
    if cfg.require_group and cfg.require_group not in groups_of(backend, response, cfg.groups_claim):
        logger.warning(json.dumps({"event": "auspex_sso_refused", "user": (details or {}).get("username"),
                                   "reason": "hors du groupe exigé"}, ensure_ascii=False))
        raise AuthForbidden(backend)


def sync_groups(backend, user=None, response=None, *args, **kwargs):
    cfg = _oidc()
    if cfg is None or user is None:
        return
    names = groups_of(backend, response, cfg.groups_claim)
    Group = user.groups.model
    user.groups.set([Group.objects.get_or_create(name=n)[0] for n in names])
    superuser = bool(cfg.superuser_group) and cfg.superuser_group in names
    if user.is_superuser != superuser:
        user.is_superuser = superuser
        user.save(update_fields=["is_superuser"])
    logger.info(json.dumps({"event": "auspex_sso_login", "user": user.get_username(), "groups": names,
                            "superuser": superuser}, ensure_ascii=False))
