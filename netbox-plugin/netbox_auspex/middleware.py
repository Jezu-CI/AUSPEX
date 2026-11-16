"""Middleware « trusted hosts » : refuse une requête authentifiée qui ne vient
pas d'une adresse autorisée pour son utilisateur.

- Session de l'interface : l'utilisateur est connu ici ; en cas de refus, la
  session est fermée.
- Jeton d'API : NetBox n'identifie l'utilisateur qu'au moment de traiter la
  requête, trop tard pour une écriture. Le jeton est donc identifié ici, avant
  toute action. Si cette identification échoue de façon inattendue, la
  requête est refusée (on ne laisse jamais passer faute de savoir).
- auspex.yaml est relu dès qu'il change. Illisible ou invalide : verrouillage,
  seul l'administrateur local reste accepté (depuis la machine du central).
"""

from __future__ import annotations

import json
import logging
import os
import threading

from django.contrib.auth import logout
from django.http import HttpResponseForbidden, JsonResponse

from auspex.access import AccessPolicy
from auspex.config import ConfigError, load_config

try:
    from netbox.plugins.utils import get_plugin_config
except ImportError:  # pragma: no cover - selon la version de NetBox
    from extras.plugins.utils import get_plugin_config

logger = logging.getLogger("netbox_auspex")


class _PolicyCache:
    """Politique d'accès, relue quand auspex.yaml change."""

    def __init__(self):
        self.lock = threading.Lock()
        self.stamp = None
        self.policy: AccessPolicy | None = None

    def get(self) -> AccessPolicy:
        path = get_plugin_config("netbox_auspex", "config_path")
        subnet = get_plugin_config("netbox_auspex", "internal_subnet")
        try:
            st = os.stat(path)
            stamp = (st.st_mtime_ns, st.st_size)
        except OSError:
            stamp = None
        with self.lock:
            if self.policy is not None and stamp == self.stamp:
                return self.policy
            try:
                if stamp is None:
                    raise ConfigError([f"{path} : fichier introuvable"])
                self.policy = AccessPolicy(load_config(path).access, subnet,
                                           front_proxy=os.environ.get("AUSPEX_FRONT_IP") or None)
                logger.info(json.dumps({"event": "auspex_access_policy_loaded", "path": path}))
            except ConfigError as exc:
                self.policy = AccessPolicy(None, subnet, front_proxy=os.environ.get("AUSPEX_FRONT_IP") or None)
                logger.error(json.dumps({"event": "auspex_access_lockdown", "path": path,
                                         "problems": exc.problems}, ensure_ascii=False))
            except Exception as exc:  # configuration illisible : on verrouille
                self.policy = AccessPolicy(None, subnet, front_proxy=os.environ.get("AUSPEX_FRONT_IP") or None)
                logger.error(json.dumps({"event": "auspex_access_lockdown", "path": path,
                                         "error": str(exc)}, ensure_ascii=False))
            self.stamp = stamp
            return self.policy


_cache = _PolicyCache()


class _Unidentified(Exception):
    pass


class _UnknownToken(Exception):
    pass


def _token_user(header: str):
    """Utilisateur du jeton présenté, retrouvé comme le fait NetBox 4.7
    (netbox/api/authentication.py) : « nbt_CLÉ.SECRET » → jeton v2 (clé, puis
    empreinte du secret) ; sinon jeton v1 (valeur en clair), quel que soit le
    mot-clé (Token ou Bearer)."""
    parts = header.split()
    if not parts or parts[0].lower() not in ("token", "bearer"):
        return None
    if len(parts) != 2:
        raise _UnknownToken("en-tête d'authentification mal formé")
    value = parts[1]
    try:
        from users.models import Token
        qs = Token.objects.select_related("user")
        if value.startswith("nbt_"):
            key, sep, secret = value[4:].partition(".")
            token = qs.filter(version=2, key=key).first() if sep else None
            if token is not None and not token.validate(secret):
                token = None
        else:
            token = qs.filter(version=1, plaintext=value).first()
    except Exception as exc:
        raise _Unidentified(str(exc)) from exc
    # Jeton inconnu : refusé ici aussi. Si la recherche de NetBox venait un jour
    # à différer de la nôtre, un jeton qu'il accepterait ne passerait pas sans
    # contrôle de l'adresse (refus par défaut).
    if token is None:
        raise _UnknownToken("jeton inconnu")
    return token.user


class TrustedHostsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        via = None
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated:
            via = "session"
        else:
            header = request.META.get("HTTP_AUTHORIZATION", "")
            if header:
                try:
                    user = _token_user(header)
                except _UnknownToken as exc:
                    logger.warning(json.dumps({"event": "auspex_access_denied", "reason": str(exc),
                                               "remote_addr": request.META.get("REMOTE_ADDR"),
                                               "path": request.path}, ensure_ascii=False))
                    return self._deny(request, str(exc), api=True)
                except _Unidentified as exc:
                    logger.error(json.dumps({"event": "auspex_access_denied", "reason":
                                             f"identification du jeton impossible : {exc}"}, ensure_ascii=False))
                    return self._deny(request, "identification du jeton impossible", api=True)
                via = "token" if user is not None else None

        if via is not None:
            groups = list(user.groups.values_list("name", flat=True))
            decision = _cache.get().decide(user.username, groups, request.META.get("REMOTE_ADDR"),
                                           request.META.get("HTTP_X_FORWARDED_FOR"))
            if not decision.allowed:
                logger.warning(json.dumps({
                    "event": "auspex_access_denied", "user": user.username, "via": via,
                    "client_ip": decision.client_ip, "remote_addr": request.META.get("REMOTE_ADDR"),
                    "path": request.path, "reason": decision.reason}, ensure_ascii=False))
                if via == "session":
                    logout(request)
                return self._deny(request, decision.reason, api=(via == "token" or request.path.startswith("/api/")))
        return self.get_response(request)

    @staticmethod
    def _deny(request, reason: str, api: bool):
        message = f"Accès refusé depuis cette adresse ({reason})."
        if api:
            return JsonResponse({"detail": message}, status=403)
        from django.template.loader import render_to_string
        return HttpResponseForbidden(render_to_string("netbox_auspex/mfa.html", {"mode": "ip_refused"}))
