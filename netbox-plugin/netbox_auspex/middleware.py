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


def _token_user(header: str):
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() not in ("token", "bearer"):
        return None
    key = parts[1].strip()
    try:
        from users.models import Token
        token = Token.objects.select_related("user").filter(key=key).first()
    except Exception as exc:
        raise _Unidentified(str(exc)) from exc
    # Jeton inconnu : NetBox le refusera lui-même, rien à décider ici.
    return token.user if token is not None else None


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
