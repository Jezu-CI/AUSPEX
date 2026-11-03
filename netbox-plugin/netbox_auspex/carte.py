"""Connexion par carte à puce (certificat client).

Le front HTTPS d'Auspex (nginx) exige et vérifie le certificat sur le port
carte : chaîne jusqu'aux autorités des cartes, révocation, possession de la
clé privée (donc de la carte et de son code PIN). Il transmet le certificat
à NetBox avec un secret partagé (AUSPEX_PROXY_SECRET) : une requête qui ne
vient pas du front (en-têtes forgés en direct sur NetBox) est refusée.

NetBox refait les contrôles sans coût (dates, émetteur parmi les autorités
déclarées), retrouve le compte (insensible à la casse) et ouvre la session.
La carte vaut double authentification. Comptes d'administration locaux et
brise-glace : jamais par carte (toujours compte local + double
authentification).
"""

from __future__ import annotations

import hmac
import logging
import os

from django.contrib.auth import get_user_model, login
from django.contrib.auth.backends import BaseBackend
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import render
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache

from auspex import carte as core
from auspex.access import LOCAL_ADMINS
from auspex.netbox_auth import CARD_BACKEND

from .mfa import _access, _log, _url

logger = logging.getLogger("netbox_auspex")
SECRET_ENV = "AUSPEX_PROXY_SECRET"


class CarteBackend(BaseBackend):
    """Backend de session des connexions par carte. N'authentifie rien par
    lui-même (seule la vue ci-dessous ouvre une session) et n'accorde aucun
    droit : les droits restent ceux de NetBox (ObjectPermissionBackend)."""

    def authenticate(self, request, **credentials):
        return None

    def get_user(self, user_id):
        return get_user_model().objects.filter(pk=user_id, is_active=True).first()


def _refuse(request, reason: str, **fields):
    _log("auspex_carte_refused", request, reason=reason, **fields)
    return render(request, "netbox_auspex/mfa.html", {
        "mode": "card_refused", "reason": reason, "login_url": _url("login") or "/login/",
        "logout_url": _url("logout") or "/logout/"}, status=403)


def _issuers(path: str) -> set:
    try:
        with open(path, "rb") as fh:
            return {ca.subject for ca in core.load_authorities(fh.read())}
    except (OSError, core.CardError):
        return set()


@never_cache
def card_login_view(request):
    access = _access()
    card = access.card if access is not None else None
    if card is None:
        raise Http404("connexion par carte non configurée")
    secret = os.environ.get(SECRET_ENV, "")
    given = request.META.get("HTTP_X_AUSPEX_PROXY", "")
    if len(secret) < 32 or not hmac.compare_digest(given.encode(), secret.encode()):
        return _refuse(request, "requête hors du front HTTPS d'Auspex (port carte)")
    if request.META.get("HTTP_X_AUSPEX_CARTE_VERIF") != "SUCCESS":
        return _refuse(request, "certificat de carte non vérifié",
                       verif=request.META.get("HTTP_X_AUSPEX_CARTE_VERIF", "")[:100])
    try:
        cert = core.parse_forwarded_cert(request.META.get("HTTP_X_AUSPEX_CARTE", ""))
        ident = core.identity(cert, card.identifier)
    except core.CardError as exc:
        return _refuse(request, str(exc))
    if cert.issuer not in _issuers(card.ca_file):
        return _refuse(request, "émetteur de la carte absent des autorités déclarées", issuer=ident.issuer)
    names = {n.lower() for n in LOCAL_ADMINS} | ({access.break_glass_user.lower()} if access.break_glass_user else set())
    if ident.username.lower() in names:
        return _refuse(request, "compte d'administration local : connexion par carte interdite",
                       user=ident.username)
    User = get_user_model()
    users = list(User.objects.filter(username__iexact=ident.username)[:2])
    if len(users) > 1:
        return _refuse(request, "plusieurs comptes correspondent à la carte (casse)", user=ident.username)
    if users:
        user = users[0]
    elif card.create_users:
        user = User.objects.create_user(ident.username)        # mot de passe inutilisable, aucun droit
        _log("auspex_carte_account_created", request, logging.INFO, user=user.username)
    else:
        return _refuse(request, "aucun compte Auspex pour cette carte", user=ident.username)
    if not user.is_active:
        return _refuse(request, "compte désactivé", user=user.username)
    login(request, user, backend=CARD_BACKEND)
    logger.info(__import__("json").dumps({
        "event": "auspex_carte_ok", "user": user.username, "remote_addr": request.META.get("REMOTE_ADDR"),
        "subject": ident.subject, "issuer": ident.issuer, "serial": ident.serial}, ensure_ascii=False))
    target = request.GET.get("next", "/")
    if not url_has_allowed_host_and_scheme(target, allowed_hosts=None) or not target.startswith("/"):
        target = "/"
    return HttpResponseRedirect(target)
