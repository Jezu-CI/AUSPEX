"""Double authentification (TOTP) pour les connexions qui ne passent pas par un
fournisseur d'identité : comptes locaux (dont le brise-glace) et LDAPS.

- Middleware : tant que la session n'a pas passé la MFA, tout est refusé
  (redirection vers la page de code, ou HTTP 403 pour l'API), sauf les pages
  de MFA, de connexion et de déconnexion. Les requêtes par jeton d'API ne
  sont pas concernées : elles ne portent pas de session, et sont filtrées
  par les trusted hosts.
- Première connexion : inscription (secret à saisir dans l'application,
  confirmation par un premier code, 10 codes de secours montrés une fois).
- Ensuite : code de l'application ou code de secours. Anti-rejeu, et
  verrouillage progressif après 5 échecs.
- Chaque événement est journalisé en JSON (auspex_mfa_*), prêt pour le SIEM.

La logique (TOTP, codes de secours, verrouillage, quelles connexions sont
concernées) est dans auspex.mfa, testé sans Django.
"""

from __future__ import annotations

import json
import logging
import os
import ssl
import time
from datetime import datetime, timezone as dt_timezone

from django.conf import settings
from django.contrib.auth import BACKEND_SESSION_KEY, logout
from django.core.cache import cache
from django.core.mail import EmailMessage, get_connection
from django.core.mail.backends.smtp import EmailBackend
from django.db import transaction
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.urls import NoReverseMatch, reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme, urlencode
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect

from auspex import mfa as core
from auspex import qrcode
from auspex import webauthn as wa
from auspex.access import LOCAL_ADMINS
from auspex.netbox_auth import LOCAL_BACKENDS, local_login_allowed

from .middleware import _cache, get_plugin_config
from .models import TOTPDevice, WebAuthnKey

logger = logging.getLogger("netbox_auspex")

SESSION_OK = "auspex_mfa_ok"          # identifiant de l'utilisateur qui a passé la MFA
SESSION_SECRET = "auspex_mfa_enroll"  # secret proposé pendant l'inscription
SESSION_METHOD = "auspex_mfa_method"  # méthode choisie pendant l'inscription
SESSION_CHALLENGE = "auspex_webauthn"  # défi WebAuthn en cours (usage unique, 5 min)
CHALLENGE_TTL = 300


def _log(event: str, request, level: int = logging.WARNING, **fields) -> None:
    user = getattr(request, "user", None)
    logger.log(level, json.dumps({"event": event, "user": getattr(user, "username", None),
                               "remote_addr": request.META.get("REMOTE_ADDR"), **fields},
                              ensure_ascii=False))


def _url(name: str) -> str | None:
    for candidate in (f"plugins:netbox_auspex:{name}", name):
        try:
            return reverse(candidate)
        except NoReverseMatch:
            continue
    return None


def _next(request) -> str:
    target = request.POST.get("next") or request.GET.get("next") or ""
    if target and url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()},
                                                  require_https=request.is_secure()):
        return target
    return _url("home") or "/"


def _with_next(url: str | None, target: str) -> str:
    return f"{url or '/'}?{urlencode({'next': target})}"


def mfa_pending(request) -> bool:
    """La session est authentifiée mais n'a pas (encore) passé la MFA."""
    user = getattr(request, "user", None)
    if user is None or not user.is_authenticated:
        return False
    if not core.mfa_required(request.session.get(BACKEND_SESSION_KEY)):
        return False
    return request.session.get(SESSION_OK) != user.pk


def _passed(request, device: TOTPDevice) -> None:
    # Nouvel identifiant de session : une session volée avant la MFA ne sert plus.
    request.session.cycle_key()
    request.session[SESSION_OK] = request.user.pk
    device.failures = 0
    device.locks = 0
    device.locked_until = None
    device.last_used = timezone.now()


class MFARequiredMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def process_exception(self, request, exception):
        """Connexion SSO refusée (hors du groupe, assertion invalide, certificat
        non reconnu...) : page de refus propre, au lieu de la page d'erreur de
        NetBox qui affiche le détail de l'exception."""
        if not type(exception).__module__.startswith("social_core."):
            return None
        _log("auspex_sso_refused", request, reason=type(exception).__name__, detail=str(exception)[:300])
        return render(request, "netbox_auspex/mfa.html", {
            "mode": "sso_refused", "logout_url": _url("logout") or "/logout/",
            "login_url": _url("login") or "/login/"}, status=403)

    def _exempt(self, path: str) -> bool:
        prefixes = [p for p in (_url("mfa"), _url("mfa_setup"), _url("login"), _url("logout")) if p]
        static = getattr(settings, "STATIC_URL", None)
        if static:
            prefixes.append(static if static.startswith("/") else "/" + static)
        return any(path.startswith(p) for p in prefixes)

    def __call__(self, request):
        # SAML : le bouton de NetBox mène à /oauth/login/saml/ sans le nom du
        # fournisseur, que social-auth exige (?idp=...). On le complète.
        if request.path.rstrip("/").endswith("/oauth/login/saml") and "idp" not in request.GET:
            from auspex.netbox_auth import SAML_IDP_NAME
            query = request.GET.copy()
            query["idp"] = SAML_IDP_NAME
            return HttpResponseRedirect(f"{request.path}?{query.urlencode()}")
        user = getattr(request, "user", None)
        if (user is not None and user.is_authenticated
                and request.session.get(BACKEND_SESSION_KEY) in LOCAL_BACKENDS
                and not local_login_allowed(_access(), user.get_username(), LOCAL_ADMINS)):
            # Méthode principale configurée (LDAPS...) : un compte local autre
            # que le brise-glace ne doit plus servir (compte oublié, créé à la
            # main, ancien mot de passe...).
            _log("auspex_auth_local_refused", request)
            logout(request)
            if "/api/" in request.path:
                return JsonResponse({"detail": "Connexion locale réservée au compte de secours."}, status=403)
            return render(request, "netbox_auspex/mfa.html", {
                "mode": "local_refused", "logout_url": _url("logout") or "/logout/",
                "login_url": _url("login") or "/login/"}, status=403)
        if mfa_pending(request) and not self._exempt(request.path):
            api = "/api/" in request.path or "/graphql" in request.path
            if api:
                return JsonResponse({"detail": "Double authentification requise : terminer la "
                                               "connexion dans l'interface."}, status=403)
            if request.method == "GET":
                return HttpResponseRedirect(_with_next(_url("mfa"), request.get_full_path()))
            return HttpResponseRedirect(_url("mfa") or "/")
        return self.get_response(request)


# --- Méthodes proposées --------------------------------------------------------------

def _access():
    try:
        return _cache.get().access
    except Exception:  # configuration illisible : comme le verrouillage, TOTP seul
        return None


def available_methods(user, access=None) -> list[str]:
    """Méthodes d'inscription possibles pour cet utilisateur.

    Le brise-glace et l'administrateur local : TOTP seulement (ils doivent
    fonctionner quand la messagerie est en panne). E-mail : seulement si la
    méthode est activée, le serveur d'envoi configuré, et l'adresse de
    l'utilisateur renseignée (par l'administrateur ou l'annuaire).
    """
    if access is None:
        return ["totp"]
    admins = set(LOCAL_ADMINS) | ({access.break_glass_user} if access.break_glass_user else set())
    if user.get_username() in admins:
        # Méthode imposée au brise-glace : TOTP, ou clé de sécurité (fonctionne
        # hors ligne, sans messagerie ni téléphone).
        return ["webauthn"] if access.break_glass_mfa == "webauthn" and access.webauthn else ["totp"]
    methods = []
    if "webauthn" in access.mfa_methods and access.webauthn is not None:
        methods.append("webauthn")
    if "totp" in access.mfa_methods:
        methods.append("totp")
    if "email" in access.mfa_methods and access.mail is not None and user.email:
        methods.append("email")
    return methods or ["totp"]  # jamais d'utilisateur sans méthode possible


# --- Envoi des codes par e-mail -----------------------------------------------------------

class VerifiedSMTPBackend(EmailBackend):
    """SMTP avec vérification du certificat du serveur, toujours (autorité
    interne possible : auth.mfa.email.ca_file)."""

    ca_file = None

    @property
    def ssl_context(self):
        ctx = ssl.create_default_context(cafile=self.ca_file)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx


def _hmac_key() -> bytes:
    return ("auspex-mfa-email:" + settings.SECRET_KEY).encode()


def _sent_key(user) -> str:
    return f"auspex_mfa_mail_sent:{user.pk}"


def _code_key(user) -> str:
    return f"auspex_mfa_mail_code:{user.pk}"


def _client_ip(request) -> str:
    try:
        ip, _ = _cache.get().client_ip(request.META.get("REMOTE_ADDR"), request.META.get("HTTP_X_FORWARDED_FOR"))
        return str(ip)
    except Exception:
        return str(request.META.get("REMOTE_ADDR"))


def _deliver(mail, to: str, subject: str, body: str) -> None:
    backend = get_plugin_config("netbox_auspex", "email_backend")
    kwargs = {}
    if backend.endswith("VerifiedSMTPBackend"):
        kwargs = dict(host=mail.server, port=mail.port, username=mail.username or "",
                      password=os.environ.get("AUSPEX_SMTP_PASSWORD", ""),
                      use_tls=mail.security == "starttls", use_ssl=mail.security == "tls", timeout=10)
    connection = get_connection(backend, **kwargs)
    if isinstance(connection, VerifiedSMTPBackend):
        connection.ca_file = mail.ca_file
    EmailMessage(subject, body, mail.sender, [to], connection=connection).send()


def send_code(request, access) -> str | None:
    """Envoie un nouveau code. Renvoie un message d'erreur, ou None si envoyé."""
    user = request.user
    now = time.time()
    allowed, wait, recent = core.can_send_email(cache.get(_sent_key(user)) or [], now)
    if not allowed:
        return f"Un code vient d'être envoyé : nouvel envoi possible dans {wait} s."
    code, digest = core.new_email_code(_hmac_key())
    cache.set(_code_key(user), {"digest": digest, "expires": now + core.EMAIL_TTL, "tries": 0}, core.EMAIL_TTL)
    when = datetime.fromtimestamp(now, dt_timezone.utc).strftime("%d/%m/%Y à %H:%M")
    body = (f"Bonjour,\n\nVotre code de connexion à Auspex (compte {user.get_username()}) : {code}\n\n"
            f"Il est valable {core.EMAIL_TTL // 60} minutes et ne sert qu'une fois.\n"
            f"Demande faite depuis l'adresse {_client_ip(request)}, le {when} UTC.\n\n"
            "Si vous n'êtes pas à l'origine de cette demande, votre mot de passe est probablement connu "
            "d'un tiers : changez-le et prévenez l'équipe sécurité.\n\n"
            "Ne communiquez ce code à personne : aucun administrateur ne vous le demandera.\n")
    try:
        _deliver(access.mail, user.email, "Auspex : votre code de connexion", body)
    except Exception as exc:
        cache.delete(_code_key(user))
        _log("auspex_mfa_email_error", request, error=type(exc).__name__)
        return "Envoi de l'e-mail impossible pour le moment. Réessayer, ou utiliser un code de secours."
    cache.set(_sent_key(user), recent + [now], 3600)
    _log("auspex_mfa_email_sent", request, logging.INFO, to=core.mask_email(user.email))
    return None


def check_code(request, code: str) -> bool:
    """Vérifie le code e-mail en cours ; le consomme s'il est bon. 5 essais par code."""
    key = _code_key(request.user)
    pending = cache.get(key)
    if not pending:
        return False
    if core.check_email_code(code, pending["digest"], pending["expires"], _hmac_key()):
        cache.delete(key)
        return True
    pending["tries"] += 1
    if pending["tries"] >= core.MAX_FAILURES:
        cache.delete(key)  # code grillé : il faudra en demander un autre
    else:
        cache.set(key, pending, max(1, int(pending["expires"] - time.time())))
    return False


# --- Clés de sécurité (WebAuthn) ----------------------------------------------------------

def _new_challenge(request) -> bytes:
    challenge = os.urandom(32)
    request.session[SESSION_CHALLENGE] = {"c": wa.b64url(challenge), "t": time.time()}
    return challenge


def _take_challenge(request) -> bytes | None:
    """Défi en cours, retiré de la session : chaque défi ne sert qu'une fois."""
    data = request.session.pop(SESSION_CHALLENGE, None)
    if not isinstance(data, dict) or time.time() - float(data.get("t", 0)) > CHALLENGE_TTL:
        return None
    try:
        return wa.b64url_decode(data.get("c"))
    except wa.WebAuthnError:
        return None


def _credential(request) -> dict | None:
    """Réponse du navigateur (JSON du champ « credential »)."""
    raw = request.POST.get("credential", "")
    if not raw or len(raw) > 64 * 1024:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    return data if isinstance(data, dict) and isinstance(data.get("response"), dict) else None


def _key_name(request) -> str:
    name = " ".join(str(request.POST.get("nom", "")).split())[:64]
    return name or "clé de sécurité"


def _register_options(request, access) -> dict:
    exclude = [wa.b64url_decode(k.credential_id) for k in WebAuthnKey.objects.filter(user=request.user)]
    return wa.registration_options(_new_challenge(request), access.webauthn.rp_id, "Auspex",
                                   wa.user_handle(settings.SECRET_KEY, request.user.pk),
                                   request.user.get_username(), exclude)


def _register(request, access) -> tuple[wa.Registration | None, str | None]:
    challenge = _take_challenge(request)
    cred = _credential(request)
    if challenge is None or cred is None:
        return None, "Délai dépassé ou réponse de la clé manquante : recommencer."
    try:
        reg = wa.verify_registration(cred["response"], challenge, access.webauthn.origin,
                                     access.webauthn.rp_id, access.webauthn.require_uv)
    except wa.WebAuthnError as exc:
        _log("auspex_webauthn_refused", request, step="inscription", reason=str(exc)[:200])
        return None, "Clé refusée : " + str(exc)
    if WebAuthnKey.objects.filter(credential_id=wa.b64url(reg.credential_id)).exists():
        return None, "Cette clé est déjà inscrite."
    return reg, None


def _save_key(request, reg: wa.Registration) -> WebAuthnKey:
    return WebAuthnKey.objects.create(user=request.user, credential_id=wa.b64url(reg.credential_id),
                                      public_key=wa.b64url(reg.public_key), sign_count=reg.sign_count,
                                      name=_key_name(request))


def _assertion_options(request, access) -> dict:
    allow = [wa.b64url_decode(k.credential_id) for k in WebAuthnKey.objects.filter(user=request.user)]
    return wa.assertion_options(_new_challenge(request), access.webauthn.rp_id, allow)


def _check_assertion(request, access) -> bool:
    """Vérifie la réponse de la clé ; met à jour son compteur. Faux sinon (journalisé)."""
    challenge = _take_challenge(request)
    cred = _credential(request)
    if challenge is None or cred is None:
        return False
    key = WebAuthnKey.objects.select_for_update().filter(user=request.user,
                                                          credential_id=str(cred.get("id", ""))).first()
    if key is None:
        _log("auspex_webauthn_refused", request, step="connexion", reason="clé inconnue pour ce compte")
        return False
    try:
        count = wa.verify_assertion(cred["response"], wa.b64url_decode(key.public_key), key.sign_count,
                                    challenge, access.webauthn.origin, access.webauthn.rp_id,
                                    access.webauthn.require_uv)
    except wa.WebAuthnError as exc:
        _log("auspex_webauthn_refused", request, step="connexion", key=key.name, reason=str(exc)[:200])
        return False
    key.sign_count = count
    key.last_used = timezone.now()
    key.save(update_fields=["sign_count", "last_used"])
    return True


# --- Pages ------------------------------------------------------------------------------

def _page(request, mode: str, status: int = 200, **ctx):
    ctx.update(mode=mode, next=_next(request), username=request.user.get_username(),
               logout_url=_url("logout") or "/logout/", mfa_url=_url("mfa"), setup_url=_url("mfa_setup"),
               switch_url=_url("mfa_switch"), masked_email=core.mask_email(request.user.email or ""))
    return render(request, "netbox_auspex/mfa.html", ctx, status=status)


def _guard(request):
    """Redirection si la page n'a pas lieu d'être, sinon None."""
    if not request.user.is_authenticated:
        return HttpResponseRedirect(_url("login") or "/login/")
    if not mfa_pending(request):
        return HttpResponseRedirect(_next(request))
    return None


@never_cache
@csrf_protect
def verify_view(request):
    redirect = _guard(request)
    if redirect:
        return redirect
    device = TOTPDevice.objects.filter(user=request.user).first()
    if device is None:
        return HttpResponseRedirect(_with_next(_url("mfa_setup"), _next(request)))
    access = _access()
    by_email = device.method == "email"
    by_key = device.method == "webauthn"
    mode = "verify_email" if by_email else ("verify_webauthn" if by_key else "verify")
    notice = None
    if by_email and "email" not in available_methods(request.user, access):
        # Méthode retirée de la configuration, ou adresse effacée : seuls les
        # codes de secours restent utilisables.
        mode, by_email = "verify_recovery", False
        notice = ("La connexion par e-mail n'est plus disponible pour ce compte : utiliser un code de "
                  "secours, ou demander une réinitialisation à un administrateur.")
    elif by_key and (access is None or access.webauthn is None):
        mode, by_key = "verify_recovery", False
        notice = ("Les clés de sécurité ne sont plus configurées : utiliser un code de secours, ou "
                  "demander une réinitialisation à un administrateur.")

    def page(status=200, **ctx):
        if by_key:
            ctx["options"] = _assertion_options(request, access)
        return _page(request, mode, status=status, notice=notice, **ctx)
    if core.locked(device.locked_until, time.time()):
        _log("auspex_mfa_refused_locked", request)
        return page(status=429, error="Trop d'échecs : réessayer plus tard.",
                    locked_minutes=int((device.locked_until - time.time()) // 60) + 1)

    if request.method != "POST" or request.POST.get("action") == "resend":
        error = None
        if by_email and (request.method == "POST" or not cache.get(_code_key(request.user))):
            error = send_code(request, access)
        return page(error=error)

    code = request.POST.get("code", "")
    with transaction.atomic():
        # Verrou de ligne : deux requêtes simultanées ne peuvent pas utiliser
        # le même code, ni contourner le compteur d'échecs.
        device = TOTPDevice.objects.select_for_update().get(pk=device.pk)
        now = time.time()
        if core.locked(device.locked_until, now):
            _log("auspex_mfa_refused_locked", request)
            # Le code n'est même pas évalué : pas d'oracle pendant le verrouillage.
            return page(status=429, error="Trop d'échecs : réessayer plus tard.",
                        locked_minutes=int((device.locked_until - now) // 60) + 1)
        if by_email:
            if check_code(request, code):
                _passed(request, device)
                device.save()
                _log("auspex_mfa_ok", request, logging.INFO, method="email")
                return HttpResponseRedirect(_next(request))
        elif by_key and request.POST.get("credential"):
            if _check_assertion(request, access):
                _passed(request, device)
                device.save()
                _log("auspex_mfa_ok", request, logging.INFO, method="webauthn")
                return HttpResponseRedirect(_next(request))
        elif mode == "verify":
            counter = core.verify(device.secret, code, device.last_counter, now)
            if counter is not None:
                device.last_counter = counter
                _passed(request, device)
                device.save()
                _log("auspex_mfa_ok", request, logging.INFO, method="totp")
                return HttpResponseRedirect(_next(request))
        left = core.use_recovery_code(code, device.recovery_hashes) if code else None
        if left is not None:
            device.recovery_hashes = left
            _passed(request, device)
            device.save()
            _log("auspex_mfa_ok", request, logging.INFO, method="recovery_code", recovery_codes_left=len(left))
            return HttpResponseRedirect(_next(request))
        device.failures, device.locks, device.locked_until = core.after_failure(device.failures, device.locks, now)
        device.save()
    if device.locked_until is not None and core.locked(device.locked_until, now):
        _log("auspex_mfa_locked", request, seconds=int(device.locked_until - now))
    else:
        _log("auspex_mfa_failed", request, failures=device.failures, method=device.method)
    by_key_attempt = by_key and bool(request.POST.get("credential"))
    return page(status=403, error="Clé refusée ou délai dépassé : réessayer." if by_key_attempt
                else "Code incorrect.")


def _totp_ctx(request, secret: str) -> dict:
    uri = core.otpauth_uri(secret, request.user.get_username())
    # SVG produit ici à partir de géométrie seule (aucun texte de l'utilisateur) :
    # sûr à insérer tel quel dans la page.
    return {"secret": core.grouped(secret), "uri": uri, "qr_svg": qrcode.to_svg(qrcode.encode(uri))}


def _enroll(request, method: str, secret: str = "", last_counter=None, key: wa.Registration | None = None):
    codes, hashes = core.new_recovery_codes()
    with transaction.atomic():
        device, created = TOTPDevice.objects.get_or_create(
            user=request.user, defaults={"method": method, "secret": secret, "last_counter": last_counter,
                                         "recovery_hashes": hashes})
        if not created:  # inscription simultanée dans un autre onglet : on garde la première
            return HttpResponseRedirect(_with_next(_url("mfa"), _next(request)))
        if key is not None:
            _save_key(request, key)
        _passed(request, device)
        device.save()
    request.session.pop(SESSION_SECRET, None)
    request.session.pop(SESSION_METHOD, None)
    _log("auspex_mfa_enrolled", request, logging.INFO, method=method)
    # Codes de secours montrés une seule fois, dans cette réponse.
    return _page(request, "codes", codes=codes, keys_url=_url("mfa_keys") if method == "webauthn" else None)


@never_cache
@csrf_protect
def setup_view(request):
    redirect = _guard(request)
    if redirect:
        return redirect
    if TOTPDevice.objects.filter(user=request.user).exists():
        # Déjà inscrit : jamais de nouvelle inscription sans réinitialisation
        # par un administrateur (sinon un mot de passe volé suffirait).
        return HttpResponseRedirect(_with_next(_url("mfa"), _next(request)))
    access = _access()
    methods = available_methods(request.user, access)
    chosen = request.GET.get("method") or request.session.get(SESSION_METHOD)
    if chosen not in methods:
        if len(methods) > 1:
            return _page(request, "choose", methods=methods)
        chosen = methods[0]
    request.session[SESSION_METHOD] = chosen

    if chosen == "webauthn":
        if request.method != "POST":
            return _page(request, "setup_webauthn", options=_register_options(request, access),
                         can_switch=len(methods) > 1)
        reg, error = _register(request, access)
        if reg is None:
            return _page(request, "setup_webauthn", status=403, error=error,
                         options=_register_options(request, access), can_switch=len(methods) > 1)
        return _enroll(request, "webauthn", key=reg)

    if chosen == "email":
        if request.method != "POST" or request.POST.get("action") == "resend":
            error = None
            if request.method == "POST" or not cache.get(_code_key(request.user)):
                error = send_code(request, access)
            return _page(request, "setup_email", error=error, can_switch=len(methods) > 1)
        if not check_code(request, request.POST.get("code", "")):
            return _page(request, "setup_email", status=403, error="Code incorrect ou expiré.",
                         can_switch=len(methods) > 1)
        return _enroll(request, "email")

    secret = request.session.get(SESSION_SECRET)
    if not secret:
        secret = request.session[SESSION_SECRET] = core.new_secret()
    if request.method != "POST":
        return _page(request, "setup", can_switch=len(methods) > 1, **_totp_ctx(request, secret))
    counter = core.verify(secret, request.POST.get("code", ""))
    if counter is None:
        return _page(request, "setup", status=403, error="Code incorrect : vérifier l'heure du téléphone.",
                     can_switch=len(methods) > 1, **_totp_ctx(request, secret))
    return _enroll(request, "totp", secret=secret, last_counter=counter)


@never_cache
def switch_view(request):
    """Revenir au choix de la méthode pendant l'inscription."""
    request.session.pop(SESSION_METHOD, None)
    return HttpResponseRedirect(_with_next(_url("mfa_setup"), _next(request)))


@never_cache
@csrf_protect
def keys_view(request):
    """Clés de sécurité de l'utilisateur : en ajouter une de secours, en retirer une perdue."""
    if not request.user.is_authenticated:
        return HttpResponseRedirect(_url("login") or "/login/")
    if mfa_pending(request):
        return HttpResponseRedirect(_with_next(_url("mfa"), request.get_full_path()))
    access = _access()
    device = TOTPDevice.objects.filter(user=request.user).first()
    if device is None or device.method != "webauthn" or access is None or access.webauthn is None:
        return HttpResponseRedirect("/")
    error = None
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "ajouter":
            reg, error = _register(request, access)
            if reg is not None:
                key = _save_key(request, reg)
                _log("auspex_webauthn_key_added", request, logging.INFO, key=key.name)
                return HttpResponseRedirect(_url("mfa_keys"))
        elif action == "retirer":
            with transaction.atomic():
                keys = list(WebAuthnKey.objects.select_for_update().filter(user=request.user))
                key = next((k for k in keys if str(k.pk) == request.POST.get("cle")), None)
                if key is None:
                    error = "Clé introuvable."
                elif len(keys) <= 1:
                    error = "Impossible de retirer la dernière clé : en ajouter une autre d'abord."
                else:
                    key.delete()
                    _log("auspex_webauthn_key_removed", request, key=key.name)
                    return HttpResponseRedirect(_url("mfa_keys"))
    keys = WebAuthnKey.objects.filter(user=request.user)
    return _page(request, "keys", status=403 if error else 200, error=error, keys=keys,
                 options=_register_options(request, access), keys_url=_url("mfa_keys"))
