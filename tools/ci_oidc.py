#!/usr/bin/env python3
"""Preuve « connexion unique OIDC » sur le central complet (exécuté par la CI).

Monte un vrai fournisseur d'identité (Keycloak, en HTTPS avec un certificat
d'une autorité créée pour l'occasion), passe le central en auth.primary: oidc,
puis se connecte comme un navigateur : NetBox → Keycloak → NetBox.

Prérequis (CI) : « sso.ville.test » résolu en 127.0.0.1 sur la machine (/etc/hosts).
Usage (dans deploy/, après ci_ldap.py) : python ../tools/ci_oidc.py
"""

from __future__ import annotations

import html
import http.cookiejar
import json
import re
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_mfa import CONFIG, ENV, PAGE, SETUP_PATH, URL, Browser, api  # noqa: E402

WORK = Path("oidc-ci")
KC = "https://sso.ville.test:9443"   # (9443 : 8443 est le port carte du front) nom complet : la bibliothèque SAML refuse les noms sans point
REALM = "auspex"
ISSUER = f"{KC}/realms/{REALM}"
CLIENT = "10.20.0.5"
SAML_SP = "http://127.0.0.1:8080/saml-sp"   # identifiant de NetBox chez le fournisseur SAML
RESULTS: list[tuple[str, bool]] = []


def check(label: str, ok: bool) -> None:
    ok = bool(ok)
    RESULTS.append((label, ok))
    print(f"  {'OK ' if ok else 'ÉCHEC'}  {label}", flush=True)
    if not ok:
        print(f"::error title=OIDC::{label}", flush=True)


def run(*cmd, check_rc=True):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if check_rc and r.returncode != 0:
        print(f"::error title=OIDC::{' '.join(cmd[:4])} : {r.stderr[-400:]}", flush=True)
        raise SystemExit(1)
    return r


def make_certificates() -> None:
    certs = WORK / "certs"
    certs.mkdir(parents=True, exist_ok=True)
    o = lambda *a: run("openssl", *a)  # noqa: E731
    o("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(WORK / "ca.key"), "-out",
      str(WORK / "ca.crt"), "-days", "2", "-subj", "/CN=Autorite CI OIDC")
    o("req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(certs / "kc.key"), "-out", str(WORK / "kc.csr"),
      "-subj", "/CN=sso.ville.test")
    (WORK / "ext.cnf").write_text("subjectAltName=DNS:sso.ville.test\n")
    o("x509", "-req", "-in", str(WORK / "kc.csr"), "-CA", str(WORK / "ca.crt"), "-CAkey", str(WORK / "ca.key"),
      "-CAcreateserial", "-out", str(certs / "kc.crt"), "-days", "2", "-extfile", str(WORK / "ext.cnf"))
    o("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(WORK / "autre.key"), "-out",
      str(WORK / "autre-ca.crt"), "-days", "2", "-subj", "/CN=Autorite inconnue OIDC")
    for f in certs.iterdir():
        f.chmod(0o644)


def realm(secret: str, pw1: str, pw2: str) -> dict:
    def user(name, group, pw):
        return {"username": name, "enabled": True, "email": f"{name}@ville.test", "emailVerified": True,
                "firstName": name.capitalize(), "lastName": "Test", "requiredActions": [],
                "credentials": [{"type": "password", "value": pw, "temporary": False}], "groups": [f"/{group}"]}
    return {
        "realm": REALM, "enabled": True,
        "groups": [{"name": "auspex-utilisateurs"}, {"name": "autres"}],
        "users": [user("oidc1", "auspex-utilisateurs", pw1), user("oidc2", "autres", pw2),
                  user("saml1", "auspex-utilisateurs", pw1), user("saml2", "autres", pw2)],
        "clients": [{
            "clientId": "auspex-netbox", "enabled": True, "protocol": "openid-connect", "publicClient": False,
            "secret": secret, "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
            "redirectUris": ["http://127.0.0.1:8080/oauth/complete/oidc/"],
            "protocolMappers": [{
                "name": "groupes", "protocol": "openid-connect", "protocolMapper": "oidc-group-membership-mapper",
                "config": {"claim.name": "groups", "full.path": "false", "id.token.claim": "true",
                           "access.token.claim": "true", "userinfo.token.claim": "true"}}],
        }, {
            # Client SAML (étape suivante de la CI, tools/ci_saml.py)
            "clientId": SAML_SP, "enabled": True, "protocol": "saml", "frontchannelLogout": False,
            "redirectUris": ["http://127.0.0.1:8080/oauth/complete/saml/"],
            "attributes": {"saml.client.signature": "false", "saml.assertion.signature": "true",
                           "saml.server.signature": "false",
                           # Déclaration d'authentification (activée par défaut dans la console
                           # Keycloak, pas lors d'un import) : exigée par la bibliothèque SAML.
                           "saml.authnstatement": "true", "saml.signature.algorithm": "RSA_SHA256",
                           "saml_force_name_id_format": "true", "saml_name_id_format": "username",
                           "saml_assertion_consumer_url_post": "http://127.0.0.1:8080/oauth/complete/saml/"},
            "protocolMappers": [
                {"name": "username", "protocol": "saml", "protocolMapper": "saml-user-property-mapper",
                 "config": {"user.attribute": "username", "attribute.name": "username",
                            "attribute.nameformat": "Basic"}},
                {"name": "email", "protocol": "saml", "protocolMapper": "saml-user-property-mapper",
                 "config": {"user.attribute": "email", "attribute.name": "email", "attribute.nameformat": "Basic"}},
                {"name": "groupes", "protocol": "saml", "protocolMapper": "saml-group-membership-mapper",
                 "config": {"attribute.name": "groups", "single": "true", "full.path": "false",
                            "attribute.nameformat": "Basic"}},
            ],
        }],
    }


def tls_context(cafile: Path) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(cafile))


def start_keycloak(secret: str, pw1: str, pw2: str) -> None:
    imp = WORK / "import"
    imp.mkdir(exist_ok=True)
    (imp / "auspex-realm.json").write_text(json.dumps(realm(secret, pw1, pw2)))
    (imp / "auspex-realm.json").chmod(0o644)
    run("docker", "run", "-d", "--name", "keycloak", "--hostname", "sso.ville.test", "--network", "auspex_default",
        "--network-alias", "sso.ville.test",
        "-p", "127.0.0.1:9443:9443",
        "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=kcadmin", "-e", f"KC_BOOTSTRAP_ADMIN_PASSWORD={secrets.token_urlsafe(16)}",
        "-v", f"{imp.resolve()}:/opt/keycloak/data/import:ro", "-v", f"{(WORK / 'certs').resolve()}:/certs:ro",
        "quay.io/keycloak/keycloak:26.0", "start-dev", "--import-realm", "--https-port=9443",
        "--https-certificate-file=/certs/kc.crt", "--https-certificate-key-file=/certs/kc.key",
        f"--hostname={KC}")
    ctx = tls_context(WORK / "ca.crt")
    for _ in range(120):
        try:
            with urllib.request.urlopen(ISSUER + "/.well-known/openid-configuration", timeout=5, context=ctx) as r:
                if json.loads(r.read()).get("issuer") == ISSUER:
                    check("Keycloak prêt, en HTTPS, émetteur conforme", True)
                    return
        except Exception:
            pass
        time.sleep(3)
    check("Keycloak prêt, en HTTPS, émetteur conforme", False)
    logs = run("docker", "logs", "--tail", "40", "keycloak", check_rc=False)
    for line in (logs.stdout + logs.stderr).splitlines()[-40:]:
        print(f"::error title=OIDC journal Keycloak::{line[:300]}", flush=True)
    raise SystemExit(1)


class SSOBrowser:
    """Navigateur : cookies des deux sites, autorité CI reconnue côté Keycloak."""

    def __init__(self):
        jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar),
            urllib.request.HTTPSHandler(context=tls_context(WORK / "ca.crt")))

    def open(self, url, data=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(url, data=body, headers={"X-Forwarded-For": CLIENT})
        try:
            with self.opener.open(req, timeout=30) as r:
                return r.status, r.geturl(), r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.geturl(), e.read().decode("utf-8", "replace")

    def sso_login(self, user, password):
        status, url, page = self.open(f"{URL}/oauth/login/oidc/?next={PAGE}")
        if not url.startswith(KC):
            return status, url, page
        form = re.search(r'<form[^>]*id="kc-form-login"[^>]*>', page) or re.search(r"<form[^>]*>", page)
        action = re.search(r'action="([^"]+)"', form.group(0)) if form else None
        if not action:
            return 0, url, page
        return self.open(html.unescape(action.group(1)), {"username": user, "password": password,
                                                          "credentialId": ""})


def ensure_group_can_view(name: str) -> None:
    """Droit de lecture du groupe du fournisseur : donné par ci_ldap.py dans la CI complète,
    absent quand ce script est lancé seul (captures d'écran). Sans lui, la page d'arrivée
    répond 403. Idempotent."""
    _, found = api("GET", f"/api/users/groups/?name={name}")
    if found and found.get("count"):
        gid = found["results"][0]["id"]
    else:
        code, created = api("POST", "/api/users/groups/", {"name": name})
        gid = (created or {}).get("id")
    _, perms = api("GET", f"/api/users/permissions/?group_id={gid}")
    def grants(p) -> bool:  # filtre group_id vérifié aussi côté script
        return ("view" in p.get("actions", []) and "ipam.ipaddress" in p.get("object_types", [])
                and gid in [g.get("id") if isinstance(g, dict) else g for g in p.get("groups", [])])
    if gid and not any(grants(p) for p in (perms or {}).get("results", [])):
        api("POST", "/api/users/permissions/", {"name": f"ci-lecture-{name}", "object_types": ["ipam.ipaddress"],
                                                "actions": ["view"], "groups": [gid]})


def path_of(url: str) -> str:
    return urllib.parse.urlparse(url).path


def set_env(key: str, value: str) -> None:
    env = Path(".env")
    lines = [l for l in env.read_text().splitlines() if not l.startswith(f"{key}=")]
    env.write_text("\n".join(lines + [f"{key}={value}"]) + "\n")


def restart_netbox() -> bool:
    run("docker", "compose", "up", "-d", "--force-recreate", "netbox")
    for _ in range(120):
        try:
            with urllib.request.urlopen(URL + "/login/", timeout=5) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(3)
    return False


def use_ca(name: str) -> None:
    cfg = yaml.safe_load(CONFIG.read_text())
    cfg["auth"]["oidc"]["ca_file"] = name
    CONFIG.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))


def main() -> int:
    secret, pw1, pw2 = (secrets.token_urlsafe(18) for _ in range(3))
    print("Fournisseur d'identité Keycloak en HTTPS")
    make_certificates()
    start_keycloak(secret, pw1, pw2)
    # Mots de passe des comptes SAML, pour tools/ci_saml.py
    creds = WORK / "saml-users.json"
    creds.write_text(json.dumps({"saml1": pw1, "saml2": pw2}))
    creds.chmod(0o600)
    (CONFIG.parent / "oidc-ca.pem").write_bytes((WORK / "ca.crt").read_bytes())
    (CONFIG.parent / "oidc-autre-ca.pem").write_bytes((WORK / "autre-ca.crt").read_bytes())

    print("Central en auth.primary: oidc")
    cfg = yaml.safe_load(CONFIG.read_text())
    cfg["auth"]["primary"] = "oidc"
    cfg["auth"].pop("ldaps", None)
    cfg["auth"]["oidc"] = {"issuer": ISSUER, "client_id": "auspex-netbox", "label": "Keycloak",
                           "require_group": "auspex-utilisateurs", "ca_file": "oidc-ca.pem"}
    if not any(r.get("group") == "auspex-utilisateurs" for r in cfg["access"]["trusted_hosts"]):
        cfg["access"]["trusted_hosts"].append({"group": "auspex-utilisateurs", "allow": ["10.20.0.0/24"]})
    CONFIG.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))
    set_env("AUSPEX_OIDC_CLIENT_SECRET", secret)
    check("NetBox redémarré avec le fournisseur d'identité", restart_netbox())
    r = run("docker", "compose", "exec", "-T", "netbox", "/opt/netbox/venv/bin/python", "/opt/netbox/netbox/manage.py",
            "shell", "-c", "from django.conf import settings; print(settings.AUTHENTICATION_BACKENDS)", check_rc=False)
    check("NetBox utilise le backend OIDC (et garde le backend local)",
          "OpenIdConnectAuth" in r.stdout and "ObjectPermissionBackend" in r.stdout)
    with urllib.request.urlopen(URL + "/login/", timeout=10) as resp:
        check("bouton « Keycloak » sur la page de connexion", "Keycloak" in resp.read().decode("utf-8", "replace"))

    ensure_group_can_view("auspex-utilisateurs")

    print("Connexions")
    b = SSOBrowser()
    status, url, _ = b.sso_login("oidc1", pw1)
    check(f"oidc1 (groupe exigé) : NetBox → Keycloak → NetBox → {path_of(url)} (attendu {PAGE}, sans MFA Auspex)",
          status == 200 and url.startswith(URL) and path_of(url) == PAGE)
    _, users = api("GET", "/api/users/users/?username=oidc1")
    u = users["results"][0] if users and users.get("count") else {}
    check("e-mail repris du fournisseur", u.get("email") == "oidc1@ville.test")
    groups = [g.get("name") for g in u.get("groups", [])]
    check(f"groupe du fournisseur recopié dans NetBox ({groups})", groups == ["auspex-utilisateurs"])
    r = run("docker", "compose", "exec", "-T", "netbox", "/opt/netbox/venv/bin/python", "/opt/netbox/netbox/manage.py",
            "shell", "-c", "from django.contrib.auth import get_user_model as g; "
            "print('superuser=', g().objects.get(username='oidc1').is_superuser)", check_rc=False)
    check("pas administrateur NetBox (aucun superuser_group)", "superuser= False" in r.stdout)

    status, url, page = SSOBrowser().sso_login("oidc2", pw2)
    _, users = api("GET", "/api/users/users/?username=oidc2")
    check(f"oidc2, hors du groupe exigé → HTTP {status}, page de refus, aucun compte créé",
          status == 403 and 'id="sso-refused"' in page and users is not None and users.get("count") == 0)

    local_pw = secrets.token_urlsafe(18) + "Aa9"
    _, user = api("POST", "/api/users/users/", {"username": "local-oidc", "password": local_pw})
    cfg = yaml.safe_load(CONFIG.read_text())
    cfg["access"]["trusted_hosts"].append({"user": "local-oidc", "allow": ["10.20.0.0/24"]})
    CONFIG.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))
    time.sleep(1.2)
    status, _, page = Browser().login("local-oidc", local_pw)
    check(f"compte local (bon mot de passe, pas le brise-glace) → HTTP {status}, refusé",
          status == 403 and 'id="local-refused"' in page)
    admin = Browser(xff=None)
    _, where, page = admin.login("admin", ENV["NETBOX_ADMIN_PASSWORD"])
    check(f"brise-glace local toujours accepté (avec la MFA Auspex) → {where}",
          where in (SETUP_PATH, "/plugins/auspex/mfa/"))

    print("Fournisseur au certificat non reconnu : refusé")
    use_ca("oidc-autre-ca.pem")
    check("NetBox redémarré avec une autre autorité", restart_netbox())
    status, url, _ = SSOBrowser().sso_login("oidc1", pw1)
    check(f"oidc1, certificat du fournisseur non reconnu → {status} {path_of(url)} (refusé)",
          not (status == 200 and url.startswith(URL) and path_of(url) == PAGE))
    logs = run("docker", "compose", "logs", "--no-color", "netbox", check_rc=False).stdout
    check("secret du client absent du journal", secret not in logs and pw1 not in logs)
    use_ca("oidc-ca.pem")
    check("retour à la bonne autorité", restart_netbox())
    status, url, _ = SSOBrowser().sso_login("oidc1", pw1)
    check(f"oidc1 de nouveau accepté → {path_of(url)}", path_of(url) == PAGE)

    failed = [label for label, ok in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} vérifications réussies")
    return 1 if failed else 0


if __name__ == "__main__":
    import traceback
    try:
        rc = main()
    except SystemExit:
        raise
    except Exception:
        for line in traceback.format_exc().splitlines()[-12:]:
            print(f"::error title=OIDC exception::{line}", flush=True)
        rc = 1
    print(f"::notice title=OIDC::{sum(ok for _, ok in RESULTS)}/{len(RESULTS)} vérifications réussies", flush=True)
    raise SystemExit(rc)
