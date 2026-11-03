#!/usr/bin/env python3
"""Preuve « connexion unique SAML » sur le central complet (exécuté par la CI).

Réutilise le Keycloak de tools/ci_oidc.py comme fournisseur SAML : métadonnées
téléchargées, central passé en auth.primary: saml, puis connexion comme un
navigateur (NetBox → Keycloak → assertion postée à NetBox).
Vérifie aussi le refus d'une assertion modifiée et d'un fournisseur dont le
certificat ne correspond pas aux métadonnées.

Usage (dans deploy/, après ci_oidc.py) : python ../tools/ci_saml.py
"""

from __future__ import annotations

import base64
import html
import json
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_mfa import CONFIG, ENV, PAGE, URL, Browser, api  # noqa: E402
from ci_oidc import KC, REALM, SAML_SP, WORK, SSOBrowser, path_of, restart_netbox, run, tls_context  # noqa: E402

RESULTS: list[tuple[str, bool]] = []


def check(label: str, ok: bool) -> None:
    ok = bool(ok)
    RESULTS.append((label, ok))
    print(f"  {'OK ' if ok else 'ÉCHEC'}  {label}", flush=True)
    if not ok:
        print(f"::error title=SAML::{label}", flush=True)


def form_fields(page: str) -> tuple[str | None, dict]:
    form = re.search(r'<form[^>]*action="([^"]+)"', page)
    fields = {html.unescape(n): html.unescape(v) for n, v in
              re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', page)}
    return (html.unescape(form.group(1)) if form else None), fields


def saml_login(user: str, password: str, tamper=None, expect_ok: bool = True, b=None):
    """Connexion SAML complète. `tamper` : modifie l'assertion avant de la poster."""
    b = b or SSOBrowser()
    status, url, page = b.open(f"{URL}/oauth/login/saml/?next={PAGE}")
    if not url.startswith(KC):
        diagnose("pas de redirection vers le fournisseur", status, url, page)
        return status, url, page
    action, _ = form_fields(re.search(r'<form[^>]*id="kc-form-login".*?</form>', page, re.S).group(0)
                            if 'id="kc-form-login"' in page else page)
    status, url, page = b.open(action, {"username": user, "password": password, "credentialId": ""})
    acs, fields = form_fields(page)
    if not acs or "SAMLResponse" not in fields:
        diagnose("pas d'assertion renvoyée par le fournisseur", status, url, page)
        return status, url, page
    if tamper:
        xml = base64.b64decode(fields["SAMLResponse"]).decode()
        fields["SAMLResponse"] = base64.b64encode(tamper(xml).encode()).decode()
    status, url, page = b.open(acs, fields)
    if expect_ok and not tamper and path_of(url) != PAGE:
        xml = base64.b64decode(fields["SAMLResponse"]).decode("utf-8", "replace")
        bare = re.sub(r"<(\w+:)?Signature\b.*?</(\w+:)?Signature>", "", xml, flags=re.S)
        start = bare.find("Assertion")
        print(f"::error title=SAML assertion::{bare[max(0, start - 20):start + 1500]}", flush=True)
        diagnose("assertion refusée par NetBox", status, url, page)
    return status, url, page


DIAGNOSED: set[str] = set()


def diagnose(what: str, status, url, page: str) -> None:
    """Une seule fois par cause : réponse reçue et fin de la trace d'erreur de NetBox."""
    if what in DIAGNOSED:
        return
    DIAGNOSED.add(what)
    text = re.sub(r"<[^>]+>", " ", page)
    text = re.sub(r"\s+", " ", text)[:400]
    print(f"::error title=SAML diagnostic::{what} : HTTP {status} {url} — {text}", flush=True)
    logs = run("docker", "compose", "logs", "--no-color", "--tail", "300", "netbox", check_rc=False).stdout
    lines = logs.splitlines()
    idx = [i for i, l in enumerate(lines) if "Traceback" in l]
    if idx:
        for l in lines[idx[-1]:idx[-1] + 40][-14:]:
            print(f"::error title=SAML trace NetBox::{l[:300]}", flush=True)


def other_certificate() -> str:
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(WORK / "faux-idp.key"),
        "-out", str(WORK / "faux-idp.crt"), "-days", "2", "-subj", "/CN=faux fournisseur")
    pem = (WORK / "faux-idp.crt").read_text()
    return "".join(l for l in pem.splitlines() if "CERTIFICATE" not in l)


def use_metadata(name: str) -> None:
    cfg = yaml.safe_load(CONFIG.read_text())
    cfg["auth"]["saml"]["idp_metadata"] = name
    CONFIG.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))


def main() -> int:
    creds = json.loads((WORK / "saml-users.json").read_text())
    print("Métadonnées SAML du fournisseur")
    ctx = tls_context(WORK / "ca.crt")
    with urllib.request.urlopen(f"{KC}/realms/{REALM}/protocol/saml/descriptor", timeout=20, context=ctx) as r:
        metadata = r.read().decode()
    (CONFIG.parent / "saml-idp.xml").write_text(metadata)
    cert = re.search(r"<(?:ds:)?X509Certificate>([^<]+)<", metadata).group(1)
    (CONFIG.parent / "saml-idp-autre.xml").write_text(metadata.replace(cert, other_certificate()))
    check("métadonnées téléchargées (identifiant, adresse, certificat)", "IDPSSODescriptor" in metadata)

    print("Central en auth.primary: saml")
    cfg = yaml.safe_load(CONFIG.read_text())
    cfg["auth"]["primary"] = "saml"
    cfg["auth"].pop("oidc", None)
    cfg["auth"]["saml"] = {"sp_entity_id": SAML_SP, "idp_metadata": "saml-idp.xml", "label": "Keycloak SAML",
                           "attributes": {"permanent_id": "username", "username": "username", "email": "email"},
                           "groups_attribute": "groups", "require_group": "auspex-utilisateurs"}
    CONFIG.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))
    check("NetBox redémarré avec le fournisseur SAML", restart_netbox())
    r = run("docker", "compose", "exec", "-T", "netbox", "/opt/netbox/venv/bin/python", "/opt/netbox/netbox/manage.py",
            "shell", "-c", "from django.conf import settings; print(settings.AUTHENTICATION_BACKENDS)", check_rc=False)
    check("NetBox utilise le backend SAML (et garde le backend local)",
          "SAMLAuth" in r.stdout and "ObjectPermissionBackend" in r.stdout)

    print("Connexions")
    status, url, _ = saml_login("saml1", creds["saml1"])
    check(f"saml1 (groupe exigé) : NetBox → Keycloak → assertion → {path_of(url)} (attendu {PAGE}, sans MFA Auspex)",
          status == 200 and url.startswith(URL) and path_of(url) == PAGE)
    _, users = api("GET", "/api/users/users/?username=saml1")
    u = users["results"][0] if users and users.get("count") else {}
    check("e-mail repris de l'assertion", u.get("email") == "saml1@ville.test")
    check("groupe recopié dans NetBox", [g.get("name") for g in u.get("groups", [])] == ["auspex-utilisateurs"])

    status, url, page = saml_login("saml2", creds["saml2"], expect_ok=False)
    _, users = api("GET", "/api/users/users/?username=saml2")
    check(f"saml2, hors du groupe exigé → HTTP {status}, page de refus, aucun compte créé",
          status == 403 and 'id="sso-refused"' in page and users is not None and users.get("count") == 0)

    def impersonate(xml: str) -> str:   # se faire passer pour l'administrateur
        return xml.replace(">saml1<", ">admin<")
    status, url, page = saml_login("saml1", creds["saml1"], tamper=impersonate)
    check(f"assertion modifiée (saml1 → admin) → HTTP {status}, refusée",
          status == 403 and 'id="sso-refused"' in page)
    _, users = api("GET", "/api/users/users/?username=admin")
    check("le compte admin n'a pas été rattaché au fournisseur",
          users is not None and users.get("count") == 1 and not users["results"][0].get("groups"))

    admin = Browser(xff=None)
    _, where, _ = admin.login("admin", ENV["NETBOX_ADMIN_PASSWORD"])
    check(f"brise-glace local toujours accepté (avec la MFA Auspex) → {where}", where.startswith("/plugins/auspex/mfa"))

    print("Certificat du fournisseur différent des métadonnées : refusé")
    use_metadata("saml-idp-autre.xml")
    check("NetBox redémarré avec des métadonnées au mauvais certificat", restart_netbox())
    status, url, page = saml_login("saml1", creds["saml1"], expect_ok=False)
    check(f"saml1, signature non reconnue → HTTP {status}, refusée", status == 403 and 'id="sso-refused"' in page)
    logs = run("docker", "compose", "logs", "--no-color", "netbox", check_rc=False).stdout
    check("refus journalisés (auspex_sso_refused)", '"event": "auspex_sso_refused"' in logs)
    use_metadata("saml-idp.xml")
    check("retour aux bonnes métadonnées", restart_netbox())
    status, url, _ = saml_login("saml1", creds["saml1"])
    check(f"saml1 de nouveau accepté → {path_of(url)}", path_of(url) == PAGE)

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
            print(f"::error title=SAML exception::{line}", flush=True)
        rc = 1
    print(f"::notice title=SAML::{sum(ok for _, ok in RESULTS)}/{len(RESULTS)} vérifications réussies", flush=True)
    raise SystemExit(rc)
