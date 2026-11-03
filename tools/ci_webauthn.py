#!/usr/bin/env python3
"""Preuve « clé de sécurité (WebAuthn) » sur le central complet (exécuté par la CI).

Vrai NetBox, vrai navigateur (Chromium) et clé de sécurité virtuelle (protocole
CTAP2, comme une clé USB FIDO2) : le compte de secours passe à la clé de
sécurité, s'inscrit, se reconnecte avec sa clé, est refusé sans elle, se
dépanne avec un code de secours, ajoute une clé de secours ; la réinitialisation
révoque les clés.

Usage (dans deploy/) : python ../tools/ci_webauthn.py
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import yaml
from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_mfa import CONFIG, ENV  # noqa: E402

URL = "http://localhost:8080"      # WebAuthn : HTTPS obligatoire, sauf sur « localhost »
MANAGE = ["docker", "compose", "exec", "-T", "netbox", "/opt/netbox/venv/bin/python", "/opt/netbox/netbox/manage.py"]
RESULTS: list[tuple[str, bool]] = []


def check(label: str, ok) -> None:
    ok = bool(ok)
    RESULTS.append((label, ok))
    print(f"  {'OK ' if ok else 'ÉCHEC'}  {label}", flush=True)


def run(*cmd) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)


def set_auth(break_glass_mfa: str, webauthn: bool) -> None:
    cfg = yaml.safe_load(CONFIG.read_text())
    auth = cfg.setdefault("auth", {})
    auth.setdefault("break_glass", {})["mfa"] = break_glass_mfa
    mfa = auth.setdefault("mfa", {"methods": ["totp"]})
    methods = [m for m in mfa.get("methods", ["totp"]) if m != "webauthn"]
    if webauthn:
        mfa["methods"] = ["webauthn", *methods]
        mfa["webauthn"] = {"domaine": "localhost", "adresse": URL}
    else:
        mfa["methods"] = methods or ["totp"]
        mfa.pop("webauthn", None)
    CONFIG.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))


def login(page) -> None:
    page.goto(f"{URL}/logout/")
    page.goto(f"{URL}/login/?next=/")
    page.fill("input[name=username]", "admin")
    page.fill("input[name=password]", ENV["NETBOX_ADMIN_PASSWORD"])
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle")


def main() -> int:
    print("Compte de secours : clé de sécurité exigée")
    original = CONFIG.read_text()
    r = run(*MANAGE, "auspex_mfa", "reset", "admin")
    check("inscription TOTP de l'administrateur réinitialisée", r.returncode == 0 or "n'est pas inscrit" in r.stderr)
    set_auth("webauthn", True)
    codes: list[str] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            # Le compte de secours n'est accepté que depuis la machine du central : pas
            # d'X-Forwarded-For (la passerelle Docker est alors l'adresse vue par NetBox).
            ctx = browser.new_context(locale="fr-FR")
            page = ctx.new_page()
            cdp = ctx.new_cdp_session(page)
            cdp.send("WebAuthn.enable")
            auth_id = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
                "protocol": "ctap2", "transport": "usb", "hasResidentKey": False,
                "hasUserVerification": True, "isUserVerified": True}})["authenticatorId"]
            errors: list[str] = []
            page.on("pageerror", lambda e: errors.append(str(e)))

            login(page)
            ok = "/mfa/setup/" in page.url and page.is_visible("#webauthn-create")
            check(f"première connexion → inscription de la clé ({page.url.replace(URL, '')})", ok)
            if not ok:
                print("    page affichée : " + " ".join(page.inner_text("body").split())[:400])
                return 1
            page.fill("#nom", "clé USB de la CI")
            page.click("#webauthn-create")
            page.wait_for_selector("#recovery-codes", timeout=20000)
            codes = page.locator("#recovery-codes li").all_inner_texts()
            check(f"clé inscrite, {len(codes)} codes de secours affichés", len(codes) == 10)
            creds = cdp.send("WebAuthn.getCredentials", {"authenticatorId": auth_id})["credentials"]
            check(f"une clé enregistrée dans l'authentificateur ({len(creds)})", len(creds) == 1)

            login(page)
            check("reconnexion → demande de la clé", "/mfa/" in page.url and page.is_visible("#webauthn-get"))
            page.click("#webauthn-get")
            # La clé répond, puis le formulaire part : attendre la navigation, pas le réseau.
            page.wait_for_url(lambda u: "/mfa/" not in u, timeout=30000)
            page.wait_for_load_state("networkidle")
            check(f"connecté avec la clé ({page.url.replace(URL, '') or '/'})", "/mfa/" not in page.url
                  and "/login/" not in page.url)
            sign = cdp.send("WebAuthn.getCredentials", {"authenticatorId": auth_id})["credentials"][0]["signCount"]
            check(f"compteur de signatures de la clé : {sign}", sign >= 2)

            page.goto(f"{URL}/plugins/auspex/mfa/cles/")
            check("page « Mes clés de sécurité »", "clé USB de la CI" in page.inner_text("#webauthn-keys"))
            page.fill("#nom", "même clé")
            page.click("#webauthn-create")
            page.wait_for_selector("#webauthn-error:not([hidden])", timeout=20000)
            check("même clé inscrite deux fois : refusée, message clair",
                  "déjà inscrite" in page.inner_text("#webauthn-error")
                  and page.locator("#webauthn-keys li").count() == 1)
            page.goto(f"{URL}/plugins/auspex/mfa/cles/")
            # Clé de secours = un AUTRE authentificateur : une même clé refuse de s'inscrire deux
            # fois pour le même compte (excludeCredentials), comme une vraie YubiKey (relevé en CI).
            cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": auth_id})
            auth_id = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
                "protocol": "ctap2", "transport": "usb", "hasResidentKey": False,
                "hasUserVerification": True, "isUserVerified": True}})["authenticatorId"]
            page.fill("#nom", "clé de secours")
            page.click("#webauthn-create")
            page.locator("#webauthn-keys li").nth(1).wait_for(timeout=30000)
            check("seconde clé (de secours) ajoutée", page.locator("#webauthn-keys li").count() == 2)

            cdp.send("WebAuthn.clearCredentials", {"authenticatorId": auth_id})
            login(page)
            page.click("#webauthn-get")
            page.wait_for_selector("#webauthn-error:not([hidden])", timeout=20000)
            check("sans la clé : connexion refusée, message affiché", "/mfa/" in page.url
                  and page.inner_text("#webauthn-error").strip())
            page.click("details.recovery summary")
            page.fill("#code", codes[0])
            page.click("details.recovery button[type=submit]")
            page.wait_for_url(lambda u: "/mfa/" not in u, timeout=30000)
            page.wait_for_load_state("networkidle")
            check("dépannage par code de secours", "/mfa/" not in page.url and "/login/" not in page.url)
            check("aucune erreur JavaScript", not errors)
            browser.close()
    finally:
        r = run(*MANAGE, "auspex_mfa", "reset", "admin")
        check("réinitialisation : clés de sécurité révoquées", "2 clé(s) de sécurité révoquée(s)" in r.stdout)
        CONFIG.write_text(original)

    logs = run("docker", "compose", "logs", "--no-color", "--since", "10m", "netbox").stdout
    check("journal : connexion par clé (auspex_mfa_ok, webauthn)",
          re.search(r'"event": "auspex_mfa_ok".*"method": "webauthn"', logs))
    check("journal : clé ajoutée (auspex_webauthn_key_added)", "auspex_webauthn_key_added" in logs)

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
            print(f"::error title=WebAuthn exception::{line}", flush=True)
        rc = 1
    print(f"::notice title=WebAuthn::{sum(ok for _, ok in RESULTS)}/{len(RESULTS)} vérifications réussies",
          flush=True)
    raise SystemExit(rc)
