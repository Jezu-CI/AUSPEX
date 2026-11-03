#!/usr/bin/env python3
"""Captures d'écran des écrans d'Auspex sur un central réel (workflow « Captures »).

Parcourt chaque étape comme un utilisateur, avec un vrai navigateur
(Playwright), en clair et en sombre, et écrit les images et un index dans
captures/ (dans deploy/).

Prérequis : central installé et premier cycle passé, Mailpit démarré sur le
réseau du central (port 8025), « sso.ville.test » résolu en 127.0.0.1.
Usage (dans deploy/) : python ../tools/captures.py
"""

from __future__ import annotations

import json
import re
import secrets
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import yaml
from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_mfa import CONFIG, ENV, URL, api, mfa  # noqa: E402

OUT = Path("captures")
CLIENT = "10.20.0.5"
INDEX: list[dict] = []
GATEWAY = "172.31.250.1"


def shot(page, name: str, stage: str, title: str, text: str, full: bool = False) -> None:
    OUT.mkdir(exist_ok=True)
    path = OUT / f"{len(INDEX) + 1:02d}-{name}.png"
    page.screenshot(path=str(path), full_page=full)
    INDEX.append({"file": path.name, "stage": stage, "title": title, "text": text})
    print(f"  capture {path.name} — {title}", flush=True)


def context(browser, dark: bool = False, xff: str | None = CLIENT):
    ctx = browser.new_context(viewport={"width": 1280, "height": 860}, locale="fr-FR",
                              color_scheme="dark" if dark else "light",
                              extra_http_headers={"X-Forwarded-For": xff} if xff else {})
    # Thème de NetBox : mémorisé dans le navigateur.
    ctx.add_init_script(f"try {{ localStorage.setItem('netbox-color-mode', '{'dark' if dark else 'light'}'); }} catch (e) {{}}")
    return ctx


def login(page, user: str, password: str) -> None:
    page.goto(f"{URL}/login/?next=/")
    page.fill("input[name=username]", user)
    page.fill("input[name=password]", password)
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle")


def totp_from_page(page) -> str:
    secret = page.inner_text("#secret").replace(" ", "")
    return secret


def submit_code(page, code: str) -> None:
    page.fill("#code", code)
    page.click("form button[type=submit]")
    page.wait_for_load_state("networkidle")


def user(name: str, password: str, email: str = "", superuser: bool = False) -> int:
    code, u = api("POST", "/api/users/users/", {"username": name, "password": password, "email": email,
                                                "is_superuser": superuser})
    if code != 201:
        raise SystemExit(f"création de {name} : HTTP {code}")
    api("POST", "/api/users/permissions/", {"name": f"captures-{name}", "object_types": ["ipam.ipaddress"],
                                           "actions": ["view"], "users": [u["id"]]})
    return u["id"]


def configure() -> None:
    cfg = yaml.safe_load(CONFIG.read_text())
    cfg["access"]["trusted_proxies"] = [GATEWAY]
    cfg["access"]["trusted_hosts"] = [{"user": u, "allow": ["10.20.0.0/24"]}
                                      for u in ("agent", "agent2", "verrou", "local-sso")]
    cfg["auth"]["break_glass"]["allow"] = ["10.20.0.0/24"]
    cfg["auth"]["mfa"] = {"methods": ["totp", "email"],
                          "email": {"smtp_server": "mailpit", "port": 1025, "security": "none",
                                    "from": "auspex@ville.test"}}
    CONFIG.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))
    time.sleep(1.5)


def mailpit_last(address: str) -> str | None:
    with urllib.request.urlopen("http://127.0.0.1:8025/api/v1/messages", timeout=10) as r:
        for m in json.loads(r.read())["messages"]:
            if any(t["Address"] == address for t in m.get("To") or []):
                return m["ID"]
    return None


def local_screens(browser) -> None:
    pw = {n: secrets.token_urlsafe(14) for n in ("agent", "agent2", "verrou")}
    user("agent", pw["agent"], "agent@ville.test")
    user("agent2", pw["agent2"], "jean.dupont@ville.test")
    user("verrou", pw["verrou"], "verrou@ville.test")
    configure()

    # --- Trusted hosts ---------------------------------------------------------------
    ctx = context(browser, xff="8.8.8.8")
    page = ctx.new_page()
    login(page, "agent", pw["agent"])
    shot(page, "trusted-hosts-refus", "Trusted hosts", "Connexion refusée hors des adresses autorisées",
         "agent n'est autorisé que depuis 10.20.0.0/24 ; depuis 8.8.8.8, la requête est refusée avant toute "
         "action et la session fermée.")
    ctx.close()

    # --- MFA : choix, QR code, codes de secours, vérification ---------------------------
    # Mode sombre d'abord : l'inscription n'est terminée qu'au passage en clair.
    for dark in (True, False):
        ctx = context(browser, dark=dark)
        page = ctx.new_page()
        page.goto(f"{URL}/login/")
        if not dark:
            shot(page, "connexion", "Connexion", "Page de connexion de NetBox", "Comptes locaux uniquement.")
        login(page, "agent", pw["agent"])
        suffix = "-sombre" if dark else ""
        shot(page, f"mfa-choix{suffix}", "Double authentification", "Choix de la méthode"
             + (" (mode sombre)" if dark else ""),
             "Première connexion : application d'authentification (recommandée) ou code par e-mail.")
        page.click("#choose-totp")
        page.wait_for_load_state("networkidle")
        shot(page, f"mfa-qr{suffix}", "Double authentification", "Inscription : QR code"
             + (" (mode sombre)" if dark else ""),
             "Le QR code se scanne avec Aegis, FreeOTP, Google ou Microsoft Authenticator, KeePassXC… "
             "La clé reste lisible pour une saisie à la main.", full=True)
        if dark:
            ctx.close()
            continue
        secret = totp_from_page(page)
        submit_code(page, mfa.totp(secret))
        shot(page, "mfa-codes-secours", "Double authentification", "Codes de secours",
             "Dix codes à usage unique, montrés une seule fois.", full=True)
        ctx.close()
        # connexion suivante
        ctx = context(browser)
        page = ctx.new_page()
        login(page, "agent", pw["agent"])
        page.fill("#code", "123456")
        page.click("form button[type=submit]")
        page.wait_for_load_state("networkidle")
        shot(page, "mfa-code-incorrect", "Double authentification", "Connexion suivante : code demandé",
             "Code de l'application ou code de secours ; ici un code incorrect.")
        ctx.close()

    # --- Verrouillage -------------------------------------------------------------------
    ctx = context(browser)
    page = ctx.new_page()
    login(page, "verrou", pw["verrou"])
    page.click("#choose-totp")
    page.wait_for_load_state("networkidle")
    submit_code(page, mfa.totp(totp_from_page(page)))
    ctx.close()
    ctx = context(browser)
    page = ctx.new_page()
    login(page, "verrou", pw["verrou"])
    for _ in range(6):
        page.fill("#code", "000000")
        page.click("form button[type=submit]")
        page.wait_for_load_state("networkidle")
    shot(page, "mfa-verrouillage", "Double authentification", "Verrouillage après 5 échecs",
         "5 minutes, puis 10, 20… jusqu'à 24 h tant qu'aucune connexion ne réussit. Chaque échec est journalisé.")
    ctx.close()

    # --- Code par e-mail -------------------------------------------------------------------
    ctx = context(browser)
    page = ctx.new_page()
    login(page, "agent2", pw["agent2"])
    page.click("#choose-email")
    page.wait_for_load_state("networkidle")
    shot(page, "mfa-email", "Double authentification", "Code par e-mail",
         "Pour les équipes sans téléphone professionnel : code de 8 chiffres, valable 10 minutes. "
         "L'adresse est masquée à l'écran.")
    time.sleep(2)
    mid = mailpit_last("jean.dupont@ville.test")
    if mid:
        with urllib.request.urlopen(f"http://127.0.0.1:8025/api/v1/message/{mid}", timeout=10) as r:
            msg = json.loads(r.read())
        import html
        mp = ctx.new_page()
        mp.set_content(f"""<html><body style="font:15px system-ui;margin:40px;max-width:720px">
          <div style="color:#555">De : {html.escape(msg['From']['Address'])}<br>À : jean.dupont@ville.test<br>
          Objet : <b>{html.escape(msg['Subject'])}</b></div><hr>
          <pre style="font:15px system-ui;white-space:pre-wrap">{html.escape(msg['Text'])}</pre></body></html>""")
        shot(mp, "mfa-email-message", "Double authentification", "Message reçu",
             "Le message indique l'adresse du poste qui se connecte et quoi faire si ce n'est pas vous.")
    ctx.close()


def admin_screens(browser) -> None:
    for dark in (False, True):
        ctx = context(browser, dark=dark)
        page = ctx.new_page()
        login(page, "admin", ENV["NETBOX_ADMIN_PASSWORD"])
        if "/setup/" in page.url:
            secret = totp_from_page(page)
            submit_code(page, mfa.totp(secret))
            Path("captures-admin-secret").write_text(secret)
        else:
            secret = Path("captures-admin-secret").read_text()
            while True:  # code de la période suivante (anti-rejeu)
                time.sleep(1)
                if int(time.time()) % 30 == 1:
                    break
            submit_code(page, mfa.totp(secret))
        page.goto(f"{URL}/")
        page.wait_for_load_state("networkidle")
        time.sleep(1.5)
        suffix, label = ("-sombre", " (mode sombre)") if dark else ("", "")
        shot(page, f"tableau-de-bord{suffix}", "Tableau de bord", "Accueil de NetBox avec les widgets Auspex" + label,
             "Écarts ouverts, état du service, inventaire observé, matrice des zones. Chacun réorganise son "
             "tableau (ajout, retrait, déplacement, taille).", full=True)
        page.goto(f"{URL}/plugins/auspex/ecarts/")
        page.wait_for_load_state("networkidle")
        shot(page, f"ecarts{suffix}", "Tableau de bord", "Page « Écarts de conformité »" + label,
             "Tous les écarts ouverts, filtrables par gravité, origine, zone et recherche libre.", full=True)
        map_screens(page, suffix, label)
        if not dark:
            audit_screens(browser, page)
        ctx.close()


def audit_screens(browser, page) -> None:
    """Export d'audit NIS2 produit par le central, page NetBox et rapport."""
    import yaml
    import zipfile
    cfg_path = Path("config/auspex.yaml")
    cfg = yaml.safe_load(cfg_path.read_text())
    cfg["organisation"] = "Ville de Démo"
    cfg_path.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))
    for fw in ("iec62443", "nis2"):
        r = subprocess.run(["docker", "compose", "exec", "-T", "auspex", "auspex", "-c", "/etc/auspex/auspex.yaml",
                            "audit", "export", fw], capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"export d'audit {fw} : {r.stdout}{r.stderr}")
    page.goto(f"{URL}/plugins/auspex/audits/")
    page.wait_for_load_state("networkidle")
    shot(page, "audits", "Exports d'audit", "Page « Exports d'audit »",
         "Exports signés par référentiel, produits par le service ou à la demande ; empreinte de la clé à "
         "communiquer à l'auditeur, commandes de vérification sans Auspex.")
    archive = max(Path("data/state/tableau/audits").glob("auspex-audit-nis2-*.zip"), key=lambda p: p.stat().st_mtime)
    with zipfile.ZipFile(archive) as z:
        member = next(n for n in z.namelist() if n.endswith("/rapport.html"))
        report = OUT / "rapport-nis2.html"
        report.write_bytes(z.read(member))
    rp = browser.new_page(viewport={"width": 1280, "height": 860})
    rp.goto(report.resolve().as_uri())
    shot(rp, "rapport-synthese", "Exports d'audit", "Rapport NIS2 : synthèse",
         "Constat par exigence (écarts ouverts, sans écart, preuve, non évalué), périmètre observé, "
         "couverture des flux par les règles.")
    rp.evaluate("document.querySelector('section.control').scrollIntoView()")
    shot(rp, "rapport-exigence", "Exports d'audit", "Rapport NIS2 : exigence par exigence",
         "Pour chaque exigence : apport d'Auspex, ce qui reste hors périmètre, écarts avec chemin, gravité "
         "et dates d'observation.")
    rp.close()
    report.unlink()


def map_screens(page, suffix: str, label: str) -> None:
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    page.goto(f"{URL}/plugins/auspex/carte/")
    page.wait_for_selector("#auspex-map.ready", timeout=20000)
    time.sleep(0.5)
    shot(page, f"carte{suffix}", "Carte", "Carte interactive des actifs" + label,
         "Zones de gestion (tiers) à gauche, zones industrielles (Purdue) à droite ; flux observés agrégés, "
         "en rouge ceux en écart. Zoom à la molette, déplacement à la souris.")
    if not suffix:
        page.locator(".auspex-map-svg .node:has(.halo)").first.click()
        time.sleep(0.4)
        shot(page, "carte-selection", "Carte", "Détail d'un actif sélectionné",
             "Identification, écarts et flux de l'actif ; chaque flux mène à l'actif d'en face.")
        page.evaluate("window.auspexMap.clear()")
        page.locator("#auspex-map-issues").check()
        time.sleep(0.4)
        shot(page, "carte-ecarts", "Carte", "Filtre « Écarts seulement »",
             "Seuls les flux en écart et les actifs concernés restent en avant.")
    if errors:
        raise RuntimeError(f"erreurs JavaScript sur la carte : {errors}")


def sso_screens(browser) -> None:
    print("Passage en connexion unique (OIDC, Keycloak)", flush=True)
    r = subprocess.run([sys.executable, str(Path(__file__).parent / "ci_oidc.py")], capture_output=True, text=True)
    print(r.stdout[-1500:], r.stderr[-800:], flush=True)
    creds = json.loads(Path("oidc-ci/saml-users.json").read_text())
    pw_local = secrets.token_urlsafe(14) + "Aa9"
    user("local-sso", pw_local)
    cfg = yaml.safe_load(CONFIG.read_text())
    cfg["access"]["trusted_hosts"].append({"user": "local-sso", "allow": ["10.20.0.0/24"]})
    CONFIG.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))
    time.sleep(1.5)

    ctx = browser.new_context(viewport={"width": 1280, "height": 860}, locale="fr-FR", ignore_https_errors=False,
                              extra_http_headers={"X-Forwarded-For": CLIENT})
    page = ctx.new_page()
    page.goto(f"{URL}/login/")
    shot(page, "sso-connexion", "Connexion unique", "Page de connexion avec le bouton SSO",
         "auth.primary: oidc — bouton « Keycloak » ; le formulaire local reste pour le brise-glace.")
    ctx.close()

    # Refus SSO (oidc2, hors du groupe exigé) — l'autorité CI n'est pas connue du navigateur.
    ctx = browser.new_context(viewport={"width": 1280, "height": 860}, locale="fr-FR", ignore_https_errors=True,
                              extra_http_headers={"X-Forwarded-For": CLIENT})
    page = ctx.new_page()
    page.goto(f"{URL}/oauth/login/oidc/?next=/")
    page.wait_for_load_state("networkidle")
    shot(page, "sso-fournisseur", "Connexion unique", "Page du fournisseur d'identité",
         "Redirection vers le fournisseur (ici Keycloak) ; sa propre MFA s'applique.")
    page.fill("input[name=username]", "oidc2")
    page.fill("input[name=password]", creds["saml2"])
    page.click("#kc-login")
    page.wait_for_load_state("networkidle")
    shot(page, "sso-refus", "Connexion unique", "Refus : hors du groupe exigé",
         "Page de refus propre, sans détail technique ; l'événement auspex_sso_refused est journalisé.")
    ctx.close()

    ctx = context(browser)
    page = ctx.new_page()
    login(page, "local-sso", pw_local)
    shot(page, "compte-local-refuse", "Connexion unique", "Compte local refusé",
         "Avec une méthode principale, seul le brise-glace peut encore se connecter en local.")
    ctx.close()


def main() -> int:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        local_screens(browser)
        admin_screens(browser)
        sso_screens(browser)
        browser.close()
    (OUT / "index.json").write_text(json.dumps(INDEX, ensure_ascii=False, indent=1))
    print(f"{len(INDEX)} captures", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
