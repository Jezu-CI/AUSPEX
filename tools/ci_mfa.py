#!/usr/bin/env python3
"""Preuve « double authentification » sur le central complet (exécuté par la CI).

Un utilisateur local se connecte à l'interface de NetBox, avec une vraie
application d'authentification simulée (auspex.mfa calcule les codes).

Usage (dans deploy/, après ci_trusted_hosts.py) : python ../tools/ci_mfa.py
"""

from __future__ import annotations

import http.cookiejar
import json
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from auspex import mfa  # noqa: E402

URL = "http://127.0.0.1:8080"
GATEWAY = "172.31.250.1"
CLIENT = "10.20.0.5"           # poste autorisé pour mfa1 (via la passerelle, proxy déclaré)
CONFIG = Path("config/auspex.yaml")
ENV = dict(l.split("=", 1) for l in Path(".env").read_text().splitlines() if "=" in l and not l.startswith("#"))
ADMIN = ENV["NETBOX_ADMIN_TOKEN"]
MFA_PATH = "/plugins/auspex/mfa/"
SETUP_PATH = "/plugins/auspex/mfa/setup/"
PAGE = "/ipam/ip-addresses/"
MAILPIT = "http://127.0.0.1:8025"   # serveur de messagerie de test (CI), API de lecture
RESULTS: list[tuple[str, bool]] = []
COMMAND_OUTPUT: list[str] = []  # journal des actions d'administration (processus manage.py)


def check(label: str, ok: bool) -> None:
    ok = bool(ok)
    RESULTS.append((label, ok))
    print(f"  {'OK ' if ok else 'ÉCHEC'}  {label}", flush=True)
    if not ok:
        print(f"::error title=MFA::{label}", flush=True)


def api(method, path, body=None):
    req = urllib.request.Request(URL + path, method=method, data=json.dumps(body).encode() if body else None,
                                 headers={"Authorization": f"Token {ADMIN}", "Accept": "application/json",
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, None


class Browser:
    """Navigateur minimal : cookies, redirections, jeton CSRF des formulaires."""

    def __init__(self, xff: str | None = CLIENT):
        self.xff = xff  # None : connexion directe depuis la machine du central
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def open(self, path, data=None, headers=None):
        h = {**({"X-Forwarded-For": self.xff} if self.xff else {}), **(headers or {})}
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(URL + path, data=body, headers=h)
        try:
            with self.opener.open(req, timeout=20) as r:
                return r.status, urllib.parse.urlparse(r.geturl()).path, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, urllib.parse.urlparse(e.geturl()).path, e.read().decode("utf-8", "replace")

    @staticmethod
    def csrf(page):
        m = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', page)
        return m.group(1) if m else ""

    def login(self, user, password):
        _, _, page = self.open("/login/")
        return self.open("/login/", {"csrfmiddlewaretoken": self.csrf(page), "username": user,
                                     "password": password, "next": PAGE})

    def submit_code(self, path, code):
        _, _, page = self.open(path + "?next=" + PAGE)
        return self.open(path, {"csrfmiddlewaretoken": self.csrf(page), "code": code, "next": PAGE})


def wait_next_period(counter: int) -> None:
    """Attend la période TOTP suivante (un code déjà utilisé n'est plus accepté)."""
    while mfa.counter_at() <= counter:
        time.sleep(1)


def manage(*args):
    r = subprocess.run(["docker", "compose", "exec", "-T", "netbox", "/opt/netbox/venv/bin/python",
                        "/opt/netbox/netbox/manage.py", "auspex_mfa", *args], capture_output=True, text=True, timeout=120)
    COMMAND_OUTPUT.append(r.stdout + r.stderr)
    return r


def mailbox(address: str) -> list[str]:
    """Textes des messages reçus par `address`, du plus récent au plus ancien."""
    with urllib.request.urlopen(MAILPIT + "/api/v1/messages", timeout=20) as r:
        messages = json.loads(r.read())["messages"]
    out = []
    for m in messages:
        if any(t["Address"] == address for t in m.get("To") or []):
            with urllib.request.urlopen(f"{MAILPIT}/api/v1/message/{m['ID']}", timeout=20) as r:
                out.append(json.loads(r.read())["Text"])
    return out


def mail_code(address: str, previous: int) -> tuple[str, str]:
    """Attend un nouveau message et renvoie (code, texte)."""
    for _ in range(30):
        texts = mailbox(address)
        if len(texts) > previous:
            return re.search(r"\b(\d{8})\b", texts[0]).group(1), texts[0]
        time.sleep(1)
    return "", ""


def email_scenario() -> None:
    print("Code par e-mail (équipes sans téléphone professionnel)")
    address = "mfa2@exemple.test"
    password = secrets.token_urlsafe(24) + "Aa9"
    code, user = api("POST", "/api/users/users/", {"username": "mfa2", "password": password, "email": address})
    check("création de mfa2, avec son adresse e-mail", code == 201)
    api("POST", "/api/users/permissions/", {"name": "ci-mfa2-lecture", "object_types": ["ipam.ipaddress"],
                                           "actions": ["view"], "users": [user["id"]]})
    cfg = yaml.safe_load(CONFIG.read_text())
    cfg["access"]["trusted_hosts"].append({"user": "mfa2", "allow": ["10.20.0.0/24"]})
    cfg.setdefault("auth", {"break_glass": {"user": "admin", "mfa": "totp"}})
    cfg["auth"]["mfa"] = {"methods": ["totp", "email"],
                          "email": {"smtp_server": "mailpit", "port": 1025, "security": "none",
                                    "from": "auspex@exemple.test"}}
    CONFIG.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))
    time.sleep(1.2)

    b = Browser()
    _, where, page = b.login("mfa2", password)
    check("choix proposé : application ou e-mail",
          where == SETUP_PATH and 'id="choose-totp"' in page and 'id="choose-email"' in page)
    _, _, page = b.open(SETUP_PATH + "?method=email&next=" + PAGE)
    first, text = mail_code(address, 0)
    check("code reçu par e-mail (8 chiffres)", len(first) == 8)
    check(f"l'e-mail indique l'adresse du poste ({CLIENT})", CLIENT in text)
    check("adresse masquée sur la page", "m***@exemple.test" in page and address not in page)
    status, _, page = b.open(SETUP_PATH, {"csrfmiddlewaretoken": b.csrf(page), "code": first, "next": PAGE})
    check("inscription par e-mail confirmée, codes de secours affichés",
          status == 200 and 'id="recovery-codes"' in page)
    status, where, _ = b.open(PAGE)
    check(f"page de NetBox → HTTP {status} {where}", status == 200 and where == PAGE)

    print("  (attente d'une minute : un envoi par minute au plus)")
    time.sleep(62)
    b = Browser()
    _, where, page = b.login("mfa2", password)
    second, _ = mail_code(address, 1)
    check("connexion suivante : nouveau code envoyé automatiquement", where == MFA_PATH and len(second) == 8)
    status, _, page = b.open(MFA_PATH, {"csrfmiddlewaretoken": b.csrf(page), "code": first, "next": PAGE})
    check(f"ancien code (déjà utilisé) → HTTP {status} (attendu 403)", status == 403)
    status, where, _ = b.open(MFA_PATH, {"csrfmiddlewaretoken": b.csrf(page), "code": second, "next": PAGE})
    check(f"nouveau code → {where} (attendu {PAGE})", where == PAGE)
    Browser().login("mfa2", password)   # nouvelle session tout de suite après : pas de nouvel envoi
    time.sleep(2)
    check("pas de nouvel envoi avant une minute, même dans une autre session", len(mailbox(address)) == 2)


def main() -> int:
    print("Mise en place : mfa1, compte local, autorisé depuis 10.20.0.0/24")
    password = secrets.token_urlsafe(24) + "Aa9"
    code, user = api("POST", "/api/users/users/", {"username": "mfa1", "password": password})
    check("création de mfa1", code == 201)
    code, _ = api("POST", "/api/users/permissions/", {"name": "ci-mfa1-lecture", "object_types": ["ipam.ipaddress"],
                                                      "actions": ["view"], "users": [user["id"]]})
    check("droit de lecture des adresses IP pour mfa1", code == 201)
    cfg = yaml.safe_load(CONFIG.read_text())
    acc = cfg.setdefault("access", {})
    acc["trusted_proxies"] = sorted(set((acc.get("trusted_proxies") or []) + [GATEWAY]))
    acc["trusted_hosts"] = (acc.get("trusted_hosts") or []) + [{"user": "mfa1", "allow": ["10.20.0.0/24"]}]
    CONFIG.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))
    time.sleep(1.2)

    print("Première connexion : inscription obligatoire")
    b = Browser()
    status, where, _ = b.login("mfa1", password)
    check(f"après le mot de passe → {where} (attendu {SETUP_PATH})", where == SETUP_PATH)
    status, where, _ = b.open(PAGE)
    check(f"page de NetBox avant la MFA → {where} (attendu l'inscription)", where == SETUP_PATH)
    status, _, body = b.open("/api/ipam/ip-addresses/?limit=1", headers={"Accept": "application/json"})
    check(f"API avec la session avant la MFA → HTTP {status} (attendu 403)",
          status == 403 and "Double authentification" in body)
    _, _, page = b.open(SETUP_PATH)
    m = re.search(r'id="secret">([A-Z2-7 ]+)<', page)
    check("secret affiché pour l'application", m is not None)
    secret = m.group(1).replace(" ", "") if m else "A" * 32
    status, _, _ = b.submit_code(SETUP_PATH, "000000")
    check(f"inscription avec un mauvais code → HTTP {status} (attendu 403)", status == 403)
    enrolled_at = mfa.counter_at()
    status, _, page = b.submit_code(SETUP_PATH, mfa.hotp(mfa._key(secret), enrolled_at))
    codes = re.findall(r"<li>([a-z0-9]{5}-[a-z0-9]{5})</li>", page)
    check(f"inscription confirmée, {len(codes)} codes de secours (attendu 10)", status == 200 and len(codes) == 10)
    status, where, _ = b.open(PAGE)
    check(f"page de NetBox après la MFA → HTTP {status} {where}", status == 200 and where == PAGE)

    print("Connexion suivante : code de l'application")
    b = Browser()
    _, where, _ = b.login("mfa1", password)
    check(f"après le mot de passe → {where} (attendu {MFA_PATH})", where == MFA_PATH)
    # Le code exact de l'inscription (encore dans la fenêtre de tolérance) : rejeu.
    status, _, _ = b.submit_code(MFA_PATH, mfa.hotp(mfa._key(secret), enrolled_at))
    check(f"rejeu du code de l'inscription → HTTP {status} (attendu 403)", status == 403)
    wait_next_period(max(enrolled_at, mfa.counter_at()))
    status, where, _ = b.submit_code(MFA_PATH, mfa.totp(secret))
    check(f"code valide → {where} (attendu {PAGE})", status == 200 and where == PAGE)
    used = mfa.counter_at()
    b2 = Browser()
    b2.login("mfa1", password)
    status, _, _ = b2.submit_code(MFA_PATH, mfa.hotp(mfa._key(secret), used))
    check(f"même code dans une autre session → HTTP {status} (attendu 403, anti-rejeu)", status == 403)

    print("Codes de secours")
    b = Browser()
    b.login("mfa1", password)
    status, where, _ = b.submit_code(MFA_PATH, codes[0])
    check(f"code de secours → {where} (attendu {PAGE})", where == PAGE)
    b = Browser()
    b.login("mfa1", password)
    status, _, _ = b.submit_code(MFA_PATH, codes[0])
    check(f"même code de secours une 2e fois → HTTP {status} (attendu 403)", status == 403)

    print("Verrouillage après 5 échecs, puis déverrouillage par un administrateur")
    b = Browser()
    b.login("mfa1", password)
    for _ in range(4):
        b.submit_code(MFA_PATH, "000000")
    b.submit_code(MFA_PATH, "000000")
    status, _, _ = b.submit_code(MFA_PATH, mfa.totp(secret))
    check(f"bon code pendant le verrouillage → HTTP {status} (attendu 429)", status == 429)
    r = manage("status")
    check("manage.py auspex_mfa status : mfa1 verrouillé", "mfa1" in r.stdout and "verrouillé" in r.stdout)
    r = manage("unlock", "mfa1")
    check("manage.py auspex_mfa unlock mfa1", r.returncode == 0)
    wait_next_period(mfa.counter_at())
    status, where, _ = b.submit_code(MFA_PATH, mfa.totp(secret))
    check(f"après déverrouillage → {where} (attendu {PAGE})", where == PAGE)

    print("Téléphone perdu : réinitialisation, nouvelle inscription")
    r = manage("reset", "mfa1")
    check("manage.py auspex_mfa reset mfa1", r.returncode == 0)
    b = Browser()
    _, where, _ = b.login("mfa1", password)
    check(f"connexion suivante → {where} (attendu {SETUP_PATH})", where == SETUP_PATH)
    _, _, page = b.open(SETUP_PATH)
    m = re.search(r'id="secret">([A-Z2-7 ]+)<', page)
    new_secret = m.group(1).replace(" ", "") if m else ""
    status, _, _ = b.submit_code(SETUP_PATH, mfa.totp(new_secret)) if new_secret else (0, "", "")
    check("nouvelle inscription, nouveau secret", status == 200 and new_secret and new_secret != secret)

    email_scenario()

    print("Ce qui n'est pas concerné")
    code, _ = api("GET", "/api/ipam/ip-addresses/?limit=1")
    check(f"jeton d'API (administrateur) : pas de MFA → HTTP {code}", code == 200)

    print("Journal de sécurité")
    logs = subprocess.run(["docker", "compose", "logs", "--no-color", "netbox"], capture_output=True,
                          text=True, timeout=60).stdout
    for event in ("auspex_mfa_enrolled", "auspex_mfa_ok", "auspex_mfa_failed", "auspex_mfa_locked",
                  "auspex_mfa_refused_locked", "auspex_mfa_email_sent"):
        check(f"événement {event} journalisé par NetBox", f'"event": "{event}"' in logs)
    admin = "".join(COMMAND_OUTPUT)
    for event in ("auspex_mfa_unlock", "auspex_mfa_reset"):
        check(f"événement {event} journalisé par la commande d'administration", f'"event": "{event}"' in admin)
    check("aucun secret, code de secours ni adresse e-mail complète dans le journal",
          secret not in logs and new_secret not in logs and not any(c in logs for c in codes)
          and "mfa2@exemple.test" not in logs)

    failed = [label for label, ok in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} vérifications réussies")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
