#!/usr/bin/env python3
"""Preuve « trusted hosts » sur le central complet (exécuté par la CI).

Depuis la machine du central, les requêtes arrivent à NetBox par la passerelle
du réseau interne (172.31.250.1). Cette passerelle est déclarée comme proxy de
confiance : l'en-tête X-Forwarded-For simule alors le poste d'origine.

Usage (dans deploy/) : python ../tools/ci_trusted_hosts.py
"""

from __future__ import annotations

import http.cookiejar
import json
import re
import secrets
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

URL = "http://127.0.0.1:8080"
GATEWAY = "172.31.250.1"
CONFIG = Path("config/auspex.yaml")
ENV = dict(l.split("=", 1) for l in Path(".env").read_text().splitlines() if "=" in l and not l.startswith("#"))
ADMIN, LIBRARIAN = ENV["NETBOX_ADMIN_TOKEN"], ENV["LIBRARIAN_TOKEN"]
RESULTS: list[tuple[str, bool]] = []
# Un refus du plugin porte ce message ; un 403 de NetBox (droits manquants) non.
# Sans cette distinction, un refus pour une autre raison passerait pour un succès.
PLUGIN_DENY = "depuis cette adresse"  # partie ASCII : JsonResponse échappe les accents
DENIED = "refus du plugin"


def check(label: str, ok: bool) -> None:
    ok = bool(ok)
    RESULTS.append((label, ok))
    print(f"  {'OK ' if ok else 'ÉCHEC'}  {label}", flush=True)
    if not ok:  # lisible dans le rapport de la CI (annotations)
        print(f"::error title=Trusted hosts::{label}", flush=True)


def call(token, method, path, body=None, xff=None):
    headers = {"Authorization": f"Token {token}", "Accept": "application/json",
               "Content-Type": "application/json"}
    if xff:
        headers["X-Forwarded-For"] = xff
    req = urllib.request.Request(URL + path, method=method, headers=headers,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        return (DENIED if e.code == 403 and PLUGIN_DENY in body else e.code), body


def write_config(mutate) -> None:
    cfg = yaml.safe_load(CONFIG.read_text())
    mutate(cfg)
    CONFIG.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))
    time.sleep(1.2)  # horodatage du fichier différent : relecture garantie


def session_login(user, password, xff):
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def get(path, ip):
        req = urllib.request.Request(URL + path, headers={"X-Forwarded-For": ip})
        try:
            with opener.open(req, timeout=20) as r:
                return r.status, r.geturl(), r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            return (DENIED if e.code == 403 and PLUGIN_DENY in body else e.code), path, body

    _, _, page = get("/login/", xff)
    csrf = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', page).group(1)
    data = urllib.parse.urlencode({"csrfmiddlewaretoken": csrf, "username": user,
                                   "password": password, "next": "/"}).encode()
    req = urllib.request.Request(URL + "/login/", data=data, headers={"X-Forwarded-For": xff})
    opener.open(req, timeout=20).read()
    return get


def main() -> int:
    print("Mise en place : user1 et ses deux adresses autorisées")
    password = secrets.token_urlsafe(24) + "Aa9"
    user_key = secrets.token_hex(20)
    code, user = call(ADMIN, "POST", "/api/users/users/", {"username": "user1", "password": password})
    check("création de user1 par l'administrateur (depuis la machine du central)", code == 201)
    code, _ = call(ADMIN, "POST", "/api/users/tokens/", {"user": user["id"], "key": user_key})
    check("création du jeton de user1", code == 201)
    # Droit de lecture des adresses IP : sans lui, NetBox refuserait de lui-même.
    code, _ = call(ADMIN, "POST", "/api/users/permissions/", {
        "name": "ci-user1-lecture", "object_types": ["ipam.ipaddress"], "actions": ["view"],
        "users": [user["id"]]})
    check("droit de lecture des adresses IP pour user1", code == 201)
    write_config(lambda c: c["access"].update({
        "trusted_proxies": [GATEWAY],
        "trusted_hosts": [{"user": "user1", "allow": ["10.10.1.2/32", "172.16.20.2/32"]}]}))

    print("Jeton d'API de user1")
    for ip, expected in (("10.10.1.2", 200), ("172.16.20.2", 200), ("10.10.1.3", DENIED), ("8.8.8.8", DENIED)):
        code, _ = call(user_key, "GET", "/api/ipam/ip-addresses/?limit=1", xff=ip)
        check(f"user1 depuis {ip} → HTTP {code} (attendu {expected})", code == expected)
    code, _ = call(user_key, "GET", "/api/ipam/ip-addresses/?limit=1")
    check(f"user1 sans X-Forwarded-For (vu comme la passerelle) → {code} (attendu {DENIED})", code == DENIED)
    code, _ = call(user_key, "POST", "/api/ipam/ip-addresses/",
                   {"address": "10.249.9.9/32", "status": "active"}, xff="8.8.8.8")
    _, found = call(ADMIN, "GET", "/api/ipam/ip-addresses/?address=10.249.9.9/32")
    check(f"écriture refusée ({code}) et rien n'a été créé", code == DENIED and found["count"] == 0)

    print("X-Forwarded-For falsifié depuis une machine qui n'est pas un proxy déclaré")
    spoof = subprocess.run(
        ["docker", "compose", "exec", "-T", "-e", f"K={user_key}", "auspex", "python", "-c",
         "import os,urllib.request,urllib.error\n"
         "r=urllib.request.Request('http://netbox:8080/api/ipam/ip-addresses/?limit=1',headers={"
         "'Authorization':'Token '+os.environ['K'],'X-Forwarded-For':'10.10.1.2'})\n"
         "try: print(urllib.request.urlopen(r,timeout=20).status)\n"
         "except urllib.error.HTTPError as e: print(e.code, e.read().decode())"],
        capture_output=True, text=True, timeout=60)
    out = spoof.stdout.strip()
    code = DENIED if out.startswith("403") and PLUGIN_DENY in out else out[:60]
    check(f"user1 « se disant » 10.10.1.2 depuis le conteneur Auspex → {code} (attendu {DENIED})", code == DENIED)

    print("Session de l'interface web de user1")
    get = session_login("user1", password, "10.10.1.2")
    status, final, _ = get("/ipam/ip-addresses/", "10.10.1.2")
    check(f"page depuis 10.10.1.2 → HTTP {status}, connecté", status == 200 and "/login/" not in final)
    status, _, _ = get("/ipam/ip-addresses/", "8.8.8.8")
    check(f"même session depuis 8.8.8.8 → {status} (attendu {DENIED})", status == DENIED)
    status, final, _ = get("/ipam/ip-addresses/", "10.10.1.2")
    check("après le refus, la session est fermée (retour à la page de connexion)", "/login/" in final)

    print("Comptes particuliers")
    code, _ = call(LIBRARIAN, "GET", "/api/ipam/ip-addresses/?limit=1")
    check(f"Librarian depuis la machine (hors réseau interne) → {code} (attendu {DENIED})", code == DENIED)
    code, _ = call(ADMIN, "GET", "/api/ipam/ip-addresses/?limit=1")
    check(f"brise-glace (admin) depuis la machine du central → HTTP {code} (attendu 200)", code == 200)
    code, _ = call(ADMIN, "GET", "/api/ipam/ip-addresses/?limit=1", xff="8.8.8.8")
    check(f"brise-glace via proxy depuis 8.8.8.8 → {code} (attendu {DENIED})", code == DENIED)

    print("Configuration corrompue : verrouillage, puis retour à la normale")
    good = CONFIG.read_text()
    CONFIG.write_text(good + "\naccess: [ceci n'est pas valide\n")
    time.sleep(1.2)
    code, _ = call(user_key, "GET", "/api/ipam/ip-addresses/?limit=1", xff="10.10.1.2")
    check(f"verrouillage : user1 depuis 10.10.1.2 → {code} (attendu {DENIED})", code == DENIED)
    code, _ = call(ADMIN, "GET", "/api/ipam/ip-addresses/?limit=1")
    check(f"verrouillage : admin depuis la machine du central → HTTP {code} (attendu 200)", code == 200)
    CONFIG.write_text(good)
    time.sleep(1.2)
    code, _ = call(user_key, "GET", "/api/ipam/ip-addresses/?limit=1", xff="10.10.1.2")
    check(f"configuration réparée, sans redémarrage : user1 → HTTP {code} (attendu 200)", code == 200)

    failed = [label for label, ok in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} vérifications réussies")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
