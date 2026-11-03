#!/usr/bin/env python3
"""Preuve « connexion par carte à puce » sur le central complet (exécuté par la CI).

PKI de test (openssl) : une autorité de cartes, des certificats d'agents
(UPN Microsoft, comme les cartes d'ouverture de session), un certificat
révoqué (liste de révocation), une autorité pirate. Connexions avec curl et
le certificat client, à travers le vrai front HTTPS (nginx) et le vrai
NetBox : session ouverte sans double authentification pour une carte
valide ; refus motivés et journalisés sinon ; en-têtes forgés directement
sur NetBox ou par le site principal refusés.

Usage (dans deploy/) : python ../tools/ci_carte.py
"""

from __future__ import annotations

import json
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_mfa import CONFIG, api  # noqa: E402

WORK = Path("carte-ci").resolve()
MAIN, CARD = "https://localhost", "https://localhost:8443"
GATEWAY = "172.31.250.1"
STATE = Path("data/state")
RESULTS: list[tuple[str, bool]] = []


def check(label: str, ok) -> None:
    ok = bool(ok)
    RESULTS.append((label, ok))
    print(f"  {'OK ' if ok else 'ÉCHEC'}  {label}", flush=True)


def run(*cmd, cwd=WORK, check_rc=True) -> subprocess.CompletedProcess:
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, timeout=120)
    if check_rc and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} : {r.stderr.strip()[-300:]}")
    return r


def pki() -> None:
    WORK.mkdir(exist_ok=True)
    # Noms distincts de ceux des cartes : l'AC pirate et la carte « pirate » écrasaient
    # mutuellement leurs fichiers (relevé en CI).
    for name in ("ac", "ac-pirate"):
        run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-days", "30", "-subj", f"/CN=AC Cartes {name}", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", f"{name}.key", "-out", f"{name}.crt")
    (WORK / "index.txt").write_text("")
    (WORK / "crlnumber").write_text("01\n")
    (WORK / "ca.cnf").write_text("""[ca]
default_ca = ac
[ac]
database = index.txt
crlnumber = crlnumber
certificate = ac.crt
private_key = ac.key
default_md = sha256
default_crl_days = 7
""")
    for user, ca in (("carte1", "ac"), ("carte2", "ac"), ("carte3", "ac"), ("admin", "ac"), ("pirate", "ac-pirate")):
        upn = "carte1" if user == "pirate" else user
        (WORK / f"{user}.ext").write_text(
            f"subjectAltName=otherName:1.3.6.1.4.1.311.20.2.3;UTF8:{upn}@ville.test,email:{upn}@ville.test\n"
            "extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\n")
        run("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-subj", f"/CN={upn}", "-keyout", f"{user}.key", "-out", f"{user}.csr")
        run("openssl", "x509", "-req", "-in", f"{user}.csr", "-CA", f"{ca}.crt", "-CAkey", f"{ca}.key",
            "-CAcreateserial", "-days", "30", "-sha256", "-extfile", f"{user}.ext", "-out", f"{user}.crt")
    run("openssl", "ca", "-config", "ca.cnf", "-revoke", "carte2.crt", "-batch")
    run("openssl", "ca", "-config", "ca.cnf", "-gencrl", "-out", "lcr.pem", "-batch")


def curl(url: str, user: str | None = None, jar: str | None = None, headers=(), follow=True) -> tuple[int, str, str]:
    cmd = ["curl", "-sk", "-o", str(WORK / "page.html"), "-w", "%{http_code} %{url_effective}", "--max-time", "30"]
    if follow:
        cmd.append("-L")
    if user:
        cmd += ["--cert", str(WORK / f"{user}.crt"), "--key", str(WORK / f"{user}.key")]
    if jar:
        cmd += ["-c", str(WORK / jar), "-b", str(WORK / jar)]
    for h in headers:
        cmd += ["-H", h]
    r = run(*cmd, url, check_rc=False)
    code, _, final = r.stdout.partition(" ")
    page = (WORK / "page.html").read_text(errors="replace") if (WORK / "page.html").exists() else ""
    return int(code or 0), final, page


def main() -> int:
    print("PKI de test et configuration")
    pki()
    tls = Path("config/tls")
    (tls / "cartes-ac.pem").write_bytes((WORK / "ac.crt").read_bytes())
    (tls / "cartes-lcr.pem").write_bytes((WORK / "lcr.pem").read_bytes())
    for name in ("carte1", "carte2"):
        api("POST", "/api/users/users/", {"username": name, "password": secrets.token_urlsafe(24) + "Aa9"})
    original = CONFIG.read_text()
    cfg = yaml.safe_load(original)
    cfg["auth"]["carte"] = {"adresse": CARD, "autorites": "tls/cartes-ac.pem", "revocation": "tls/cartes-lcr.pem",
                            "identifiant": "upn_court"}
    hosts = cfg.setdefault("access", {}).setdefault("trusted_hosts", [])
    hosts += [{"user": u, "allow": [f"{GATEWAY}/32"]} for u in ("carte1", "carte2", "carte3")]
    CONFIG.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))
    try:
        for _ in range(30):
            conf = STATE / "acces" / "carte.conf"
            if conf.exists() and conf.stat().st_size > 0:
                break
            time.sleep(3)
        check("bloc du port carte écrit par le service (data/state/acces/carte.conf)",
              (STATE / "acces" / "carte.conf").exists() and (STATE / "acces" / "carte.conf").stat().st_size > 0)
        logs = ""
        for _ in range(20):
            logs = run("docker", "compose", "logs", "--no-color", "acces", cwd=None, check_rc=False).stdout
            if "port carte actif" in logs:
                break
            time.sleep(3)
        check("front HTTPS rechargé, port carte actif", "port carte actif" in logs)
        run("docker", "compose", "up", "-d", "--force-recreate", "netbox", cwd=None)
        for _ in range(60):
            code, _, page = curl(f"{MAIN}/login/")
            if code == 200:
                break
            time.sleep(5)

        print("Front HTTPS")
        hsts = run("curl", "-skI", f"{MAIN}/login/", check_rc=False).stdout
        check(f"site principal en HTTPS → HTTP {code}, HSTS", code == 200 and "strict-transport-security" in hsts.lower())
        check("bouton « Connexion par carte à puce » sur la page de connexion",
              'id="auspex-carte"' in page and f"{CARD}/plugins/auspex/carte-a-puce/" in page)

        print("Connexions par carte")
        code, final, page = curl(f"{CARD}/plugins/auspex/carte-a-puce/?next=/", "carte1", jar="c1.jar")
        check(f"carte valide → session ouverte ({code} {final})", code == 200 and final.rstrip("/") == MAIN
              and "carte1" in page and "/mfa/" not in final)
        code, final, page = curl(f"{MAIN}/plugins/auspex/ecarts/", jar="c1.jar", follow=False)
        check(f"session valable sur le site principal, sans double authentification → HTTP {code}",
              code in (200, 403) and "/mfa/" not in page[:2000])
        for user, label, needle in (
                (None, "sans carte", "non vérifié"),
                ("carte2", "carte révoquée", "non vérifié"),
                ("pirate", "carte d'une autre autorité", "non vérifié"),
                ("carte3", "carte sans compte Auspex", "aucun compte"),
                ("admin", "carte au nom de l'administrateur local", "administration local")):
            code, final, page = curl(f"{CARD}/plugins/auspex/carte-a-puce/", user, jar=f"refus-{user}.jar")
            check(f"{label} → HTTP {code}, refus motivé", code == 403 and needle in page.lower())

        print("En-têtes forgés")
        cert = quote((WORK / "carte1.crt").read_text(), safe="")
        forged = (f"X-Auspex-Carte: {cert}", "X-Auspex-Carte-Verif: SUCCESS", "X-Auspex-Proxy: " + "0" * 64)
        code, _, page = curl("http://127.0.0.1:8080/plugins/auspex/carte-a-puce/", headers=forged, jar="f1.jar")
        check(f"directement sur NetBox (sans le front) → HTTP {code}", code == 403 and "hors du front" in page.lower())
        code, _, page = curl(f"{MAIN}/plugins/auspex/carte-a-puce/", headers=forged, jar="f2.jar")
        check(f"par le site principal (en-têtes effacés) → HTTP {code}", code == 403 and "hors du front" in page.lower())

        nb = run("docker", "compose", "logs", "--no-color", "--since", "10m", "netbox", cwd=None, check_rc=False).stdout
        check("journal : connexion par carte (auspex_carte_ok, carte1)",
              re.search(r'"event": "auspex_carte_ok", "user": "carte1"', nb))
        check("journal : refus motivés (auspex_carte_refused)", nb.count("auspex_carte_refused") >= 6)
        ac = run("docker", "compose", "logs", "--no-color", "acces", cwd=None, check_rc=False).stdout
        entries = [json.loads(line.split("|", 1)[1]) for line in ac.splitlines()
                   if "|" in line and line.split("|", 1)[1].strip().startswith("{")]
        check("journal du front : sujet de la carte enregistré",
              any("carte1" in e.get("carte_sujet", "") for e in entries))
    finally:
        CONFIG.write_text(original)

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
            print(f"::error title=Carte exception::{line}", flush=True)
        rc = 1
    print(f"::notice title=Carte à puce::{sum(ok for _, ok in RESULTS)}/{len(RESULTS)} vérifications réussies",
          flush=True)
    raise SystemExit(rc)
