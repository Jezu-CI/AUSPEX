#!/usr/bin/env python3
"""Preuve « annuaire LDAPS » sur le central complet (exécuté par la CI).

Monte un vrai annuaire OpenLDAP en LDAPS (certificat signé par une autorité
créée pour l'occasion), passe le central en auth.primary: ldaps, puis vérifie
la connexion, les groupes, la MFA, le refus des comptes locaux, et le refus
d'un annuaire dont le certificat n'est pas reconnu.

Usage (dans deploy/, après ci_mfa.py) : python ../tools/ci_ldap.py
"""

from __future__ import annotations

import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_mfa import CONFIG, ENV, PAGE, SETUP_PATH, URL, Browser, api, mfa  # noqa: E402

BASE = "dc=ville,dc=test"
LDAP_ADMIN = f"cn=admin,{BASE}"
WORK = Path("ldap-ci")
RESULTS: list[tuple[str, bool]] = []


def check(label: str, ok: bool) -> None:
    ok = bool(ok)
    RESULTS.append((label, ok))
    print(f"  {'OK ' if ok else 'ÉCHEC'}  {label}", flush=True)
    if not ok:
        print(f"::error title=LDAPS::{label}", flush=True)


def run(*cmd, input=None, check_rc=True):
    r = subprocess.run(cmd, input=input, capture_output=True, text=True, timeout=300)
    if check_rc and r.returncode != 0:
        print(f"::error title=LDAPS::{' '.join(cmd[:4])} : {r.stderr[-400:]}", flush=True)
        raise SystemExit(1)
    return r


def make_certificates() -> None:
    WORK.mkdir(exist_ok=True)
    certs = WORK / "certs"
    certs.mkdir(exist_ok=True)
    o = lambda *a: run("openssl", *a)  # noqa: E731
    o("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(WORK / "ca.key"), "-out",
      str(certs / "ca.crt"), "-days", "2", "-subj", "/CN=Autorite CI Auspex")
    o("req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(certs / "ldap.key"), "-out", str(WORK / "ldap.csr"),
      "-subj", "/CN=ldap")
    (WORK / "ext.cnf").write_text("subjectAltName=DNS:ldap\n")
    o("x509", "-req", "-in", str(WORK / "ldap.csr"), "-CA", str(certs / "ca.crt"), "-CAkey", str(WORK / "ca.key"),
      "-CAcreateserial", "-out", str(certs / "ldap.crt"), "-days", "2", "-extfile", str(WORK / "ext.cnf"))
    o("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(WORK / "autre.key"), "-out",
      str(WORK / "autre-ca.crt"), "-days", "2", "-subj", "/CN=Autorite inconnue")
    for f in certs.iterdir():
        f.chmod(0o644)


def start_directory(password: str, pw1: str, pw2: str) -> None:
    """OpenLDAP (paquets Alpine officiels), configuration minimale écrite ici :
    LDAPS sur 636 avec le certificat de l'autorité CI."""
    conf = WORK / "conf"
    conf.mkdir(exist_ok=True)
    (conf / "slapd.conf").write_text(f"""include /etc/openldap/schema/core.schema
include /etc/openldap/schema/cosine.schema
include /etc/openldap/schema/inetorgperson.schema
modulepath /usr/lib/openldap
moduleload back_mdb.so
TLSCACertificateFile /certs/ca.crt
TLSCertificateFile /certs/ldap.crt
TLSCertificateKeyFile /certs/ldap.key
database mdb
maxsize 104857600
suffix "{BASE}"
rootdn "{LDAP_ADMIN}"
rootpw {password}
directory /var/lib/openldap/openldap-data
""")
    run("docker", "run", "-d", "--name", "ldap", "--hostname", "ldap", "--network", "auspex_default",
        "-v", f"{(WORK / 'certs').resolve()}:/certs:ro", "-v", f"{conf.resolve()}:/conf:ro", "alpine:3.20", "sh", "-c",
        "apk add --no-cache openldap openldap-back-mdb openldap-clients >/dev/null"
        " && mkdir -p /var/lib/openldap/openldap-data /run/openldap"
        " && exec slapd -d 256 -f /conf/slapd.conf -h 'ldap:/// ldaps:///'")
    for _ in range(90):
        r = run("docker", "exec", "ldap", "ldapsearch", "-x", "-H", "ldap://localhost", "-b", "",
                "-s", "base", "-D", LDAP_ADMIN, "-w", password, check_rc=False)
        if r.returncode in (0, 32):  # 32 : base vide, mais le serveur répond
            break
        time.sleep(2)
    else:
        check("annuaire OpenLDAP démarré", False)
        logs = run("docker", "logs", "--tail", "60", "ldap", check_rc=False)
        state = run("docker", "inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", "ldap", check_rc=False)
        print(f"::error title=LDAPS conteneur::{state.stdout.strip()}", flush=True)
        for line in (logs.stdout + logs.stderr).splitlines()[-60:]:
            print(f"::error title=LDAPS journal::{line[:300]}", flush=True)
        raise SystemExit(1)
    ldif = f"""dn: {BASE}
objectClass: dcObject
objectClass: organization
o: Ville
dc: ville

dn: ou=people,{BASE}
objectClass: organizationalUnit
ou: people

dn: ou=groups,{BASE}
objectClass: organizationalUnit
ou: groups

dn: uid=agent1,ou=people,{BASE}
objectClass: inetOrgPerson
uid: agent1
cn: Agent Un
givenName: Agent
sn: Un
mail: agent1@ville.test
userPassword: {pw1}

dn: uid=agent2,ou=people,{BASE}
objectClass: inetOrgPerson
uid: agent2
cn: Agent Deux
sn: Deux
mail: agent2@ville.test
userPassword: {pw2}

dn: cn=auspex-utilisateurs,ou=groups,{BASE}
objectClass: groupOfNames
cn: auspex-utilisateurs
member: uid=agent1,ou=people,{BASE}
"""
    run("docker", "exec", "-i", "ldap", "ldapadd", "-x", "-H", "ldap://localhost", "-D", LDAP_ADMIN, "-w", password,
        input=ldif)
    r = run("docker", "exec", "-e", "LDAPTLS_CACERT=/certs/ca.crt", "ldap",
            "ldapsearch", "-x", "-H", "ldaps://ldap:636", "-b", BASE, "-D", LDAP_ADMIN, "-w", password, "uid=agent1",
            check_rc=False)
    check("annuaire joignable en LDAPS (port 636, certificat de l'autorité CI)", r.returncode == 0 and "agent1" in r.stdout)


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
    cfg["auth"]["ldaps"]["ca_file"] = name
    CONFIG.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))


def main() -> int:
    password, pw1, pw2 = (secrets.token_urlsafe(18) for _ in range(3))
    print("Annuaire OpenLDAP en LDAPS")
    make_certificates()
    start_directory(password, pw1, pw2)
    shutil.copy(WORK / "certs" / "ca.crt", CONFIG.parent / "ldap-ca.pem")
    shutil.copy(WORK / "autre-ca.crt", CONFIG.parent / "autre-ca.pem")

    print("Central en auth.primary: ldaps")
    cfg = yaml.safe_load(CONFIG.read_text())
    cfg["auth"]["primary"] = "ldaps"
    cfg["auth"]["ldaps"] = {
        "servers": ["ldaps://ldap:636"], "bind_dn": LDAP_ADMIN,
        "user_search_base": f"ou=people,{BASE}", "user_attribute": "uid",
        "group_search_base": f"ou=groups,{BASE}", "group_type": "group_of_names",
        "require_group": f"cn=auspex-utilisateurs,ou=groups,{BASE}", "ca_file": "ldap-ca.pem"}
    # Accès accordé au GROUPE de l'annuaire : prouve que les groupes arrivent dans NetBox.
    cfg["access"]["trusted_hosts"].append({"group": "auspex-utilisateurs", "allow": ["10.20.0.0/24"]})
    cfg["access"]["trusted_hosts"].append({"user": "agent2", "allow": ["10.20.0.0/24"]})
    CONFIG.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))
    set_env("AUSPEX_LDAP_BIND_PASSWORD", password)
    check("NetBox redémarré avec l'annuaire", restart_netbox())
    r = run("docker", "compose", "exec", "-T", "netbox", "/opt/netbox/venv/bin/python", "/opt/netbox/netbox/manage.py",
            "shell", "-c", "from django.conf import settings; print(settings.AUTHENTICATION_BACKENDS)", check_rc=False)
    check("NetBox utilise le backend LDAP (et garde le backend local)",
          "netbox.authentication.LDAPBackend" in r.stdout and "ObjectPermissionBackend" in r.stdout)

    print("Connexions")
    b = Browser()
    _, where, _ = b.login("agent1", pw1)
    check(f"agent1, membre du groupe exigé → {where} (attendu la MFA)", where == SETUP_PATH)
    _, _, page = b.open(SETUP_PATH + "?method=totp&next=" + PAGE)
    m = re.search(r'id="secret">([A-Z2-7 ]+)<', page)
    secret = m.group(1).replace(" ", "") if m else ""
    status, _, page = b.submit_code(SETUP_PATH, mfa.totp(secret)) if secret else (0, "", "")
    check("agent1 inscrit à la MFA (codes de secours affichés)", status == 200 and 'id="recovery-codes"' in page)
    # Droits donnés au GROUPE de l'annuaire (recopié dans NetBox à la connexion).
    _, found = api("GET", "/api/users/groups/?name=auspex-utilisateurs")
    gid = found["results"][0]["id"] if found and found.get("count") else None
    code, _ = api("POST", "/api/users/permissions/", {"name": "ci-groupe-annuaire", "object_types": ["ipam.ipaddress"],
                                                      "actions": ["view"], "groups": [gid]}) if gid else (0, None)
    check("droit de lecture donné au groupe de l'annuaire", code == 201)
    status, where, _ = b.open(PAGE)
    check(f"agent1, par son groupe, voit la page de NetBox → HTTP {status}", status == 200 and where == PAGE)
    code, users = api("GET", "/api/users/users/?username=agent1")
    u = (users or {}).get("results", [{}])[0] if users else {}
    check("e-mail repris de l'annuaire", u.get("email") == "agent1@ville.test")
    groups = [g.get("name") for g in u.get("groups", [])]
    check(f"groupe de l'annuaire recopié dans NetBox ({groups})", "auspex-utilisateurs" in groups)

    _, where, _ = Browser().login("agent1", "mauvais-mot-de-passe")
    check(f"agent1, mauvais mot de passe → {where} (attendu /login/)", where == "/login/")
    _, where, _ = Browser().login("agent2", pw2)
    check(f"agent2, hors du groupe exigé → {where} (attendu /login/)", where == "/login/")
    _, where, page = Browser().login("mfa1", "nimporte")
    check("compte local inconnu de l'annuaire → refusé", where == "/login/" or 'id="local-refused"' in page)

    # Un compte local qui existe (mot de passe connu) : refusé, la méthode principale est l'annuaire.
    local_pw = secrets.token_urlsafe(18) + "Aa9"
    # « Aa9 » : NetBox exige majuscule, minuscule et chiffre ; un jeton aléatoire n'en
    # contient pas toujours (relevé en CI : création refusée une fois sur ~20).
    code, user = api("POST", "/api/users/users/", {"username": "ancien-local", "password": local_pw})
    if not user:
        raise RuntimeError(f"création du compte local refusée par NetBox (HTTP {code})")
    api("POST", "/api/users/permissions/", {"name": "ci-ancien-local", "object_types": ["ipam.ipaddress"],
                                           "actions": ["view"], "users": [user["id"]]})
    cfg = yaml.safe_load(CONFIG.read_text())
    cfg["access"]["trusted_hosts"].append({"user": "ancien-local", "allow": ["10.20.0.0/24"]})
    CONFIG.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))
    time.sleep(1.2)
    status, _, page = Browser().login("ancien-local", local_pw)
    check(f"compte local oublié (bon mot de passe) → HTTP {status}, refusé",
          status == 403 and 'id="local-refused"' in page)

    admin = Browser(xff=None)
    _, where, page = admin.login("admin", ENV["NETBOX_ADMIN_PASSWORD"])
    check(f"brise-glace (compte local admin) toujours accepté → {where}", where == SETUP_PATH)
    check("brise-glace : TOTP imposé, jamais l'e-mail", 'id="qr"' in page and 'id="choose-email"' not in page)
    code, _ = api("GET", "/api/ipam/ip-addresses/?limit=1")
    check(f"jetons d'API inchangés → HTTP {code}", code == 200)

    print("Annuaire au certificat non reconnu : refusé")
    use_ca("autre-ca.pem")
    check("NetBox redémarré avec une autre autorité", restart_netbox())
    _, where, _ = Browser().login("agent1", pw1)
    check(f"agent1, bon mot de passe, certificat non reconnu → {where} (attendu /login/)", where == "/login/")
    logs = run("docker", "compose", "logs", "--no-color", "netbox", check_rc=False).stdout
    check("mot de passe du compte de lecture absent du journal", password not in logs and pw1 not in logs)
    use_ca("ldap-ca.pem")
    check("retour à la bonne autorité", restart_netbox())
    _, where, _ = Browser().login("agent1", pw1)
    check(f"agent1 de nouveau accepté → {where}", where != "/login/")

    failed = [label for label, ok in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} vérifications réussies")
    return 1 if failed else 0


if __name__ == "__main__":
    import traceback
    try:
        rc = main()
    except SystemExit:
        raise
    except Exception:  # erreur inattendue : visible dans le rapport de la CI
        for line in traceback.format_exc().splitlines()[-12:]:
            print(f"::error title=LDAPS exception::{line}", flush=True)
        rc = 1
    print(f"::notice title=LDAPS::{sum(ok for _, ok in RESULTS)}/{len(RESULTS)} vérifications réussies", flush=True)
    raise SystemExit(rc)
