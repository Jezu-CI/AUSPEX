#!/usr/bin/env python3
"""Preuve « exports d'audit signés » sur le central complet (exécuté par la CI).

Export périodique produit par le vrai service, page NetBox, téléchargement
avec une vraie session (utilisateur SSO de tools/ci_saml.py), vérification
de l'archive téléchargée SANS Auspex (openssl, sha256sum), puis par
« auspex audit verify » ; altérations détectées ; clé privée hors de portée
de NetBox.

Usage (dans deploy/, après ci_saml.py) : python ../tools/ci_audit.py
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_mfa import CONFIG, URL  # noqa: E402
from ci_oidc import CLIENT, WORK, SSOBrowser  # noqa: E402
from ci_saml import saml_login  # noqa: E402

A = ["docker", "compose", "exec", "-T", "auspex", "auspex", "-c", "/etc/auspex/auspex.yaml"]
STATE = Path("data/state")
AUDITS = STATE / "tableau" / "audits"
RESULTS: list[tuple[str, bool]] = []


def check(label: str, ok) -> None:
    ok = bool(ok)
    RESULTS.append((label, ok))
    print(f"  {'OK ' if ok else 'ÉCHEC'}  {label}", flush=True)


def run(*cmd, cwd=None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)


def download(b: SSOBrowser, url: str) -> tuple[int, bytes, dict]:
    req = urllib.request.Request(url, headers={"X-Forwarded-For": CLIENT})
    try:
        with b.opener.open(req, timeout=30) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def main() -> int:
    print("Export périodique par le service")
    cfg = yaml.safe_load(CONFIG.read_text())
    cfg["organisation"] = "Ville de CI"
    # Logs de démonstration datés d'octobre : période de 60 jours pour les couvrir.
    cfg["audit"] = {"referentiels": ["nis2", "iec62443"], "frequence": "quotidienne", "periode_jours": 60}
    CONFIG.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))
    index = {}
    for _ in range(30):                                        # cycle de 20 s en CI
        try:
            index = json.loads((AUDITS / "index.json").read_text())
        except (OSError, ValueError):
            index = {}
        autos = {e["referentiel"] for e in index.get("exports", []) if e.get("automatique")}
        if {"nis2", "iec62443"} <= autos:
            break
        time.sleep(5)
    autos = {e["referentiel"]: e for e in index.get("exports", []) if e.get("automatique")}
    check(f"exports automatiques produits : {', '.join(sorted(autos)) or 'aucun'}", {"nis2", "iec62443"} <= set(autos))
    if "nis2" not in autos:
        return 1
    entry = autos["nis2"]
    check(f"synthèse NIS2 : {entry['synthese']}",
          entry["synthese"].get("§6.8") == "ecarts" and entry["synthese"].get("§3.2") == "preuve")
    r = run(*A, "audit", "cle")
    fp = r.stdout.split("Empreinte : ")[-1].strip()
    check(f"empreinte de la clé (auspex audit cle) : {fp}", r.returncode == 0 and fp == index.get("cle"))
    r = run(*A, "audit", "list")
    check("journal des exports (auspex audit list)", r.returncode == 0 and entry["fichier"] in r.stdout)

    print("Clé privée")
    key = STATE / "cles" / "audit-ed25519.pem"
    mode = stat.S_IMODE(key.stat().st_mode) if key.exists() else None
    check(f"clé privée dans l'état d'Auspex, droits {oct(mode) if mode is not None else '—'}", mode == 0o600)
    leaked = [p for p in (STATE / "tableau").rglob("*") if p.is_file() and b"PRIVATE KEY" in p.read_bytes()]
    check("aucune clé privée dans le répertoire lu par NetBox", not leaked)
    r = run("docker", "compose", "exec", "-T", "netbox", "sh", "-c",
            "grep -rl 'PRIVATE KEY' /var/lib/auspex-tableau /etc/auspex 2>/dev/null; true")
    check("aucune clé privée visible depuis le conteneur NetBox", r.stdout.strip() == "")

    print("Page NetBox et téléchargement (session SSO saml1)")
    creds = json.loads((WORK / "saml-users.json").read_text())
    b = SSOBrowser()
    saml_login("saml1", creds["saml1"], b=b)
    status, _, page = b.open(f"{URL}/plugins/auspex/audits/")
    check(f"page « Exports d'audit » → HTTP {status}", status == 200 and 'id="auspex-audits"' in page)
    check("empreinte affichée dans NetBox", fp and fp in page)
    check("entrée « Exports d'audit » dans le menu", "Exports d&#x27;audit" in page or "Exports d'audit" in page)
    status, data, headers = download(b, f"{URL}/plugins/auspex/audits/{entry['fichier']}")
    check(f"téléchargement → HTTP {status}, {len(data)} octets",
          status == 200 and headers.get("Content-Type") == "application/zip"
          and hashlib.sha256(data).hexdigest() == entry["sha256"])
    for bad in ("..%2F..%2Fdashboard.json", "index.json", "auspex-audit-nis2-20000101T0000Z.zip"):
        st, _, _ = download(b, f"{URL}/plugins/auspex/audits/{bad}")
        check(f"refus de « {bad} » → HTTP {st}", st == 404)
    st, final, body = SSOBrowser().open(f"{URL}/plugins/auspex/audits/{entry['fichier']}")
    check(f"sans session → page de connexion ({final.split('?')[0]})", "/login" in final and not body.startswith("PK"))
    r = run("docker", "compose", "logs", "--no-color", "--since", "5m", "netbox")
    check("téléchargement journalisé (auspex_audit_download)",
          "auspex_audit_download" in r.stdout and entry["fichier"] in r.stdout)

    print("Vérification de l'archive téléchargée, sans Auspex")
    work = Path(tempfile.mkdtemp(prefix="audit-"))
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        z.extractall(work)
    folder = next(p for p in work.iterdir() if p.is_dir())
    r = run("openssl", "pkeyutl", "-verify", "-pubin", "-inkey", "cle-publique.pem", "-rawin",
            "-in", "MANIFEST.json", "-sigfile", "MANIFEST.sig", cwd=folder)
    check(f"openssl : {r.stdout.strip() or r.stderr.strip()}", r.returncode == 0 and "Verified Successfully" in r.stdout)
    r = run("sha256sum", "-c", "SHA256SUMS", cwd=folder)
    check(f"sha256sum : {r.stdout.count(': OK')} fichiers OK", r.returncode == 0)
    report = (folder / "rapport.html").read_text(encoding="utf-8")
    check("rapport : organisation, référentiel, empreinte, aucun script",
          "Ville de CI" in report and "NIS2" in report and fp in report and "<script" not in report.lower())
    manifest = json.loads((folder / "MANIFEST.json").read_text())
    check(f"manifeste : période {manifest['periode']['debut'][:10]} → {manifest['periode']['fin'][:10]}, "
          f"{len(manifest['fichiers'])} fichiers", manifest["referentiel"] == "nis2" and manifest["fichiers"])

    print("Vérification par Auspex et altérations")
    inside = f"/var/lib/auspex/state/tableau/audits/{entry['fichier']}"
    r = run(*A, "audit", "verify", inside)
    check("auspex audit verify : intègre, clé attendue", r.returncode == 0 and "clé attendue" in r.stdout)
    (folder / "ecarts.csv").write_bytes((folder / "ecarts.csv").read_bytes().replace(b"critique", b"faible"))
    r = run("sha256sum", "-c", "--quiet", "SHA256SUMS", cwd=folder)
    check("sha256sum détecte l'écart maquillé (critique → faible)", r.returncode != 0)
    tampered = Path("data/altere.zip")
    shutil.make_archive(str(tampered.with_suffix("")), "zip", work)
    r = run(*A, "audit", "verify", "/var/lib/auspex/altere.zip")
    check("auspex audit verify refuse l'archive modifiée", r.returncode == 1 and "ecarts.csv" in r.stdout)
    tampered.unlink(missing_ok=True)
    shutil.rmtree(work, ignore_errors=True)

    print("Export à la demande")
    r = run(*A, "audit", "export", "dora", "--jours", "60")
    check("auspex audit export dora", r.returncode == 0 and "RTS art. 13" in r.stdout)
    index = json.loads((AUDITS / "index.json").read_text())
    check("export à la demande visible dans l'index NetBox",
          index["exports"][0]["referentiel"] == "dora" and not index["exports"][0]["automatique"])
    check("chaînage : l'export référence le précédent",
          bool(re.search(r"[0-9a-f]{64}", json.dumps(_last_manifest(index["exports"][0]["fichier"])["precedent"]))))

    failed = [label for label, ok in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} vérifications réussies")
    return 1 if failed else 0


def _last_manifest(name: str) -> dict:
    with zipfile.ZipFile(AUDITS / name) as z:
        member = next(n for n in z.namelist() if n.endswith("/MANIFEST.json"))
        return json.loads(z.read(member))


if __name__ == "__main__":
    import traceback
    try:
        rc = main()
    except SystemExit:
        raise
    except Exception:
        for line in traceback.format_exc().splitlines()[-12:]:
            print(f"::error title=Audit exception::{line}", flush=True)
        rc = 1
    print(f"::notice title=Exports d'audit::{sum(ok for _, ok in RESULTS)}/{len(RESULTS)} vérifications réussies",
          flush=True)
    raise SystemExit(rc)
