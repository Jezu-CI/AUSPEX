#!/usr/bin/env python3
"""Captures industrielles publiques rejouées dans le vrai capteur (jalon J2–J3).

  telecharger DEST    récupère les captures et logs listés dans captures-reelles.yaml
                      (dépôt épinglé par commit, Git LFS), vérifie chaque SHA-256 ;
                      DEST/pcap/<nom>.<ext> et DEST/zeek/<nom>/*.log
  zeek DEST IMAGE     fait lire chaque capture au capteur (réseau coupé, lecture seule) :
                      DEST/logs/<nom>/
  rapport DEST        par capture : logs produits, champs utiles et valeurs observées,
                      puis identification par Auspex ; compare aux attendus
                      (captures-reelles-attendus.yaml). Code 1 si un attendu manque.

Les captures ne sont pas redistribuées : elles sont téléchargées au moment du test.
"""

from __future__ import annotations

import collections
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "captures-reelles.yaml"
EXPECTED = HERE / "captures-reelles-attendus.yaml"
INTERESTING = re.compile(
    r"(vendor|product|model|firmware|revision|version|name|subject|issuer|server|client|user_agent|"
    r"display_string|software|device|szl|identity|order|serial|module|func|fc_|function|service|"
    r"type|cpu|station|object|class|command|unit|protocol|status)", re.I)
PROPERTIES = {"vendor-name", "model-name", "firmware-revision", "application-software-version", "object-name",
              "vendor-identifier", "description", "location"}
SKIP_FIELDS = {"uid", "ts", "id.orig_p", "id.resp_p", "fuid", "conn_uids", "id", "password", "username"}
CONFIG = """version: 1
state_dir: ./state
zones:
  - { name: PRIVE-10,  class: other, prefixes: [10.0.0.0/8] }
  - { name: PRIVE-172, class: other, prefixes: [172.16.0.0/12] }
  - { name: PRIVE-192, class: other, prefixes: [192.168.0.0/16] }
  - { name: AUTRES,    class: other, prefixes: [0.0.0.0/0] }       # captures de labo en adresses publiques
"""


def run(*cmd, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def fetch(dest: Path) -> int:
    m = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    src = dest / "source"
    if not (src / ".git").exists():
        src.mkdir(parents=True, exist_ok=True)
        for cmd in (["git", "init", "-q"], ["git", "remote", "add", "origin", m["depot"]],
                    ["git", "fetch", "-q", "--depth", "1", "origin", m["commit"]]):
            r = run(*cmd, cwd=src)
            if r.returncode:
                print(f"::error title=Captures::{' '.join(cmd)} : {r.stderr.strip()[-300:]}")
                return 1
    env = {**os.environ, "GIT_LFS_SKIP_SMUDGE": "1"}
    r = run("git", "checkout", "-q", m["commit"], cwd=src, env=env)
    if r.returncode:
        print(f"::error title=Captures::checkout : {r.stderr.strip()[-300:]}")
        return 1
    lfs = [c["chemin"] for c in m["captures"] if c.get("lfs")]
    r = run("git", "lfs", "pull", "--include", ",".join(lfs), cwd=src)
    if r.returncode:
        print(f"::error title=Captures::git lfs pull : {r.stderr.strip()[-400:]}")
        return 1
    bad = 0
    (dest / "pcap").mkdir(exist_ok=True)
    for c in m["captures"]:
        p = src / c["chemin"]
        ok = p.is_file() and p.stat().st_size == c["taille"] and sha256(p) == c["sha256"]
        if not ok:
            print(f"::error title=Captures::{c['nom']} : empreinte ou taille inattendue ({c['chemin']})")
            bad += 1
            continue
        shutil.copyfile(p, dest / "pcap" / f"{c['nom']}{Path(c['chemin']).suffix}")
    for z in m.get("logs_zeek") or []:
        out = dest / "zeek" / z["nom"]
        out.mkdir(parents=True, exist_ok=True)
        for name, digest in z["fichiers"].items():
            p = src / z["dossier"] / name
            if not p.is_file() or sha256(p) != digest:
                print(f"::error title=Captures::{z['nom']}/{name} : empreinte inattendue")
                bad += 1
                continue
            shutil.copyfile(p, out / name)
    n = len(m["captures"]) + sum(len(z["fichiers"]) for z in m.get("logs_zeek") or [])
    print(f"{n - bad}/{n} fichiers vérifiés (SHA-256), dépôt {m['depot']} @ {m['commit'][:12]}")
    return 1 if bad else 0


def zeek(dest: Path, image: str) -> int:
    logs = dest / "logs"
    logs.mkdir(exist_ok=True)
    failed = 0
    for pcap in sorted((dest / "pcap").iterdir()):
        r = run("docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp",
                "-v", f"{pcap.parent.resolve()}:/pcap:ro", "-v", f"{logs.resolve()}:/logs",
                image, "read", f"/pcap/{pcap.name}", timeout=900)
        produced = list((logs / pcap.stem).glob("*.log")) if (logs / pcap.stem).exists() else []
        print(f"  {pcap.stem:<26} {len(produced):>3} log(s)" + ("" if r.returncode == 0 else
              f"  (code {r.returncode} : {r.stderr.strip()[-160:]})"))
        failed += r.returncode != 0
    return 1 if failed else 0


def records(path: Path):
    """Enregistrements d'un log Zeek JSON (une ligne par enregistrement) ou TSV."""
    fields = None
    with open(path, errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("{"):
                try:
                    yield json.loads(line)
                except ValueError:
                    continue
            elif line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif fields and line and not line.startswith("#"):
                yield {k: v for k, v in zip(fields, line.split("\t")) if v not in ("-", "(empty)")}


def summarize(folder: Path, out: list[str]) -> None:
    for log in sorted(folder.glob("*.log")):
        if log.stem in ("packet_filter", "reporter", "weird", "loaded_scripts", "stats", "capture_loss"):
            continue
        n = 0
        values: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
        keys: set[str] = set()
        for rec in records(log):
            n += 1
            keys.update(rec)
            for k, v in rec.items():
                if k in SKIP_FIELDS or not INTERESTING.search(k) or isinstance(v, (dict,)):
                    continue
                values[k][json.dumps(v, ensure_ascii=False)[:120] if isinstance(v, list) else str(v)[:120]] += 1
        out.append(f"    {log.stem} : {n} enregistrement(s) ; champs : {', '.join(sorted(keys))[:600]}")
        if "property" in keys and "value" in keys:       # BACnet : couples propriété = valeur
            pairs = collections.Counter(
                f"{r.get('source_h') or r.get('id.resp_h')} {r['property']}={str(r['value'])[:60]}"
                for r in records(log) if r.get("property") in PROPERTIES and r.get("value"))
            for v, c in pairs.most_common(30):
                out.append(f"      [propriété] {v} ×{c}")
        for k in sorted(values):
            top = ", ".join(f"{v} ×{c}" for v, c in values[k].most_common(6))
            out.append(f"      {k} = {top}"[:400])


def identify(folder: Path) -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Path(tmp) / "auspex.yaml"
        cfg.write_text(CONFIG)
        run("auspex", "-c", str(cfg), "analyze", "--logs", str(folder), "--now", "logs", "--no-send", timeout=1800)
        r = run("auspex", "-c", str(cfg), "assets", "--json")
        try:
            return json.loads(r.stdout or "[]")
        except ValueError:
            return []


def flat(asset: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for attr, v in asset.get("identification", {}).items():
        out[attr] = [x["value"] for x in v] if isinstance(v, list) else [v["value"]]
    return out


def report(dest: Path) -> int:
    expected = yaml.safe_load(EXPECTED.read_text(encoding="utf-8")) if EXPECTED.exists() else {}
    expected = expected.get("captures") or {}
    lines: list[str] = []
    missing: list[str] = []
    folders = sorted((dest / "logs").iterdir()) if (dest / "logs").exists() else []
    folders += sorted((dest / "zeek").iterdir()) if (dest / "zeek").exists() else []
    checked = 0
    for folder in folders:
        if not folder.is_dir():
            continue
        lines.append(f"\n=== {folder.name}")
        summarize(folder, lines)
        assets = identify(folder)
        lines.append(f"  Identification Auspex : {len(assets)} actif(s)")
        by_ip = {a["ip"]: flat(a) for a in assets}
        for ip, attrs in sorted(by_ip.items()):
            if attrs:
                lines.append(f"    {ip:<16} " + " ; ".join(f"{k}={' | '.join(v)}" for k, v in sorted(attrs.items()))[:400])
        for ip, want in (expected.get(folder.name) or {}).items():
            if want == "absent":                        # pas un actif (diffusion, cible de balayage…)
                checked += 1
                if ip in by_ip:
                    missing.append(f"{folder.name} {ip} : ne devrait pas figurer à l'inventaire ({by_ip[ip]})")
                continue
            got = by_ip.get(ip, {})
            for attr, wanted in want.items():
                for value in wanted if isinstance(wanted, list) else [wanted]:
                    checked += 1
                    values = got.get(attr, [])
                    value = str(value)
                    if value.startswith("!"):           # ne doit PAS apparaître (faux positif connu)
                        if any(value[1:].lower() in v.lower() for v in values):
                            missing.append(f"{folder.name} {ip} {attr} : « {value[1:]} » ne devrait pas "
                                           f"apparaître ({values})")
                    elif not any(value.lower() in v.lower() for v in values):
                        missing.append(f"{folder.name} {ip} {attr} : attendu « {value} », obtenu "
                                       f"{values or 'rien'}")
    print("\n".join(lines))
    print(f"\nAttendus vérifiés : {checked - len(missing)}/{checked}")
    for m in missing:
        print(f"::error title=Captures réelles::{m}")
    print(f"::notice title=Captures réelles::{checked - len(missing)}/{checked} identifications attendues "
          f"sur {len(folders)} captures réelles")
    return 1 if missing else 0


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "telecharger":
        return fetch(Path(argv[1]))
    if len(argv) >= 3 and argv[0] == "zeek":
        return zeek(Path(argv[1]), argv[2])
    if len(argv) >= 2 and argv[0] == "rapport":
        return report(Path(argv[1]))
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
