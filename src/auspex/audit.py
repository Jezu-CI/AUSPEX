"""Exports d'audit signés, par référentiel (NIS2, DORA, IEC 62443, ISO 27001, ANSSI).

Un export est une archive ZIP qui contient :

- ``rapport.html`` : rapport lisible et imprimable (exigence par exigence) ;
- ``ecarts.csv``, ``inventaire.csv``, ``regles.csv``, ``flux-inter-zones.csv``,
  ``donnees.json`` : les preuves, exploitables par un tableur ou un script ;
- ``SHA256SUMS`` et ``VERIFIER.txt`` : vérification avec les outils standards ;
- ``MANIFEST.json`` : empreinte SHA-256 de chaque fichier, période, référentiel,
  empreinte de l'export précédent (chaînage) ;
- ``MANIFEST.sig`` : signature Ed25519 du manifeste ; ``cle-publique.pem``.

La signature prouve qu'aucun fichier n'a été modifié depuis l'export, à
condition de comparer l'empreinte de la clé publique à celle publiée par
l'exploitant (affichée par ``auspex audit cle`` et dans NetBox). La vérification
ne demande pas Auspex : ``openssl`` et ``sha256sum`` suffisent.

Auspex fournit les preuves observables sur le réseau. Il ne remplace pas
l'évaluation complète d'une exigence (procédures, revues, organisation) :
le rapport le dit pour chaque exigence.
"""

from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import os
import re
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from . import __version__
from .compliance import SEVERITY_ORDER, TITLES, count_label
from .config import Config
from .state import AlertStore, AssetStore, FlowStore
from .zones import ZoneMap

FORMAT = "auspex-audit/1"
KEY_FILE = "audit-ed25519.pem"
SIGNED = "MANIFEST.json"
SIGNATURE = "MANIFEST.sig"
PUBLIC_KEY = "cle-publique.pem"
OUTSIDE_MANIFEST = {SIGNED, SIGNATURE, PUBLIC_KEY}
EXPORT_DIR = "audits"          # sous <state>/tableau/ : visible (en lecture seule) par NetBox
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
HTML_ROWS = 500                # lignes par tableau dans le rapport (tout est dans les CSV)

SEV_LABEL = {"critical": "critique", "high": "élevée", "medium": "moyenne", "low": "faible", "info": "info"}

# --- Référentiels ---------------------------------------------------------------------

INVENTORY = ("actif_inconnu", "actif_silencieux", "identification_divergente", "fiche_incomplete")
UNDECLARED = ("nouveau_flux_non_declare", "flux_non_declare_persistant")
RULES = ("regle_expiree_utilisee", "regle_jamais_utilisee")
IT_OT = ("flux_it_vers_ot_direct",)
ADMIN = ("flux_admin_inter_tiers",)
SCAN = ("balayage_reseau",)


@dataclass(frozen=True)
class Control:
    ref: str
    title: str
    types: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()        # inventaire | regles | flux | surveillance
    covers: str = ""                      # ce qu'Auspex apporte
    not_covered: str = ""                 # ce qui reste à évaluer hors d'Auspex


@dataclass(frozen=True)
class Framework:
    key: str
    title: str
    basis: str
    controls: tuple[Control, ...]


_ORG = "relève de l'organisation (procédures, revues, décisions) et n'est pas évalué ici"

FRAMEWORKS: dict[str, Framework] = {f.key: f for f in (
    Framework("nis2", "NIS2", "Directive (UE) 2022/2555, art. 21 ; règlement d'exécution (UE) 2024/2690, annexe", (
        Control("§6.8", "Segmentation du réseau", UNDECLARED + IT_OT + ADMIN, ("flux",),
                "flux observés entre zones, comparés aux flux autorisés ; administration et flux IT/OT",
                "la justification des zones par l'analyse de risque " + _ORG),
        Control("§6.7", "Sécurité des réseaux", RULES, ("regles", "flux"),
                "règles de flux en vigueur, expirées encore utilisées, jamais utilisées",
                "le schéma d'architecture et la revue des accès à distance " + _ORG),
        Control("§12.4", "Inventaire des actifs", INVENTORY, ("inventaire",),
                "actifs observés rapprochés de la CMDB : absents, silencieux, divergents, fiches incomplètes",
                "la classification des actifs " + _ORG),
        Control("§3.2", "Surveillance et journalisation", SCAN, ("surveillance",),
                "observation continue du trafic réseau entrant et sortant (§3.2.3 a)), alertes vers le SIEM, "
                "dont les balayages du réseau",
                "les autres journaux (comptes, accès, sauvegardes) et leur conservation " + _ORG),
    )),
    Framework("dora", "DORA", "Règlement (UE) 2022/2554 ; règlement délégué (UE) 2024/1774 (RTS)", (
        Control("RTS art. 13 a)", "Cloisonnement et segmentation des réseaux", IT_OT + UNDECLARED, ("flux",),
                "flux observés entre zones, flux IT/OT directs",
                "le lien avec la criticité des fonctions " + _ORG),
        Control("RTS art. 13 b)", "Documentation des connexions et flux de données", UNDECLARED, ("flux", "regles"),
                "flux observés non documentés dans les règles de flux",
                "les flux hors du périmètre observé par les capteurs ne sont pas couverts"),
        Control("RTS art. 13 c)", "Réseau dédié à l'administration", ADMIN, ("flux",),
                "administration observée depuis une zone moins sensible",
                "l'architecture du réseau d'administration " + _ORG),
        Control("RTS art. 13 h)", "Gouvernance des règles de filtrage", RULES, ("regles",),
                "règles expirées encore utilisées, règles jamais utilisées",
                "le circuit d'approbation des règles " + _ORG),
        Control("Art. 8", "Identification des actifs TIC", INVENTORY, ("inventaire",),
                "actifs observés rapprochés de la CMDB, fonctions métier et criticité renseignées",
                "la cartographie des fonctions et des dépendances " + _ORG),
    )),
    Framework("iec62443", "IEC 62443", "IEC 62443-3-3 (exigences de sécurité système) ; IEC 62443-3-2", (
        Control("SR 5.1", "Segmentation du réseau", UNDECLARED, ("flux",),
                "flux observés entre zones, comparés aux conduits autorisés", ""),
        Control("SR 5.2", "Protection des frontières de zone", IT_OT, ("flux",),
                "flux IT vers OT sans DMZ industrielle (zones et conduits, IEC 62443-3-2)", ""),
        Control("SR 6.2", "Surveillance continue", SCAN, ("surveillance",),
                "observation passive et continue du réseau industriel, sans émission ; balayages du réseau signalés", ""),
        Control("SR 7.8", "Inventaire des composants du système de commande", INVENTORY, ("inventaire",),
                "automates et équipements industriels identifiés passivement, rapprochés de la CMDB", ""),
    )),
    Framework("iso27001", "ISO 27001", "ISO/IEC 27001:2022, annexe A", (
        Control("A.8.22", "Cloisonnement des réseaux", UNDECLARED + IT_OT + ADMIN, ("flux",),
                "flux observés entre zones, comparés aux flux autorisés", ""),
        Control("A.8.20", "Sécurité des réseaux", RULES, ("regles",),
                "règles de flux en vigueur, expirées encore utilisées, jamais utilisées", ""),
        Control("A.5.9", "Inventaire des informations et autres actifs associés", INVENTORY, ("inventaire",),
                "actifs observés rapprochés de la CMDB", "les actifs informationnels (non réseau) " + _ORG),
        Control("A.8.16", "Activités de surveillance", SCAN, ("surveillance",),
                "surveillance du trafic réseau et alertes vers le SIEM, dont les balayages du réseau", ""),
    )),
    Framework("anssi", "ANSSI", "Guides de l'ANSSI (administration sécurisée, cartographie, systèmes industriels)", (
        Control("Administration", "Administration sécurisée (modèle en tiers)", ADMIN, ("flux",),
                "administration observée depuis un tier moins sensible", ""),
        Control("Cloisonnement", "Cloisonnement et filtrage des flux", UNDECLARED + RULES, ("flux", "regles"),
                "flux non autorisés, règles expirées ou inutilisées", ""),
        Control("Industriel", "Cloisonnement des systèmes industriels", IT_OT, ("flux",),
                "flux IT vers OT sans DMZ industrielle", ""),
        Control("Cartographie", "Cartographie du système d'information", INVENTORY, ("inventaire", "flux"),
                "inventaire observé et flux entre zones (état réel, à comparer à la cartographie déclarée)", ""),
    )),
)}


# --- Clé de signature -------------------------------------------------------------------

def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - dépendance déclarée
        raise AuditError("module « cryptography » absent : réinstaller Auspex") from exc
    return serialization, ed25519


class AuditError(Exception):
    pass


def key_path(state_dir: Path, name: str = KEY_FILE) -> Path:
    return Path(state_dir) / "cles" / name


def load_or_create_key(state_dir: Path, name: str = KEY_FILE):
    """Clé privée Ed25519 de l'instance (créée au premier usage, droits 0600)."""
    serialization, ed25519 = _crypto()
    path = key_path(state_dir, name)
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise AuditError(f"{path} : clé de signature inattendue (Ed25519 attendue)")
        return key
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    fd = os.open(path.with_suffix(".tmp"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    os.replace(path.with_suffix(".tmp"), path)
    return key


def public_pem(key) -> bytes:
    serialization, _ = _crypto()
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def fingerprint(public_key_pem: bytes) -> str:
    """Empreinte lisible : SHA-256 de la clé publique brute, par groupes de 4."""
    serialization, _ = _crypto()
    pub = serialization.load_pem_public_key(public_key_pem)
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    digest = hashlib.sha256(raw).hexdigest().upper()
    return ":".join(digest[i:i + 4] for i in range(0, 32, 4))   # 128 premiers bits, assez pour comparer à l'œil


# --- Collecte ---------------------------------------------------------------------------

def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    d = datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _value(ident: dict, key: str):
    v = ident.get(key)
    return v.get("value") if isinstance(v, dict) else None


def _alerts_in_period(state_dir: Path, start: datetime, end: datetime) -> list[dict]:
    """Écarts ouverts à un moment de la période, avec leur état à la fin de la période."""
    out = []
    for alert in AlertStore(state_dir).load().values():
        opened, resolved = _dt(alert.get("opened_at")), _dt(alert.get("resolved_at"))
        if opened is None or opened > end or (resolved is not None and resolved < start):
            continue
        open_at_end = resolved is None or resolved > end
        f = dict(alert["finding"])
        f.setdefault("title", TITLES.get(f.get("type"), f.get("type")))
        f.update(scope=alert.get("scope", "flux"), opened_at=opened.isoformat(timespec="seconds"),
                 resolved_at=resolved.isoformat(timespec="seconds") if resolved and not open_at_end else None,
                 open_at_end=open_at_end, opened_in_period=opened >= start)
        out.append(f)
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    out.sort(key=lambda f: (not f["open_at_end"], -rank.get(f["severity"], 0), f["opened_at"]))
    return out


def _flows_between_zones(cfg: Config, start: datetime, end: datetime) -> tuple[list[dict], dict]:
    from .flowrules import RuleStore
    zmap = ZoneMap(cfg.zones)
    rules = RuleStore(cfg.state_dir).load([z.name for z in cfg.zones])
    rows: dict[tuple, dict] = {}
    observed = 0
    for fl in FlowStore(cfg.state_dir).load().values():
        if fl.last_seen < start or fl.first_seen > end:
            continue
        observed += 1
        sz, dz = zmap.name_of(fl.src), zmap.name_of(fl.dst)
        if sz == dz:
            continue
        covered = any(r.matches(fl.src, sz, fl.dst, dz, fl.proto, fl.port) for r in rules)
        key = (sz, dz, fl.proto, fl.port)
        r = rows.setdefault(key, {"zone_source": sz, "zone_destination": dz, "protocole": fl.proto,
                                  "port": fl.port, "services": set(), "couples": 0, "connexions": 0,
                                  "premier_vu": fl.first_seen, "dernier_vu": fl.last_seen, "couvert": True})
        r["services"] |= set(fl.services)
        r["couples"] += 1
        r["connexions"] += fl.count
        r["premier_vu"] = min(r["premier_vu"], fl.first_seen)
        r["dernier_vu"] = max(r["dernier_vu"], fl.last_seen)
        r["couvert"] = r["couvert"] and covered
    out = []
    for r in sorted(rows.values(), key=lambda r: (r["couvert"], r["zone_source"], r["zone_destination"],
                                                   r["protocole"], r["port"] if r["port"] is not None else -1)):
        out.append({**r, "services": " ".join(sorted(r["services"])),
                    "premier_vu": r["premier_vu"].isoformat(timespec="seconds"),
                    "dernier_vu": r["dernier_vu"].isoformat(timespec="seconds")})
    covered = sum(1 for r in out if r["couvert"])
    return out, {"flux_observes": observed, "flux_inter_zones": len(out), "couverts": covered,
                 "taux_couverture": round(100 * covered / len(out)) if out else None, "regles": len(rules)}


def _inventory(cfg: Config, start: datetime, end: datetime, normalizer=None) -> list[dict]:
    rows = []
    for a in AssetStore(cfg.state_dir).load().values():
        if a.last_seen and a.last_seen < start or a.first_seen and a.first_seen > end:
            continue
        ident = a.conclusions(normalizer)
        rows.append({
            "ip": a.ip, "zone": a.zone or "hors zones", "noms": " ".join(sorted(a.hostnames)),
            "mac": " ".join(sorted(a.macs)), "type": _value(ident, "device_type") or "",
            "systeme": " ".join(x for x in (_value(ident, "os_family"), _value(ident, "os_version")) if x),
            "fabricant": _value(ident, "vendor") or "", "modele": _value(ident, "model") or "",
            "firmware": _value(ident, "firmware") or "",
            "premier_vu": a.first_seen.isoformat(timespec="seconds") if a.first_seen else "",
            "dernier_vu": a.last_seen.isoformat(timespec="seconds") if a.last_seen else "",
        })
    rows.sort(key=lambda r: (r["zone"], _ip_key(r["ip"])))
    return rows


def _ip_key(ip: str):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
        return (a.version, int(a))
    except ValueError:
        return (9, 0)


def _rules(cfg: Config, end: datetime) -> list[dict]:
    from .flowrules import RuleStore
    today = end.date()
    out = []
    for r in RuleStore(cfg.state_dir).load([z.name for z in cfg.zones]):
        d = r.to_dict()
        d["statut"] = "expirée" if r.expired(today) else ("expire bientôt" if r.expire_le and
                                                          date.fromisoformat(r.expire_le) <= today + timedelta(days=30)
                                                          else "en vigueur")
        out.append(d)
    return out


def _service(state_dir: Path) -> dict:
    hb = Path(state_dir) / "heartbeat.json"
    try:
        status = json.loads(hb.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        status = {}
    return {"etat": "en service" if status.get("ok") else ("en erreur" if status else "inconnu"),
            "dernier_cycle": status.get("finished"), "intervalle_s": status.get("interval"),
            "rapprochement_netbox": bool(status.get("netbox"))}


def _evaluate(fw: Framework, findings: list[dict], ctx: dict) -> list[dict]:
    out = []
    for c in fw.controls:
        mine = [f for f in findings if f.get("type") in c.types]
        open_end = [f for f in mine if f["open_at_end"]]
        resolved = [f for f in mine if not f["open_at_end"]]
        delays = [(_dt(f["resolved_at"]) - _dt(f["opened_at"])).total_seconds() / 86400 for f in resolved
                  if f.get("resolved_at")]
        reason = None
        if "inventaire" in c.evidence and not ctx["netbox"] and set(c.types) & set(INVENTORY):
            reason = "rapprochement avec NetBox non configuré : écarts d'inventaire non évalués"
        elif "regles" in c.evidence and not ctx["rules"] and set(c.types) & set(RULES):
            reason = "aucune règle de flux chargée"
        elif not ctx["observed"]:
            reason = "aucun trafic observé sur la période : vérifier les capteurs"
        # Un écart encore ouvert est toujours rapporté ; une donnée manquante empêche
        # seulement d'affirmer « aucun écart » (ou de fournir la preuve de surveillance).
        if open_end:
            status, reason = "ecarts", None
        elif reason:
            status = "non_evalue"
        elif not c.types or "surveillance" in c.evidence:
            # Contrôle de surveillance : la surveillance elle-même est la preuve ;
            # ses écarts (balayages) ne le font passer en « ecarts » qu'ouverts.
            status = "preuve"
        else:
            status = "aucun_ecart"
        out.append({
            "ref": c.ref, "titre": c.title, "statut": status, "raison": reason,
            "apport_auspex": c.covers, "hors_perimetre": c.not_covered, "types": list(c.types),
            "preuves": list(c.evidence),
            "ouverts_fin": len(open_end),
            "ouverts_fin_par_gravite": {s: sum(1 for f in open_end if f["severity"] == s) for s in SEVERITY_ORDER},
            "ouverts_periode": sum(1 for f in mine if f["opened_in_period"]),
            "resolus_periode": len(resolved),
            "delai_moyen_resolution_j": round(sum(delays) / len(delays), 1) if delays else None,
            "ecarts": [f["id"] for f in mine],
        })
    return out


# --- Fichiers de l'export ---------------------------------------------------------------

_FORMULA = re.compile(r"^[=+\-@\t\r]")


def _cell(v) -> str:
    """Valeur CSV sûre : une valeur observée sur le réseau (nom d'hôte...) qui commence
    par =, +, -, @ serait exécutée comme une formule par un tableur."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "oui" if v else "non"
    if isinstance(v, (list, tuple, set)):
        v = " ; ".join(str(x) for x in v)
    s = str(v)
    return "'" + s if _FORMULA.match(s) else s


def _csv(rows: list[dict], columns: list[tuple[str, str]]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";", lineterminator="\r\n")
    w.writerow([label for _, label in columns])
    for r in rows:
        w.writerow([_cell(r.get(k)) for k, _ in columns])
    return ("﻿" + buf.getvalue()).encode("utf-8")   # BOM : accents corrects dans Excel


FINDING_COLUMNS = [("id", "Identifiant"), ("exigences", "Exigences"), ("title", "Écart"), ("severity_label", "Gravité"),
                   ("etat", "État en fin de période"), ("opened_at", "Ouvert le"), ("resolved_at", "Résolu le"),
                   ("src", "Source"), ("src_zone", "Zone source"), ("dst", "Destination"),
                   ("dst_zone", "Zone destination"), ("proto", "Protocole"), ("port", "Port"),
                   ("service", "Service"), ("message", "Détail"), ("references", "Références")]
INVENTORY_COLUMNS = [("ip", "Adresse"), ("zone", "Zone"), ("noms", "Noms d'hôte"), ("mac", "MAC"),
                     ("type", "Type"), ("systeme", "Système"), ("fabricant", "Fabricant"), ("modele", "Modèle"),
                     ("firmware", "Firmware"), ("premier_vu", "Premier passage"), ("dernier_vu", "Dernier passage")]
RULE_COLUMNS = [("id", "Identifiant"), ("source", "Source"), ("destination", "Destination"),
                ("protocole", "Protocole"), ("port", "Port"), ("description", "Description"),
                ("proprietaire", "Propriétaire"), ("expire_le", "Expire le"), ("statut", "Statut")]
FLOW_COLUMNS = [("zone_source", "Zone source"), ("zone_destination", "Zone destination"),
                ("protocole", "Protocole"), ("port", "Port"), ("services", "Services"),
                ("couples", "Couples d'actifs"), ("connexions", "Connexions"), ("premier_vu", "Premier passage"),
                ("dernier_vu", "Dernier passage"), ("couvert", "Couvert par une règle")]


VERIFY_TEXT = """Vérifier cet export d'audit Auspex
=================================

1. Comparer l'empreinte de la clé à celle publiée par l'exploitant d'Auspex
   (commande « auspex audit cle », ou page « Exports d'audit » dans NetBox) :

     {fingerprint}

   Sans cette comparaison, la signature prouve seulement que l'export n'a pas
   été modifié depuis sa signature, pas qui l'a signé.

2. Vérifier la signature du manifeste (OpenSSL 3) :

     openssl pkeyutl -verify -pubin -inkey cle-publique.pem -rawin \\
         -in MANIFEST.json -sigfile MANIFEST.sig

   Résultat attendu : « Signature Verified Successfully ».

3. Vérifier les fichiers (les empreintes figurent aussi dans MANIFEST.json) :

     sha256sum -c SHA256SUMS

   Résultat attendu : « OK » pour chaque fichier.

Avec Auspex : auspex audit verify <archive.zip> --empreinte "{fingerprint}"
"""


def _h(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def build_export(cfg: Config, framework: str, end: datetime | None = None, days: int = 30,
                 organisation: str | None = None, normalizer=None, previous: dict | None = None,
                 key=None) -> tuple[dict[str, bytes], dict]:
    """Fichiers de l'export (nom → contenu) et manifeste, sans écrire sur disque."""
    if framework not in FRAMEWORKS:
        raise AuditError(f"référentiel inconnu : {framework} (au choix : {', '.join(FRAMEWORKS)})")
    if days < 1 or days > 3660:
        raise AuditError("période : entre 1 et 3660 jours")
    fw = FRAMEWORKS[framework]
    # Pleine précision pour les comparaisons : un écart ouvert dans la seconde qui précède
    # l'export doit y figurer (seul l'affichage est arrondi à la seconde).
    end = (end or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start = end - timedelta(days=days)
    key = key or load_or_create_key(cfg.state_dir)
    pub = public_pem(key)
    fp = fingerprint(pub)

    findings = _alerts_in_period(cfg.state_dir, start, end)
    flows, coverage = _flows_between_zones(cfg, start, end)
    inventory = _inventory(cfg, start, end, normalizer)
    rules = _rules(cfg, end)
    service = _service(cfg.state_dir)
    ctx = {"netbox": cfg.netbox is not None, "rules": bool(rules), "observed": coverage["flux_observes"] > 0}
    controls = _evaluate(fw, findings, ctx)

    by_finding: dict[str, list[str]] = {}
    for c in controls:
        for fid in c["ecarts"]:
            by_finding.setdefault(fid, []).append(c["ref"])
    relevant = [f for f in findings if f["id"] in by_finding]
    for f in relevant:
        f["exigences"] = by_finding[f["id"]]
        f["severity_label"] = SEV_LABEL.get(f["severity"], f["severity"])
        f["etat"] = "ouvert" if f["open_at_end"] else "résolu"

    meta = {
        "format": FORMAT, "referentiel": framework, "referentiel_titre": fw.title, "base": fw.basis,
        "organisation": organisation, "periode": {"debut": start.isoformat(timespec="seconds"), "fin": end.isoformat(timespec="seconds"),
                    "jours": days},
        "genere_le": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "auspex_version": __version__, "cle": fp,
        "precedent": previous,
    }
    zones = [{"nom": z.name, "classe": z.zclass, "prefixes": [str(p) for p in z.prefixes],
              "actifs": sum(1 for a in inventory if a["zone"] == z.name)} for z in cfg.zones]
    sensors = [{"nom": s.name, "zone": s.zone, "mode": s.mode} for s in cfg.sensors]
    data = {**meta, "exigences": controls,
            "perimetre": {"zones": zones, "capteurs": sensors, "couverture": coverage, "service": service,
                          "actifs": len(inventory)},
            "ecarts": relevant}

    files: dict[str, bytes] = {
        "ecarts.csv": _csv(relevant, FINDING_COLUMNS),
        "inventaire.csv": _csv(inventory, INVENTORY_COLUMNS),
        "regles.csv": _csv(rules, RULE_COLUMNS),
        "flux-inter-zones.csv": _csv(flows, FLOW_COLUMNS),
        "donnees.json": json.dumps(data, ensure_ascii=False, indent=1, default=str).encode("utf-8"),
    }
    files["rapport.html"] = _report(meta, fw, controls, relevant, inventory, rules, flows, zones, sensors,
                                    coverage, service).encode("utf-8")
    files["VERIFIER.txt"] = VERIFY_TEXT.format(fingerprint=fp).encode("utf-8")
    files["SHA256SUMS"] = "".join(f"{hashlib.sha256(b).hexdigest()}  {n}\n"
                                  for n, b in sorted(files.items())).encode("ascii")
    manifest = {**meta, "fichiers": {n: {"sha256": hashlib.sha256(b).hexdigest(), "taille": len(b)}
                                     for n, b in sorted(files.items())},
                "synthese": {c["ref"]: c["statut"] for c in controls}}
    signed = json.dumps(manifest, ensure_ascii=False, indent=1, sort_keys=True).encode("utf-8")
    files[SIGNED] = signed
    files[SIGNATURE] = key.sign(signed)
    files[PUBLIC_KEY] = pub
    return files, manifest


def archive_name(framework: str, end: datetime) -> str:
    return f"auspex-audit-{framework}-{end.astimezone(timezone.utc):%Y%m%dT%H%MZ}"


def write_zip(files: dict[str, bytes], dest: Path, folder: str, stamp: datetime) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")
    ts = stamp.astimezone(timezone.utc).timetuple()[:6]
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
        for name in sorted(files):
            info = zipfile.ZipInfo(f"{folder}/{name}", date_time=ts)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, files[name])
    os.replace(tmp, dest)
    return dest


def journal_path(state_dir: Path) -> Path:
    return Path(state_dir) / "audits" / "journal.jsonl"


def last_export(state_dir: Path) -> dict | None:
    entries = journal(state_dir)
    return entries[-1] if entries else None


def export(cfg: Config, framework: str, end: datetime | None = None, days: int = 30, out_dir: Path | None = None,
           organisation: str | None = None, normalizer=None, keep: int | None = None,
           automatic: bool = False) -> tuple[Path, dict]:
    """Construit, signe et écrit l'export ; l'inscrit au journal (chaînage)."""
    prev = last_export(cfg.state_dir)
    previous = ({"manifeste_sha256": prev["manifeste_sha256"], "fichier": prev["fichier"],
                 "genere_le": prev["genere_le"], "referentiel": prev["referentiel"]} if prev else None)
    files, manifest = build_export(cfg, framework, end, days, organisation, normalizer, previous)
    end_dt = _dt(manifest["periode"]["fin"])
    name = archive_name(framework, end_dt)
    out_dir = Path(out_dir) if out_dir else Path(cfg.state_dir) / "tableau" / EXPORT_DIR
    dest = out_dir / f"{name}.zip"
    n = 2
    while dest.exists():
        dest = out_dir / f"{name}-{n}.zip"
        n += 1
    write_zip(files, dest, dest.stem, end_dt)
    entry = {"fichier": dest.name, "referentiel": framework, "genere_le": manifest["genere_le"],
             "periode": manifest["periode"], "manifeste_sha256": hashlib.sha256(files[SIGNED]).hexdigest(),
             "synthese": manifest["synthese"], "automatique": automatic}
    jp = journal_path(cfg.state_dir)
    jp.parent.mkdir(parents=True, exist_ok=True)
    with jp.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    if keep:
        _prune(out_dir, framework, keep)
    if out_dir == Path(cfg.state_dir) / "tableau" / EXPORT_DIR:
        write_index(cfg.state_dir, manifest["cle"])
    return dest, manifest


INDEX = "index.json"


def write_index(state_dir: Path, key_fingerprint: str) -> Path:
    """Liste des exports présents, lue par la page « Exports d'audit » de NetBox
    (qui n'a ainsi besoin ni de la clé ni de la bibliothèque de signature)."""
    out_dir = Path(state_dir) / "tableau" / EXPORT_DIR
    entries = []
    for e in journal(state_dir):
        path = out_dir / e.get("fichier", "")
        if e.get("fichier") and path.is_file() and path.parent == out_dir:
            data = path.read_bytes()
            entries.append({**{k: e.get(k) for k in ("fichier", "referentiel", "genere_le", "periode", "synthese",
                                                      "automatique", "manifeste_sha256")},
                            "titre": FRAMEWORKS[e["referentiel"]].title if e.get("referentiel") in FRAMEWORKS
                            else e.get("referentiel"),
                            "taille": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    entries.reverse()   # plus récent d'abord
    index = {"version": 1, "cle": key_fingerprint, "exports": entries,
             "genere_le": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    path = out_dir / INDEX
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(index, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, path)
    return path


def journal(state_dir: Path) -> list[dict]:
    path = journal_path(state_dir)
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def due(cfg: Config, now: datetime) -> list[str]:
    """Référentiels dont l'export périodique (audit.frequence) est à produire."""
    from .config import AUDIT_FREQUENCIES
    if not cfg.audit.frameworks:
        return []
    every = timedelta(days=AUDIT_FREQUENCIES[cfg.audit.frequency])
    last: dict[str, datetime] = {}
    for e in journal(cfg.state_dir):
        when = _dt(e.get("genere_le"))
        if when and e.get("automatique"):
            last[e["referentiel"]] = max(last.get(e["referentiel"], when), when)
    # Petite marge : un cycle de quelques minutes ne doit pas décaler l'export d'une période.
    return [f for f in cfg.audit.frameworks if f not in last or now - last[f] >= every - timedelta(minutes=30)]


def _prune(out_dir: Path, framework: str, keep: int) -> None:
    mine = sorted(out_dir.glob(f"auspex-audit-{framework}-*.zip"), key=lambda p: p.stat().st_mtime)
    for p in mine[:-keep]:
        p.unlink()


# --- Vérification -----------------------------------------------------------------------

@dataclass
class Verification:
    ok: bool
    fingerprint: str | None = None
    key_matches: bool | None = None       # None : pas d'empreinte de référence fournie
    manifest: dict = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)


def _read_bundle(path: Path) -> dict[str, bytes]:
    path = Path(path)
    if path.is_dir():
        return {p.name: p.read_bytes() for p in path.iterdir() if p.is_file()}
    files: dict[str, bytes] = {}
    total = 0
    try:
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()
            prefixes = {i.filename.split("/", 1)[0] for i in infos}
            for i in infos:
                if i.is_dir():
                    continue
                parts = i.filename.split("/")
                if (len(prefixes) != 1 or len(parts) != 2 or ".." in parts or i.filename.startswith("/")
                        or "\\" in i.filename):
                    raise AuditError(f"archive inattendue : {i.filename!r}")
                total += i.file_size
                if total > MAX_ARCHIVE_BYTES:
                    raise AuditError("archive trop volumineuse")
                files[parts[1]] = z.read(i)
    except zipfile.BadZipFile as exc:
        raise AuditError(f"{path} : archive ZIP illisible") from exc
    return files


def _normalize_fp(s: str) -> str:
    return re.sub(r"[^0-9A-F]", "", s.upper())


def verify(path: Path, expected_fingerprint: str | None = None) -> Verification:
    serialization, ed25519 = _crypto()
    from cryptography.exceptions import InvalidSignature
    v = Verification(ok=False)
    try:
        files = _read_bundle(path)
    except (AuditError, OSError) as exc:
        v.problems.append(str(exc))
        return v
    for name in (SIGNED, SIGNATURE, PUBLIC_KEY):
        if name not in files:
            v.problems.append(f"{name} absent")
    if v.problems:
        return v
    try:
        pub = serialization.load_pem_public_key(files[PUBLIC_KEY])
        if not isinstance(pub, ed25519.Ed25519PublicKey):
            raise ValueError
    except ValueError:
        v.problems.append("clé publique illisible ou non Ed25519")
        return v
    v.fingerprint = fingerprint(files[PUBLIC_KEY])
    if expected_fingerprint:
        v.key_matches = _normalize_fp(expected_fingerprint) == _normalize_fp(v.fingerprint)
        if not v.key_matches:
            v.problems.append(f"clé différente de celle attendue : {v.fingerprint}")
    try:
        pub.verify(files[SIGNATURE], files[SIGNED])
    except InvalidSignature:
        v.problems.append("signature du manifeste invalide : MANIFEST.json modifié ou signé par une autre clé")
        return v
    try:
        manifest = json.loads(files[SIGNED])
        listed = manifest["fichiers"]
    except (ValueError, KeyError, TypeError):
        v.problems.append("manifeste illisible")
        return v
    v.manifest = manifest
    if manifest.get("format") != FORMAT:
        v.problems.append(f"format inattendu : {manifest.get('format')}")
    for name, meta in sorted(listed.items()):
        data = files.get(name)
        if data is None:
            v.problems.append(f"{name} : absent")
        elif hashlib.sha256(data).hexdigest() != meta.get("sha256"):
            v.problems.append(f"{name} : modifié (empreinte différente)")
    for name in sorted(set(files) - set(listed) - OUTSIDE_MANIFEST):
        v.problems.append(f"{name} : fichier ajouté, absent du manifeste")
    v.ok = not v.problems
    return v


# --- Rapport HTML -----------------------------------------------------------------------

STATUS = {"ecarts": ("Écarts ouverts", "bad"), "aucun_ecart": ("Aucun écart observé", "ok"),
          "preuve": ("Preuve fournie", "info"), "non_evalue": ("Non évalué", "na")}

CSS = """
:root{--fg:#1d262b;--muted:#5b6b72;--line:#d5dde0;--bg:#fff;--soft:#f2f5f5;--accent:#12805a;
--bad:#c62828;--warn:#b26a00;--info:#1f5f8b;--na:#6b7b82}
*{box-sizing:border-box}body{margin:0;background:var(--soft);color:var(--fg);
font:14px/1.5 "Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif}
main{max-width:1080px;margin:0 auto;padding:32px 28px 60px;background:var(--bg)}
header.top{border-bottom:3px solid var(--accent);padding-bottom:18px;margin-bottom:24px}
.kicker{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--accent);font-weight:600}
h1{font-size:26px;margin:4px 0 6px}h2{font-size:19px;margin:34px 0 10px;padding-bottom:6px;
border-bottom:1px solid var(--line)}h3{font-size:15px;margin:22px 0 6px}
.meta{display:grid;grid-template-columns:max-content 1fr;gap:2px 16px;color:var(--muted);font-size:13px}
.meta b{color:var(--fg);font-weight:500}.mono{font-family:ui-monospace,"Cascadia Mono",Consolas,monospace;
font-size:12.5px}
.note{background:var(--soft);border-left:3px solid var(--accent);padding:10px 14px;margin:14px 0;font-size:13px}
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0}
.tile{border:1px solid var(--line);border-radius:8px;padding:10px 12px}.tile .n{font-size:24px;font-weight:600}
.tile .l{font-size:12px;color:var(--muted)}.tile.bad .n{color:var(--bad)}.tile.ok .n{color:var(--accent)}
table{width:100%;border-collapse:collapse;margin:8px 0 6px;font-size:12.5px}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--soft);font-weight:600;font-size:12px}td.num,th.num{text-align:right;white-space:nowrap}
.pill{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.pill.bad{background:#fde8e8;color:var(--bad)}.pill.ok{background:#e2f3eb;color:#0b5a3f}
.pill.info{background:#e3eef7;color:var(--info)}.pill.na{background:#eceff0;color:var(--na)}
.sev{font-weight:600}.sev.critical,.sev.high{color:var(--bad)}.sev.medium{color:var(--warn)}
.sev.low,.sev.info{color:var(--info)}
.control{border:1px solid var(--line);border-radius:10px;padding:12px 16px;margin:14px 0;break-inside:avoid-page}
.control h3{margin:0 0 6px;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.control .ref{font-family:ui-monospace,Consolas,monospace;color:var(--accent);font-size:13px}
.small{font-size:12.5px;color:var(--muted)}.trunc{font-size:12px;color:var(--muted);font-style:italic}
footer{margin-top:40px;font-size:12px;color:var(--muted);border-top:1px solid var(--line);padding-top:10px}
@media print{body{background:#fff}main{padding:0;max-width:none}h2{break-after:avoid}
tr{break-inside:avoid}@page{size:A4;margin:16mm 14mm}}
@media (max-width:700px){.tiles{grid-template-columns:repeat(2,1fr)}}
"""


def _table(rows: list[dict], columns: list[tuple[str, str]], numeric: set[str] = frozenset(),
           limit: int = HTML_ROWS, csv_name: str = "") -> str:
    if not rows:
        return '<p class="small">Aucun élément.</p>'
    head = "".join(f'<th class="{"num" if k in numeric else ""}">{_h(label)}</th>' for k, label in columns)
    body = []
    for r in rows[:limit]:
        cells = []
        for k, _ in columns:
            v = r.get(k)
            if isinstance(v, bool):
                v = "oui" if v else "non"
            elif isinstance(v, (list, tuple)):
                v = " ; ".join(map(str, v))
            cells.append(f'<td class="{"num" if k in numeric else ""}">{_h(v)}</td>')
        body.append("<tr>" + "".join(cells) + "</tr>")
    more = (f'<p class="trunc">{len(rows) - limit} ligne(s) de plus dans {_h(csv_name)}.</p>'
            if len(rows) > limit else "")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>{more}"


def _fmt(ts: str | None) -> str:
    return ts[:16].replace("T", " ") if ts else ""


def _report(meta, fw: Framework, controls, findings, inventory, rules, flows, zones, sensors, coverage,
            service) -> str:
    counts = Counter(c["statut"] for c in controls)
    p = meta["periode"]
    org = meta.get("organisation")
    fid = {f["id"]: f for f in findings}
    parts = [f"""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Audit {_h(fw.title)}{' — ' + _h(org) if org else ''} — Auspex</title><style>{CSS}</style></head><body><main>
<header class="top"><div class="kicker">Rapport d'audit · Auspex</div>
<h1>{_h(fw.title)}{' — ' + _h(org) if org else ''}</h1>
<div class="meta"><span>Référentiel</span><b>{_h(fw.basis)}</b>
<span>Période observée</span><b>du {_fmt(p['debut'])} au {_fmt(p['fin'])} UTC ({p['jours']} jours)</b>
<span>Généré le</span><b>{_fmt(meta['genere_le'])} UTC, Auspex {_h(meta['auspex_version'])}</b>
<span>Clé de signature</span><b class="mono">{_h(meta['cle'])}</b></div></header>
<div class="note"><b>Portée.</b> Auspex observe le réseau sans agent ni émission. Ce rapport apporte les
preuves <i>observables</i> pour chaque exigence : flux entre zones, règles de flux, inventaire rapproché de
la CMDB, continuité de la surveillance. Il ne remplace pas l'évaluation complète de l'exigence ; ce qui
reste hors de son périmètre est indiqué exigence par exigence. Un réseau non couvert par un capteur
n'apparaît pas ici.</div>
<h2>Synthèse</h2>
<div class="tiles">
<div class="tile bad"><div class="n">{counts['ecarts']}</div><div class="l">exigence(s) avec écarts ouverts</div></div>
<div class="tile ok"><div class="n">{counts['aucun_ecart']}</div><div class="l">sans écart observé</div></div>
<div class="tile"><div class="n">{counts['preuve']}</div><div class="l">preuve(s) de surveillance</div></div>
<div class="tile"><div class="n">{counts['non_evalue']}</div><div class="l">non évaluée(s)</div></div></div>
<table><thead><tr><th>Exigence</th><th>Intitulé</th><th>Constat</th><th class="num">Ouverts (fin)</th>
<th class="num">Ouverts (période)</th><th class="num">Résolus</th><th class="num">Délai moyen</th></tr></thead><tbody>"""]
    for c in controls:
        label, cls = STATUS[c["statut"]]
        delay = f"{c['delai_moyen_resolution_j']} j" if c["delai_moyen_resolution_j"] is not None else "—"
        parts.append(f'<tr><td class="mono">{_h(c["ref"])}</td><td>{_h(c["titre"])}</td>'
                     f'<td><span class="pill {cls}">{label}</span></td><td class="num">{c["ouverts_fin"]}</td>'
                     f'<td class="num">{c["ouverts_periode"]}</td><td class="num">{c["resolus_periode"]}</td>'
                     f'<td class="num">{delay}</td></tr>')
    parts.append("</tbody></table>")

    parts.append("<h2>Périmètre observé</h2>")
    cov = coverage
    rate = f"{cov['taux_couverture']} %" if cov["taux_couverture"] is not None else "—"
    parts.append(f"""<div class="tiles">
<div class="tile"><div class="n">{len(inventory)}</div><div class="l">actifs observés</div></div>
<div class="tile"><div class="n">{cov['flux_inter_zones']}</div><div class="l">flux distincts entre zones</div></div>
<div class="tile {'ok' if cov['taux_couverture'] == 100 else ''}"><div class="n">{rate}</div>
<div class="l">de ces flux couverts par une règle</div></div>
<div class="tile"><div class="n">{cov['regles']}</div><div class="l">règles de flux</div></div></div>
<p class="small">Service Auspex : {_h(service['etat'])}{', dernier cycle ' + _fmt(service['dernier_cycle']) + ' UTC'
        if service.get('dernier_cycle') else ''} · rapprochement NetBox :
{'actif' if service['rapprochement_netbox'] else 'inactif'} · capteurs : {_h(', '.join(
        f"{s['nom']} ({s['zone']})" for s in sensors) or 'aucun déclaré')}</p>""")
    parts.append(_table(zones, [("nom", "Zone"), ("classe", "Classe"), ("prefixes", "Préfixes"),
                                ("actifs", "Actifs")], {"actifs"}))

    parts.append("<h2>Exigence par exigence</h2>")
    for c in controls:
        label, cls = STATUS[c["statut"]]
        parts.append(f'<section class="control"><h3><span class="ref">{_h(c["ref"])}</span>{_h(c["titre"])}'
                     f'<span class="pill {cls}">{label}</span></h3>')
        if c["raison"]:
            parts.append(f'<p class="small"><b>Non évalué :</b> {_h(c["raison"])}.</p>')
        parts.append(f'<p class="small"><b>Apport d\'Auspex :</b> {_h(c["apport_auspex"])}.')
        if c["hors_perimetre"]:
            parts.append(f' <b>Hors périmètre :</b> {_h(c["hors_perimetre"])}.')
        parts.append("</p>")
        if c["types"]:
            types = ", ".join(TITLES.get(t, t) for t in c["types"])
            parts.append(f'<p class="small">Écarts recherchés : {_h(types)}.</p>')
        mine = [fid[i] for i in c["ecarts"] if i in fid]
        if mine:
            parts.append(_findings_table(mine))
        elif c["statut"] == "aucun_ecart":
            parts.append('<p class="small">Aucun écart de ces types sur la période.</p>')
        parts.append("</section>")

    parts.append("<h2>Annexe A — Flux entre zones</h2>")
    parts.append('<p class="small">Flux observés pendant la période, agrégés par zones, protocole et port. '
                 "Les flux non couverts par une règle viennent en premier.</p>")
    parts.append(_table(flows, [("zone_source", "Source"), ("zone_destination", "Destination"),
                                ("protocole", "Proto"), ("port", "Port"), ("services", "Services"),
                                ("couples", "Couples"), ("connexions", "Connexions"),
                                ("dernier_vu", "Dernier passage"), ("couvert", "Règle")],
                        {"couples", "connexions", "port"}, csv_name="flux-inter-zones.csv"))
    parts.append("<h2>Annexe B — Règles de flux</h2>")
    parts.append(_table(rules, [("id", "Id"), ("source", "Source"), ("destination", "Destination"),
                                ("protocole", "Proto"), ("port", "Port"), ("proprietaire", "Propriétaire"),
                                ("expire_le", "Expire le"), ("statut", "Statut")], csv_name="regles.csv"))
    parts.append("<h2>Annexe C — Inventaire observé</h2>")
    parts.append(_table(inventory, [("ip", "Adresse"), ("zone", "Zone"), ("noms", "Noms"), ("type", "Type"),
                                    ("systeme", "Système"), ("fabricant", "Fabricant"), ("modele", "Modèle"),
                                    ("dernier_vu", "Dernier passage")], csv_name="inventaire.csv"))
    prev = meta.get("precedent")
    parts.append(f"""<h2>Intégrité de l'export</h2>
<p>Chaque fichier de l'export est inscrit, avec son empreinte SHA-256, dans <span class="mono">MANIFEST.json</span>,
signé par la clé Ed25519 de cette instance d'Auspex (<span class="mono">MANIFEST.sig</span>). Le fichier
<span class="mono">VERIFIER.txt</span> donne les commandes de vérification (OpenSSL, sha256sum).</p>
<div class="meta"><span>Empreinte de la clé</span><b class="mono">{_h(meta['cle'])}</b>
<span>Export précédent</span><b class="mono">{_h(prev['fichier'] + ' — manifeste ' + prev['manifeste_sha256'][:16] + '…')
        if prev else 'aucun (premier export de cette instance)'}</b></div>
<footer>Auspex {_h(meta['auspex_version'])} · format {_h(meta['format'])} · ce rapport ne contient aucun script.</footer>
</main></body></html>""")
    return "".join(parts)


def _findings_table(rows: list[dict], limit: int = 50) -> str:
    out = ['<table><thead><tr><th>Gravité</th><th>Écart</th><th>Chemin</th><th>Ouvert le</th>'
           '<th>État</th></tr></thead><tbody>']
    for f in rows[:limit]:
        path = ""
        if f.get("src") or f.get("dst"):
            src = f"{f.get('src') or ''} ({f.get('src_zone') or '?'})" if f.get("src") else ""
            dst = f"{f.get('dst') or ''} ({f.get('dst_zone') or '?'})" if f.get("dst") else ""
            svc = f" {f.get('proto')}/{f.get('port')}" if f.get("proto") and f.get("port") is not None else ""
            path = " → ".join(x for x in (src, dst) if x) + svc
        state = "ouvert" if f["open_at_end"] else f"résolu le {_fmt(f.get('resolved_at'))}"
        if f.get("first_seen"):   # flux : dates d'observation plutôt que le message (qui répète le chemin)
            first, last = _fmt(f["first_seen"]), _fmt(f.get("last_seen"))
            detail = f"observé le {first}" if first == last or not last else f"observé du {first} au {last}"
            if f.get("count"):
                detail += f", {count_label(f['type'], f['count'])}"
        else:
            detail = f.get("message") or ""
        out.append(f'<tr><td class="sev {_h(f["severity"])}">{_h(SEV_LABEL.get(f["severity"], f["severity"]))}</td>'
                   f'<td>{_h(f.get("title"))}<div class="small">{_h(detail)}</div></td>'
                   f'<td class="mono">{_h(path)}</td><td>{_fmt(f.get("opened_at"))}</td><td>{_h(state)}</td></tr>')
    out.append("</tbody></table>")
    if len(rows) > limit:
        out.append(f'<p class="trunc">{len(rows) - limit} écart(s) de plus dans ecarts.csv.</p>')
    return "".join(out)

