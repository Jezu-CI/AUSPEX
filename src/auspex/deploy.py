"""`auspex plan` et `auspex apply` : l'état voulu (auspex.yaml) rendu réel.

Le plan compare auspex.yaml à l'état réel, section par section :
- modules communautaires à installer ou retirer ;
- règles de flux à importer depuis le fichier CSV/XLSX ;
- champs Auspex à créer dans NetBox.

`apply` refuse de commencer si une section contient une erreur. Il applique
ensuite les sections dans l'ordre ; si l'une échoue, les précédentes restent
appliquées et relancer `apply` après correction reprend là où il s'est arrêté.
Relancer `apply` sur un déploiement conforme ne fait rien.
"""

from __future__ import annotations

from pathlib import Path
from dataclasses import dataclass, field
from typing import Callable

from .config import Config
from .flowrules import RuleStore, diff_rules, import_rules
from .modules import ModuleError, ModuleManager
from .netbox import NetBoxError, apply_setup, client_from_config, setup_plan


class DeploymentError(Exception):
    """Le déploiement ne peut pas être rendu conforme à auspex.yaml."""


@dataclass
class Section:
    title: str
    changes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    action: Callable[[], str] | None = None


def _modules_section(cfg: Config) -> Section:
    sec = Section("Modules")
    mgr = ModuleManager(cfg.base_dir, cfg.state_dir)
    try:
        p = mgr.plan(cfg.modules)
    except ModuleError as exc:
        sec.errors.append(str(exc))
        return sec
    lock = mgr.lock()
    by_dir = {v.get("dir"): k for k, v in lock.items()}
    sec.changes += [f"+ {s.spec}" for s in p["install"]]
    sec.changes += [f"- {by_dir.get(slug, slug)}" for slug in p["remove"]]
    if p["unchanged"]:
        sec.notes.append(f"{p['unchanged']} module(s) déjà installé(s) et à jour")

    def run() -> str:
        for slug in p["remove"]:
            mgr.remove(slug)
        done = [mgr.install(s) for s in p["install"]]
        return (f"{len(done)} installé(s), {len(p['remove'])} retiré(s)"
                + "".join(f"\n      {e['name']} {e['version']} ({e['commit'][:12]})" for e in done))

    if sec.changes:
        sec.action = run
    return sec


def _flow_rules_section(cfg: Config) -> Section:
    sec = Section("Règles de flux")
    if not cfg.flow_rules_file:
        sec.notes.append("non configuré (flow_rules.file)")
        return sec
    if not cfg.flow_rules_file.exists():
        sec.errors.append(f"{cfg.flow_rules_file} introuvable")
        return sec
    names = [z.name for z in cfg.zones]
    res = import_rules(cfg.flow_rules_file, names)
    if res.problems:
        sec.errors += [f"{cfg.flow_rules_file.name}, {p}" for p in res.problems]
        return sec
    store = RuleStore(cfg.state_dir)
    d = diff_rules(store.load(names), res.rules)
    sec.changes += [f"+ {r.id} {r.source} → {r.destination} {r.protocole}/{r.port}" for r in d.added]
    sec.changes += [f"~ {new.id}" for _, new in d.modified]
    sec.changes += [f"- {r.id}" for r in d.removed]
    if d.unchanged:
        sec.notes.append(f"{d.unchanged} règle(s) inchangée(s)")

    def run() -> str:
        store.save(res.rules, source=str(cfg.flow_rules_file))
        return f"{len(d.added)} ajoutée(s), {len(d.modified)} modifiée(s), {len(d.removed)} supprimée(s)"

    if not d.is_empty:
        sec.action = run
    return sec


def _netbox_section(cfg: Config) -> Section:
    sec = Section("NetBox")
    if not cfg.netbox:
        sec.notes.append("non configuré (section netbox)")
        return sec
    try:
        client = client_from_config(cfg.netbox)
        major, minor = client.version()
        plan = setup_plan(client)
    except NetBoxError as exc:
        sec.errors.append(str(exc))
        return sec
    sec.notes.append(f"NetBox {major}.{minor} joignable")
    sec.changes += [f"+ {'champ' if i['kind'] == 'custom-field' else 'étiquette'} {i['name']}" for i in plan]

    def run() -> str:
        apply_setup(client, plan)
        return f"{len(plan)} objet(s) créé(s)"

    if plan:
        sec.action = run
    return sec


def _reception_section(cfg: Config) -> Section:
    from .reception import (authorized_line, authorized_path, current_lines, fingerprint, render_authorized_keys,
                            write_authorized_keys)
    sec = Section("Réception des capteurs")
    wanted = {s.name: authorized_line(s) for s in cfg.sensors if s.key}
    keys = {s.name: s.key for s in cfg.sensors if s.key}
    path = authorized_path(cfg.state_dir)
    if not wanted and not path.exists():
        sec.notes.append("aucun capteur avec clé d'envoi (sensors[].key)")
        return sec
    current = current_lines(cfg.state_dir)
    sec.changes += [f"+ {n} ({fingerprint(keys[n])})" for n in wanted if n not in current]
    sec.changes += [f"~ {n} (clé ou adresses autorisées)" for n, line in wanted.items()
                    if n in current and current[n] != line]
    sec.changes += [f"- {n}" for n in current if n not in wanted]
    if not sec.changes and (not path.exists() or
                            path.read_text(encoding="utf-8") != render_authorized_keys(cfg.sensors)):
        sec.changes.append("~ fichier des clés autorisées")
    if not sec.changes:
        sec.notes.append(f"{len(wanted)} capteur(s) autorisé(s) à envoyer leurs logs")

    def run() -> str:
        write_authorized_keys(cfg.state_dir, cfg.sensors)
        return f"{len(wanted)} capteur(s) autorisé(s)"

    if sec.changes:
        sec.action = run
    return sec


CARD_SERVER = """# Généré par Auspex depuis auspex.yaml (auth.carte) : ne pas modifier à la main.
server {{
    listen 9443 ssl;
    ssl_client_certificate /etc/auspex-acces/cartes-ac.pem;
    ssl_verify_client optional;
    ssl_verify_depth 4;
{crl}
    # Certificat invalide (autorité inconnue, révoqué, expiré) : la page de refus de
    # NetBox affiche et journalise le motif ($ssl_client_verify), au lieu de l'erreur brute.
    error_page 495 496 = /plugins/auspex/carte-a-puce/;
    location = /plugins/auspex/carte-a-puce/ {{
        proxy_pass http://netbox;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Auspex-Proxy "@@SECRET@@";
        proxy_set_header X-Auspex-Carte $ssl_client_escaped_cert;
        proxy_set_header X-Auspex-Carte-Verif $ssl_client_verify;
    }}
    location / {{
        return 302 https://$host@@HTTPS_SUFFIX@@$request_uri;
    }}
}}
"""


def card_files(cfg: Config) -> dict[str, bytes]:
    """Fichiers du front HTTPS pour le port carte (vide : port carte inactif)."""
    card = cfg.access.card
    if card is None:
        return {"carte.conf": b""}
    files = {"cartes-ac.pem": Path(card.ca_file).read_bytes()}
    crl = ""
    if card.crl_file:
        files["cartes-lcr.pem"] = Path(card.crl_file).read_bytes()
        crl = "    ssl_crl /etc/auspex-acces/cartes-lcr.pem;"
    files["carte.conf"] = CARD_SERVER.format(crl=crl).encode()
    return files


def _card_section(cfg: Config) -> Section:
    import os
    from datetime import datetime, timedelta, timezone
    sec = Section("Accès par carte à puce")
    folder = cfg.state_dir / "acces"
    try:
        wanted = card_files(cfg)
    except OSError as exc:
        sec.errors.append(str(exc))
        return sec
    current = {p.name: p.read_bytes() for p in folder.glob("*") if p.is_file()} if folder.is_dir() else {}
    if cfg.access.card is None:
        if current.get("carte.conf"):
            sec.changes.append("- port carte désactivé")
        elif not current:
            sec.changes.append("~ port carte inactif (fichier du front)")
        else:
            sec.notes.append("non configuré (auth.carte)")
    else:
        changed = [n for n, b in wanted.items() if current.get(n) != b]
        if changed:
            sec.changes.append(f"~ port carte : {', '.join(sorted(changed))}")
        else:
            sec.notes.append("port carte actif")
        if cfg.access.card.crl_file:
            from .carte import CardError, crl_expiry
            try:
                due = crl_expiry(wanted["cartes-lcr.pem"])
            except CardError:
                due = None
            now = datetime.now(timezone.utc)
            if due and due < now:
                # Avertissement, pas une erreur : l'analyse réseau ne doit pas s'arrêter pour ça.
                sec.notes.append(f"ATTENTION : liste de révocation périmée depuis le {due:%Y-%m-%d} : toutes les "
                                 "cartes sont refusées, la remplacer")
            elif due and due < now + timedelta(days=7):
                sec.notes.append(f"ATTENTION : liste de révocation à renouveler avant le {due:%Y-%m-%d %H:%M} UTC")
        else:
            sec.notes.append("sans liste de révocation : une carte perdue resterait acceptée jusqu'à expiration")

    def run() -> str:
        folder.mkdir(parents=True, exist_ok=True)
        for name in set(current) - set(wanted):
            (folder / name).unlink()
        for name, data in wanted.items():
            tmp = folder / f".{name}.tmp"
            tmp.write_bytes(data)
            os.chmod(tmp, 0o644)
            os.replace(tmp, folder / name)
        return "port carte " + ("actif" if cfg.access.card else "inactif")

    if sec.changes and not sec.errors:
        sec.action = run
    return sec


def compute_plan(cfg: Config) -> list[Section]:
    # Ordre d'application : les modules d'abord (ils apportent des règles).
    return [_modules_section(cfg), _flow_rules_section(cfg), _netbox_section(cfg), _reception_section(cfg),
            _card_section(cfg)]


def render(sections: list[Section], max_lines: int = 15) -> list[str]:
    out = []
    for s in sections:
        status = "erreur" if s.errors else (f"{len(s.changes)} changement(s)" if s.changes else "à jour")
        out.append(f"  {s.title:<16}: {status}")
        for e in s.errors:
            out.append(f"      ✗ {e}")
        for c in s.changes[:max_lines]:
            out.append(f"      {c}")
        if len(s.changes) > max_lines:
            out.append(f"      … et {len(s.changes) - max_lines} autre(s)")
        for n in s.notes:
            out.append(f"      ({n})")
    return out


def reconcile_deployment(cfg: Config) -> list[str]:
    """Applique le plan s'il est sans erreur ; lève DeploymentError sinon.

    Utilisé par le service à chaque cycle : tant que le déploiement n'est pas
    conforme (jeton NetBox absent, fichier de règles invalide...), aucune
    analyse n'est faite et aucune alerte n'est émise, pour ne jamais inonder
    le SIEM d'écarts calculés sans les règles de flux.
    """
    sections = compute_plan(cfg)
    errors = [f"{s.title} : {e}" for s in sections for e in s.errors]
    if errors:
        raise DeploymentError("déploiement non conforme à auspex.yaml, analyse suspendue et aucune alerte "
                              "émise — " + " ; ".join(errors[:5]))
    return [f"{s.title} : {s.action()}" for s in sections if s.action]
