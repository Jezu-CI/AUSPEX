"""Interface en ligne de commande `auspex`.

    auspex validate                      vérifie auspex.yaml
    auspex daemon --logs RÉP [--once]    service : analyse, NetBox et alertes en continu
    auspex health                        état du service (vérification de santé Docker)
    auspex plan                          ce que « apply » changerait
    auspex apply                         rend le déploiement conforme à auspex.yaml
    auspex rules import [FICHIER]        simule l'import des règles de flux
    auspex rules import [FICHIER] --apply   applique l'import
    auspex rules export FICHIER          exporte les règles actives en CSV
    auspex analyze --logs RÉPERTOIRE     ingère des logs Zeek, identifie, évalue, alerte
    auspex assets                        inventaire identifié
    auspex findings                      écarts ouverts
    auspex alerts test                   envoie une alerte factice à chaque sortie
    auspex backup [FICHIER]              sauvegarde l'état et la configuration
    auspex restore FICHIER [--check]     vérifie ou restaure une sauvegarde
    auspex module list                   modules installés et leur intégrité
    auspex module check [RÉPERTOIRE]     vérifie un module (auteurs de modules)
    auspex netbox setup [--apply]        crée les champs Auspex dans NetBox
    auspex netbox sync [--apply]         écrit l'inventaire observé, rapproche du déclaré
"""

from __future__ import annotations

import argparse
import os
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __codename__, __version__
from .compliance import SEVERITY_ORDER, Finding, evaluate
from .config import Config, ConfigError, load_config
from .fingerprint import FingerprintEngine, Normalizer, load_normalizer, load_rules
from .fingerprint.engine import RuleError, load_oui
from .flowrules import RuleStore, diff_rules, export_rules_csv, import_rules
from .backup import BackupError
from .deploy import DeploymentError
from .modules import ModuleError, ModuleManager, load_references
from .netbox import NetBoxError
from .outputs import Dispatcher
from .state import AlertStore, AssetStore, FlowStore, IngestLedger
from .zeek import aggregate_conn, iter_logs
from .zones import ZoneMap

REPO_RULES = Path(__file__).resolve().parents[2] / "rules"
SEV_LABEL = {"critical": "CRITIQUE", "high": "ÉLEVÉE", "medium": "MOYENNE", "low": "FAIBLE", "info": "INFO"}


def _err(msg: str) -> None:
    print(f"Erreur : {msg}", file=sys.stderr)


def _load(args) -> Config:
    return load_config(args.config)


def _rule_paths(cfg: Config) -> list[Path]:
    if cfg.fingerprint_rules:
        return cfg.fingerprint_rules
    env = os.environ.get("AUSPEX_RULES_DIR")  # image Docker : règles livrées avec l'image
    if env and Path(env).is_dir():
        return [Path(env)]
    if REPO_RULES.exists():
        return [REPO_RULES]
    raise ConfigError(["fingerprint_rules : aucun répertoire de règles trouvé, à préciser dans auspex.yaml"])


def _modules(cfg: Config):
    """Modules déclarés, installés et intacts (empreinte vérifiée)."""
    return ModuleManager(cfg.base_dir, cfg.state_dir).verified(cfg.modules) if cfg.modules else []


def _extra_references(cfg: Config) -> dict[str, list[str]]:
    extra: dict[str, list[str]] = {}
    for manifest, path in _modules(cfg):
        if manifest.type == "references":
            for t, refs in load_references(path).items():
                extra.setdefault(t, []).extend(refs)
    return extra


def _add_references(findings, extra: dict[str, list[str]]) -> None:
    for f in findings:
        for ref in extra.get(f.type, []):
            if ref not in f.references:
                f.references = [*f.references, ref]


def _rule_data(cfg: Config) -> tuple[list, dict, Normalizer]:
    """Règles d'identification, préfixes MAC et alias : projet + modules de règles."""
    paths = _rule_paths(cfg) + [path / "rules" for m, path in _modules(cfg) if m.type == "rules"]
    oui: dict = {}
    normalizer = Normalizer()
    for p in paths:
        if not p.is_dir():
            continue
        if (p / "oui.yaml").exists():
            oui.update(load_oui(p / "oui.yaml"))
        if (p / "aliases.yaml").exists():
            n = load_normalizer(p / "aliases.yaml")
            for attr, table in n.aliases.items():
                normalizer.aliases.setdefault(attr, {}).update(table)
            for attr, values in n.generic.items():
                normalizer.generic.setdefault(attr, set()).update(values)
    return load_rules(paths), oui, normalizer


def cmd_validate(args) -> int:
    cfg = _load(args)
    print(f"Configuration valide : {args.config}")
    print(f"  zones      : {len(cfg.zones)} ({', '.join(z.name for z in cfg.zones)})")
    print(f"  capteurs   : {len(cfg.sensors)}")
    print(f"  sorties    : {len(cfg.alerts.outputs)} ({', '.join(o.type for o in cfg.alerts.outputs) or 'aucune'})")
    print(f"  règles flux: {cfg.flow_rules_file or 'non configuré'}")
    print(f"  état       : {cfg.state_dir}")
    return 0


def cmd_rules_import(args) -> int:
    cfg = _load(args)
    path = Path(args.file) if args.file else cfg.flow_rules_file
    if not path:
        _err("aucun fichier indiqué et flow_rules.file absent de auspex.yaml")
        return 2
    names = [z.name for z in cfg.zones]
    res = import_rules(path, names)
    if res.problems:
        print(f"{len(res.problems)} problème(s) dans {path} — rien n'a été importé :")
        for p in res.problems:
            print(f"  - {p}")
        return 1
    store = RuleStore(cfg.state_dir)
    d = diff_rules(store.load(names), res.rules)
    print(f"{path} : {len(res.rules)} règle(s) valides")
    for r in d.added:
        print(f"  + {r.id:<10} {r.source} → {r.destination} {r.protocole}/{r.port}"
              + (f" (expire le {r.expire_le})" if r.expire_le else ""))
    for old, new in d.modified:
        changes = [f"{k} : {v} → {new.to_dict()[k]}" for k, v in old.to_dict().items() if v != new.to_dict()[k]]
        print(f"  ~ {new.id:<10} " + " ; ".join(changes))
    for r in d.removed:
        print(f"  - {r.id:<10} {r.source} → {r.destination} {r.protocole}/{r.port}")
    print(f"  {len(d.added)} ajout(s), {len(d.modified)} modification(s), "
          f"{len(d.removed)} suppression(s), {d.unchanged} inchangée(s)")
    if d.is_empty:
        print("Aucun changement.")
        return 0
    if not args.apply:
        print("Simulation uniquement. Relancer avec --apply pour appliquer.")
        return 0
    store.save(res.rules, source=str(path))
    print("Import appliqué.")
    return 0


def cmd_rules_export(args) -> int:
    cfg = _load(args)
    rules = RuleStore(cfg.state_dir).load([z.name for z in cfg.zones])
    export_rules_csv(rules, args.file)
    print(f"{len(rules)} règle(s) exportée(s) vers {args.file}")
    return 0


def _now_from(arg: str | None, latest: datetime | None) -> datetime:
    if arg in (None, "now"):
        return datetime.now(timezone.utc)
    if arg == "logs":
        return latest or datetime.now(timezone.utc)
    dt = datetime.fromisoformat(arg)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def run_analysis(cfg: Config, logs: Path, now_arg: str | None = None, send: bool = True) -> dict:
    """Ingère les nouveaux enregistrements, identifie, évalue, émet les alertes.

    Seuls les enregistrements jamais lus sont traités (registre d'ingestion) :
    relancer l'analyse sur les mêmes logs ne compte rien deux fois.
    """
    zmap = ZoneMap(cfg.zones)
    fp_rules, oui, normalizer = _rule_data(cfg)
    # On inventorie les IP des zones déclarées (et les IP privées hors zones,
    # qui sont justement celles qu'il faut voir apparaître).
    # Relevé sur captures réelles : des réseaux industriels utilisent des adresses
    # publiques ; déclarées dans une zone, elles doivent être inventoriées.
    from .fingerprint.engine import inventoriable
    from .zones import UNKNOWN_ZONE
    engine = FingerprintEngine(fp_rules, oui, zone_of=zmap.name_of, normalizer=normalizer,
                               keep=lambda ip: inventoriable(ip, zmap.name_of(ip) != UNKNOWN_ZONE))
    ledger = IngestLedger(cfg.state_dir)

    conn_records = []
    for kind, rec in iter_logs(logs, ledger):
        if kind == "conn":
            conn_records.append(rec)
        engine.observe(kind, rec)
    engine.finalize()

    flow_store, asset_store = FlowStore(cfg.state_dir), AssetStore(cfg.state_dir)
    flows = FlowStore.merge(flow_store.load(), aggregate_conn(iter(conn_records)))
    assets = AssetStore.merge(asset_store.load(), engine.assets)
    latest = max([f.last_seen for f in flows.values()] + [a.last_seen for a in assets.values() if a.last_seen],
                 default=None)
    now = _now_from(now_arg, latest)
    pruned_f = FlowStore.prune(flows, now, cfg.retention_days)
    pruned_a = AssetStore.prune(assets, now, cfg.retention_days)

    names = [z.name for z in cfg.zones]
    rules = RuleStore(cfg.state_dir).load(names)
    report = evaluate(list(flows.values()), rules, zmap, cfg.alerts, now=now)
    _add_references(report.findings, _extra_references(cfg))

    # Ordre d'enregistrement : données d'abord, registre ensuite. Une analyse
    # interrompue avant la fin sera simplement refaite au passage suivant.
    flow_store.save(flows)
    asset_store.save(assets)
    ledger.prune(cfg.retention_days)
    ledger.save()
    events = AlertStore(cfg.state_dir).reconcile(report.findings, now)

    errors = []
    if send and cfg.alerts.outputs:
        errors = Dispatcher(cfg.alerts.outputs, cfg.state_dir, cfg.base_dir).dispatch(events, now)

    summary = {
        "analysed_at": now.isoformat(), "records": ledger.stats["records"],
        "files": {k: ledger.stats[k] for k in ("new", "resumed", "unchanged")},
        "flows_total": len(flows), "flows_inter_zone": report.flows_evaluated,
        "flows_covered": report.flows_covered, "assets": len(assets), "rules": len(rules),
        "findings": report.by_type(),
        "events": {k: sum(1 for e in events if e["event"] == k) for k in ("open", "update", "resolve")},
        "pruned": {"flows": pruned_f, "assets": pruned_a}, "delivery_errors": errors,
    }
    (cfg.state_dir / "report.json").write_text(
        json.dumps({**summary, "findings_detail": [f.to_dict() for f in report.findings]},
                   ensure_ascii=False, indent=1), encoding="utf-8")
    return summary


def cmd_analyze(args) -> int:
    cfg = _load(args)
    logs = Path(args.logs)
    if not logs.is_dir():
        _err(f"{logs} n'est pas un répertoire")
        return 2
    summary = run_analysis(cfg, logs, args.now, send=not args.no_send)
    errors = summary["delivery_errors"]
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=1))
        return 3 if errors else 0
    now = datetime.fromisoformat(summary["analysed_at"])
    fl = summary["files"]
    print(f"Analyse du {now:%Y-%m-%d %H:%M} UTC : {summary['records']} nouvel(s) enregistrement(s) lu(s)")
    print(f"  fichiers de logs   : {fl['new']} nouveau(x), {fl['resumed']} complété(s), "
          f"{fl['unchanged']} déjà analysé(s)")
    print(f"  actifs inventoriés : {summary['assets']}")
    print(f"  flux agrégés       : {summary['flows_total']} ({summary['flows_inter_zone']} évalués, "
          f"{summary['flows_covered']} couverts par une règle)")
    if not summary["rules"]:
        print("  règles de flux     : aucune — lancer « auspex rules import --apply »")
    n = sum(summary["findings"].values())
    print(f"  écarts             : {n}")
    for t, k in sorted(summary["findings"].items()):
        print(f"    {k:>4} × {t}")
    ev = summary["events"]
    print(f"  alertes            : {ev['open']} ouverte(s), {ev['update']} mise(s) à jour, "
          f"{ev['resolve']} résolue(s)")
    for e in errors:
        print(f"  ⚠ envoi : {e}")
    return 3 if errors else 0


def cmd_assets(args) -> int:
    cfg = _load(args)
    assets = AssetStore(cfg.state_dir).load()
    _, _, normalizer = _rule_data(cfg)
    inv = [a.to_dict(normalizer) for a in assets.values()]
    if args.zone:
        inv = [a for a in inv if a["zone"] == args.zone]
    inv.sort(key=lambda a: tuple(int(x) if x.isdigit() else 0 for x in a["ip"].replace(":", ".").split(".")))
    if args.json:
        print(json.dumps(inv, ensure_ascii=False, indent=1))
        return 0

    def val(i, k):
        v = i.get(k)
        return f"{v['value']} ({int(v['confidence'] * 100)} %)" if v else "-"

    print(f"{len(inv)} actif(s)")
    for a in inv:
        i = a["identification"]
        print(f"\n{a['ip']}  [{a['zone']}]  {', '.join(a['hostnames']) or ''}")
        print(f"  OS          : {val(i, 'os_family')}"
              + (f" — {i['os_version']['value']}" if i.get("os_version") else ""))
        for k, label in (("device_type", "type"), ("vendor", "fabricant"), ("model", "modèle"),
                         ("firmware", "firmware")):
            if i.get(k):
                print(f"  {label:<12}: {val(i, k)}")
        for r in i.get("role", []):
            print(f"  rôle        : {r['value']} ({int(r['confidence'] * 100)} %)")
        if a["macs"]:
            print(f"  MAC         : {', '.join(a['macs'])}")
    return 0


def cmd_findings(args) -> int:
    cfg = _load(args)
    alerts = AlertStore(cfg.state_dir).open_alerts()
    floor = SEVERITY_ORDER.index(args.min_severity)
    rows = [a["finding"] for a in alerts if SEVERITY_ORDER.index(a["finding"]["severity"]) >= floor]
    rows.sort(key=lambda f: -SEVERITY_ORDER.index(f["severity"]))
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=1))
        return 0
    print(f"{len(rows)} écart(s) ouvert(s)")
    for f in rows:
        print(f"\n[{SEV_LABEL[f['severity']]}] {f['title']}  ({f['id']})")
        print(f"  {f['message']}")
        if f.get("first_seen"):
            print(f"  vu du {f['first_seen'][:16]} au {f['last_seen'][:16]}, {f['count']} connexion(s)")
        if f.get("references"):
            print(f"  référentiels : {' ; '.join(f['references'])}")
    return 0


def cmd_alerts_test(args) -> int:
    cfg = _load(args)
    if not cfg.alerts.outputs:
        _err("aucune sortie configurée dans alerts.outputs")
        return 2
    now = datetime.now(timezone.utc)
    fake = Finding(id="AUSPEX-TEST", type="test", severity="critical",
                   message="Alerte de test envoyée par « auspex alerts test » : à ignorer.",
                   src="192.0.2.1", dst="192.0.2.2", src_zone="TEST", dst_zone="TEST",
                   proto="tcp", port=0, first_seen=now.isoformat(), last_seen=now.isoformat())
    ok = True
    for out in cfg.alerts.outputs:
        d = Dispatcher([out], cfg.state_dir / "test-outbox", cfg.base_dir)
        errors = d.dispatch([{"event": "open", **fake.to_dict()}], now)
        target = out.url or out.path
        if errors:
            ok = False
            print(f"  ÉCHEC  {out.type:<8} {target} : {errors[0]}")
        else:
            print(f"  OK     {out.type:<8} {target}")
    return 0 if ok else 3


def _netbox_client(cfg: Config):
    from .netbox import client_from_config
    if not cfg.netbox:
        raise ConfigError(["netbox : section absente de auspex.yaml"])
    return client_from_config(cfg.netbox)


def cmd_netbox_setup(args) -> int:
    """Mise en place, avec le jeton ADMINISTRATEUR : champs, étiquette, compte Librarian."""
    from .netbox import LIBRARIAN, apply_librarian, apply_setup, librarian_plan, setup_plan
    cfg = _load(args)
    client = _netbox_client(cfg)
    major, minor = client.version()
    plan = setup_plan(client)
    lib_token = os.environ.get(args.librarian_token_env)
    lib_plan = librarian_plan(client, lib_token, cfg.netbox.ca_file) if lib_token else []
    print(f"NetBox {major}.{minor} : {len(plan) + len(lib_plan)} élément(s) à créer ou corriger")
    labels = {"custom-field": "champ", "tag": "étiquette", "user": "utilisateur", "user-fix": "utilisateur",
              "permission": "permission", "permission-fix": "permission", "token": "jeton"}
    for item in plan + lib_plan:
        verb = "~" if item["kind"].endswith("-fix") else "+"
        print(f"  {verb} {labels[item['kind']]:<11} {item['name']}")
    if not lib_token:
        print(f"  (compte {LIBRARIAN} non géré : variable d'environnement {args.librarian_token_env} absente)")
    if not plan and not lib_plan:
        print("Rien à faire : NetBox est prêt.")
        return 0
    if not args.apply:
        print("Simulation uniquement. Relancer avec --apply pour appliquer.")
        return 0
    apply_setup(client, plan)
    if lib_plan:
        apply_librarian(client, lib_plan, lib_token, cfg.netbox.ca_file)
        print(f"Compte {LIBRARIAN} prêt : droits restreints vérifiés.")
    print("Mise en place appliquée.")
    return 0


def run_netbox_sync(cfg: Config, now_arg: str | None = None, apply: bool = False, send: bool = True) -> dict:
    """Rapproche l'inventaire observé de NetBox ; écrit et alerte si `apply`."""
    from .netbox import apply_plan, build_plan, fetch_declared, reconcile, setup_plan
    client = _netbox_client(cfg)
    if setup_plan(client):
        raise NetBoxError("NetBox n'est pas prêt : lancer d'abord « auspex apply »")
    _, _, normalizer = _rule_data(cfg)
    assets = [a.to_dict(normalizer) for a in AssetStore(cfg.state_dir).load().values()]
    latest = max((datetime.fromisoformat(a["last_seen"]) for a in assets if a.get("last_seen")), default=None)
    now = _now_from(now_arg, latest)

    ip_objects = client.list("/api/ipam/ip-addresses/")
    declared = fetch_declared(client)
    plan = build_plan(cfg, assets, ip_objects)
    findings = reconcile(cfg, assets, ip_objects, declared, now)
    _add_references(findings, _extra_references(cfg))
    result = {"now": now, "assets": len(assets), "ip_objects": len(ip_objects), "declared": len(declared),
              "plan": plan, "findings": findings, "events": [], "errors": []}
    if not apply:
        return result
    apply_plan(client, plan)
    events = AlertStore(cfg.state_dir).reconcile(findings, now, scope="inventaire")
    if send and cfg.alerts.outputs:
        result["errors"] = Dispatcher(cfg.alerts.outputs, cfg.state_dir, cfg.base_dir).dispatch(events, now)
    result["events"] = events
    (cfg.state_dir / "netbox_report.json").write_text(json.dumps({
        "synced_at": now.isoformat(), "created": len(plan.creates), "updated": len(plan.updates),
        "unchanged": plan.unchanged, "findings": [f.to_dict() for f in findings],
    }, ensure_ascii=False, indent=1), encoding="utf-8")
    return result


def _count_events(events: list[dict]) -> dict[str, int]:
    return {k: sum(1 for e in events if e["event"] == k) for k in ("open", "update", "resolve")}


def cmd_netbox_sync(args) -> int:
    cfg = _load(args)
    r = run_netbox_sync(cfg, args.now, apply=args.apply, send=not args.no_send)
    plan, findings = r["plan"], r["findings"]
    if not r["assets"]:
        print("Aucun actif observé : lancer d'abord « auspex analyze ».")
    print(f"NetBox : {r['ip_objects']} adresse(s) IP, {r['declared']} équipement(s) et VM déclarés")
    print(f"  adresses observées : {len(plan.creates)} à créer, {len(plan.updates)} à enrichir, "
          f"{plan.unchanged} inchangée(s)")
    by_type: dict[str, int] = {}
    for f in findings:
        by_type[f.type] = by_type.get(f.type, 0) + 1
    print(f"  écarts d'inventaire : {len(findings)}")
    for t, n in sorted(by_type.items()):
        print(f"    {n:>4} × {t}")
    if not args.apply:
        for f in findings[:10]:
            print(f"    - {f.message}")
        print("Simulation uniquement. Relancer avec --apply pour écrire dans NetBox et émettre les alertes.")
        return 0
    ev = _count_events(r["events"])
    print(f"Synchronisation appliquée. Alertes : {ev['open']} ouverte(s), {ev['update']} mise(s) à jour, "
          f"{ev['resolve']} résolue(s)")
    for e in r["errors"]:
        print(f"  ⚠ envoi : {e}")
    return 3 if r["errors"] else 0


def _heartbeat_path(cfg: Config) -> Path:
    return cfg.state_dir / "heartbeat.json"


def cmd_daemon(args) -> int:
    import signal
    import threading

    cfg = _load(args)  # une configuration invalide au démarrage est fatale
    logs = Path(args.logs)
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())

    def log(**fields) -> None:
        print(json.dumps({"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), **fields},
                         ensure_ascii=False, default=str), flush=True)

    log(event="démarrage", logs=str(logs), interval=args.interval, netbox=bool(cfg.netbox))
    while True:
        try:
            cfg = load_config(args.config)  # relue à chaque cycle : pas de redémarrage nécessaire
        except ConfigError as exc:
            log(event="configuration_invalide", problems=exc.problems, note="configuration précédente conservée")
        status: dict = {"started": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        "interval": args.interval}
        try:
            if args.apply:
                from .deploy import reconcile_deployment
                applied = reconcile_deployment(cfg)
                if applied:
                    status["apply"] = applied
            if not logs.is_dir():
                raise OSError(f"{logs} n'est pas un répertoire")
            a = run_analysis(cfg, logs, None, send=True)
            status["analyse"] = {"records": a["records"], "findings": sum(a["findings"].values()),
                                 "events": a["events"], "delivery_errors": a["delivery_errors"]}
            if cfg.netbox:
                n = run_netbox_sync(cfg, None, apply=True, send=True)
                status["netbox"] = {"created": len(n["plan"].creates), "updated": len(n["plan"].updates),
                                    "findings": len(n["findings"]), "events": _count_events(n["events"]),
                                    "delivery_errors": n["errors"]}
            status["ok"] = True
        except (DeploymentError, NetBoxError, ModuleError, RuleError, BackupError, OSError, ValueError) as exc:
            status.update(ok=False, error=str(exc))
        status["finished"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        cfg.state_dir.mkdir(parents=True, exist_ok=True)
        _heartbeat_path(cfg).write_text(json.dumps(status, ensure_ascii=False, default=str), encoding="utf-8")
        # Instantané du tableau de bord (widgets NetBox) : jamais bloquant.
        try:
            from .dashboard import write_snapshot
            write_snapshot(cfg, normalizer=_rule_data(cfg)[2])
        except Exception as exc:  # noqa: BLE001 - le tableau de bord ne doit pas arrêter le service
            log(event="tableau_de_bord_erreur", error=str(exc))
        # Exports d'audit périodiques (audit.referentiels) : jamais bloquants, et seulement
        # après un cycle réussi (sinon les preuves seraient périmées).
        if status.get("ok"):
            try:
                from . import audit
                for fw in audit.due(cfg, datetime.now(timezone.utc)):
                    dest, m = audit.export(cfg, fw, days=cfg.audit.period_days, organisation=cfg.organisation,
                                           normalizer=_rule_data(cfg)[2], keep=cfg.audit.keep, automatic=True)
                    log(event="export_audit", referentiel=fw, fichier=dest.name, synthese=m["synthese"])
            except Exception as exc:  # noqa: BLE001 - l'audit ne doit pas arrêter le service
                log(event="export_audit_erreur", error=str(exc))
        log(event="cycle", **status)
        if args.once or stop.wait(args.interval):
            break
    log(event="arrêt")
    return 0 if status.get("ok") else 1


def cmd_audit_export(args) -> int:
    from . import audit
    cfg = _load(args)
    latest = None
    if args.fin == "logs":
        flows = FlowStore(cfg.state_dir).load().values()
        latest = max((f.last_seen for f in flows), default=None)
    try:
        end = _now_from(args.fin, latest)
    except ValueError:
        _err(f"--fin : date invalide : {args.fin}")
        return 2
    try:
        dest, m = audit.export(cfg, args.referentiel, end=end, days=args.jours,
                               out_dir=Path(args.sortie) if args.sortie else None,
                               organisation=cfg.organisation, normalizer=_rule_data(cfg)[2])
    except audit.AuditError as exc:
        _err(str(exc))
        return 2
    labels = {"ecarts": "écarts ouverts", "aucun_ecart": "aucun écart observé", "preuve": "preuve fournie",
              "non_evalue": "non évalué"}
    print(f"Export {m['referentiel_titre']} : {dest}")
    print(f"  période : {m['periode']['debut'][:16]} → {m['periode']['fin'][:16]} UTC")
    for ref, st in m["synthese"].items():
        print(f"  {ref:<16} {labels[st]}")
    print(f"  clé de signature : {m['cle']}")
    return 0


def cmd_audit_verify(args) -> int:
    from . import audit
    v = audit.verify(Path(args.archive), args.empreinte)
    if v.ok and v.key_matches is None:
        # Sur le central, la clé de référence est connue : la comparer d'office.
        try:
            cfg = _load(args)
            kp = audit.key_path(cfg.state_dir)
            if kp.exists():
                own = audit.fingerprint(audit.public_pem(audit.load_or_create_key(cfg.state_dir)))
                v = audit.verify(Path(args.archive), own)
        except (ConfigError, OSError, audit.AuditError):
            pass  # vérification hors du central (poste d'un auditeur) : sans clé de référence
    m = v.manifest
    if m:
        print(f"Export {m.get('referentiel_titre')} du {str(m.get('genere_le'))[:16]} UTC, "
              f"période {str(m['periode']['debut'])[:10]} → {str(m['periode']['fin'])[:10]}")
        print(f"  {len(m.get('fichiers', {}))} fichiers contrôlés")
    if v.fingerprint:
        print(f"  clé : {v.fingerprint}")
    for p in v.problems:
        print(f"  ÉCHEC : {p}")
    if not v.ok:
        print("Export NON VÉRIFIÉ")
        return 1
    if v.key_matches:
        print("Export intègre, signé par la clé attendue.")
    else:
        print("Export intègre. Comparez l'empreinte de la clé à celle publiée par l'exploitant "
              "(ou passez --empreinte).")
    return 0


def cmd_audit_key(args) -> int:
    from . import audit
    cfg = _load(args)
    pem = audit.public_pem(audit.load_or_create_key(cfg.state_dir))
    print(f"Empreinte : {audit.fingerprint(pem)}")
    if args.pem:
        print(pem.decode(), end="")
    return 0


def cmd_audit_list(args) -> int:
    from . import audit
    cfg = _load(args)
    entries = audit.journal(cfg.state_dir)
    if not entries:
        print("aucun export d'audit")
        return 0
    for e in entries[-args.dernier:]:
        bad = sum(1 for v in e.get("synthese", {}).values() if v == "ecarts")
        print(f"{e['genere_le'][:16]}  {e['referentiel']:<9} {e['fichier']}  "
              f"{bad} exigence(s) avec écarts{'  (auto)' if e.get('automatique') else ''}")
    return 0


def _logs_dir(cfg: Config, arg: str | None) -> Path:
    return Path(arg or os.environ.get("AUSPEX_LOGS") or cfg.state_dir.parent / "logs")


def cmd_sensor_fingerprint(args) -> int:
    from .reception import host_key_fingerprint
    cfg = _load(args)
    fp = host_key_fingerprint(cfg.state_dir.parent / "reception")
    if not fp:
        _err("clé d'hôte de la réception introuvable : le service « reception » a-t-il démarré ?")
        return 1
    print(f"Empreinte du central (à saisir sur chaque capteur) : {fp}")
    return 0


def cmd_sensor_list(args) -> int:
    from . import maj
    from .reception import current_lines, fingerprint, sensor_activity
    cfg = _load(args)
    logs = _logs_dir(cfg, args.logs)
    active = current_lines(cfg.state_dir)
    if not cfg.sensors:
        print("aucun capteur déclaré (sensors dans auspex.yaml)")
        return 0
    for s in cfg.sensors:
        if not s.key:
            state = "sans clé d'envoi (logs déposés à la main)"
        elif s.name not in active:
            state = "clé déclarée, pas encore appliquée (prochain cycle ou auspex apply)"
        else:
            act = sensor_activity(logs, s.name)
            state = (f"autorisé ({fingerprint(s.key)}) ; " +
                     (f"dernier dépôt il y a {act['minutes']} min, {act['files']} fichier(s)" if act["last"]
                      else "aucun dépôt reçu"))
            if s.allow:
                state += f" ; depuis {', '.join(map(str, s.allow))}"
            st = maj.sensor_status(logs, s.name)
            if st and st["analyse"]:
                state += f" ; analyse {st['analyse']}"
                if st["maj"] in ("echec", "refusee"):
                    state += f" (dernière mise à jour : {st['maj']}, {st['detail']})"
        print(f"{s.name:<20} {s.zone:<16} {state}")
    pub = maj.current(cfg.state_dir)
    if pub:
        print(f"mise à jour publiée : {pub['version']}" if pub["valide"] else f"publication invalide : {pub['raison']}")
    return 0


def cmd_sensor_update_key(args) -> int:
    from . import maj
    cfg = _load(args)
    k = maj.key(cfg.state_dir)
    print("# Clé de mises à jour des capteurs (empreinte " + maj.fingerprint(k) + ")")
    print("# À ajouter dans capteur.conf de chaque capteur (support AUSPEX-CONF ou console) :")
    print(f"MAJ_CLE={maj.public_value(k)}")
    return 0


def cmd_sensor_publish(args) -> int:
    from . import maj
    cfg = _load(args)
    try:
        info = maj.publish(cfg.state_dir, Path(args.image), args.version, args.force)
    except maj.MajError as exc:
        _err(str(exc))
        return 1
    print(f"Image d'analyse {info['version']} publiée ({info['taille'] // (1024 * 1024)} Mio, "
          f"sha256 {info['sha256'][:16]}…), signée par la clé {maj.fingerprint(maj.key(cfg.state_dir))}")
    print("Les capteurs la récupèrent au prochain passage (MAJ_FREQUENCE), l'essaient, "
          "et reviennent seuls à leur version en cas d'échec.")
    return 0


def cmd_health(args) -> int:
    """Vérification de santé (HEALTHCHECK Docker) : dernier cycle récent et réussi."""
    cfg = _load(args)
    hb = _heartbeat_path(cfg)
    if not hb.exists():
        print("aucun cycle terminé")
        return 1
    st = json.loads(hb.read_text(encoding="utf-8"))
    if args.since:
        since = datetime.fromisoformat(args.since)
        since = since if since.tzinfo else since.replace(tzinfo=timezone.utc)
        if datetime.fromisoformat(st["started"]) < since:
            print(f"aucun cycle commencé depuis {args.since} (dernier : {st['started']})")
            return 1
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(st["finished"])).total_seconds()
    if age > 3 * int(st.get("interval", 300)) + 60:
        print(f"dernier cycle il y a {int(age)} s : service bloqué ?")
        return 1
    if not st.get("ok"):
        print(f"dernier cycle en erreur : {st.get('error')}")
        return 1
    print(f"ok (dernier cycle il y a {int(age)} s)")
    return 0


def cmd_plan(args) -> int:
    from .deploy import compute_plan, render
    cfg = _load(args)
    sections = compute_plan(cfg)
    print(f"Plan pour {args.config} :")
    print("\n".join(render(sections)))
    errors = sum(len(s.errors) for s in sections)
    pending = [s for s in sections if s.action]
    if errors:
        print(f"\n{errors} erreur(s) à corriger : « auspex apply » refusera de s'exécuter.")
        return 1
    if not pending:
        print("\nRien à faire : le déploiement est conforme à auspex.yaml.")
        return 0
    print(f"\n{len(pending)} section(s) à modifier. Lancer « auspex apply » pour appliquer.")
    return 0


def cmd_apply(args) -> int:
    from .deploy import compute_plan, render
    cfg = _load(args)
    sections = compute_plan(cfg)
    if any(s.errors for s in sections):
        print("Rien n'a été appliqué : le plan contient des erreurs.")
        print("\n".join(render(sections)))
        return 1
    pending = [s for s in sections if s.action]
    if not pending:
        print("Rien à faire : le déploiement est conforme à auspex.yaml.")
        return 0
    for s in pending:
        print(f"  ✓ {s.title:<16}: {s.action()}")
    print("Déploiement conforme à auspex.yaml.")
    return 0


def cmd_module_check(args) -> int:
    from . import __version__
    from .modules import check_data_only, read_manifest, validate_content, version_matches
    root = Path(args.dir)
    m = read_manifest(root)
    check_data_only(root)
    validate_content(root, m)
    compatible = version_matches(__version__, m.auspex)
    print(f"Module valide : {m.name} {m.version} (type {m.type}, licence {m.license})")
    print(f"  compatible avec cette version d'Auspex ({__version__}) : {'oui' if compatible else 'NON'}")
    return 0 if compatible else 5


def cmd_module_list(args) -> int:
    cfg = _load(args)
    mods = _modules(cfg)
    lock = ModuleManager(cfg.base_dir, cfg.state_dir).lock()
    if not mods:
        print("Aucun module installé.")
        return 0
    for spec in cfg.modules:
        e = lock[spec]
        print(f"  {e['name']:<32} {e['version']:<10} {e['type']:<11} {e['commit'][:12]}  intègre  {spec}")
    return 0


def cmd_backup(args) -> int:
    from .backup import create_backup, inspect_backup
    cfg = _load(args)
    path = create_backup(cfg, Path(args.file) if args.file else None)
    n = len(inspect_backup(path)["files"])  # relue et vérifiée aussitôt écrite
    print(f"Sauvegarde créée et vérifiée : {path} ({n} fichier(s), {path.stat().st_size // 1024} Kio)")
    return 0


def cmd_restore(args) -> int:
    from .backup import inspect_backup, restore_backup
    cfg = _load(args)
    archive = Path(args.file)
    if args.check:
        m = inspect_backup(archive)
        print(f"Archive valide : {len(m['files'])} fichier(s), Auspex {m['auspex_version']}, "
              f"créée le {m['created_at'][:19]}")
        return 0
    res = restore_backup(cfg, archive, force=args.force, with_config=args.with_config)
    if res["previous"]:
        print(f"État précédent sauvegardé dans {res['previous']}")
    print(f"Restauration terminée : {len(res['manifest']['files'])} fichier(s) "
          f"(sauvegarde du {res['manifest']['created_at'][:19]})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="auspex", description="Auspex — CMDB passive IT/OT")
    p.add_argument("-c", "--config", default="auspex.yaml", help="fichier de configuration (défaut : auspex.yaml)")
    p.add_argument("--version", action="version", version=f"auspex {__version__} « {__codename__} »")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("validate", help="vérifier auspex.yaml").set_defaults(func=cmd_validate)
    dm = sub.add_parser("daemon", help="service : analyse, synchronisation NetBox et alertes en continu")
    dm.add_argument("--logs", required=True, help="répertoire où arrivent les logs des capteurs")
    dm.add_argument("--interval", type=int, default=300, help="secondes entre deux cycles (défaut : 300)")
    dm.add_argument("--once", action="store_true", help="un seul cycle puis arrêt")
    dm.add_argument("--apply", action="store_true",
                    help="rendre le déploiement conforme à auspex.yaml à chaque cycle ; "
                         "analyse suspendue tant qu'il ne l'est pas")
    dm.set_defaults(func=cmd_daemon)
    he = sub.add_parser("health", help="état du service (pour Docker)")
    he.add_argument("--since", help="exiger un cycle commencé après cette date ISO (mises à jour)")
    he.set_defaults(func=cmd_health)
    sub.add_parser("plan", help="ce que « apply » changerait (modules, règles, NetBox)").set_defaults(func=cmd_plan)
    sub.add_parser("apply", help="rendre le déploiement conforme à auspex.yaml").set_defaults(func=cmd_apply)

    rules = sub.add_parser("rules", help="règles de flux").add_subparsers(dest="rules_cmd", required=True)
    ri = rules.add_parser("import", help="importer un CSV/XLSX (simulation par défaut)")
    ri.add_argument("file", nargs="?")
    ri.add_argument("--apply", action="store_true", help="appliquer réellement l'import")
    ri.set_defaults(func=cmd_rules_import)
    re_ = rules.add_parser("export", help="exporter les règles actives en CSV")
    re_.add_argument("file")
    re_.set_defaults(func=cmd_rules_export)

    an = sub.add_parser("analyze", help="analyser des logs Zeek")
    an.add_argument("--logs", required=True, help="répertoire des logs Zeek")
    an.add_argument("--now", help="instant de référence : now (défaut), logs, ou date ISO")
    an.add_argument("--no-send", action="store_true", help="ne pas envoyer les alertes")
    an.add_argument("--json", action="store_true")
    an.set_defaults(func=cmd_analyze)

    a = sub.add_parser("assets", help="inventaire identifié")
    a.add_argument("--zone")
    a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_assets)

    f = sub.add_parser("findings", help="écarts ouverts")
    f.add_argument("--min-severity", default="info", choices=SEVERITY_ORDER)
    f.add_argument("--json", action="store_true")
    f.set_defaults(func=cmd_findings)

    bk = sub.add_parser("backup", help="sauvegarder l'état et la configuration")
    bk.add_argument("file", nargs="?", help="archive à créer (défaut : backups/auspex-DATE.tar.gz)")
    bk.set_defaults(func=cmd_backup)
    rs = sub.add_parser("restore", help="restaurer une sauvegarde")
    rs.add_argument("file")
    rs.add_argument("--check", action="store_true", help="vérifier l'archive sans rien restaurer")
    rs.add_argument("--force", action="store_true", help="remplacer un état existant (sauvegardé avant)")
    rs.add_argument("--with-config", action="store_true", help="restaurer aussi auspex.yaml et les règles")
    rs.set_defaults(func=cmd_restore)

    mo = sub.add_parser("module", help="modules communautaires").add_subparsers(dest="mod_cmd", required=True)
    mc = mo.add_parser("check", help="vérifier un module (pour les auteurs de modules)")
    mc.add_argument("dir", nargs="?", default=".")
    mc.set_defaults(func=cmd_module_check)
    mo.add_parser("list", help="modules installés et leur intégrité").set_defaults(func=cmd_module_list)

    nb = sub.add_parser("netbox", help="synchronisation avec NetBox").add_subparsers(dest="nb_cmd", required=True)
    ns = nb.add_parser("setup", help="mise en place avec le jeton administrateur : champs, compte Librarian")
    ns.add_argument("--apply", action="store_true")
    ns.add_argument("--librarian-token-env", default="LIBRARIAN_TOKEN",
                    help="variable contenant le jeton du compte de service Librarian (défaut : LIBRARIAN_TOKEN)")
    ns.set_defaults(func=cmd_netbox_setup)
    ny = nb.add_parser("sync", help="écrire l'inventaire observé et rapprocher du déclaré")
    ny.add_argument("--apply", action="store_true", help="écrire réellement dans NetBox")
    ny.add_argument("--now", help="instant de référence : now (défaut), logs, ou date ISO")
    ny.add_argument("--no-send", action="store_true", help="ne pas envoyer les alertes")
    ny.set_defaults(func=cmd_netbox_sync)

    cp = sub.add_parser("capteur", help="capteurs : réception des logs").add_subparsers(dest="capteur_cmd",
                                                                                     required=True)
    cp.add_parser("empreinte", help="empreinte du central, à saisir sur chaque capteur").set_defaults(
        func=cmd_sensor_fingerprint)
    cl = cp.add_parser("liste", help="capteurs déclarés, autorisés, dernier dépôt reçu")
    cl.add_argument("--logs", help="répertoire des logs reçus (défaut : AUSPEX_LOGS ou à côté de l'état)")
    cl.set_defaults(func=cmd_sensor_list)
    cp.add_parser("cle-maj", help="clé de mises à jour : ligne MAJ_CLE à mettre dans capteur.conf").set_defaults(
        func=cmd_sensor_update_key)
    cu = cp.add_parser("publier", help="signer et publier une image d'analyse pour les capteurs")
    cu.add_argument("image", help="auspex-capteur-<version>.squashfs (produite par appliance/build.sh)")
    cu.add_argument("--version", help="version de l'image (défaut : tirée du nom du fichier)")
    cu.add_argument("--force", action="store_true", help="republier une version qui n'est pas plus récente")
    cu.set_defaults(func=cmd_sensor_publish)

    au = sub.add_parser("audit", help="exports d'audit signés par référentiel").add_subparsers(
        dest="audit_cmd", required=True)
    ae = au.add_parser("export", help="produire un export signé (rapport, preuves CSV/JSON, signature)")
    ae.add_argument("referentiel", choices=["nis2", "dora", "iec62443", "iso27001", "anssi"])
    ae.add_argument("--jours", type=int, default=30, help="durée de la période (défaut : 30 jours)")
    ae.add_argument("--fin", help="fin de la période : now (défaut), logs, ou date ISO")
    ae.add_argument("--sortie", help="répertoire de l'archive (défaut : <state>/tableau/audits, visible dans NetBox)")
    ae.set_defaults(func=cmd_audit_export)
    av = au.add_parser("verify", help="vérifier un export (signature, empreintes, fichiers ajoutés)")
    av.add_argument("archive", help="archive .zip ou répertoire extrait")
    av.add_argument("--empreinte", help="empreinte attendue de la clé (sinon : clé de ce central si présente)")
    av.set_defaults(func=cmd_audit_verify)
    ak = au.add_parser("cle", help="empreinte de la clé de signature (à communiquer aux auditeurs)")
    ak.add_argument("--pem", action="store_true", help="afficher aussi la clé publique")
    ak.set_defaults(func=cmd_audit_key)
    al_ = au.add_parser("list", help="exports produits (journal chaîné)")
    al_.add_argument("--dernier", type=int, default=20)
    al_.set_defaults(func=cmd_audit_list)

    al = sub.add_parser("alerts", help="sorties SIEM").add_subparsers(dest="alerts_cmd", required=True)
    al.add_parser("test", help="envoyer une alerte factice").set_defaults(func=cmd_alerts_test)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as exc:
        _err(f"configuration invalide ({len(exc.problems)} problème(s)) :")
        for pb in exc.problems:
            print(f"  - {pb}", file=sys.stderr)
        return 1
    except NetBoxError as exc:
        _err(f"NetBox : {exc}")
        return 4
    except ModuleError as exc:
        _err(f"module : {exc}")
        return 5
    except BackupError as exc:
        _err(f"sauvegarde : {exc}")
        return 6
    except RuleError as exc:
        _err(f"règle d'identification invalide : {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
