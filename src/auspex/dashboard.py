"""Instantané pour le tableau de bord (widgets du plugin NetBox).

Écrit par le service à la fin de chaque cycle dans <state_dir>/tableau/,
seul répertoire que NetBox lit (en lecture seule). Il ne contient que ce que
les widgets affichent : écarts ouverts, inventaire résumé, matrice des zones,
état du service. Les flux et l'inventaire complets restent chez Auspex.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from .config import Config
from .state import AlertStore, AssetStore, FlowStore, _atomic_write
from .zones import ZoneMap

SNAPSHOT_DIR = "tableau"
SNAPSHOT_FILE = "dashboard.json"
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
MAX_FINDINGS = 500           # au-delà : la page des écarts affiche « et N autres »
MAX_NEW_ASSETS = 10


def snapshot_path(state_dir: Path) -> Path:
    return Path(state_dir) / SNAPSHOT_DIR / SNAPSHOT_FILE


def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    d = datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _value(ident: dict, attr: str) -> str | None:
    v = ident.get(attr)
    return v.get("value") if isinstance(v, dict) else None


def _findings(state_dir: Path) -> list[dict]:
    out = []
    for alert in AlertStore(state_dir).open_alerts():
        f = dict(alert["finding"])
        f.update(scope=alert.get("scope", "flux"), opened_at=alert.get("opened_at"))
        out.append(f)
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    # Plus grave d'abord ; à gravité égale, le plus ancien (celui qui traîne).
    out.sort(key=lambda f: (rank.get(f["severity"], 99), f.get("opened_at") or "", f["id"]))
    return out


def _inventory(state_dir: Path, now: datetime, normalizer) -> dict:
    assets = AssetStore(state_dir).load()
    by_zone, by_type, by_os = Counter(), Counter(), Counter()
    new, silent, unidentified = [], 0, 0
    for a in assets.values():
        ident = a.conclusions(normalizer)
        dtype, os_family = _value(ident, "device_type"), _value(ident, "os_family")
        by_zone[a.zone or "hors zones"] += 1
        by_type[dtype or "type inconnu"] += 1
        by_os[os_family or "système inconnu"] += 1
        if not dtype and not os_family:
            unidentified += 1
        if a.last_seen and a.last_seen < now - timedelta(days=7):
            silent += 1
        if a.first_seen and a.first_seen >= now - timedelta(hours=24):
            new.append({"ip": a.ip, "zone": a.zone, "hostname": sorted(a.hostnames)[0] if a.hostnames else None,
                        "device_type": dtype, "os_family": os_family, "first_seen": a.first_seen.isoformat()})
    new.sort(key=lambda x: x["first_seen"], reverse=True)
    return {"total": len(assets), "new_24h": len(new), "silent_7d": silent, "unidentified": unidentified,
            "by_zone": dict(by_zone.most_common()), "by_type": dict(by_type.most_common()),
            "by_os": dict(by_os.most_common()), "new": new[:MAX_NEW_ASSETS]}


def _zone_matrix(cfg: Config, findings: list[dict]) -> dict:
    """Flux entre zones (microsegmentation) : nombre de flux et d'écarts par couple."""
    zmap = ZoneMap(cfg.zones)
    flows = Counter()
    for f in FlowStore(cfg.state_dir).load().values():
        sz, dz = zmap.name_of(f.src), zmap.name_of(f.dst)
        if sz and dz and sz != dz:
            flows[(sz, dz)] += 1
    issues = Counter((f.get("src_zone"), f.get("dst_zone")) for f in findings
                     if f.get("scope", "flux") == "flux" and f.get("src_zone") and f.get("dst_zone"))
    pairs = sorted(set(flows) | set(issues))
    return {"zones": [z.name for z in cfg.zones],
            "classes": {z.name: z.zclass for z in cfg.zones},
            "pairs": [{"src": s, "dst": d, "flows": flows[(s, d)], "findings": issues[(s, d)]} for s, d in pairs]}


def _rules(cfg: Config, today: date) -> dict:
    from .flowrules import RuleStore
    rules = RuleStore(cfg.state_dir).load([z.name for z in cfg.zones])
    soon = today + timedelta(days=7)
    expiring = [r for r in rules if r.expire_le and today <= date.fromisoformat(r.expire_le) <= soon]
    return {"total": len(rules), "expired": sum(1 for r in rules if r.expired(today)),
            "expiring_7d": len(expiring)}


def _service(state_dir: Path) -> dict:
    hb = Path(state_dir) / "heartbeat.json"
    status = json.loads(hb.read_text(encoding="utf-8")) if hb.exists() else {}
    outbox = Path(state_dir) / "outbox"
    pending = 0
    if outbox.is_dir():
        for f in outbox.glob("*.jsonl"):
            with f.open(encoding="utf-8") as fh:
                pending += sum(1 for line in fh if line.strip())
    analyse, netbox = status.get("analyse") or {}, status.get("netbox") or {}
    return {
        "ok": status.get("ok"), "error": status.get("error"),
        "started": status.get("started"), "finished": status.get("finished"),
        "interval": status.get("interval"), "records": analyse.get("records"),
        "delivery_errors": len(analyse.get("delivery_errors") or []) + len(netbox.get("delivery_errors") or []),
        "outbox_pending": pending, "netbox_sync": bool(netbox),
    }


def build_snapshot(cfg: Config, now: datetime | None = None, normalizer=None) -> dict:
    now = now or datetime.now(timezone.utc)
    findings = _findings(cfg.state_dir)
    sev = Counter(f["severity"] for f in findings)
    return {
        "version": 1,
        "generated_at": now.isoformat(timespec="seconds"),
        "service": _service(cfg.state_dir),
        "findings_total": len(findings),
        "findings_by_severity": {s: sev[s] for s in SEVERITY_ORDER},
        "findings_by_type": dict(Counter(f.get("title") or f["type"] for f in findings).most_common()),
        "findings": findings[:MAX_FINDINGS],
        "inventory": _inventory(cfg.state_dir, now, normalizer),
        "zones": _zone_matrix(cfg, findings),
        "rules": _rules(cfg, now.date()),
    }


# --- Carte interactive ----------------------------------------------------------------

MAP_FILE = "carte.json"
MAX_MAP_NODES = 1500
MAX_MAP_EDGES = 4000
# Ordre d'affichage des zones : tiers IT d'un côté, niveaux Purdue (5 → 0) de l'autre.
ZONE_ORDER = ("tier0", "admin", "tier1", "tier2", "dmz", "other",
              "purdue5", "purdue4", "purdue3.5", "purdue3", "purdue2", "purdue1", "purdue0")


def map_path(state_dir: Path) -> Path:
    return Path(state_dir) / SNAPSHOT_DIR / MAP_FILE


def _port_label(proto: str, port, services) -> str:
    label = f"{proto}/{port}" if port is not None else proto
    return f"{label} {sorted(services)[0]}" if services else label


def build_map(cfg: Config, now: datetime | None = None, normalizer=None, findings: list[dict] | None = None) -> dict:
    """Actifs (nœuds), flux agrégés par couple (liens) et zones, pour la carte."""
    now = now or datetime.now(timezone.utc)
    zmap = ZoneMap(cfg.zones)
    findings = findings if findings is not None else _findings(cfg.state_dir)
    by_ip: Counter = Counter()
    inventory_by_ip: dict[str, list[str]] = {}
    pair_findings: dict[tuple, list[str]] = {}
    for f in findings:
        if f.get("scope", "flux") != "flux":
            # Écart d'inventaire (actif absent de la CMDB...) : montré dans le détail de
            # l'actif, sans le cercle rouge réservé aux flux en écart (sinon, sur une CMDB
            # encore vide, tous les actifs seraient marqués et le signal se perdrait).
            for ip in {f.get("src"), f.get("dst"), f.get("ip")} - {None}:
                inventory_by_ip.setdefault(ip, []).append(f.get("title") or f["type"])
            continue
        for ip in {f.get("src"), f.get("dst")} - {None}:
            by_ip[ip] += 1
        if f.get("src") and f.get("dst"):
            pair_findings.setdefault((f["src"], f["dst"]), []).append(f.get("title") or f["type"])

    nodes = {}
    for a in AssetStore(cfg.state_dir).load().values():
        ident = a.conclusions(normalizer)
        nodes[a.ip] = {
            "id": a.ip, "zone": a.zone or zmap.name_of(a.ip), "hostname": sorted(a.hostnames)[0] if a.hostnames else None,
            "type": _value(ident, "device_type"), "os": _value(ident, "os_family"),
            "vendor": _value(ident, "vendor"), "model": _value(ident, "model"),
            "roles": [r["value"] for r in ident.get("role", [])][:4] if isinstance(ident.get("role"), list) else [],
            "first_seen": a.first_seen.isoformat() if a.first_seen else None,
            "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            "silent": bool(a.last_seen and a.last_seen < now - timedelta(days=7)),
            "findings": by_ip[a.ip],
            "inventory_findings": sorted(set(inventory_by_ip.get(a.ip, []))),
        }

    edges: dict[tuple, dict] = {}
    for fl in FlowStore(cfg.state_dir).load().values():
        if fl.src not in nodes or fl.dst not in nodes:
            continue
        e = edges.setdefault((fl.src, fl.dst), {"src": fl.src, "dst": fl.dst, "count": 0, "ports": Counter(),
                                                "last_seen": fl.last_seen})
        e["count"] += fl.count
        e["ports"][_port_label(fl.proto, fl.port, fl.services)] += fl.count
        e["last_seen"] = max(e["last_seen"], fl.last_seen)
    out_edges = []
    for (src, dst), e in edges.items():
        issues = pair_findings.get((src, dst), [])
        out_edges.append({"src": src, "dst": dst, "count": e["count"],
                          "ports": [p for p, _ in e["ports"].most_common(6)],
                          "last_seen": e["last_seen"].isoformat(), "findings": sorted(set(issues)),
                          "inter_zone": nodes[src]["zone"] != nodes[dst]["zone"]})
    # Les liens en écart d'abord, puis les plus fréquents : ce qui compte reste
    # visible même sur un très grand réseau.
    out_edges.sort(key=lambda e: (not e["findings"], -e["count"]))
    kept_edges = out_edges[:MAX_MAP_EDGES]
    kept = sorted(nodes.values(), key=lambda n: (-n["findings"], n["id"]))[:MAX_MAP_NODES]
    kept_ids = {n["id"] for n in kept}
    kept_edges = [e for e in kept_edges if e["src"] in kept_ids and e["dst"] in kept_ids]
    order = {c: i for i, c in enumerate(ZONE_ORDER)}
    zones = [{"name": z.name, "class": z.zclass, "ot": z.is_ot,
              "assets": sum(1 for n in kept if n["zone"] == z.name)}
             for z in sorted(cfg.zones, key=lambda z: (order.get(z.zclass, 99), z.name))]
    if any(n["zone"] is None for n in kept):
        zones.append({"name": None, "class": "hors zones", "ot": False,
                      "assets": sum(1 for n in kept if n["zone"] is None)})
    return {"version": 1, "generated_at": now.isoformat(timespec="seconds"), "zones": zones,
            "nodes": kept, "edges": kept_edges,
            "truncated": {"nodes": max(0, len(nodes) - len(kept)), "edges": max(0, len(out_edges) - len(kept_edges))}}


def write_snapshot(cfg: Config, now: datetime | None = None, normalizer=None) -> Path:
    path = snapshot_path(cfg.state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    snapshot = build_snapshot(cfg, now, normalizer)
    _atomic_write(path, snapshot)
    _atomic_write(map_path(cfg.state_dir), build_map(cfg, now, normalizer, _findings(cfg.state_dir)))
    return path
