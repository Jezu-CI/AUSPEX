"""Persistance de l'état entre deux analyses (répertoire d'état, JSON).

Les logs Zeek ne vivent que 24 à 48 h sur le capteur : pour détecter un flux
qui persiste depuis plusieurs jours, les flux agrégés et les votes
d'identification sont cumulés ici, puis purgés au-delà de la durée de rétention.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

from .compliance import Finding
from .fingerprint.engine import Asset
from .zeek import Flow


def _atomic_write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    tmp.replace(path)


def _read(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _dt(s: str | None) -> datetime | None:
    return datetime.fromisoformat(s) if s else None


class FlowStore:
    def __init__(self, state_dir: Path):
        self.path = Path(state_dir) / "flows.json"

    def load(self) -> dict[tuple, Flow]:
        flows = {}
        for d in _read(self.path, []):
            f = Flow(d["src"], d["dst"], d["proto"], d["port"], _dt(d["first_seen"]), _dt(d["last_seen"]),
                     d["count"], d["bytes"], d.get("attempts_rejected", 0), set(d.get("services", [])))
            flows[f.key] = f
        return flows

    @staticmethod
    def merge(base: dict[tuple, Flow], new: dict[tuple, Flow]) -> dict[tuple, Flow]:
        for key, f in new.items():
            cur = base.get(key)
            if cur is None:
                base[key] = f
                continue
            cur.first_seen = min(cur.first_seen, f.first_seen)
            cur.last_seen = max(cur.last_seen, f.last_seen)
            cur.count += f.count
            cur.bytes += f.bytes
            cur.attempts_rejected += f.attempts_rejected
            cur.services |= f.services
        return base

    @staticmethod
    def prune(flows: dict[tuple, Flow], now: datetime, retention_days: int) -> int:
        limit = now - timedelta(days=retention_days)
        old = [k for k, f in flows.items() if f.last_seen < limit]
        for k in old:
            del flows[k]
        return len(old)

    def save(self, flows: dict[tuple, Flow]) -> None:
        _atomic_write(self.path, [f.to_dict() for f in flows.values()])


class AssetStore:
    """Conserve les votes bruts : la confiance est recalculée à chaque lecture."""

    def __init__(self, state_dir: Path):
        self.path = Path(state_dir) / "assets.json"

    def load(self) -> dict[str, Asset]:
        assets = {}
        for d in _read(self.path, []):
            a = Asset(ip=d["ip"], macs=set(d["macs"]), hostnames=set(d["hostnames"]), zone=d.get("zone"),
                      first_seen=_dt(d["first_seen"]), last_seen=_dt(d["last_seen"]), votes=d["votes"])
            assets[a.ip] = a
        return assets

    @staticmethod
    def merge(base: dict[str, Asset], new: dict[str, Asset]) -> dict[str, Asset]:
        for ip, a in new.items():
            cur = base.get(ip)
            if cur is None:
                base[ip] = a
                continue
            cur.macs |= a.macs
            cur.hostnames |= a.hostnames
            cur.zone = a.zone or cur.zone
            cur.seen(a.first_seen)
            cur.seen(a.last_seen)
            for attr, values in a.votes.items():
                for value, rules in values.items():
                    for rid, w in rules.items():
                        cur.vote(attr, value, rid, w)
        return base

    @staticmethod
    def prune(assets: dict[str, Asset], now: datetime, retention_days: int) -> int:
        limit = now - timedelta(days=retention_days)
        old = [ip for ip, a in assets.items() if a.last_seen and a.last_seen < limit]
        for ip in old:
            del assets[ip]
        return len(old)

    def save(self, assets: dict[str, Asset]) -> None:
        _atomic_write(self.path, [{
            "ip": a.ip, "macs": sorted(a.macs), "hostnames": sorted(a.hostnames), "zone": a.zone,
            "first_seen": a.first_seen.isoformat() if a.first_seen else None,
            "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            "votes": a.votes,
        } for a in assets.values()])


class AlertStore:
    """Cycle de vie des alertes : ouverture, mise à jour, résolution.

    Une alerte garde son identifiant de l'ouverture à la résolution. Une mise à
    jour n'est émise que si le type ou la gravité change (ex. un flux non
    déclaré qui devient persistant), pas à chaque analyse.
    """

    def __init__(self, state_dir: Path):
        self.path = Path(state_dir) / "alerts.json"

    def load(self) -> dict[str, dict]:
        return _read(self.path, {})

    def reconcile(self, findings: list[Finding], now: datetime, scope: str = "flux") -> list[dict]:
        """`scope` cloisonne les sources d'écarts (« flux » : analyse des logs,
        « inventaire » : rapprochement avec NetBox). Une analyse ne résout que
        les alertes de son propre périmètre."""
        alerts = self.load()
        events: list[dict] = []
        current = {f.id: f for f in findings}
        stamp = now.isoformat()
        for fid, f in current.items():
            prev = alerts.get(fid)
            data = f.to_dict()
            if prev is None or prev["status"] == "resolved":
                alerts[fid] = {"status": "open", "scope": scope, "opened_at": stamp, "updated_at": stamp,
                               "finding": data}
                events.append({"event": "open", **data})
            elif (prev["finding"]["type"], prev["finding"]["severity"]) != (f.type, f.severity):
                prev.update(updated_at=stamp, finding=data)
                events.append({"event": "update", **data})
            else:
                prev["finding"] = data  # dates et compteurs à jour, sans événement
        for fid, prev in alerts.items():
            if prev["status"] == "open" and prev.get("scope", "flux") == scope and fid not in current:
                prev.update(status="resolved", resolved_at=stamp, updated_at=stamp)
                events.append({"event": "resolve", **prev["finding"]})
        _atomic_write(self.path, alerts)
        return events

    def open_alerts(self) -> list[dict]:
        return [a for a in self.load().values() if a["status"] == "open"]


class IngestLedger:
    """Registre d'ingestion : jusqu'où chaque fichier de log a déjà été lu.

    Sans lui, relancer une analyse sur les mêmes logs compterait chaque
    connexion une fois de plus à chaque passage.
    """

    def __init__(self, state_dir: Path):
        self.path = Path(state_dir) / "ingest.json"
        self.entries: dict[str, dict] = _read(self.path, {})
        self.stats = {"new": 0, "resumed": 0, "unchanged": 0, "records": 0}

    def offset(self, ident: str) -> int:
        return int(self.entries.get(ident, {}).get("offset", 0))

    def record(self, ident: str, path: Path, end: int, records: int) -> None:
        prev = self.offset(ident)
        if ident not in self.entries:
            self.stats["new"] += 1
        elif end > prev:
            self.stats["resumed"] += 1
        else:
            self.stats["unchanged"] += 1
        self.stats["records"] += records
        self.entries[ident] = {"path": str(path), "offset": max(end, prev),
                               "updated": datetime.now().isoformat(timespec="seconds")}

    def prune(self, retention_days: int) -> None:
        limit = datetime.now() - timedelta(days=retention_days)
        self.entries = {k: v for k, v in self.entries.items()
                        if datetime.fromisoformat(v["updated"]) >= limit}

    def save(self) -> None:
        _atomic_write(self.path, self.entries)
