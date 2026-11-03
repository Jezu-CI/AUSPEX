"""Sorties d'alertes vers le SIEM.

Toutes les sorties partagent :
- un format d'événement normalisé, aligné sur OCSF (severity_id 1 à 5) ;
- un filtre de gravité minimale par sortie ;
- une file d'attente sur disque : un envoi en échec est conservé et
  réexpédié à la distribution suivante, sans perte.
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .. import __version__
from ..compliance import SEVERITY_ORDER
from ..config import Output

PRODUCT = "auspex"
OCSF_SEVERITY = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
SYSLOG_SEVERITY = {"info": 6, "low": 5, "medium": 4, "high": 3, "critical": 2}
CEF_SEVERITY = {"info": 1, "low": 3, "medium": 5, "high": 8, "critical": 10}
FACILITY_LOCAL0 = 16


def normalize(event: dict, now: datetime | None = None) -> dict:
    """Événement normalisé, indépendant de la sortie."""
    now = now or datetime.now(timezone.utc)
    sev = event.get("severity", "info")
    return {
        "time": now.isoformat(),
        "product": {"name": PRODUCT, "version": __version__},
        "activity": event.get("event", "open"),
        "id": event["id"],
        "type": event["type"],
        "title": event.get("title", event["type"]),
        "severity": sev,
        "severity_id": OCSF_SEVERITY.get(sev, 1),
        "message": event.get("message", ""),
        "src_endpoint": {"ip": event.get("src"), "zone": event.get("src_zone")},
        "dst_endpoint": {"ip": event.get("dst"), "zone": event.get("dst_zone"), "port": event.get("port")},
        "connection_info": {"protocol_name": event.get("proto"), "service": event.get("service")},
        "first_seen": event.get("first_seen"),
        "last_seen": event.get("last_seen"),
        "count": event.get("count", 0),
        "rule_ids": event.get("rule_ids", []),
        "references": event.get("references", []),
    }


def _cef_header(s: str) -> str:
    return str(s).replace("\\", "\\\\").replace("|", "\\|")


def _cef_ext(s) -> str:
    return (str(s).replace("\\", "\\\\").replace("=", "\\=")
            .replace("\r", "\\r").replace("\n", "\\n"))


def to_cef(ev: dict) -> str:
    ext = {
        "rt": int(datetime.fromisoformat(ev["time"]).timestamp() * 1000),
        "externalId": ev["id"],
        "act": ev["activity"],
        "msg": ev["message"],
        "src": ev["src_endpoint"]["ip"], "dst": ev["dst_endpoint"]["ip"],
        "dpt": ev["dst_endpoint"]["port"], "proto": ev["connection_info"]["protocol_name"],
        "app": ev["connection_info"]["service"],
        "cnt": ev["count"],
        "cs1Label": "srcZone", "cs1": ev["src_endpoint"]["zone"],
        "cs2Label": "dstZone", "cs2": ev["dst_endpoint"]["zone"],
        "cs3Label": "references", "cs3": "; ".join(ev["references"]),
        "cs4Label": "ruleIds", "cs4": ",".join(ev["rule_ids"]),
    }
    exts = " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items() if v not in (None, ""))
    header = "|".join(_cef_header(x) for x in (
        "CEF:0", PRODUCT, PRODUCT, __version__, ev["type"], ev["title"], CEF_SEVERITY[ev["severity"]],
    ))
    return f"{header}|{exts}"


def to_syslog(ev: dict, body: str, hostname: str | None = None) -> str:
    """Message RFC 5424."""
    pri = FACILITY_LOCAL0 * 8 + SYSLOG_SEVERITY[ev["severity"]]
    host = (hostname or socket.gethostname() or "-")[:255]
    return f"<{pri}>1 {ev['time']} {host} {PRODUCT} - {ev['type'][:32]} - {body}"


def passes(ev: dict, min_severity: str) -> bool:
    return SEVERITY_ORDER.index(ev["severity"]) >= SEVERITY_ORDER.index(min_severity)


class DeliveryError(Exception):
    pass


def _send_syslog(out: Output, messages: list[str]) -> None:
    u = urlparse(out.url)
    scheme = u.scheme
    host, port = u.hostname, u.port or (6514 if scheme == "tls" else 514)
    try:
        if scheme in {"udp", "syslog"}:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                for m in messages:
                    s.sendto(m.encode("utf-8"), (host, port))
            return
        raw = socket.create_connection((host, port), timeout=10)
        if scheme == "tls":
            # Vérification du certificat toujours active ; ca_file pour une AC privée.
            ctx = ssl.create_default_context(cafile=out.ca_file)
            raw = ctx.wrap_socket(raw, server_hostname=host)
        with raw as s:
            for m in messages:
                data = m.encode("utf-8")
                s.sendall(f"{len(data)} ".encode() + data)  # RFC 6587, octet counting
            _close_gracefully(s)
    except (OSError, ssl.SSLError) as exc:
        raise DeliveryError(f"syslog {out.url} : {exc}") from exc


def _close_gracefully(s, timeout: float = 2.0) -> None:
    """Fermeture propre de la connexion vers le SIEM.

    Fermer une socket qui contient encore des données reçues non lues (en TLS
    1.3, les tickets de session envoyés par le serveur après la poignée de
    main) provoque une réinitialisation TCP (RST) au lieu d'une fin normale :
    le serveur peut alors perdre les derniers messages qu'il n'avait pas
    encore lus. On termine donc proprement : fin TLS (close_notify), fin
    d'émission, puis lecture de ce qui reste, avant de fermer.
    """
    s.settimeout(timeout)
    try:
        if isinstance(s, ssl.SSLSocket):
            s = s.unwrap()
        s.shutdown(socket.SHUT_WR)
        while s.recv(4096):
            pass
    except (OSError, ssl.SSLError, ValueError):
        pass  # le serveur a déjà fermé, ou ne répond pas : les messages sont partis


def _send_webhook(out: Output, events: list[dict]) -> None:
    headers = {"Content-Type": "application/json", "User-Agent": f"{PRODUCT}/{__version__}"}
    if out.token_env:
        token = os.environ.get(out.token_env)
        if not token:
            raise DeliveryError(f"webhook {out.url} : variable d'environnement {out.token_env} absente")
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps({"events": events}, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(out.url, data=body, headers=headers, method="POST")
    ctx = ssl.create_default_context(cafile=out.ca_file) if out.url.startswith("https") else None
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            if resp.status >= 300:
                raise DeliveryError(f"webhook {out.url} : HTTP {resp.status}")
    except urllib.error.URLError as exc:
        raise DeliveryError(f"webhook {out.url} : {exc}") from exc


def _send_file(out: Output, events: list[dict], base_dir: Path) -> None:
    path = Path(out.path)
    if not path.is_absolute():
        path = base_dir / path
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev, ensure_ascii=False) + "\n")


def deliver(out: Output, events: list[dict], base_dir: Path) -> None:
    if not events:
        return
    if out.type == "syslog":
        bodies = [to_cef(e) if out.format == "cef" else json.dumps(e, ensure_ascii=False) for e in events]
        _send_syslog(out, [to_syslog(e, b) for e, b in zip(events, bodies)])
    elif out.type == "webhook":
        _send_webhook(out, events)
    elif out.type == "file":
        _send_file(out, events, base_dir)


class Dispatcher:
    def __init__(self, outputs: list[Output], state_dir: Path, base_dir: Path):
        self.outputs = outputs
        self.outbox = Path(state_dir) / "outbox"
        self.base_dir = base_dir

    def _queue_path(self, i: int, out: Output) -> Path:
        return self.outbox / f"{i:02d}-{out.type}.jsonl"

    def dispatch(self, raw_events: list[dict], now: datetime | None = None) -> list[str]:
        """Envoie les événements ; renvoie la liste des erreurs (vide si tout est parti)."""
        events = [normalize(e, now) for e in raw_events]
        errors = []
        for i, out in enumerate(self.outputs):
            qpath = self._queue_path(i, out)
            pending = []
            if qpath.exists():
                pending = [json.loads(l) for l in qpath.read_text(encoding="utf-8").splitlines() if l]
            batch = pending + [e for e in events if passes(e, out.min_severity)]
            if not batch:
                continue
            try:
                deliver(out, batch, self.base_dir)
                if qpath.exists():
                    qpath.unlink()
            except DeliveryError as exc:
                self.outbox.mkdir(parents=True, exist_ok=True)
                qpath.write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in batch),
                                 encoding="utf-8")
                errors.append(f"{exc} — {len(batch)} événement(s) conservé(s) pour le prochain envoi")
        return errors
