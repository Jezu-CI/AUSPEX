"""Lecture de l'instantané du tableau de bord écrit par le service Auspex,
et page « Écarts de conformité ».

NetBox ne lit que ce fichier (monté en lecture seule) : jamais l'état complet
d'Auspex. Accès réservé aux comptes qui peuvent lire l'inventaire
(ipam.view_ipaddress), comme les données qu'il résume.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone

from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse
from django.shortcuts import render
from django.urls import reverse

from .middleware import get_plugin_config

REQUIRED_PERMISSION = "ipam.view_ipaddress"
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_LABELS = {"critical": "critique", "high": "élevée", "medium": "moyenne", "low": "faible", "info": "info"}
SEVERITY_COLORS = {"critical": "red", "high": "orange", "medium": "yellow", "low": "blue", "info": "secondary"}
SCOPES = {"flux": "flux", "inventaire": "inventaire"}


class _SnapshotCache:
    def __init__(self, filename: str | None = None):
        self.filename = filename  # None : l'instantané du tableau de bord ; sinon un fichier voisin
        self.lock = threading.Lock()
        self.stamp = None
        self.data = None

    def get(self) -> dict | None:
        path = get_plugin_config("netbox_auspex", "dashboard_path")
        if self.filename:
            path = os.path.join(os.path.dirname(path), self.filename)
        try:
            st = os.stat(path)
        except OSError:
            return None
        stamp = (st.st_mtime_ns, st.st_size)
        with self.lock:
            if stamp != self.stamp:
                try:
                    with open(path, encoding="utf-8") as fh:
                        self.data = json.load(fh)
                except (OSError, ValueError):
                    return self.data  # écriture en cours ou fichier abîmé : dernière version lue
                self.stamp = stamp
            return self.data


_snapshot = _SnapshotCache()
_map = _SnapshotCache("carte.json")


def allowed(user) -> bool:
    return bool(user and user.is_authenticated and (user.is_superuser or user.has_perm(REQUIRED_PERMISSION)))


def freshness(snapshot: dict | None, now: datetime | None = None) -> dict:
    """Âge des données et alerte si le service ne les met plus à jour."""
    if not snapshot:
        return {"missing": True, "stale": True, "age_minutes": None}
    now = now or datetime.now(timezone.utc)
    generated = datetime.fromisoformat(snapshot["generated_at"])
    generated = generated if generated.tzinfo else generated.replace(tzinfo=timezone.utc)
    age = (now - generated).total_seconds()
    interval = (snapshot.get("service") or {}).get("interval") or 300
    return {"missing": False, "stale": age > 3 * int(interval) + 60, "age_minutes": max(0, int(age // 60)),
            "generated_at": generated}


def decorate(finding: dict) -> dict:
    f = dict(finding)
    f["severity_label"] = SEVERITY_LABELS.get(f.get("severity"), f.get("severity"))
    f["severity_color"] = SEVERITY_COLORS.get(f.get("severity"), "secondary")
    endpoint = lambda ip, zone: f"{ip or '?'}" + (f" ({zone})" if zone else "")  # noqa: E731
    if f.get("src") or f.get("dst"):
        f["path"] = f"{endpoint(f.get('src'), f.get('src_zone'))} → {endpoint(f.get('dst'), f.get('dst_zone'))}"
    if f.get("port") is not None:
        f["port_label"] = f"{f.get('proto') or ''}/{f['port']}" + (f" {f['service']}" if f.get("service") else "")
    return f


def filter_findings(findings: list[dict], severity_min: str | None = None, scope: str | None = None,
                    zone: str | None = None, text: str | None = None) -> list[dict]:
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    out = findings
    if severity_min in rank:
        out = [f for f in out if rank.get(f.get("severity"), 99) <= rank[severity_min]]
    if scope in SCOPES:
        out = [f for f in out if f.get("scope", "flux") == scope]
    if zone:
        out = [f for f in out if zone in (f.get("src_zone"), f.get("dst_zone"))]
    if text:
        t = text.lower()
        out = [f for f in out if t in json.dumps(f, ensure_ascii=False).lower()]
    return out


def findings_view(request):
    if not request.user.is_authenticated:
        return redirect_to_login(request.get_full_path(), login_url="/login/")  # « next » encodé
    if not allowed(request.user):
        raise PermissionDenied
    snapshot = _snapshot.get()
    findings = (snapshot or {}).get("findings", [])
    q = request.GET
    selected = filter_findings(findings, q.get("gravite"), q.get("type"), q.get("zone"), q.get("q"))
    zones = sorted({z for f in findings for z in (f.get("src_zone"), f.get("dst_zone")) if z})
    return render(request, "netbox_auspex/findings.html", {
        "snapshot": snapshot, "fresh": freshness(snapshot),
        "findings": [decorate(f) for f in selected], "total": (snapshot or {}).get("findings_total", 0),
        "truncated": (snapshot or {}).get("findings_total", 0) > len(findings),
        "severities": [(s, SEVERITY_LABELS[s]) for s in SEVERITIES], "zones": zones,
        "filters": {"gravite": q.get("gravite", ""), "type": q.get("type", ""), "zone": q.get("zone", ""),
                    "q": q.get("q", "")},
    })


def _guard(request):
    if not request.user.is_authenticated:
        return redirect_to_login(request.get_full_path(), login_url="/login/")  # « next » encodé
    if not allowed(request.user):
        raise PermissionDenied
    return None


def map_view(request):
    redirect_ = _guard(request)
    if redirect_:
        return redirect_
    return render(request, "netbox_auspex/carte.html", {"data_url": reverse("plugins:netbox_auspex:map_data")})


def map_data_view(request):
    if not request.user.is_authenticated or not allowed(request.user):
        return JsonResponse({"detail": "Lecture de l'inventaire nécessaire."}, status=403)
    data = _map.get()
    if data is None:
        return JsonResponse({"detail": "Carte pas encore produite par le service Auspex."}, status=404)
    return JsonResponse(data)
