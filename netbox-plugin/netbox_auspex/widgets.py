"""Widgets Auspex pour le tableau de bord de NetBox.

Chaque utilisateur les ajoute, déplace, redimensionne et configure lui-même
(tableau de bord personnalisable de NetBox). Données : instantané écrit par
le service Auspex à chaque cycle (voir dashboard.py).
"""

from __future__ import annotations

from django import forms
from django.template.loader import render_to_string

from extras.dashboard.widgets import DashboardWidget, WidgetConfigForm, register_widget

from .dashboard import (SEVERITIES, SEVERITY_COLORS, SEVERITY_LABELS, _snapshot, allowed, decorate,
                        filter_findings, freshness)

SEVERITY_CHOICES = [("", "toutes")] + [(s, f"{SEVERITY_LABELS[s]} et plus grave") for s in SEVERITIES]
SCOPE_CHOICES = [("", "flux et inventaire"), ("flux", "flux seulement"), ("inventaire", "inventaire seulement")]


class _AuspexWidget(DashboardWidget):
    template_name = ""

    def context(self, snapshot: dict) -> dict:
        return {}

    def render(self, request):
        if not allowed(request.user):
            return render_to_string("netbox_auspex/widgets/denied.html")
        snapshot = _snapshot.get()
        ctx = {"snapshot": snapshot, "fresh": freshness(snapshot), "config": self.config}
        if snapshot:
            ctx.update(self.context(snapshot))
        return render_to_string(self.template_name, ctx, request=request)


@register_widget
class FindingsWidget(_AuspexWidget):
    default_title = "Auspex — Écarts ouverts"
    description = "Écarts de conformité ouverts (flux et inventaire), du plus grave au plus ancien."
    template_name = "netbox_auspex/widgets/findings.html"
    width = 6
    height = 5

    class ConfigForm(WidgetConfigForm):
        severity_min = forms.ChoiceField(choices=SEVERITY_CHOICES, required=False, label="Gravité")
        scope = forms.ChoiceField(choices=SCOPE_CHOICES, required=False, label="Origine")
        max_items = forms.IntegerField(min_value=1, max_value=50, initial=8, required=False, label="Lignes")

    def context(self, snapshot):
        items = filter_findings(snapshot.get("findings", []), self.config.get("severity_min") or None,
                                self.config.get("scope") or None)
        limit = int(self.config.get("max_items") or 8)
        by_sev = snapshot.get("findings_by_severity", {})
        return {"items": [decorate(f) for f in items[:limit]], "more": max(0, len(items) - limit),
                "counters": [(SEVERITY_LABELS[s], SEVERITY_COLORS[s], by_sev.get(s, 0), s) for s in SEVERITIES]}


@register_widget
class ServiceWidget(_AuspexWidget):
    default_title = "Auspex — État du service"
    description = "Dernier cycle d'analyse, erreurs, alertes en attente d'envoi au SIEM."
    template_name = "netbox_auspex/widgets/service.html"
    width = 3
    height = 3

    def context(self, snapshot):
        return {"service": snapshot.get("service", {}), "rules": snapshot.get("rules", {})}


@register_widget
class InventoryWidget(_AuspexWidget):
    default_title = "Auspex — Inventaire observé"
    description = "Actifs vus sur le réseau : nouveaux, silencieux, non identifiés, par type et par OS."
    template_name = "netbox_auspex/widgets/inventory.html"
    width = 3
    height = 5

    class ConfigForm(WidgetConfigForm):
        breakdown = forms.ChoiceField(choices=[("by_type", "par type"), ("by_os", "par système"),
                                               ("by_zone", "par zone")], required=False, label="Répartition")

    def context(self, snapshot):
        inv = snapshot.get("inventory", {})
        key = self.config.get("breakdown") or "by_type"
        total = inv.get("total") or 0
        rows = [(name, n, int(100 * n / total) if total else 0) for name, n in list(inv.get(key, {}).items())[:8]]
        return {"inv": inv, "rows": rows}


@register_widget
class ZoneMatrixWidget(_AuspexWidget):
    default_title = "Auspex — Matrice des zones"
    description = "Flux observés entre zones (microsegmentation) et écarts associés."
    template_name = "netbox_auspex/widgets/zones.html"
    width = 6
    height = 5

    def context(self, snapshot):
        z = snapshot.get("zones", {})
        names = [n for n in z.get("zones", []) if any(n in (p["src"], p["dst"]) for p in z.get("pairs", []))]
        cells = {(p["src"], p["dst"]): p for p in z.get("pairs", [])}
        grid = [(src, [cells.get((src, dst)) if src != dst else "self" for dst in names]) for src in names]
        return {"names": names, "grid": grid, "classes": z.get("classes", {})}
