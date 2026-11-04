"""Comparaison des flux observés aux règles déclarées et au modèle d'architecture.

Deux familles d'écarts :

1. Écarts aux règles déclarées (fichier CSV/XLSX importé) :
   - nouveau_flux_non_declare      flux sans règle, vu depuis moins de N jours
   - flux_non_declare_persistant   flux sans règle, observé sur N jours ou plus
   - regle_expiree_utilisee        seule une règle expirée couvre ce flux
   - regle_jamais_utilisee         règle sans aucun trafic sur la fenêtre d'observation

2. Violations d'architecture, signalées même si une règle les autorise :
   - flux_admin_inter_tiers        protocole d'administration d'un tier moins
                                   sensible vers un tier plus sensible (modèle ANSSI)
   - flux_it_vers_ot_direct        flux du SI de gestion vers les niveaux Purdue 0-2
                                   sans passer par la DMZ industrielle (IEC 62443)

3. Comportement :
   - balayage_reseau               une machine tente de joindre de nombreuses cibles
                                   (adresse et port) refusées ou sans réponse ; une
                                   alerte par machine, résolue quand le balayage cesse
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone

from .config import AlertsConfig
from .flowrules import FlowRule
from .zeek import Flow
from .zones import UNKNOWN_ZONE, ZoneMap

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# Administration interactive : prise de main à distance sur la cible.
# SMB et RPC n'en font pas partie : les postes les utilisent légitimement
# vers les contrôleurs de domaine (GPO, SYSVOL) et les serveurs de fichiers.
ADMIN_PORTS = {
    ("tcp", 22): "SSH", ("tcp", 23): "Telnet", ("tcp", 3389): "RDP",
    ("tcp", 5985): "WinRM", ("tcp", 5986): "WinRM", ("tcp", 5900): "VNC",
}

OTHER_SERVICES = {("tcp", 445): "SMB", ("tcp", 135): "RPC", ("udp", 161): "SNMP"}

OT_PORTS = {
    ("tcp", 502): "Modbus/TCP", ("tcp", 102): "S7comm", ("tcp", 44818): "EtherNet/IP",
    ("udp", 2222): "EtherNet/IP I/O", ("tcp", 20000): "DNP3", ("udp", 47808): "BACnet",
    ("tcp", 4840): "OPC UA",
}

# Rang de sensibilité dans le modèle en tiers : plus petit = plus sensible.
# Une zone « admin » sert à administrer les tiers 1 et 2 ; l'administration
# du tier 0 se fait depuis une zone classée tier0.
TIER_RANK = {"tier0": 0, "admin": 1, "tier1": 1, "tier2": 2}

IT_CLASSES = {"tier0", "tier1", "tier2", "admin", "purdue4", "purdue5"}
OT_LOW_CLASSES = {"purdue0", "purdue1", "purdue2"}

REFERENCES = {
    "nouveau_flux_non_declare": [
        "NIS2 CIR 2024/2690 §6.8 (segmentation)", "IEC 62443-3-3 SR 5.1", "ISO 27001 A.8.22",
    ],
    "flux_non_declare_persistant": [
        "NIS2 CIR 2024/2690 §6.8 (segmentation)", "IEC 62443-3-3 SR 5.1", "ISO 27001 A.8.22",
    ],
    "regle_expiree_utilisee": [
        "NIS2 CIR 2024/2690 §6.7 (sécurité des réseaux)", "ISO 27001 A.8.20",
    ],
    "regle_jamais_utilisee": [
        "NIS2 CIR 2024/2690 §6.7 (sécurité des réseaux)", "ISO 27001 A.8.20",
    ],
    "flux_admin_inter_tiers": [
        "ANSSI, administration sécurisée des SI (modèle en tiers)",
        "NIS2 CIR 2024/2690 §6.8 (réseau d'administration dédié)",
    ],
    "flux_it_vers_ot_direct": [
        "IEC 62443-3-2 (zones et conduits)", "IEC 62443-3-3 SR 5.2",
        "NIS2 CIR 2024/2690 §6.8 (segmentation)",
    ],
    "balayage_reseau": [
        "NIS2 CIR 2024/2690 §3.2 (surveillance et journalisation)", "DORA art. 10 (détection)",
        "IEC 62443-3-3 SR 6.2 (surveillance continue)", "ISO 27001 A.8.16",
    ],
}

TITLES = {
    "nouveau_flux_non_declare": "Nouveau flux non déclaré",
    "flux_non_declare_persistant": "Flux non déclaré persistant",
    "regle_expiree_utilisee": "Règle expirée encore utilisée",
    "regle_jamais_utilisee": "Règle jamais utilisée",
    "flux_admin_inter_tiers": "Administration depuis un tier moins sensible",
    "flux_it_vers_ot_direct": "Flux IT vers OT sans DMZ industrielle",
    "balayage_reseau": "Balayage du réseau",
    "actif_inconnu": "Actif observé, absent de la CMDB",
    "actif_silencieux": "Actif déclaré, non observé",
    "identification_divergente": "Identification divergente",
    "fiche_incomplete": "Fiche d'inventaire incomplète",
}


def escalate(severity: str, steps: int = 1) -> str:
    i = min(SEVERITY_ORDER.index(severity) + steps, len(SEVERITY_ORDER) - 1)
    return SEVERITY_ORDER[i]


def count_label(finding_type: str, count: int) -> str:
    """« 3 connexion(s) », ou « 120 cible(s) » pour un balayage."""
    return f"{count} cible(s)" if finding_type == "balayage_reseau" else f"{count} connexion(s)"


def stable_id(*parts) -> str:
    h = hashlib.sha256("|".join("" if p is None else str(p) for p in parts).encode())
    return "AUSPEX-" + h.hexdigest()[:16]


@dataclass
class Finding:
    id: str
    type: str
    severity: str
    message: str
    src: str | None = None
    dst: str | None = None
    src_zone: str | None = None
    dst_zone: str | None = None
    proto: str | None = None
    port: int | None = None
    service: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    count: int = 0
    rule_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    @property
    def title(self) -> str:
        return TITLES.get(self.type, self.type)

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["title"] = self.title
        return d


def _service_name(proto: str, port: int | None) -> str | None:
    key = (proto, port)
    return ADMIN_PORTS.get(key) or OT_PORTS.get(key) or OTHER_SERVICES.get(key)


@dataclass
class ComplianceReport:
    findings: list[Finding]
    flows_evaluated: int
    flows_covered: int
    window_start: datetime | None
    window_end: datetime | None

    def by_type(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.type] = out.get(f.type, 0) + 1
        return out


# Cibles dont le balayage relève la gravité d'un cran : le tier 0, et
# l'atelier, où un balayage peut suffire à arrêter un automate.
SCAN_SENSITIVE = {"tier0"} | OT_LOW_CLASSES


def _scans(flows: list[Flow], zones: ZoneMap, cfg, now: datetime) -> list[Finding]:
    """Balayages : par machine source, cibles (adresse, port) jamais jointes,
    refusées ou sans réponse, dans la fenêtre récente. Une seule alerte par
    source (identifiant stable) : ouverte pendant le balayage, mise à jour si la
    gravité change, résolue quand les tentatives sortent de la fenêtre."""
    if not cfg.enabled:
        return []
    since = now - timedelta(hours=cfg.window_hours)
    by_src: dict[str, list[Flow]] = {}
    for fl in flows:
        if fl.count == 0 and fl.attempts_unanswered > 0 and fl.last_seen >= since:
            by_src.setdefault(fl.src, []).append(fl)
    out: list[Finding] = []
    for src, targets in by_src.items():
        if len(targets) < cfg.min_targets:
            continue
        try:
            addr = ipaddress.ip_address(src)
        except ValueError:
            continue
        if any(addr in net for net in cfg.allowed):
            continue
        dst_zones = sorted({zones.name_of(t.dst) for t in targets})
        sensitive = any(zones.class_of(t.dst) in SCAN_SENSITIVE for t in targets)
        severity = escalate(cfg.severity) if sensitive else cfg.severity
        ports: dict[int, int] = {}
        for t in targets:
            if t.port is not None:
                ports[t.port] = ports.get(t.port, 0) + 1
        top = [str(p) for p, _ in sorted(ports.items(), key=lambda x: (-x[1], x[0]))[:5]]
        hosts = len({t.dst for t in targets})
        sz = zones.name_of(src)
        message = (f"Balayage du réseau depuis {src} ({sz}) : {len(targets)} cibles (adresse et port) "
                   f"refusées ou sans réponse en {cfg.window_hours} h, sur {hosts} machine(s) ; "
                   f"zones visées : {', '.join(dst_zones)}")
        if top:
            message += f" ; ports les plus visés : {', '.join(top)}"
        if sensitive:
            message += " ; cibles sensibles (tier 0 ou atelier)"
        out.append(Finding(
            id=stable_id("balayage_reseau", src), type="balayage_reseau", severity=severity,
            message=message, src=src, src_zone=sz, dst_zone=", ".join(dst_zones), proto="tcp",
            # Début borné à la fenêtre : une cible tentée de longue date ne fait
            # pas remonter le balayage au-delà de ce qui a été compté.
            first_seen=max(since, min(t.first_seen for t in targets)).isoformat(),
            last_seen=max(t.last_seen for t in targets).isoformat(),
            count=len(targets),   # cibles (adresse et port) dans la fenêtre
            references=REFERENCES["balayage_reseau"],
        ))
    return out


def evaluate(flows: list[Flow], rules: list[FlowRule], zones: ZoneMap,
             alerts_cfg: AlertsConfig, now: datetime | None = None) -> ComplianceReport:
    """Évalue les flux. `now` = instant de référence (par défaut : maintenant)."""
    now = now or datetime.now(timezone.utc)
    today: date = now.date()
    persistent = timedelta(days=alerts_cfg.persistent_after_days)
    findings: list[Finding] = []
    used_rules: set[str] = set()
    evaluated = covered = 0
    window_start = min((f.first_seen for f in flows), default=None)
    window_end = max((f.last_seen for f in flows), default=None)

    for fl in flows:
        if not fl.established:
            continue  # tentatives uniquement : bloquées, pas un flux
        sz, dz = zones.name_of(fl.src), zones.name_of(fl.dst)
        sc, dc = zones.class_of(fl.src), zones.class_of(fl.dst)
        inter_zone = sz != dz or sz == UNKNOWN_ZONE
        svc = _service_name(fl.proto, fl.port)
        common = dict(
            src=fl.src, dst=fl.dst, src_zone=sz, dst_zone=dz, proto=fl.proto, port=fl.port,
            service=svc, first_seen=fl.first_seen.isoformat(), last_seen=fl.last_seen.isoformat(),
            count=fl.count,
        )
        label = f"{fl.src} ({sz}) → {fl.dst} ({dz}) {fl.proto}/{fl.port if fl.port is not None else '-'}"
        if svc:
            label += f" [{svc}]"

        # --- Violations d'architecture (indépendantes des règles) ---
        is_admin = (fl.proto, fl.port) in ADMIN_PORTS
        if is_admin and sc in TIER_RANK and dc in TIER_RANK and TIER_RANK[sc] > TIER_RANK[dc]:
            findings.append(Finding(
                id=stable_id("flux_admin_inter_tiers", fl.src, fl.dst, fl.proto, fl.port),
                type="flux_admin_inter_tiers",
                severity="critical" if dc == "tier0" else "high",
                message=f"Protocole d'administration depuis un tier moins sensible : {label}",
                references=REFERENCES["flux_admin_inter_tiers"], **common,
            ))
        if sc in IT_CLASSES and dc in OT_LOW_CLASSES:
            findings.append(Finding(
                id=stable_id("flux_it_vers_ot_direct", fl.src, fl.dst, fl.proto, fl.port),
                type="flux_it_vers_ot_direct",
                severity="critical" if is_admin else "high",
                message=f"Flux direct du SI de gestion vers l'atelier : {label}",
                references=REFERENCES["flux_it_vers_ot_direct"], **common,
            ))

        if not inter_zone and not alerts_cfg.check_intra_zone:
            continue
        evaluated += 1

        # --- Écarts aux règles déclarées ---
        matching = [r for r in rules if r.matches(fl.src, sz, fl.dst, dz, fl.proto, fl.port)]
        valid = [r for r in matching if not r.expired(today)]
        expired = [r for r in matching if r.expired(today)]
        used_rules.update(r.id for r in matching)

        if valid:
            covered += 1
            continue

        base = "medium"
        if dc == "tier0" or (dc or "").startswith("purdue") or UNKNOWN_ZONE in (sz, dz):
            base = "high"
        if is_admin and (dc == "tier0" or (dc or "").startswith("purdue")):
            base = "critical"

        if expired:
            findings.append(Finding(
                id=stable_id("regle_expiree_utilisee", fl.src, fl.dst, fl.proto, fl.port),
                type="regle_expiree_utilisee", severity=base,
                message=(f"Flux couvert uniquement par une règle expirée "
                         f"({', '.join(r.id + ' le ' + r.expire_le for r in expired)}) : {label}"),
                rule_ids=[r.id for r in expired],
                references=REFERENCES["regle_expiree_utilisee"], **common,
            ))
            continue

        duration = fl.last_seen - fl.first_seen
        if duration >= persistent:
            days = round(duration.total_seconds() / 86400)
            findings.append(Finding(
                id=stable_id("flux_non_declare", fl.src, fl.dst, fl.proto, fl.port),
                type="flux_non_declare_persistant", severity=escalate(base),
                message=f"Flux non déclaré observé depuis {days} jours : {label}",
                references=REFERENCES["flux_non_declare_persistant"], **common,
            ))
        else:
            # Même identifiant que la version persistante : l'alerte est mise
            # à jour (et non dupliquée) quand le flux devient persistant.
            findings.append(Finding(
                id=stable_id("flux_non_declare", fl.src, fl.dst, fl.proto, fl.port),
                type="nouveau_flux_non_declare", severity=base,
                message=f"Nouveau flux non déclaré : {label}",
                references=REFERENCES["nouveau_flux_non_declare"], **common,
            ))

    findings.extend(_scans(flows, zones, alerts_cfg.scan, now))

    # --- Règles jamais utilisées : seulement si la fenêtre est assez longue ---
    if window_start and window_end:
        observed_days = (window_end - window_start).days
        if observed_days >= alerts_cfg.unused_rule_after_days:
            for r in rules:
                if r.id not in used_rules and not r.expired(today):
                    findings.append(Finding(
                        id=stable_id("regle_jamais_utilisee", r.id),
                        type="regle_jamais_utilisee", severity="low",
                        message=(f"Règle {r.id} ({r.source} → {r.destination} {r.protocole}/{r.port}) "
                                 f"sans trafic depuis {observed_days} jours : candidate au nettoyage"),
                        rule_ids=[r.id], references=REFERENCES["regle_jamais_utilisee"],
                    ))

    findings.sort(key=lambda f: (-SEVERITY_ORDER.index(f.severity), f.type, f.src or "", f.dst or ""))
    return ComplianceReport(findings, evaluated, covered, window_start, window_end)
