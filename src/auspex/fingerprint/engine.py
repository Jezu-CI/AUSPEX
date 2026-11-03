"""Identification passive des actifs à partir des logs Zeek.

Principe : chaque règle observe un type de log, teste quelques champs, et
« vote » pour une ou plusieurs valeurs d'attributs (famille d'OS, type
d'équipement, fabricant, rôle...) avec un poids entre 0 et 1.

- Une règle ne vote qu'une fois par actif, quel que soit le volume de trafic :
  un contrôleur de domaine qui sert 10 000 tickets Kerberos ne pèse pas plus
  qu'un qui en sert 10.
- Les votes pour une même valeur se combinent en « OU bruité » :
  score = 1 - Π(1 - poids). Deux indices faibles concordants valent plus qu'un.
- La confiance finale est pénalisée par la meilleure valeur concurrente :
  confiance = score(1re) × (1 - 0,5 × score(2e)).
- Chaque conclusion garde la liste des règles qui l'ont produite (explicabilité).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

import yaml

from ..zeek import TCP_ESTABLISHED, ts_of

ATTRIBUTES = {"os_family", "os_version", "device_type", "vendor", "model", "firmware", "role"}
MULTI_VALUED = {"role"}  # un serveur peut être à la fois DC et DNS
ROLE_THRESHOLD = 0.4
_PLACEHOLDER = re.compile(r"\{(\d+|[A-Za-z_][\w.]*)\}")


class RuleError(Exception):
    pass


@dataclass
class Condition:
    field: str
    equals: Any = None
    one_of: tuple | None = None
    regex: re.Pattern | None = None
    exists: bool | None = None
    minimum: float | None = None

    def test(self, rec: dict) -> tuple[bool, re.Match | None]:
        has = self.field in rec and rec[self.field] not in (None, "", "-")
        if self.exists is not None:
            return has == self.exists, None
        if not has:
            return False, None
        value = rec[self.field]
        if self.minimum is not None:
            try:
                return float(value) >= self.minimum, None
            except (TypeError, ValueError):
                return False, None
        if self.equals is not None:
            return str(value).lower() == str(self.equals).lower(), None
        if self.one_of is not None:
            return str(value).lower() in self.one_of, None
        if self.regex is not None:
            m = self.regex.search(str(value))
            return m is not None, m
        return True, None


@dataclass
class FingerprintRule:
    id: str
    log: str
    target: str  # "orig", "resp" ou nom de champ IP
    conditions: list[Condition]
    votes: dict[str, str]
    weight: float
    require_established: bool = True
    description: str = ""
    # Règle d'agrégat : vote quand un même actif atteint `min_count` valeurs distinctes
    # de `count_distinct` (ex. balayage : nombre de couples destination/port tentés).
    count_distinct: tuple[str, ...] = ()
    min_count: int = 0

    def ip_of(self, rec: dict) -> str | None:
        if self.target == "orig":
            return rec.get("id.orig_h")
        if self.target == "resp":
            return rec.get("id.resp_h")
        return rec.get(self.target) or rec.get("id.resp_h")

    def evaluate(self, rec: dict) -> dict[str, str] | None:
        """Renvoie les votes (placeholders résolus) si la règle s'applique."""
        if self.require_established and self.log == "conn" and not _answered(rec):
            return None
        match = None
        for cond in self.conditions:
            ok, m = cond.test(rec)
            if not ok:
                return None
            match = m or match
        out = {}
        for attr, template in self.votes.items():
            value = _render(template, rec, match)
            if value:
                out[attr] = value
        return out or None


def _answered(rec: dict) -> bool:
    """Le répondeur a-t-il vraiment répondu ? (sinon on ne sait rien de lui)"""
    proto = (rec.get("proto") or "").lower()
    if proto == "tcp":
        return rec.get("conn_state", "SF") in TCP_ESTABLISHED
    try:
        if rec.get("resp_pkts") not in (None, "", "-"):
            # Relevé sur captures réelles : une diffusion BACnet (Who-Is) n'a aucun paquet
            # en retour, mais le service détecté la faisait passer pour une réponse.
            return int(rec["resp_pkts"]) > 0
        return int(rec.get("resp_bytes") or 0) > 0 or bool(rec.get("service"))
    except ValueError:
        return False


def _render(template: str, rec: dict, match: re.Match | None) -> str:
    def repl(m: re.Match) -> str:
        key = m.group(1)
        if key.isdigit():
            return (match.group(int(key)) or "") if match and int(key) <= match.re.groups else ""
        return str(rec.get(key, "")).strip()
    return _PLACEHOLDER.sub(repl, str(template)).strip()


def _parse_rule(d: dict, where: str) -> FingerprintRule:
    for key in ("id", "log", "set", "weight"):
        if key not in d:
            raise RuleError(f"{where} : champ « {key} » manquant")
    weight = float(d["weight"])
    if not 0 < weight <= 1:
        raise RuleError(f"{where} ({d['id']}) : weight doit être dans ]0, 1]")
    unknown = set(d["set"]) - ATTRIBUTES
    if unknown:
        raise RuleError(f"{where} ({d['id']}) : attributs inconnus {sorted(unknown)}")
    conditions = []
    for fname, spec in (d.get("match") or {}).items():
        if isinstance(spec, dict):
            if "regex" in spec:
                try:
                    rx = re.compile(spec["regex"], re.IGNORECASE)
                except re.error as exc:
                    raise RuleError(f"{where} ({d['id']}) : regex invalide sur {fname} ({exc})")
                conditions.append(Condition(fname, regex=rx))
            elif "one_of" in spec:
                conditions.append(Condition(fname, one_of=tuple(str(v).lower() for v in spec["one_of"])))
            elif "exists" in spec:
                conditions.append(Condition(fname, exists=bool(spec["exists"])))
            elif "min" in spec:
                try:
                    conditions.append(Condition(fname, minimum=float(spec["min"])))
                except (TypeError, ValueError):
                    raise RuleError(f"{where} ({d['id']}) : min doit être un nombre sur {fname}")
            else:
                raise RuleError(f"{where} ({d['id']}) : condition inconnue sur {fname}")
        else:
            conditions.append(Condition(fname, equals=spec))
    distinct = d.get("count_distinct") or ()
    if isinstance(distinct, str):
        distinct = (distinct,)
    min_count = int(d.get("min_count", 0))
    if distinct and not 2 <= min_count <= 100000:
        raise RuleError(f"{where} ({d['id']}) : min_count entre 2 et 100000 attendu avec count_distinct")
    if min_count and not distinct:
        raise RuleError(f"{where} ({d['id']}) : min_count sans count_distinct")
    return FingerprintRule(
        id=str(d["id"]), log=str(d["log"]), target=str(d.get("target", "resp")),
        conditions=conditions, votes={k: str(v) for k, v in d["set"].items()},
        weight=weight, require_established=bool(d.get("require_established", True)),
        description=str(d.get("description", "")),
        count_distinct=tuple(str(x) for x in distinct), min_count=min_count,
    )


def load_rules(paths: Iterable[str | Path]) -> list[FingerprintRule]:
    rules: list[FingerprintRule] = []
    seen: set[str] = set()
    for path in paths:
        path = Path(path)
        files = sorted(path.glob("*.yaml")) if path.is_dir() else [path]
        for f in files:
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            for i, d in enumerate(data.get("rules") or []):
                r = _parse_rule(d, f"{f.name}[{i}]")
                if r.id in seen:
                    raise RuleError(f"{f.name} : identifiant de règle « {r.id} » dupliqué")
                seen.add(r.id)
                rules.append(r)
    return rules


@dataclass
class Normalizer:
    """Alias et valeurs génériques (voir rules/aliases.yaml)."""
    aliases: dict[str, dict[str, str]] = field(default_factory=dict)
    generic: dict[str, set[str]] = field(default_factory=dict)

    def canonical(self, attr: str, value: str) -> str:
        table = self.aliases.get(attr, {})
        return table.get(value.lower(), value)

    def is_generic(self, attr: str, value: str) -> bool:
        return value.lower() in self.generic.get(attr, set())


def load_normalizer(path: str | Path) -> Normalizer:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    aliases = {attr: {str(k).lower(): str(v) for k, v in (table or {}).items()}
               for attr, table in (data.get("aliases") or {}).items()}
    generic = {attr: {str(v).lower() for v in (values or [])}
               for attr, values in (data.get("generic") or {}).items()}
    unknown = (set(aliases) | set(generic)) - ATTRIBUTES
    if unknown:
        raise RuleError(f"{Path(path).name} : attributs inconnus {sorted(unknown)}")
    return Normalizer(aliases, generic)


def load_oui(path: str | Path) -> dict[str, dict]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return {k.upper().replace("-", ":"): v for k, v in (data.get("oui") or {}).items()}


def _noisy_or(weights: list[float]) -> float:
    p = 1.0
    for w in weights:
        p *= 1 - w
    return 1 - p


@dataclass
class Asset:
    ip: str
    macs: set[str] = field(default_factory=set)
    hostnames: set[str] = field(default_factory=set)
    zone: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    # attribut → valeur → {règle: poids}
    votes: dict[str, dict[str, dict[str, float]]] = field(default_factory=dict)

    def seen(self, ts: datetime | None) -> None:
        if ts is None:
            return
        self.first_seen = ts if self.first_seen is None else min(self.first_seen, ts)
        self.last_seen = ts if self.last_seen is None else max(self.last_seen, ts)

    def vote(self, attr: str, value: str, rule_id: str, weight: float) -> None:
        by_value = self.votes.setdefault(attr, {}).setdefault(value, {})
        by_value[rule_id] = max(weight, by_value.get(rule_id, 0))

    def conclusions(self, normalizer: "Normalizer | None" = None) -> dict[str, Any]:
        norm = normalizer or Normalizer()
        out: dict[str, Any] = {}
        for attr, values in self.votes.items():
            scored = sorted(
                ((v, _noisy_or(list(rules.values())), sorted(rules)) for v, rules in values.items()),
                key=lambda t: (-t[1], t[0]),
            )
            # Une catégorie générique ne sert que faute de valeur précise.
            specific = [t for t in scored if not norm.is_generic(attr, t[0])]
            if specific and attr not in MULTI_VALUED:
                scored = specific
            if attr in MULTI_VALUED:
                out[attr] = [
                    {"value": v, "confidence": round(s, 2), "evidence": ev}
                    for v, s, ev in scored if s >= ROLE_THRESHOLD
                ]
                continue
            best_v, best_s, best_ev = scored[0]
            second = scored[1][1] if len(scored) > 1 else 0.0
            out[attr] = {
                "value": best_v,
                "confidence": round(best_s * (1 - 0.5 * second), 2),
                "evidence": best_ev,
                "alternatives": [{"value": v, "score": round(s, 2)} for v, s, _ in scored[1:4]],
            }
        return out

    def to_dict(self, normalizer: "Normalizer | None" = None) -> dict:
        return {
            "ip": self.ip, "zone": self.zone,
            "macs": sorted(self.macs), "hostnames": sorted(self.hostnames),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "identification": self.conclusions(normalizer),
        }


MAX_IPS_PER_MAC = 2  # au-delà : MAC de passerelle (routeur, pare-feu)
HOSTNAME_FIELDS = ("host_name", "client_fqdn")
_HOSTNAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}")


class FingerprintEngine:
    """Accumule les observations puis produit l'inventaire identifié."""

    def __init__(self, rules: list[FingerprintRule], oui: dict[str, dict] | None = None,
                 zone_of=None, keep=None, normalizer: Normalizer | None = None):
        self.normalizer = normalizer or Normalizer()
        self.rules_by_log: dict[str, list[FingerprintRule]] = {}
        for r in rules:
            self.rules_by_log.setdefault(r.log, []).append(r)
        self.oui = oui or {}
        self.zone_of = zone_of or (lambda ip: None)
        # Filtre des IP à inventorier (par défaut : IP privées / zones déclarées)
        self.keep = keep or _is_private
        self.assets: dict[str, Asset] = {}
        self.mac_ips: dict[str, set[str]] = {}
        self.gateway_macs: set[str] = set()
        # Règles d'agrégat (count_distinct) : valeurs vues par (règle, IP) jusqu'au seuil
        self.counters: dict[tuple[str, str], set] = {}
        self.counted: set[tuple[str, str]] = set()

    def _asset(self, ip: str) -> Asset | None:
        if not ip or not self.keep(ip):
            return None
        a = self.assets.get(ip)
        if a is None:
            a = self.assets[ip] = Asset(ip=ip, zone=self.zone_of(ip))
        return a

    def observe(self, kind: str, rec: dict) -> None:
        ts = ts_of(rec)
        if kind == "conn":
            answered = _answered(rec)
            for side in ("id.orig_h", "id.resp_h"):
                # Une IP qui n'a jamais répondu n'est pas un actif avéré
                # (cible d'un scan, machine éteinte, adresse inutilisée).
                if side == "id.resp_h" and not answered:
                    continue
                a = self._asset(rec.get(side))
                if a:
                    a.seen(ts)
        # Adresses MAC. Celle du DHCP est celle du client lui-même : fiable.
        # Celles de conn.log peuvent être celles d'un routeur (hôte distant) :
        # elles sont mises de côté et attribuées dans finalize().
        if kind == "dhcp" and rec.get("mac"):
            a = self._asset(rec.get("assigned_addr") or rec.get("client_addr"))
            if a:
                self._attach_mac(a, rec["mac"])
        elif kind == "conn":
            for mfield, ipfield in (("orig_l2_addr", "id.orig_h"), ("resp_l2_addr", "id.resp_h")):
                mac, ip = rec.get(mfield), rec.get(ipfield)
                if not mac or not ip or (mfield == "resp_l2_addr" and not _answered(rec)):
                    continue
                if self.keep(ip):
                    self.mac_ips.setdefault(mac.lower(), set()).add(ip)
        if kind == "dhcp":
            a = self._asset(rec.get("assigned_addr") or rec.get("client_addr"))
            if a:
                a.seen(ts)
                for hf in HOSTNAME_FIELDS:
                    if rec.get(hf):
                        a.hostnames.add(str(rec[hf]).lower())
        elif kind == "ntlm":
            # Authentification NTLM : nom NetBIOS du poste client et du serveur
            # (relevé sur captures réelles : postes d'IHM « PANELPC02 », serveur « IAS01 »).
            for field, ip in (("hostname", rec.get("id.orig_h")), ("server_nb_computer_name", rec.get("id.resp_h"))):
                name = str(rec.get(field) or "").strip().lower()
                if name and _HOSTNAME.fullmatch(name):
                    a = self._asset(ip)
                    if a:
                        a.hostnames.add(name)
        for rule in self.rules_by_log.get(kind, ()):
            votes = rule.evaluate(rec)
            if not votes:
                continue
            ip = rule.ip_of(rec)
            if rule.count_distinct:
                key = (rule.id, ip)
                if key in self.counted:
                    continue            # seuil déjà atteint : vote acquis
                seen = self.counters.setdefault(key, set())
                seen.add(tuple(str(rec.get(f, "")) for f in rule.count_distinct))
                if len(seen) < rule.min_count:
                    continue
                self.counted.add(key)
                del self.counters[key]  # mémoire bornée : on ne garde que le fait
            a = self._asset(ip)
            if a is None:
                continue
            a.seen(ts)
            for attr, value in votes.items():
                a.vote(attr, self.normalizer.canonical(attr, value), rule.id, rule.weight)

    def _attach_mac(self, asset: Asset, mac: str) -> None:
        asset.macs.add(mac.lower())
        self._vote_oui(asset, mac)

    def finalize(self) -> None:
        """Attribue les MAC vues dans conn.log, sauf celles des passerelles.

        Derrière un routeur, tous les hôtes distants apparaissent avec la MAC
        du routeur : une MAC associée à plus de MAX_IPS_PER_MAC adresses est
        une passerelle, et ne dit rien du fabricant de ces hôtes.
        """
        for mac, ips in self.mac_ips.items():
            if len(ips) > MAX_IPS_PER_MAC:
                self.gateway_macs.add(mac)
                continue
            for ip in ips:
                a = self.assets.get(ip)
                if a:
                    self._attach_mac(a, mac)

    def _vote_oui(self, asset: Asset, mac: str) -> None:
        prefix = mac.upper().replace("-", ":")[:8]
        info = self.oui.get(prefix)
        if not info:
            return
        rid = f"oui:{prefix}"
        for attr in ("vendor", "device_type"):
            if info.get(attr):
                asset.vote(attr, self.normalizer.canonical(attr, info[attr]), rid,
                           float(info.get("weight", 0.5)))

    def inventory(self) -> list[dict]:
        def key(a: Asset):
            ip = ipaddress.ip_address(a.ip)
            return (ip.version, int(ip))
        self.finalize()
        return [a.to_dict(self.normalizer) for a in sorted(self.assets.values(), key=key)]


def inventoriable(ip: str, declared: bool = False) -> bool:
    """IP privée, ou adresse d'une zone déclarée ; jamais multicast, diffusion, bouclage…"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if (addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified
            or addr.is_reserved or (addr.version == 4 and int(addr) & 0xFFFF == 0xFFFF)
            or str(addr) == "255.255.255.255"):
        return False
    return declared or addr.is_private


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private and not (addr.is_loopback or addr.is_link_local or addr.is_multicast
                                    or addr.is_unspecified or addr.is_reserved)
