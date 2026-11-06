"""Règles de flux (conduits) : import CSV/XLSX, validation, simulation, export.

Format d'une ligne (en-têtes insensibles à la casse et aux accents) :

    id,source,destination,protocole,port,description,proprietaire,expire_le

- source / destination : nom de zone, IP, préfixe CIDR, ou « any »
- protocole : tcp, udp, icmp ou any
- port : numéro, plage « 8000-8100 », liste « 80;443 », ou « any »
- expire_le : date AAAA-MM-JJ ou JJ/MM/AAAA, vide si la règle est permanente
"""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import unicodedata
from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Iterable

PROTOCOLS = {"tcp", "udp", "icmp", "any"}
COLUMNS = ["id", "source", "destination", "protocole", "port", "description", "proprietaire", "expire_le"]
REQUIRED = ["id", "source", "destination", "protocole", "port"]
HEADER_ALIASES = {
    "zone_source": "source", "src": "source", "zone_destination": "destination", "dst": "destination",
    "protocol": "protocole", "proto": "protocole", "ports": "port", "port_destination": "port",
    "owner": "proprietaire", "responsable": "proprietaire", "expiration": "expire_le",
    "expire": "expire_le", "date_expiration": "expire_le", "expires": "expire_le",
}


def _norm_header(h: object) -> str:
    s = "" if h is None else str(h)
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode().strip().lower()
    s = s.replace(" ", "_").replace("-", "_")
    return HEADER_ALIASES.get(s, s)


@dataclass(frozen=True)
class Endpoint:
    """Une extrémité de règle : zone nommée, réseau, ou n'importe quoi."""
    raw: str
    zone: str | None = None
    network: ipaddress._BaseNetwork | None = None

    @property
    def is_any(self) -> bool:
        return self.zone is None and self.network is None

    def matches(self, ip: str, zone_name: str) -> bool:
        if self.is_any:
            return True
        if self.zone is not None:
            return self.zone == zone_name
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return addr.version == self.network.version and addr in self.network


@dataclass(frozen=True)
class PortSpec:
    raw: str
    ranges: tuple[tuple[int, int], ...] = ()  # vide = any

    def matches(self, port: int | None) -> bool:
        if not self.ranges:
            return True
        if port is None:
            return False
        return any(lo <= port <= hi for lo, hi in self.ranges)


@dataclass
class FlowRule:
    id: str
    source: str
    destination: str
    protocole: str
    port: str
    description: str = ""
    proprietaire: str = ""
    expire_le: str = ""  # ISO AAAA-MM-JJ ou vide
    # Champs compilés (non sérialisés)
    _src: Endpoint | None = field(default=None, repr=False, compare=False)
    _dst: Endpoint | None = field(default=None, repr=False, compare=False)
    _ports: PortSpec | None = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if not k.startswith("_")}

    def expired(self, today: date) -> bool:
        return bool(self.expire_le) and date.fromisoformat(self.expire_le) < today

    def matches(self, src_ip: str, src_zone: str, dst_ip: str, dst_zone: str,
                proto: str, port: int | None) -> bool:
        if self.protocole != "any" and self.protocole != proto:
            return False
        if self.protocole != "icmp" and proto != "icmp" and not self._ports.matches(port):
            return False
        return self._src.matches(src_ip, src_zone) and self._dst.matches(dst_ip, dst_zone)


@dataclass
class ImportProblem:
    line: int
    column: str
    message: str

    def __str__(self) -> str:
        col = f", colonne « {self.column} »" if self.column else ""
        return f"ligne {self.line}{col} : {self.message}"


@dataclass
class ImportResult:
    rules: list[FlowRule]
    problems: list[ImportProblem]

    @property
    def ok(self) -> bool:
        return not self.problems


def _parse_endpoint(value: str, zone_names: set[str]) -> Endpoint | str:
    v = value.strip()
    if v.lower() in {"any", "*", "tout", "toutes"}:
        return Endpoint(raw="any")
    if v in zone_names:
        return Endpoint(raw=v, zone=v)
    try:
        return Endpoint(raw=v, network=ipaddress.ip_network(v, strict=False))
    except ValueError:
        return f"« {v} » n'est ni une zone déclarée, ni une IP, ni un préfixe CIDR"


def _parse_ports(value: str) -> PortSpec | str:
    v = value.strip().lower()
    if v in {"any", "*", "tout", "tous", ""}:
        return PortSpec(raw="any")
    ranges = []
    for part in v.replace(",", ";").split(";"):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                lo, hi = (int(x) for x in part.split("-", 1))
            else:
                lo = hi = int(float(part))  # Excel renvoie parfois 22.0
        except ValueError:
            return f"port « {value} » invalide (attendu : 443, 8000-8100, 80;443 ou any)"
        if not (0 <= lo <= hi <= 65535):
            return f"port « {value} » hors limites (0 à 65535)"
        ranges.append((lo, hi))
    return PortSpec(raw=value.strip(), ranges=tuple(ranges))


def _parse_date(value: object) -> str | None | Exception:
    if value is None or str(value).strip() == "":
        return None
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    s = str(value).strip()
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).date().isoformat()
        except ValueError:
            continue
    return ValueError(f"date « {s} » invalide (attendu : AAAA-MM-JJ ou JJ/MM/AAAA)")


def compile_rule(rule: FlowRule, zone_names: set[str]) -> list[str]:
    """Compile les champs d'une règle ; renvoie la liste des erreurs."""
    errors = []
    src = _parse_endpoint(rule.source, zone_names)
    dst = _parse_endpoint(rule.destination, zone_names)
    ports = _parse_ports(rule.port)
    if isinstance(src, str):
        errors.append(("source", src))
    if isinstance(dst, str):
        errors.append(("destination", dst))
    if isinstance(ports, str):
        errors.append(("port", ports))
    if rule.protocole not in PROTOCOLS:
        errors.append(("protocole", f"« {rule.protocole} » inconnu (attendu : tcp, udp, icmp, any)"))
    if not errors:
        rule._src, rule._dst, rule._ports = src, dst, ports
    return errors


def _rows_from_csv(path: Path, meta: dict) -> Iterable[tuple[int, dict]]:
    raw = path.read_bytes()
    text = raw.decode("utf-8-sig") if raw[:3] == b"\xef\xbb\xbf" else None
    if text is None:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("cp1252")  # export Excel français
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.reader(text.splitlines(), dialect)
    header = None
    for lineno, row in enumerate(reader, start=1):
        if not any(c.strip() for c in row):
            continue
        if header is None:
            header = meta["header"] = [_norm_header(h) for h in row]
            continue
        yield lineno, dict(zip(header, row))


def _rows_from_xlsx(path: Path, meta: dict) -> Iterable[tuple[int, dict]]:
    from openpyxl import load_workbook

    wb = load_workbook(path, read_only=True, data_only=True)
    ws = wb["regles"] if "regles" in wb.sheetnames else wb.worksheets[0]
    header = None
    for lineno, row in enumerate(ws.iter_rows(values_only=True), start=1):
        if row is None or not any(c not in (None, "") for c in row):
            continue
        if header is None:
            header = meta["header"] = [_norm_header(h) for h in row]
            continue
        yield lineno, dict(zip(header, row))
    wb.close()


def import_rules(path: str | Path, zone_names: Iterable[str]) -> ImportResult:
    """Lit et valide un fichier CSV ou XLSX. N'écrit rien."""
    path = Path(path)
    zone_names = set(zone_names)
    meta: dict = {}
    if path.suffix.lower() == ".xlsx":
        rows = _rows_from_xlsx(path, meta)
    elif path.suffix.lower() == ".csv":
        rows = _rows_from_csv(path, meta)
    else:
        return ImportResult([], [ImportProblem(0, "", f"extension {path.suffix} non supportée (.csv ou .xlsx)")])

    rules: list[FlowRule] = []
    problems: list[ImportProblem] = []
    seen: dict[str, int] = {}
    header_checked = False
    for lineno, row in rows:
        if not header_checked:
            missing = [c for c in REQUIRED if c not in row]
            if missing:
                problems.append(ImportProblem(1, "", f"colonnes obligatoires absentes : {', '.join(missing)}"))
                return ImportResult([], problems)
            header_checked = True

        def cell(name: str, row=row) -> str:
            v = row.get(name)
            if v is None:
                return ""
            if isinstance(v, float) and v.is_integer():
                v = int(v)
            return str(v).strip()

        line_problems = []
        for col in REQUIRED:
            if not cell(col):
                line_problems.append(ImportProblem(lineno, col, "valeur obligatoire manquante"))
        rid = cell("id")
        if rid and rid in seen:
            line_problems.append(ImportProblem(lineno, "id", f"identifiant « {rid} » déjà utilisé ligne {seen[rid]}"))
        expire = _parse_date(row.get("expire_le"))
        if isinstance(expire, Exception):
            line_problems.append(ImportProblem(lineno, "expire_le", str(expire)))
            expire = None
        if line_problems:
            problems.extend(line_problems)
            continue
        seen[rid] = lineno
        rule = FlowRule(
            id=rid, source=cell("source"), destination=cell("destination"),
            protocole=cell("protocole").lower(), port=cell("port"),
            description=cell("description"), proprietaire=cell("proprietaire"),
            expire_le=expire or "",
        )
        for col, msg in compile_rule(rule, zone_names):
            problems.append(ImportProblem(lineno, col, msg))
        if rule._src is not None:
            rules.append(rule)
    if not header_checked and not problems:
        header = meta.get("header")
        if header is None:
            problems.append(ImportProblem(0, "", "fichier vide (la ligne d'en-tête est attendue)"))
        else:
            missing = [c for c in REQUIRED if c not in header]
            if missing:
                problems.append(ImportProblem(1, "", f"colonnes obligatoires absentes : {', '.join(missing)}"))
            # En-tête seul : fichier valide, aucune règle (installation neuve).
    return ImportResult(rules, problems)


@dataclass
class RuleDiff:
    added: list[FlowRule]
    modified: list[tuple[FlowRule, FlowRule]]  # (ancienne, nouvelle)
    removed: list[FlowRule]
    unchanged: int

    @property
    def is_empty(self) -> bool:
        return not (self.added or self.modified or self.removed)


def diff_rules(current: list[FlowRule], incoming: list[FlowRule]) -> RuleDiff:
    cur = {r.id: r for r in current}
    inc = {r.id: r for r in incoming}
    added = [inc[i] for i in inc if i not in cur]
    removed = [cur[i] for i in cur if i not in inc]
    modified, unchanged = [], 0
    for i in inc:
        if i in cur:
            if cur[i].to_dict() != inc[i].to_dict():
                modified.append((cur[i], inc[i]))
            else:
                unchanged += 1
    return RuleDiff(added, modified, removed, unchanged)


class RuleStore:
    """Persistance des règles actives dans le répertoire d'état (JSON)."""

    def __init__(self, state_dir: str | Path):
        self.path = Path(state_dir) / "flow_rules.json"

    def load(self, zone_names: Iterable[str]) -> list[FlowRule]:
        if not self.path.exists():
            return []
        data = json.loads(self.path.read_text(encoding="utf-8"))
        names = set(zone_names)
        rules = []
        for d in data.get("rules", []):
            r = FlowRule(**d)
            if not compile_rule(r, names):
                rules.append(r)
        return rules

    def save(self, rules: list[FlowRule], source: str = "") -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = [r.to_dict() for r in sorted(rules, key=lambda r: r.id)]
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({
            "imported_at": datetime.now().isoformat(timespec="seconds"),
            "source": source, "sha256": digest, "rules": payload,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)  # écriture atomique


def export_rules_csv(rules: list[FlowRule], path: str | Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        w.writeheader()
        for r in sorted(rules, key=lambda r: r.id):
            w.writerow(r.to_dict())
