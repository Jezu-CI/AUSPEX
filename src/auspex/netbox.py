"""Synchronisation avec NetBox : l'inventaire observé à côté de l'inventaire déclaré.

Règles de conduite :
- Auspex n'écrit que dans ses propres champs personnalisés (préfixe `auspex_`
  sur les adresses IP) et pose son étiquette `auspex`. Il ne modifie jamais un
  champ saisi par un humain : description, statut, rattachement, etc.
- Une adresse IP observée et absente de NetBox est créée, marquée « Observé
  par Auspex », sans être rattachée à un équipement : c'est à un humain de
  décider ce qu'elle est.
- Tout passe d'abord par un plan (simulation), appliqué seulement sur demande.

Écarts produits par le rapprochement :
- actif_inconnu              observé sur le réseau, rattaché à aucun équipement déclaré
- actif_silencieux           équipement déclaré dans une zone écoutée, jamais vu depuis N jours
- identification_divergente  plateforme déclarée ≠ OS observé avec une bonne confiance
- fiche_incomplete           champs exigés par NIS2 (2024/2690 §12.4) ou DORA (art. 8) manquants
"""

from __future__ import annotations

import ipaddress
import json
import os
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlparse

from .compliance import Finding, stable_id
from .config import Config, NetBoxConfig

OBSERVED_DESCRIPTION = "Observé par Auspex"

TAG = {"name": "Auspex", "slug": "auspex", "color": "607d8b",
       "description": "Objet observé ou enrichi par Auspex"}

# Champs observés, sur les adresses IP : écrits par Auspex, non modifiables à la main.
IP_FIELDS = [
    ("auspex_os", "OS observé", "text"),
    ("auspex_os_confidence", "Confiance OS (%)", "integer"),
    ("auspex_type", "Type observé", "text"),
    ("auspex_vendor", "Fabricant observé", "text"),
    ("auspex_model", "Modèle observé", "text"),
    ("auspex_firmware", "Firmware observé", "text"),
    ("auspex_roles", "Rôles observés", "longtext"),
    ("auspex_zone", "Zone réseau", "text"),
    ("auspex_macs", "Adresses MAC", "text"),
    ("auspex_hostnames", "Noms d'hôte observés", "text"),
    ("auspex_first_seen", "Première observation", "text"),
    ("auspex_last_seen", "Dernière observation", "text"),
]

# Champs déclarés, sur les équipements : saisis par un humain, exigés par NIS2 / DORA.
DEVICE_FIELDS = [
    ("auspex_proprietaire", "Propriétaire de l'actif", "text"),
    ("auspex_niveau_protection", "Niveau de protection requis", "text"),
    ("auspex_fonction_metier", "Fonction métier supportée", "text"),
    ("auspex_criticite", "Criticité", "text"),
]

REFERENCES = {
    "actif_inconnu": ["NIS2 CIR 2024/2690 §12.4 (inventaire des actifs)", "DORA art. 8",
                      "ISO 27001 A.5.9", "CIS Controls v8 1.2"],
    "actif_silencieux": ["NIS2 CIR 2024/2690 §12.4 (inventaire tenu à jour et réexaminé)", "DORA art. 8"],
    "identification_divergente": ["NIS2 CIR 2024/2690 §12.4 (inventaire des actifs)", "ISO 27001 A.5.9"],
    "fiche_incomplete": ["NIS2 CIR 2024/2690 §12.4 (identifiant, description, propriétaire, "
                         "niveau de protection, localisation)", "DORA art. 8 (fonctions métier, criticité)"],
}

OS_SYNONYMS = {
    "linux": ("linux", "ubuntu", "debian", "red hat", "rhel", "centos", "rocky", "alma", "suse", "fedora"),
    "unix/linux": ("linux", "ubuntu", "debian", "red hat", "rhel", "centos", "rocky", "alma", "suse",
                   "fedora", "bsd", "unix", "solaris", "aix"),
    "windows": ("windows", "win"),
    "macos": ("macos", "mac os", "os x"),
}

BATCH = 200


class NetBoxError(Exception):
    pass


class NetBoxClient:
    def __init__(self, url: str, token: str, ca_file: str | None = None, timeout: int = 30):
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.ctx = ssl.create_default_context(cafile=ca_file) if url.startswith("https") else None
        if self.ctx:
            self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2   # certificat vérifié, TLS 1.2 minimum
        self._version: tuple[int, int] | None = None

    def _auth(self) -> str:
        # NetBox 4.5+ : jetons v2 « nbt_… » en Bearer ; avant : « Token … »
        return f"Bearer {self.token}" if self.token.startswith("nbt_") else f"Token {self.token}"

    def request(self, method: str, path: str, params: dict | None = None, body=None):
        url = path if path.startswith("http") else f"{self.url}{path}"
        if params:
            url += ("&" if "?" in url else "?") + urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": self._auth(), "Accept": "application/json",
            "Content-Type": "application/json", "User-Agent": "auspex",
        })
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise NetBoxError(f"{method} {path} : HTTP {exc.code} — {detail}") from exc
        except urllib.error.URLError as exc:
            raise NetBoxError(f"{method} {path} : {exc.reason}") from exc

    def list(self, path: str, params: dict | None = None) -> list[dict]:
        out: list[dict] = []
        page = self.request("GET", path, {"limit": 1000, **(params or {})})
        while True:
            out.extend(page["results"])
            nxt = page.get("next")
            if not nxt:
                return out
            # Le lien « next » doit pointer vers le même serveur.
            if urlparse(nxt).netloc != urlparse(self.url).netloc:
                nxt = self.url + urlparse(nxt).path + "?" + urlparse(nxt).query
            page = self.request("GET", nxt)

    def version(self) -> tuple[int, int]:
        if self._version is None:
            v = str(self.request("GET", "/api/status/").get("netbox-version", "0.0"))
            parts = [int("".join(c for c in x if c.isdigit()) or 0) for x in v.split(".")[:2]]
            self._version = (parts[0], parts[1] if len(parts) > 1 else 0)
        return self._version


def client_from_config(nb: NetBoxConfig) -> NetBoxClient:
    token = os.environ.get(nb.token_env)
    if not token:
        raise NetBoxError(f"jeton NetBox absent : définir la variable d'environnement {nb.token_env}")
    return NetBoxClient(nb.url, token, nb.ca_file)


# --- Mise en place des champs ---------------------------------------------------

def setup_plan(client: NetBoxClient) -> list[dict]:
    """Objets à créer dans NetBox (champs personnalisés et étiquette)."""
    major, _ = client.version()
    types_key = "object_types" if major >= 4 else "content_types"
    existing = {cf["name"] for cf in client.list("/api/extras/custom-fields/")}
    plan = []
    for fields, obj_types, editable in ((IP_FIELDS, ["ipam.ipaddress"], False),
                                        (DEVICE_FIELDS, ["dcim.device", "virtualization.virtualmachine"], True)):
        for name, label, ftype in fields:
            if name in existing:
                continue
            body = {"name": name, "label": label, "type": ftype, types_key: obj_types,
                    "group_name": "Auspex", "required": False}
            if not editable:
                body["description"] = "Renseigné automatiquement par Auspex"
                if major >= 4:
                    body["ui_editable"] = "no"
            plan.append({"kind": "custom-field", "name": name, "body": body})
    if not client.list("/api/extras/tags/", {"slug": TAG["slug"]}):
        plan.append({"kind": "tag", "name": TAG["slug"], "body": TAG})
    return plan


def apply_setup(client: NetBoxClient, plan: list[dict]) -> None:
    for item in plan:
        path = "/api/extras/custom-fields/" if item["kind"] == "custom-field" else "/api/extras/tags/"
        try:
            client.request("POST", path, body=item["body"])
        except NetBoxError as exc:
            if "HTTP 403" in str(exc):
                raise NetBoxError(
                    f"droits insuffisants pour créer « {item['name']} » : la mise en place se fait avec le "
                    "jeton administrateur (« ./update.sh », ou « auspex netbox setup --apply »)") from exc
            raise


# --- Compte de service « Librarian » ---------------------------------------------
#
# NetBox ne sait pas restreindre des droits champ par champ : ses permissions
# portent sur des types d'objets et des actions. Librarian reçoit le strict
# nécessaire à la synchronisation, et rien d'autre : aucune suppression,
# aucun accès aux équipements en écriture, aux utilisateurs ou aux champs.

LIBRARIAN = "Librarian"
LIBRARIAN_PERMISSIONS = [
    {"name": "Auspex Librarian · lecture",
     "description": "Lire l'inventaire déclaré et vérifier la mise en place d'Auspex",
     "object_types": ["dcim.device", "extras.customfield", "extras.tag", "ipam.ipaddress",
                      "virtualization.virtualmachine"],
     "actions": ["view"], "constraints": None},
    {"name": "Auspex Librarian · création des adresses observées",
     "description": f"Créer uniquement des adresses marquées « {OBSERVED_DESCRIPTION} »",
     "object_types": ["ipam.ipaddress"], "actions": ["add"],
     "constraints": {"description": OBSERVED_DESCRIPTION}},
    {"name": "Auspex Librarian · enrichissement des adresses",
     "description": "Écrire les champs observés (auspex_…) et l'étiquette Auspex sur les adresses IP",
     "object_types": ["ipam.ipaddress"], "actions": ["change"], "constraints": None},
]


def _token_identity(url: str, token: str, ca_file: str | None) -> str:
    """« invalide », « administrateur » ou « restreint »."""
    probe = NetBoxClient(url, token, ca_file)
    try:
        probe.request("GET", "/api/ipam/ip-addresses/", {"limit": 1})
    except NetBoxError:
        return "invalide"
    try:
        probe.request("GET", "/api/users/users/", {"limit": 1})
        return "administrateur"
    except NetBoxError:
        return "restreint"


def _perm_matches(existing: dict, spec: dict, user_id: int) -> bool:
    users = {u["id"] if isinstance(u, dict) else u for u in existing.get("users", [])}
    return (sorted(existing.get("object_types") or []) == sorted(spec["object_types"])
            and sorted(existing.get("actions") or []) == sorted(spec["actions"])
            and (existing.get("constraints") or None) == spec["constraints"]
            and existing.get("enabled", True) is True and user_id in users)


def librarian_plan(client: NetBoxClient, token: str, ca_file: str | None = None) -> list[dict]:
    """Ce qu'il faut créer ou corriger pour que Librarian existe, avec ses seuls droits."""
    if token == client.token:
        raise NetBoxError("le jeton de Librarian ne peut pas être le jeton administrateur")
    plan: list[dict] = []
    users = client.list("/api/users/users/", {"username": LIBRARIAN})
    user = users[0] if users else None
    if user is None:
        plan.append({"kind": "user", "name": LIBRARIAN})
    elif user.get("is_superuser") or user.get("is_staff") or not user.get("is_active", True):
        plan.append({"kind": "user-fix", "name": LIBRARIAN, "id": user["id"]})
    uid = user["id"] if user else None
    existing = {p["name"]: p for p in client.list("/api/users/permissions/")}
    for spec in LIBRARIAN_PERMISSIONS:
        current = existing.get(spec["name"])
        if current is None:
            plan.append({"kind": "permission", "name": spec["name"], "spec": spec})
        elif uid is None or not _perm_matches(current, spec, uid):
            plan.append({"kind": "permission-fix", "name": spec["name"], "spec": spec, "id": current["id"]})
    identity = _token_identity(client.url, token, ca_file) if user else "invalide"
    if identity == "administrateur":
        raise NetBoxError("le jeton fourni pour Librarian donne des droits d'administration : refusé")
    if identity == "invalide":
        plan.append({"kind": "token", "name": f"jeton de {LIBRARIAN}"})
    return plan


def apply_librarian(client: NetBoxClient, plan: list[dict], token: str, ca_file: str | None = None) -> None:
    import secrets
    users = client.list("/api/users/users/", {"username": LIBRARIAN})
    uid = users[0]["id"] if users else None
    for item in plan:
        if item["kind"] == "user":
            uid = client.request("POST", "/api/users/users/", body={
                "username": LIBRARIAN, "first_name": "Librarian", "last_name": "(compte de service Auspex)",
                # Mot de passe aléatoire jamais communiqué : accès par jeton uniquement.
                "password": secrets.token_urlsafe(48), "is_active": True})["id"]
        elif item["kind"] == "user-fix":
            client.request("PATCH", f"/api/users/users/{item['id']}/",
                           body={"is_superuser": False, "is_staff": False, "is_active": True})
        elif item["kind"] in ("permission", "permission-fix"):
            spec = item["spec"]
            body = {"name": spec["name"], "description": spec["description"], "enabled": True,
                    "object_types": spec["object_types"], "actions": spec["actions"],
                    "constraints": spec["constraints"], "users": [uid]}
            if item["kind"] == "permission":
                client.request("POST", "/api/users/permissions/", body=body)
            else:
                client.request("PATCH", f"/api/users/permissions/{item['id']}/", body=body)
        elif item["kind"] == "token":
            client.request("POST", "/api/users/tokens/", body={
                "user": uid, "key": token, "write_enabled": True,
                "description": "Auspex : compte de service Librarian"})
    identity = _token_identity(client.url, token, ca_file)
    if identity != "restreint":
        raise NetBoxError(f"après mise en place, le jeton de Librarian est « {identity} » au lieu de « restreint »")


# --- Synchronisation des adresses observées ----------------------------------------

def _host(address: str) -> str:
    return address.split("/", 1)[0]


def _val(ident: dict, key: str) -> str:
    v = ident.get(key)
    return v["value"] if isinstance(v, dict) else ""


def desired_fields(asset: dict) -> dict:
    i = asset["identification"]
    osf = _val(i, "os_family")
    if osf and _val(i, "os_version"):
        osf = f"{osf} — {_val(i, 'os_version')}"
    return {
        "auspex_os": osf or None,
        "auspex_os_confidence": int(round(i["os_family"]["confidence"] * 100)) if i.get("os_family") else None,
        "auspex_type": _val(i, "device_type") or None,
        "auspex_vendor": _val(i, "vendor") or None,
        "auspex_model": _val(i, "model") or None,
        "auspex_firmware": _val(i, "firmware") or None,
        "auspex_roles": "\n".join(f"{r['value']} ({int(r['confidence'] * 100)} %)" for r in i.get("role", [])) or None,
        "auspex_zone": asset.get("zone"),
        "auspex_macs": ", ".join(asset.get("macs", [])) or None,
        "auspex_hostnames": ", ".join(asset.get("hostnames", [])) or None,
        "auspex_first_seen": asset.get("first_seen"),
        "auspex_last_seen": asset.get("last_seen"),
    }


@dataclass
class SyncPlan:
    creates: list[dict] = field(default_factory=list)
    updates: list[dict] = field(default_factory=list)
    unchanged: int = 0

    @property
    def is_empty(self) -> bool:
        return not (self.creates or self.updates)


def _prefixlen(cfg: Config, ip: str) -> int:
    addr = ipaddress.ip_address(ip)
    best = None
    for z in cfg.zones:
        for p in z.prefixes:
            if p.version == addr.version and addr in p and (best is None or p.prefixlen > best):
                best = p.prefixlen
    return best if best is not None else (32 if addr.version == 4 else 128)


def build_plan(cfg: Config, assets: list[dict], ip_objects: list[dict]) -> SyncPlan:
    by_host = {_host(o["address"]): o for o in ip_objects}
    plan = SyncPlan()
    for a in assets:
        wanted = desired_fields(a)
        obj = by_host.get(a["ip"])
        if obj is None:
            plan.creates.append({
                "address": f"{a['ip']}/{_prefixlen(cfg, a['ip'])}", "status": "active",
                "description": OBSERVED_DESCRIPTION, "tags": [{"slug": TAG["slug"]}],
                "custom_fields": wanted,
            })
            continue
        current = obj.get("custom_fields") or {}
        tags = [t["slug"] for t in obj.get("tags", [])]
        fields_changed = any(current.get(k) != v for k, v in wanted.items())
        if fields_changed or TAG["slug"] not in tags:
            plan.updates.append({
                "id": obj["id"],
                # Les autres champs personnalisés (saisis par un humain) sont conservés.
                "custom_fields": {**current, **wanted},
                "tags": [{"slug": s} for s in sorted(set(tags) | {TAG["slug"]})],
                "_address": obj["address"],
            })
        else:
            plan.unchanged += 1
    return plan


def apply_plan(client: NetBoxClient, plan: SyncPlan) -> None:
    for i in range(0, len(plan.creates), BATCH):
        client.request("POST", "/api/ipam/ip-addresses/", body=plan.creates[i:i + BATCH])
    updates = [{k: v for k, v in u.items() if not k.startswith("_")} for u in plan.updates]
    for i in range(0, len(updates), BATCH):
        client.request("PATCH", "/api/ipam/ip-addresses/", body=updates[i:i + BATCH])


# --- Rapprochement observé / déclaré ------------------------------------------------

def fetch_declared(client: NetBoxClient) -> list[dict]:
    """Équipements physiques et machines virtuelles, marqués par leur type."""
    devices = [{**d, "_kind": "dcim"} for d in client.list("/api/dcim/devices/")]
    vms = [{**v, "_kind": "vm"} for v in client.list("/api/virtualization/virtual-machines/")]
    return devices + vms


def _key(d: dict) -> tuple[str, int]:
    return (d.get("_kind", "dcim"), d["id"])


def _device_ips(devices: list[dict], ip_objects: list[dict]) -> dict[tuple, set[str]]:
    """Adresses de chaque équipement ou VM : IP rattachées à ses interfaces + IP primaires."""
    out: dict[tuple, set[str]] = {_key(d): set() for d in devices}
    for o in ip_objects:
        ao = o.get("assigned_object") or {}
        otype = str(o.get("assigned_object_type") or "")
        if otype == "dcim.interface" and ao.get("device"):
            key = ("dcim", ao["device"]["id"])
        elif otype == "virtualization.vminterface" and ao.get("virtual_machine"):
            key = ("vm", ao["virtual_machine"]["id"])
        else:
            continue
        if key in out:
            out[key].add(_host(o["address"]))
    for d in devices:
        for k in ("primary_ip4", "primary_ip6", "primary_ip"):
            if d.get(k):
                out[_key(d)].add(_host(d[k]["address"]))
    return out


def _os_matches(observed: str, platform: str) -> bool:
    o, p = observed.lower(), platform.lower()
    if o in p or p in o:
        return True
    return any(word in p for word in OS_SYNONYMS.get(o, ()))


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def reconcile(cfg: Config, assets: list[dict], ip_objects: list[dict], devices: list[dict],
              now: datetime) -> list[Finding]:
    from .zones import ZoneMap

    zmap = ZoneMap(cfg.zones)
    findings: list[Finding] = []
    dev_ips = _device_ips(devices, ip_objects)
    declared = {ip: key for key, ips in dev_ips.items() for ip in ips}
    asset_by_ip = {a["ip"]: a for a in assets}
    monitored = {s.zone for s in cfg.sensors} or {z.name for z in cfg.zones}
    silent_limit = now - timedelta(days=cfg.netbox.silent_after_days if cfg.netbox else 30)

    # Actifs observés mais rattachés à aucun équipement déclaré
    for a in assets:
        if a["ip"] in declared:
            continue
        zclass = zmap.class_of(a["ip"]) or ""
        sev = "high" if (zclass == "tier0" or zclass.startswith("purdue") or not zclass) else "medium"
        what = ", ".join(x for x in (_val(a["identification"], "device_type"), _val(a["identification"], "os_family"),
                                     ", ".join(a.get("hostnames", []))) if x) or "non identifié"
        findings.append(Finding(
            id=stable_id("actif_inconnu", a["ip"]), type="actif_inconnu", severity=sev,
            message=f"{a['ip']} ({a.get('zone')}) observé sur le réseau mais rattaché à aucun équipement "
                    f"de la CMDB : {what}",
            src=a["ip"], src_zone=a.get("zone"), first_seen=a.get("first_seen"), last_seen=a.get("last_seen"),
            references=REFERENCES["actif_inconnu"],
        ))

    for d in devices:
        kind = "VM" if d.get("_kind") == "vm" else "équipement"
        name = d.get("name") or f"{kind} #{d['id']}"
        raw_status = d.get("status")
        status = raw_status.get("value") if isinstance(raw_status, dict) else (raw_status or "active")
        ips = dev_ips.get(_key(d), set())
        uid = f"{d.get('_kind', 'dcim')}-{d['id']}"

        # Équipement déclaré dans une zone écoutée, jamais vu récemment
        watched = [ip for ip in ips if zmap.name_of(ip) in monitored]
        if status == "active" and watched:
            seen = [_parse_dt(asset_by_ip[ip].get("last_seen")) for ip in watched if ip in asset_by_ip]
            last = max((s for s in seen if s), default=None)
            if last is None or last < silent_limit:
                since = f"depuis le {last:%Y-%m-%d}" if last else "jamais"
                findings.append(Finding(
                    id=stable_id("actif_silencieux", uid), type="actif_silencieux", severity="low",
                    message=f"{name} ({', '.join(sorted(watched))}) est déclaré actif mais n'a pas été "
                            f"observé {since} : équipement éteint, retiré ou fiche à mettre à jour ?",
                    src=sorted(watched)[0], src_zone=zmap.name_of(sorted(watched)[0]),
                    last_seen=last.isoformat() if last else None,
                    references=REFERENCES["actif_silencieux"],
                ))

        # Plateforme déclarée en contradiction avec l'OS observé
        platform = (d.get("platform") or {}).get("name")
        if platform:
            for ip in ips:
                osf = asset_by_ip.get(ip, {}).get("identification", {}).get("os_family")
                if osf and osf["confidence"] >= 0.7 and not _os_matches(osf["value"], platform):
                    findings.append(Finding(
                        id=stable_id("identification_divergente", uid, ip), type="identification_divergente",
                        severity="medium", src=ip, src_zone=zmap.name_of(ip),
                        message=f"{name} ({ip}) : plateforme déclarée « {platform} », OS observé "
                                f"« {osf['value']} » ({int(osf['confidence'] * 100)} %)",
                        references=REFERENCES["identification_divergente"],
                    ))

        # Champs exigés par NIS2 (2024/2690 §12.4) et DORA (art. 8)
        if status == "active":
            cf = d.get("custom_fields") or {}
            missing = []
            if not d.get("description"):
                missing.append("description")
            if not (d.get("tenant") or cf.get("auspex_proprietaire")):
                missing.append("propriétaire (tenant ou champ Auspex)")
            for key, label in (("auspex_niveau_protection", "niveau de protection"),
                               ("auspex_fonction_metier", "fonction métier"), ("auspex_criticite", "criticité")):
                if not cf.get(key):
                    missing.append(label)
            if missing:
                findings.append(Finding(
                    id=stable_id("fiche_incomplete", uid), type="fiche_incomplete", severity="low",
                    message=f"{name} : champ(s) manquant(s) — {', '.join(missing)}",
                    src=sorted(ips)[0] if ips else None,
                    references=REFERENCES["fiche_incomplete"],
                ))
    return findings
