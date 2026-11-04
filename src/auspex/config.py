"""Chargement et validation du fichier de configuration déclaratif `auspex.yaml`.

La validation collecte toutes les erreurs d'un coup (chemin + message) pour
qu'un utilisateur corrige son fichier en une passe, au lieu d'une erreur à la fois.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SUPPORTED_VERSIONS = {1}
CHANNELS = {"stable", "edge", "offline"}
ZONE_CLASSES = {
    "tier0", "tier1", "tier2", "admin", "dmz", "other",
    "purdue0", "purdue1", "purdue2", "purdue3", "purdue3.5", "purdue4", "purdue5",
}
SENSOR_MODES = {"passive", "active-light"}
OUTPUT_TYPES = {"syslog", "webhook", "file"}
SYSLOG_FORMATS = {"cef", "json"}
SEVERITIES = ("info", "low", "medium", "high", "critical")
AUTH_PRIMARY = {"ldaps", "oidc", "saml"}
MFA_KINDS = {"totp", "webauthn"}           # double authentification du brise-glace
MFA_METHODS = {"totp", "email", "webauthn"}
SMTP_SECURITY = {"starttls", "tls", "none"}


class ConfigError(Exception):
    """Erreur de configuration : contient la liste complète des problèmes."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("\n".join(problems))


@dataclass(frozen=True)
class Zone:
    name: str
    zclass: str
    prefixes: tuple[ipaddress._BaseNetwork, ...]

    @property
    def is_ot(self) -> bool:
        return self.zclass.startswith("purdue")


@dataclass(frozen=True)
class Sensor:
    name: str
    zone: str
    interface: str
    mode: str
    key: str | None = None                                  # clé SSH d'envoi des logs (ssh-ed25519)
    allow: tuple[ipaddress._BaseNetwork, ...] = ()           # adresses d'où le capteur se connecte


SENSOR_NAME = __import__("re").compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


@dataclass(frozen=True)
class Output:
    type: str
    url: str | None = None
    format: str = "json"
    min_severity: str = "info"
    path: str | None = None
    token_env: str | None = None
    ca_file: str | None = None  # AC privée du SIEM (syslog TLS, webhook)


@dataclass
class ScanConfig:
    """Alerte « balayage du réseau » : une machine qui tente de joindre de
    nombreuses cibles (adresse et port) refusées ou sans réponse."""
    enabled: bool = True
    min_targets: int = 100       # même seuil que la règle d'identification it-port-scan
    window_hours: int = 24       # seules les tentatives récentes comptent
    severity: str = "high"       # relevée d'un cran si le tier 0 ou l'atelier (Purdue 0-2) est visé
    allowed: tuple[ipaddress._BaseNetwork, ...] = ()   # scanners autorisés : pas d'alerte


@dataclass
class AlertsConfig:
    persistent_after_days: int = 3
    unused_rule_after_days: int = 90
    check_intra_zone: bool = False
    outputs: list[Output] = field(default_factory=list)
    scan: ScanConfig = field(default_factory=ScanConfig)


@dataclass(frozen=True)
class TrustedHost:
    subject_kind: str  # "user" | "group"
    subject: str
    allow: tuple[ipaddress._BaseNetwork, ...]


@dataclass
class MailConfig:
    """Serveur d'envoi des codes par e-mail. Mot de passe : variable
    d'environnement AUSPEX_SMTP_PASSWORD (jamais dans ce fichier)."""
    server: str
    sender: str
    port: int = 587
    security: str = "starttls"   # starttls | tls | none
    username: str | None = None
    ca_file: str | None = None   # autorité de certification interne, si besoin


@dataclass
class LDAPConfig:
    """Annuaire (Active Directory, OpenLDAP...) : toujours chiffré, certificat
    vérifié. Mot de passe du compte de lecture : AUSPEX_LDAP_BIND_PASSWORD."""
    servers: tuple[str, ...]
    user_search_base: str
    user_attribute: str = "sAMAccountName"
    start_tls: bool = False
    bind_dn: str | None = None
    group_search_base: str | None = None
    group_type: str = "active_directory"   # active_directory | group_of_names | posix
    require_group: str | None = None
    superuser_group: str | None = None
    ca_file: str | None = None
    attributes: dict = field(default_factory=lambda: {"first_name": "givenName", "last_name": "sn",
                                                       "email": "mail"})


@dataclass
class OIDCConfig:
    """Fournisseur d'identité OpenID Connect (Entra ID, Google, AWS Cognito,
    Keycloak...). Secret du client : AUSPEX_OIDC_CLIENT_SECRET."""
    issuer: str
    client_id: str
    label: str = "Connexion unique (SSO)"
    scopes: tuple[str, ...] = ()            # en plus de openid, profile, email
    groups_claim: str = "groups"
    require_group: str | None = None
    superuser_group: str | None = None
    ca_file: str | None = None


@dataclass
class SAMLConfig:
    """Fournisseur d'identité SAML 2.0 (ADFS, Entra ID, Keycloak...)."""
    sp_entity_id: str
    idp_entity_id: str
    idp_sso_url: str
    idp_cert: str                           # certificat de signature (base64, sans en-têtes)
    attributes: dict
    label: str = "Connexion unique (SSO)"
    groups_claim: str = "groups"            # attribut SAML qui porte les groupes
    require_group: str | None = None
    superuser_group: str | None = None
    contact: str = "admin@example.invalid"


@dataclass
class WebAuthnConfig:
    """Clés de sécurité (FIDO2, Windows Hello...). Le navigateur lie chaque clé
    au domaine : une clé inscrite ici ne sert pas sur un site d'hameçonnage."""
    rp_id: str                    # domaine (ex. auspex.ville.fr)
    origin: str                   # adresse exacte de NetBox (ex. https://auspex.ville.fr)
    require_uv: bool = False      # exiger le code PIN ou la biométrie de la clé


CARD_IDENTIFIERS = ("upn", "upn_court", "email", "cn")


@dataclass
class CardConfig:
    """Connexion par carte à puce (certificat client TLS) : port dédié du front HTTPS."""
    address: str                  # adresse du port carte, ex. https://auspex.ville.fr:8443
    ca_file: str                  # autorités émettrices des cartes (PEM)
    crl_file: str | None          # liste de révocation (PEM), recommandée
    identifier: str = "upn"       # upn | upn_court | email | cn → nom d'utilisateur NetBox
    create_users: bool = False    # créer le compte (sans droits) s'il n'existe pas


@dataclass
class AccessConfig:
    trusted_hosts: list[TrustedHost] = field(default_factory=list)
    default: str = "deny_if_unlisted"
    # Proxys dont on accepte l'en-tête X-Forwarded-For (reverse proxy TLS).
    trusted_proxies: tuple[ipaddress._BaseNetwork, ...] = ()
    # Compte brise-glace : toujours accepté depuis la machine du central,
    # et depuis ces adresses en plus.
    break_glass_user: str | None = None
    break_glass_allow: tuple[ipaddress._BaseNetwork, ...] = ()
    # Double authentification : méthodes proposées à l'inscription. Le
    # brise-glace est toujours en TOTP (il doit marcher sans messagerie).
    mfa_methods: tuple[str, ...] = ("totp",)
    mail: MailConfig | None = None
    webauthn: WebAuthnConfig | None = None
    break_glass_mfa: str = "totp"
    card: CardConfig | None = None
    # Méthode de connexion principale (en plus du brise-glace local). None :
    # comptes locaux uniquement.
    auth_primary: str | None = None
    ldap: LDAPConfig | None = None
    oidc: OIDCConfig | None = None
    saml: SAMLConfig | None = None


@dataclass
class NetBoxConfig:
    url: str
    token_env: str = "NETBOX_TOKEN"
    ca_file: str | None = None
    silent_after_days: int = 30


LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


AUDIT_FRAMEWORKS = ("nis2", "dora", "iec62443", "iso27001", "anssi")   # voir auspex.audit.FRAMEWORKS
AUDIT_FREQUENCIES = {"quotidienne": 1, "hebdomadaire": 7, "mensuelle": 30}


@dataclass
class AuditConfig:
    """Exports d'audit produits automatiquement par le service."""
    frameworks: tuple[str, ...] = ()
    frequency: str = "mensuelle"
    period_days: int = 30
    keep: int = 24


@dataclass
class Config:
    version: int
    channel: str
    zones: list[Zone]
    sensors: list[Sensor]
    flow_rules_file: Path | None
    alerts: AlertsConfig
    access: AccessConfig
    retention_days: int
    modules: list[str]
    base_dir: Path
    state_dir: Path
    fingerprint_rules: list[Path] = field(default_factory=list)
    netbox: NetBoxConfig | None = None
    organisation: str | None = None
    audit: AuditConfig = field(default_factory=AuditConfig)

    def zone_by_name(self, name: str) -> Zone | None:
        return next((z for z in self.zones if z.name == name), None)


def _net(value: Any, where: str, problems: list[str]):
    try:
        return ipaddress.ip_network(str(value), strict=False)
    except ValueError:
        problems.append(f"{where} : '{value}' n'est ni une IP ni un préfixe CIDR valide")
        return None


def _require(d: dict, key: str, where: str, problems: list[str], kind=str):
    if key not in d or d[key] in (None, ""):
        problems.append(f"{where}.{key} : champ obligatoire manquant")
        return None
    if not isinstance(d[key], kind):
        problems.append(f"{where}.{key} : type attendu {kind.__name__}")
        return None
    return d[key]


_LDAP_ATTR = __import__("re").compile(r"^[A-Za-z][A-Za-z0-9-]*$")
LDAP_GROUP_TYPES = {"active_directory", "group_of_names", "posix"}


def _parse_ldap(raw, problems: list[str], base_dir: Path) -> LDAPConfig | None:
    if not isinstance(raw, dict):
        problems.append("auth.ldaps : section obligatoire avec auth.primary: ldaps (servers, user_search_base)")
        return None
    if "bind_password" in raw or "password" in raw:
        problems.append("auth.ldaps : mot de passe interdit dans ce fichier, utiliser la variable "
                        "d'environnement AUSPEX_LDAP_BIND_PASSWORD")
    servers = raw.get("servers") or ([raw["server"]] if raw.get("server") else [])
    start_tls = raw.get("start_tls", False)
    if not isinstance(start_tls, bool):
        problems.append("auth.ldaps.start_tls : true ou false attendu")
        start_tls = False
    if not servers or not all(isinstance(u, str) for u in servers):
        problems.append("auth.ldaps.servers : au moins un serveur (ldaps://...)")
        servers = []
    for u in servers:
        if u.startswith("ldaps://"):
            continue
        if u.startswith("ldap://") and start_tls:
            continue
        problems.append(f"auth.ldaps.servers : « {u} » enverrait les mots de passe en clair ; "
                        "utiliser ldaps:// (ou ldap:// avec start_tls: true)")
    if not raw.get("user_search_base") or "=" not in str(raw.get("user_search_base")):
        problems.append("auth.ldaps.user_search_base : DN attendu (ex. OU=Utilisateurs,DC=ville,DC=local)")
    attr = raw.get("user_attribute", "sAMAccountName")
    if not isinstance(attr, str) or not _LDAP_ATTR.match(attr):
        problems.append("auth.ldaps.user_attribute : nom d'attribut LDAP attendu (sAMAccountName, uid...)")
    group_type = raw.get("group_type", "active_directory")
    if group_type not in LDAP_GROUP_TYPES:
        problems.append("auth.ldaps.group_type : 'active_directory', 'group_of_names' ou 'posix' attendu")
    for key in ("bind_dn", "group_search_base", "require_group", "superuser_group"):
        if raw.get(key) is not None and "=" not in str(raw[key]):
            problems.append(f"auth.ldaps.{key} : DN attendu")
    if (raw.get("require_group") or raw.get("superuser_group")) and not raw.get("group_search_base"):
        problems.append("auth.ldaps.group_search_base : obligatoire avec require_group ou superuser_group")
    attributes = {"first_name": "givenName", "last_name": "sn", "email": "mail"}
    extra = raw.get("attributes") or {}
    if not isinstance(extra, dict) or any(k not in attributes or not isinstance(v, str) or not _LDAP_ATTR.match(v)
                                          for k, v in extra.items()):
        problems.append("auth.ldaps.attributes : first_name, last_name, email → nom d'attribut LDAP")
    else:
        attributes.update(extra)
    ca_file = None
    if raw.get("ca_file"):
        ca_path = Path(str(raw["ca_file"]))
        ca_path = ca_path if ca_path.is_absolute() else base_dir / ca_path
        if not ca_path.is_file():
            problems.append(f"auth.ldaps.ca_file : fichier introuvable ({ca_path})")
        ca_file = str(ca_path)
    for key in ("ignore_cert_errors", "verify"):
        if key in raw:
            problems.append(f"auth.ldaps.{key} : la vérification du certificat ne se désactive pas ; "
                            "pour une autorité interne, utiliser ca_file")
    if not servers:
        return None
    return LDAPConfig(servers=tuple(servers), user_search_base=str(raw.get("user_search_base", "")),
                      user_attribute=attr if isinstance(attr, str) else "sAMAccountName", start_tls=start_tls,
                      bind_dn=raw.get("bind_dn"), group_search_base=raw.get("group_search_base"),
                      group_type=group_type if group_type in LDAP_GROUP_TYPES else "active_directory",
                      require_group=raw.get("require_group"), superuser_group=raw.get("superuser_group"),
                      ca_file=ca_file, attributes=attributes)


def _ca_file(raw: dict, where: str, problems: list[str], base_dir: Path) -> str | None:
    if not raw.get("ca_file"):
        return None
    ca_path = Path(str(raw["ca_file"]))
    ca_path = ca_path if ca_path.is_absolute() else base_dir / ca_path
    if not ca_path.is_file():
        problems.append(f"{where}.ca_file : fichier introuvable ({ca_path})")
    return str(ca_path)


def _parse_oidc(raw, problems: list[str], base_dir: Path) -> OIDCConfig | None:
    if not isinstance(raw, dict):
        problems.append("auth.oidc : section obligatoire avec auth.primary: oidc (issuer, client_id)")
        return None
    if "client_secret" in raw or "secret" in raw:
        problems.append("auth.oidc : secret interdit dans ce fichier, utiliser la variable "
                        "d'environnement AUSPEX_OIDC_CLIENT_SECRET")
    issuer = raw.get("issuer")
    if not isinstance(issuer, str) or not issuer.startswith("https://"):
        problems.append("auth.oidc.issuer : adresse https:// du fournisseur attendue "
                        "(ex. https://login.microsoftonline.com/<tenant>/v2.0)")
    if not raw.get("client_id") or not isinstance(raw.get("client_id"), str):
        problems.append("auth.oidc.client_id : obligatoire")
    scopes = raw.get("scopes") or []
    if not isinstance(scopes, list) or not all(isinstance(x, str) and x and " " not in x for x in scopes):
        problems.append("auth.oidc.scopes : liste de noms (ex. [groups])")
        scopes = []
    claim = raw.get("groups_claim", "groups")
    if not isinstance(claim, str) or not claim:
        problems.append("auth.oidc.groups_claim : nom de champ attendu")
    for key in ("ignore_cert_errors", "verify", "verify_ssl"):
        if key in raw:
            problems.append(f"auth.oidc.{key} : la vérification du certificat ne se désactive pas ; "
                            "pour une autorité interne, utiliser ca_file")
    ca_file = _ca_file(raw, "auth.oidc", problems, base_dir)
    if not isinstance(issuer, str) or not issuer.startswith("https://") or not raw.get("client_id"):
        return None
    return OIDCConfig(issuer=issuer.rstrip("/"), client_id=str(raw["client_id"]),
                      label=str(raw.get("label") or "Connexion unique (SSO)"), scopes=tuple(scopes),
                      groups_claim=claim if isinstance(claim, str) and claim else "groups",
                      require_group=raw.get("require_group"), superuser_group=raw.get("superuser_group"),
                      ca_file=ca_file)


def _parse_saml(raw, problems: list[str], base_dir: Path) -> SAMLConfig | None:
    from .netbox_auth import parse_idp_metadata
    where = "auth.saml"
    if not isinstance(raw, dict):
        problems.append(f"{where} : section obligatoire avec auth.primary: saml "
                        "(sp_entity_id, idp_metadata, attributes)")
        return None
    ok = True
    if not raw.get("sp_entity_id") or not isinstance(raw.get("sp_entity_id"), str):
        problems.append(f"{where}.sp_entity_id : identifiant de NetBox chez le fournisseur attendu "
                        "(ex. https://netbox.ville.local)")
        ok = False
    idp = None
    if raw.get("idp_metadata"):
        path = Path(str(raw["idp_metadata"]))
        path = path if path.is_absolute() else base_dir / path
        try:
            idp = parse_idp_metadata(path.read_text(encoding="utf-8"))
        except OSError:
            problems.append(f"{where}.idp_metadata : fichier introuvable ({path})")
        except ValueError as exc:
            problems.append(f"{where}.idp_metadata : {exc}")
    else:
        problems.append(f"{where}.idp_metadata : fichier de métadonnées du fournisseur obligatoire "
                        "(exporté d'ADFS, Entra ID, Keycloak...)")
    if idp is not None and not idp["sso_url"].startswith("https://"):
        problems.append(f"{where}.idp_metadata : adresse de connexion du fournisseur non chiffrée "
                        f"({idp['sso_url']}), https:// attendu")
        idp = None
    if idp is not None:
        import urllib.parse
        host = urllib.parse.urlparse(idp["sso_url"]).hostname or ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if "." not in host and host != "localhost":
                problems.append(f"{where}.idp_metadata : nom du fournisseur incomplet ({host}) ; la "
                                "bibliothèque SAML exige un nom complet (ex. sso.ville.fr)")
                idp = None
    attrs = raw.get("attributes") or {}
    if not isinstance(attrs, dict) or not attrs.get("permanent_id") or not attrs.get("username"):
        problems.append(f"{where}.attributes : permanent_id et username obligatoires "
                        "(noms des attributs SAML ; email, first_name, last_name facultatifs)")
        ok = False
    elif any(k not in ("permanent_id", "username", "email", "first_name", "last_name") for k in attrs):
        problems.append(f"{where}.attributes : permanent_id, username, email, first_name, last_name")
        ok = False
    for key in ("want_assertions_signed", "verify", "strict"):
        if key in raw:
            problems.append(f"{where}.{key} : la vérification de la signature ne se désactive pas")
    if not ok or idp is None:
        return None
    return SAMLConfig(sp_entity_id=str(raw["sp_entity_id"]), idp_entity_id=idp["entity_id"],
                      idp_sso_url=idp["sso_url"], idp_cert=idp["x509cert"], attributes=dict(attrs),
                      label=str(raw.get("label") or "Connexion unique (SSO)"),
                      groups_claim=str(raw.get("groups_attribute") or "groups"),
                      require_group=raw.get("require_group"), superuser_group=raw.get("superuser_group"),
                      contact=str(raw.get("contact") or "admin@example.invalid"))


def _parse_webauthn(raw, problems: list[str]) -> WebAuthnConfig | None:
    """auth.mfa.webauthn : { domaine: auspex.ville.fr, adresse: https://auspex.ville.fr }."""
    if raw is None:
        return None
    from urllib.parse import urlparse
    if not isinstance(raw, dict):
        problems.append("auth.mfa.webauthn : dictionnaire attendu (domaine, adresse)")
        return None
    for k in set(raw) - {"domaine", "adresse", "exiger_code"}:
        problems.append(f"auth.mfa.webauthn.{k} : clé inconnue (domaine, adresse, exiger_code)")
    rp_id, origin = str(raw.get("domaine") or ""), str(raw.get("adresse") or "").rstrip("/")
    u = urlparse(origin)
    ok = True
    if not rp_id or ipaddress_like(rp_id) or not all(part and part.replace("-", "").isalnum()
                                                     for part in rp_id.split(".")):
        problems.append("auth.mfa.webauthn.domaine : nom de domaine attendu (pas une adresse IP), "
                        "ex. auspex.ville.fr")
        ok = False
    if u.scheme not in ("https", "http") or not u.hostname or u.path or u.query:
        problems.append("auth.mfa.webauthn.adresse : adresse de NetBox attendue, ex. https://auspex.ville.fr")
        ok = False
    elif u.scheme == "http" and u.hostname != "localhost":
        problems.append("auth.mfa.webauthn.adresse : HTTPS obligatoire (les navigateurs refusent les clés "
                        "de sécurité en HTTP, sauf sur localhost)")
        ok = False
    elif rp_id and u.hostname != rp_id and not u.hostname.endswith("." + rp_id):
        problems.append(f"auth.mfa.webauthn.domaine : « {rp_id} » doit être le nom de l'adresse "
                        f"({u.hostname}) ou un de ses domaines parents")
        ok = False
    uv = raw.get("exiger_code", False)
    if not isinstance(uv, bool):
        problems.append("auth.mfa.webauthn.exiger_code : true ou false attendu")
        ok = False
    return WebAuthnConfig(rp_id=rp_id, origin=origin, require_uv=uv) if ok else None


def _parse_card(raw, problems: list[str], base_dir: Path) -> CardConfig | None:
    if raw is None:
        return None
    from urllib.parse import urlparse
    if not isinstance(raw, dict):
        problems.append("auth.carte : dictionnaire attendu (adresse, autorites, revocation, identifiant)")
        return None
    for k in set(raw) - {"adresse", "autorites", "revocation", "identifiant", "creer_comptes"}:
        problems.append(f"auth.carte.{k} : clé inconnue")
    ok = True
    address = str(raw.get("adresse") or "").rstrip("/")
    u = urlparse(address)
    if u.scheme != "https" or not u.hostname or u.path or not u.port:
        problems.append("auth.carte.adresse : adresse HTTPS du port carte attendue, ex. https://auspex.ville.fr:8443")
        ok = False

    def pem(key: str, required: bool) -> str | None:
        nonlocal ok
        value = raw.get(key)
        if not value:
            if required:
                problems.append(f"auth.carte.{key} : fichier PEM obligatoire")
                ok = False
            return None
        path = Path(str(value))
        path = path if path.is_absolute() else base_dir / path
        if not path.is_file():
            problems.append(f"auth.carte.{key} : fichier introuvable ({path})")
            ok = False
            return None
        return str(path)

    ca_file, crl_file = pem("autorites", True), pem("revocation", False)
    if ca_file:
        from .carte import CardError, load_authorities
        try:
            load_authorities(Path(ca_file).read_bytes())
        except CardError as exc:
            problems.append(f"auth.carte.autorites : {exc}")
            ok = False
    if crl_file:
        from .carte import CardError, load_crls
        try:
            load_crls(Path(crl_file).read_bytes())
        except CardError as exc:
            problems.append(f"auth.carte.revocation : {exc}")
            ok = False
    ident = raw.get("identifiant", "upn")
    if ident not in CARD_IDENTIFIERS:
        problems.append(f"auth.carte.identifiant : '{ident}' inconnu (au choix : {', '.join(CARD_IDENTIFIERS)})")
        ok = False
    create = raw.get("creer_comptes", False)
    if not isinstance(create, bool):
        problems.append("auth.carte.creer_comptes : true ou false attendu")
        ok = False
    if not ok:
        return None
    return CardConfig(address=address, ca_file=ca_file, crl_file=crl_file, identifier=ident, create_users=create)


def ipaddress_like(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip("[]"))
        return True
    except ValueError:
        return False


def _parse_mfa(raw, access: AccessConfig, problems: list[str], base_dir: Path) -> None:
    if raw is None:
        return
    if not isinstance(raw, dict):
        problems.append("auth.mfa : dictionnaire attendu")
        return
    methods = raw.get("methods", ["totp"])
    if not isinstance(methods, list) or not methods or any(m not in MFA_METHODS for m in methods):
        problems.append("auth.mfa.methods : liste non vide parmi 'totp', 'email', 'webauthn'")
        return
    access.mfa_methods = tuple(dict.fromkeys(methods))
    access.webauthn = _parse_webauthn(raw.get("webauthn"), problems)
    if "webauthn" in methods and access.webauthn is None and "webauthn" not in raw:
        problems.append("auth.mfa.webauthn : obligatoire avec la méthode 'webauthn' (domaine, adresse)")
    mail = raw.get("email")
    if "email" not in methods:
        if mail:
            problems.append("auth.mfa.email : renseigné alors que 'email' n'est pas dans auth.mfa.methods")
        return
    if not isinstance(mail, dict):
        problems.append("auth.mfa.email : serveur d'envoi obligatoire avec la méthode 'email' "
                        "(smtp_server, from)")
        return
    if "password" in mail:
        problems.append("auth.mfa.email.password : interdit dans ce fichier, utiliser la variable "
                        "d'environnement AUSPEX_SMTP_PASSWORD")
    for key in ("smtp_server", "from"):
        if not mail.get(key) or not isinstance(mail.get(key), str):
            problems.append(f"auth.mfa.email.{key} : obligatoire")
    if mail.get("from") and "@" not in str(mail["from"]):
        problems.append("auth.mfa.email.from : adresse e-mail attendue")
    security = mail.get("security", "starttls")
    if security not in SMTP_SECURITY:
        problems.append("auth.mfa.email.security : 'starttls', 'tls' ou 'none' attendu")
    port = mail.get("port", 465 if security == "tls" else 587)
    if not isinstance(port, int) or not 1 <= port <= 65535:
        problems.append("auth.mfa.email.port : entier entre 1 et 65535 attendu")
    ca_file = None
    if mail.get("ca_file"):
        ca_path = Path(str(mail["ca_file"]))
        ca_path = ca_path if ca_path.is_absolute() else base_dir / ca_path
        if not ca_path.is_file():
            problems.append(f"auth.mfa.email.ca_file : fichier introuvable ({ca_path})")
        ca_file = str(ca_path)
    if mail.get("smtp_server") and mail.get("from") and security in SMTP_SECURITY and isinstance(port, int):
        access.mail = MailConfig(server=str(mail["smtp_server"]), sender=str(mail["from"]), port=port,
                                 security=security, username=mail.get("username") or None, ca_file=ca_file)


def parse_config(raw: Any, base_dir: Path | str = ".") -> Config:
    """Valide un dictionnaire (YAML déjà chargé) et renvoie un `Config`."""
    base_dir = Path(base_dir)
    problems: list[str] = []
    if not isinstance(raw, dict):
        raise ConfigError(["racine : le fichier doit contenir un objet YAML"])

    version = raw.get("version")
    if version not in SUPPORTED_VERSIONS:
        problems.append(f"version : valeur {version!r} non supportée (attendu : 1)")

    channel = raw.get("channel", "stable")
    if channel not in CHANNELS:
        problems.append(f"channel : '{channel}' inconnu (attendu : {', '.join(sorted(CHANNELS))})")

    # Zones
    zones: list[Zone] = []
    seen_names: set[str] = set()
    for i, z in enumerate(raw.get("zones") or []):
        where = f"zones[{i}]"
        if not isinstance(z, dict):
            problems.append(f"{where} : objet attendu")
            continue
        name = _require(z, "name", where, problems)
        zclass = _require(z, "class", where, problems)
        if zclass and zclass not in ZONE_CLASSES:
            problems.append(f"{where}.class : '{zclass}' inconnue (attendu : {', '.join(sorted(ZONE_CLASSES))})")
        if name in seen_names:
            problems.append(f"{where}.name : zone '{name}' déclarée deux fois")
        if name:
            seen_names.add(name)
        prefixes = []
        for j, p in enumerate(z.get("prefixes") or []):
            n = _net(p, f"{where}.prefixes[{j}]", problems)
            if n:
                prefixes.append(n)
        if not prefixes:
            problems.append(f"{where}.prefixes : au moins un préfixe est requis")
        if name and zclass:
            zones.append(Zone(name, zclass, tuple(prefixes)))

    # Chevauchement exact de préfixes entre zones : ambigu, donc refusé.
    owner: dict[str, str] = {}
    for zone in zones:
        for p in zone.prefixes:
            if str(p) in owner and owner[str(p)] != zone.name:
                problems.append(
                    f"zones : le préfixe {p} est déclaré dans '{owner[str(p)]}' et dans '{zone.name}'"
                )
            owner[str(p)] = zone.name

    # Capteurs
    sensors: list[Sensor] = []
    for i, s in enumerate(raw.get("sensors") or []):
        where = f"sensors[{i}]"
        if not isinstance(s, dict):
            problems.append(f"{where} : objet attendu")
            continue
        name = _require(s, "name", where, problems)
        zone = _require(s, "zone", where, problems)
        iface = _require(s, "interface", where, problems)
        mode = s.get("mode", "passive")
        if zone and zone not in seen_names:
            problems.append(f"{where}.zone : zone '{zone}' inconnue")
        if mode not in SENSOR_MODES:
            problems.append(f"{where}.mode : '{mode}' inconnu (attendu : passive, active-light)")
        zobj = next((z for z in zones if z.name == zone), None)
        if mode == "active-light" and zobj and zobj.is_ot:
            problems.append(f"{where}.mode : le mode actif est interdit en zone OT ('{zone}')")
        key = s.get("key")
        allow: list = []
        if key is not None:
            from .reception import SensorKeyError, parse_public_key
            if name and not SENSOR_NAME.match(str(name)):
                problems.append(f"{where}.name : avec une clé d'envoi, nom en minuscules, chiffres et tirets "
                                "(il devient le dossier de réception)")
            try:
                key = parse_public_key(key)
            except SensorKeyError as exc:
                problems.append(f"{where}.key : {exc}")
                key = None
        for j, v in enumerate(s.get("allow") or []):
            n = _net(v, f"{where}.allow[{j}]", problems)
            if n is not None:
                if n.prefixlen == 0:
                    problems.append(f"{where}.allow[{j}] : « {v} » accepterait le capteur depuis n'importe où")
                allow.append(n)
        if s.get("allow") and key is None and "key" not in s:
            problems.append(f"{where}.allow : sans clé d'envoi (key), allow n'a pas d'effet")
        if name and zone and iface:
            sensors.append(Sensor(name, zone, iface, mode, key, tuple(allow)))
    seen_sensor: set = set()
    seen_key: set = set()
    for sn in sensors:
        if sn.name in seen_sensor:
            problems.append(f"sensors : nom « {sn.name} » déclaré deux fois")
        if sn.key and sn.key.split()[1] in seen_key:
            problems.append(f"sensors : la clé de « {sn.name} » est déjà celle d'un autre capteur")
        seen_sensor.add(sn.name)
        if sn.key:
            seen_key.add(sn.key.split()[1])

    # Règles de flux
    fr = raw.get("flow_rules") or {}
    flow_rules_file = None
    if fr:
        if not isinstance(fr, dict) or not fr.get("file"):
            problems.append("flow_rules.file : chemin du fichier CSV/XLSX attendu")
        else:
            flow_rules_file = (base_dir / fr["file"]).resolve()
            if flow_rules_file.suffix.lower() not in {".csv", ".xlsx"}:
                problems.append("flow_rules.file : extension .csv ou .xlsx attendue")

    # Alertes
    a = raw.get("alerts") or {}
    alerts = AlertsConfig()
    for key in ("persistent_after_days", "unused_rule_after_days"):
        if key in a:
            if not isinstance(a[key], int) or isinstance(a[key], bool) or a[key] < 1:
                problems.append(f"alerts.{key} : entier ≥ 1 attendu")
            else:
                setattr(alerts, key, a[key])
    if "check_intra_zone" in a:
        if not isinstance(a["check_intra_zone"], bool):
            problems.append("alerts.check_intra_zone : true ou false attendu")
        else:
            alerts.check_intra_zone = a["check_intra_zone"]
    sc = a.get("scan")
    if sc is not None:
        if not isinstance(sc, dict):
            problems.append("alerts.scan : dictionnaire attendu")
        else:
            unknown = set(sc) - {"enabled", "min_targets", "window_hours", "severity", "allowed"}
            if unknown:
                problems.append(f"alerts.scan : clé(s) inconnue(s) {', '.join(sorted(unknown))}")
            if "enabled" in sc:
                if not isinstance(sc["enabled"], bool):
                    problems.append("alerts.scan.enabled : true ou false attendu")
                else:
                    alerts.scan.enabled = sc["enabled"]
            for key, low in (("min_targets", 2), ("window_hours", 1)):
                if key in sc:
                    v = sc[key]
                    if not isinstance(v, int) or isinstance(v, bool) or v < low:
                        problems.append(f"alerts.scan.{key} : entier ≥ {low} attendu")
                    else:
                        setattr(alerts.scan, key, v)
            if "severity" in sc:
                if sc["severity"] not in SEVERITIES:
                    problems.append(f"alerts.scan.severity : '{sc['severity']}' inconnu "
                                    f"(attendu : {', '.join(SEVERITIES)})")
                else:
                    alerts.scan.severity = sc["severity"]
            allowed = sc.get("allowed") or []
            if not isinstance(allowed, list):
                problems.append("alerts.scan.allowed : liste d'IP ou de préfixes CIDR attendue")
            else:
                nets = [_net(x, f"alerts.scan.allowed[{i}]", problems) for i, x in enumerate(allowed)]
                alerts.scan.allowed = tuple(n for n in nets if n is not None)
    for i, o in enumerate(a.get("outputs") or []):
        where = f"alerts.outputs[{i}]"
        if isinstance(o, str):  # forme courte : "syslog://hote:514"
            if o.startswith(("syslog://", "tls://", "udp://", "tcp://")):
                o = {"type": "syslog", "url": o}
            elif o.startswith("https://"):
                o = {"type": "webhook", "url": o}
            else:
                problems.append(f"{where} : forme courte non reconnue '{o}'")
                continue
        otype = o.get("type")
        if otype not in OUTPUT_TYPES:
            problems.append(f"{where}.type : '{otype}' inconnu (attendu : {', '.join(sorted(OUTPUT_TYPES))})")
            continue
        fmt = o.get("format", "cef" if otype == "syslog" else "json")
        if otype == "syslog" and fmt not in SYSLOG_FORMATS:
            problems.append(f"{where}.format : '{fmt}' inconnu (attendu : cef, json)")
        sev = o.get("min_severity", "info")
        if sev not in SEVERITIES:
            problems.append(f"{where}.min_severity : '{sev}' inconnu (attendu : {', '.join(SEVERITIES)})")
        if otype in {"syslog", "webhook"} and not o.get("url"):
            problems.append(f"{where}.url : obligatoire pour une sortie {otype}")
        if otype == "webhook" and o.get("url", "").startswith("http://"):
            problems.append(f"{where}.url : HTTPS obligatoire pour un webhook")
        if otype == "file" and not o.get("path"):
            problems.append(f"{where}.path : obligatoire pour une sortie file")
        if "token" in o:
            problems.append(f"{where}.token : les secrets ne vont pas dans auspex.yaml, utilisez token_env")
        ca_file = None
        if o.get("ca_file"):
            ca_path = (base_dir / str(o["ca_file"])).resolve()
            if not ca_path.exists():
                problems.append(f"{where}.ca_file : {o['ca_file']} introuvable")
            ca_file = str(ca_path)
        alerts.outputs.append(Output(
            type=otype, url=o.get("url"), format=fmt, min_severity=sev,
            path=o.get("path"), token_env=o.get("token_env"), ca_file=ca_file,
        ))

    # Accès
    acc = raw.get("access") or {}
    access = AccessConfig(default=acc.get("default", "deny_if_unlisted"))
    if access.default not in {"deny_if_unlisted", "allow_if_unlisted"}:
        problems.append("access.default : 'deny_if_unlisted' ou 'allow_if_unlisted' attendu")
    for i, th in enumerate(acc.get("trusted_hosts") or []):
        where = f"access.trusted_hosts[{i}]"
        kinds = [k for k in ("user", "group") if k in th]
        if len(kinds) != 1:
            problems.append(f"{where} : préciser exactement un champ 'user' ou 'group'")
            continue
        nets = [n for j, v in enumerate(th.get("allow") or [])
                if (n := _net(v, f"{where}.allow[{j}]", problems))]
        if not nets:
            problems.append(f"{where}.allow : au moins une IP ou une plage est requise")
            continue
        access.trusted_hosts.append(TrustedHost(kinds[0], str(th[kinds[0]]), tuple(nets)))
    proxies = []
    for j, v in enumerate(acc.get("trusted_proxies") or []):
        n = _net(v, f"access.trusted_proxies[{j}]", problems)
        if n is not None:
            if n.prefixlen == 0:
                problems.append(f"access.trusted_proxies[{j}] : « {v} » ferait confiance à n'importe qui")
            proxies.append(n)
    access.trusted_proxies = tuple(proxies)

    # Authentification (validée ici, appliquée par le plugin NetBox)
    auth = raw.get("auth") or {}
    if auth:
        # Sans « primary » : comptes locaux uniquement.
        primary = auth.get("primary")
        if primary is not None and primary not in AUTH_PRIMARY:
            problems.append("auth.primary : 'ldaps', 'oidc' ou 'saml' attendu")
        elif primary == "saml":
            access.auth_primary = "saml"
            access.saml = _parse_saml(auth.get("saml"), problems, Path(base_dir))
        elif primary == "ldaps":
            access.auth_primary = "ldaps"
            access.ldap = _parse_ldap(auth.get("ldaps"), problems, Path(base_dir))
        elif primary == "oidc":
            access.auth_primary = "oidc"
            access.oidc = _parse_oidc(auth.get("oidc"), problems, Path(base_dir))
        for block in ("ldaps", "oidc", "saml"):
            if auth.get(block) and primary != block:
                problems.append(f"auth.{block} : renseigné alors que auth.primary n'est pas '{block}'")
        bg = auth.get("break_glass") or {}
        if not bg.get("user"):
            problems.append("auth.break_glass.user : un compte brise-glace est obligatoire")
        if bg.get("mfa") not in MFA_KINDS:
            problems.append("auth.break_glass.mfa : 'totp' ou 'webauthn' attendu")
        else:
            access.break_glass_mfa = bg["mfa"]
        # Sans « allow », le brise-glace n'est accepté que depuis la machine du central.
        bg_nets = []
        for j, v in enumerate(bg.get("allow") or []):
            n = _net(v, f"auth.break_glass.allow[{j}]", problems)
            if n is not None:
                if n.prefixlen == 0:
                    problems.append(f"auth.break_glass.allow[{j}] : « {v} » ouvrirait le brise-glace à tous")
                bg_nets.append(n)
        access.break_glass_user = str(bg["user"]) if bg.get("user") else None
        access.break_glass_allow = tuple(bg_nets)
        _parse_mfa(auth.get("mfa"), access, problems, Path(base_dir))
        access.card = _parse_card(auth.get("carte"), problems, Path(base_dir))
        if access.break_glass_mfa == "webauthn" and access.webauthn is None:
            problems.append("auth.break_glass.mfa : 'webauthn' demande la section auth.mfa.webauthn "
                            "(domaine et adresse de NetBox)")

    retention_days = raw.get("retention_days", 180)
    if not isinstance(retention_days, int) or retention_days < 1:
        problems.append("retention_days : entier ≥ 1 attendu")

    modules = raw.get("modules") or []
    from .modules import ModuleError, parse_source
    for i, m in enumerate(modules):
        if not isinstance(m, str):
            problems.append(f"modules[{i}] : forme 'github.com/org/depot@version' attendue (version épinglée)")
            continue
        try:
            parse_source(m)
        except ModuleError as exc:
            problems.append(f"modules[{i}] : {exc}")
    if len(set(modules)) != len(modules):
        problems.append("modules : un même module est déclaré deux fois")

    state_dir = (base_dir / str(raw.get("state_dir", "state"))).resolve()

    fp_rules = raw.get("fingerprint_rules")
    fingerprint_rules: list[Path] = []
    if fp_rules is not None:
        if not isinstance(fp_rules, list):
            problems.append("fingerprint_rules : liste de fichiers ou répertoires attendue")
        else:
            for i, p in enumerate(fp_rules):
                path = (base_dir / str(p)).resolve()
                if not path.exists():
                    problems.append(f"fingerprint_rules[{i}] : {p} introuvable")
                fingerprint_rules.append(path)

    netbox = None
    nb = raw.get("netbox")
    if nb is not None:
        from urllib.parse import urlparse
        if not isinstance(nb, dict) or not nb.get("url"):
            problems.append("netbox.url : adresse de NetBox attendue")
        else:
            u = urlparse(str(nb["url"]))
            if u.scheme not in {"http", "https"} or not u.hostname:
                problems.append(f"netbox.url : '{nb['url']}' n'est pas une adresse http(s) valide")
            elif u.scheme == "http" and u.hostname not in LOCAL_HOSTS:
                internal = nb.get("allow_http_internal") is True and "." not in u.hostname
                if not internal:
                    problems.append("netbox.url : HTTPS obligatoire (HTTP n'est accepté que sur la machine "
                                    "locale, ou vers un service Docker interne avec allow_http_internal: true)")
            if "token" in nb:
                problems.append("netbox.token : les secrets ne vont pas dans auspex.yaml, utilisez token_env")
            silent = nb.get("silent_after_days", 30)
            if not isinstance(silent, int) or isinstance(silent, bool) or silent < 1:
                problems.append("netbox.silent_after_days : entier ≥ 1 attendu")
            ca_file = None
            if nb.get("ca_file"):
                ca_path = (base_dir / str(nb["ca_file"])).resolve()
                if not ca_path.exists():
                    problems.append(f"netbox.ca_file : {nb['ca_file']} introuvable")
                ca_file = str(ca_path)
            netbox = NetBoxConfig(url=str(nb["url"]).rstrip("/"), token_env=str(nb.get("token_env", "NETBOX_TOKEN")),
                                  ca_file=ca_file, silent_after_days=silent if isinstance(silent, int) else 30)

    organisation = raw.get("organisation")
    if organisation is not None and (not isinstance(organisation, str) or not organisation.strip()
                                     or len(organisation) > 120):
        problems.append("organisation : nom de l'organisation (texte, 120 caractères au plus) attendu")
        organisation = None
    audit = _parse_audit(raw.get("audit"), problems)

    if problems:
        raise ConfigError(problems)

    return Config(
        version=version, channel=channel, zones=zones, sensors=sensors,
        flow_rules_file=flow_rules_file, alerts=alerts, access=access,
        retention_days=retention_days, modules=list(modules), base_dir=base_dir,
        state_dir=state_dir, fingerprint_rules=fingerprint_rules, netbox=netbox,
        organisation=organisation.strip() if organisation else None, audit=audit,
    )


def _parse_audit(raw: Any, problems: list[str]) -> AuditConfig:
    if raw is None:
        return AuditConfig()
    if not isinstance(raw, dict):
        problems.append("audit : objet attendu (referentiels, frequence, periode_jours, conserver)")
        return AuditConfig()
    for k in set(raw) - {"referentiels", "frequence", "periode_jours", "conserver"}:
        problems.append(f"audit.{k} : clé inconnue")
    fws = raw.get("referentiels") or []
    if not isinstance(fws, list):
        problems.append("audit.referentiels : liste attendue")
        fws = []
    for f in fws:
        if f not in AUDIT_FRAMEWORKS:
            problems.append(f"audit.referentiels : '{f}' inconnu (au choix : {', '.join(AUDIT_FRAMEWORKS)})")
    freq = raw.get("frequence", "mensuelle")
    if freq not in AUDIT_FREQUENCIES:
        problems.append(f"audit.frequence : '{freq}' inconnue (au choix : {', '.join(AUDIT_FREQUENCIES)})")
    days = raw.get("periode_jours", AUDIT_FREQUENCIES.get(freq, 30))
    if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= 3660:
        problems.append("audit.periode_jours : entier entre 1 et 3660 attendu")
        days = 30
    keep = raw.get("conserver", 24)
    if not isinstance(keep, int) or isinstance(keep, bool) or keep < 1:
        problems.append("audit.conserver : entier ≥ 1 attendu (exports gardés par référentiel)")
        keep = 24
    return AuditConfig(frameworks=tuple(dict.fromkeys(f for f in fws if f in AUDIT_FRAMEWORKS)),
                       frequency=freq if freq in AUDIT_FREQUENCIES else "mensuelle", period_days=days, keep=keep)


def load_config(path: str | Path) -> Config:
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError([f"{path} : fichier introuvable"])
    except yaml.YAMLError as exc:
        raise ConfigError([f"{path} : YAML invalide ({exc})"])
    return parse_config(raw, base_dir=path.parent)
