"""Raccordement d'un capteur par un code à usage unique.

Sur le central :  auspex capteur inviter capteur-ot --zone OT-N2
Sur le capteur :  rejoindre auspex.ville.fr 7K3Q-M9TD-2HXP-QF8L-ABCD-EFGH-JKMN

Le code (28 caractères, alphabet de Crockford) porte deux choses :

- un **secret** de 60 bits (12 caractères). Le capteur et le central en
  dérivent la même clé SSH d'invitation (scrypt, puis Ed25519). Le central
  autorise cette clé dans la réception, pour une seule commande
  (`auspex-inscrire NOM`) et jusqu'à l'expiration (`expiry-time`, 1 h par
  défaut). Le central ne garde que la clé publique, jamais le secret.
- le **début de l'empreinte du central** (80 bits, 16 caractères). Le capteur
  vérifie la clé d'hôte de la réception avant d'envoyer quoi que ce soit : un
  faux central est refusé, sans confiance au premier contact.

Le capteur envoie alors sa propre clé publique. La réception la dépose, une
seule fois (le code est consommé), dans `reception/inscriptions/NOM.pub`. Au
cycle suivant, le service vérifie l'invitation, enregistre le capteur dans
`state/capteurs.yaml` (lu en plus des capteurs d'auspex.yaml), retire
l'invitation et autorise la vraie clé, cantonnée comme les autres au seul
dépôt de ses logs.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"     # Crockford : ni I, L, O, U
SECRET_CARS = 12                                  # 60 bits
EMPREINTE_CARS = 16                               # 80 bits
SEL = b"auspex-invitation-v1"
INSCRIRE = "/usr/local/bin/auspex-inscrire"      # commande imposée, dans l'image de réception
DUREE_DEFAUT = timedelta(hours=1)
FICHIER_INVITATIONS = "invitations.json"
FICHIER_CAPTEURS = "capteurs.yaml"


class InvitationError(ValueError):
    pass


# --- Code ----------------------------------------------------------------------

def _b32(data: bytes, cars: int) -> str:
    n = int.from_bytes(data, "big")
    bits = len(data) * 8
    n >>= max(0, bits - cars * 5)
    return "".join(ALPHABET[(n >> (5 * (cars - 1 - i))) & 31] for i in range(cars))


def _empreinte_brute(fp: str) -> bytes:
    """« SHA256:… » (OpenSSH) → 32 octets."""
    if not fp.startswith("SHA256:"):
        raise InvitationError(f"empreinte inattendue : {fp}")
    b64 = fp[7:]
    return base64.b64decode(b64 + "=" * (-len(b64) % 4))


def prefixe_empreinte(fp: str) -> str:
    return _b32(_empreinte_brute(fp), EMPREINTE_CARS)


def normaliser(code: str) -> str:
    """Saisie tolérante : minuscules, tirets, espaces, O/I/L confondus avec 0/1."""
    s = "".join(c for c in code.upper() if c not in " -_\t")
    s = s.translate(str.maketrans({"O": "0", "I": "1", "L": "1"}))
    if len(s) != SECRET_CARS + EMPREINTE_CARS or any(c not in ALPHABET for c in s):
        raise InvitationError("code d'invitation invalide (28 caractères attendus)")
    return s


def formater(brut: str) -> str:
    return "-".join(brut[i:i + 4] for i in range(0, len(brut), 4))


def nouveau_code(empreinte_central: str) -> str:
    secret = "".join(secrets.choice(ALPHABET) for _ in range(SECRET_CARS))
    return formater(secret + prefixe_empreinte(empreinte_central))


def graine(code: str) -> bytes:
    """Graine Ed25519 de la clé d'invitation (identique sur le capteur : sensor/rejoindre.py)."""
    secret = normaliser(code)[:SECRET_CARS]
    return hashlib.scrypt(secret.encode(), salt=SEL, n=2 ** 14, r=8, p=1, dklen=32)


def cle_publique_invitation(code: str) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    pub = Ed25519PrivateKey.from_private_bytes(graine(code)).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    blob = b"".join(len(x).to_bytes(4, "big") + x for x in (b"ssh-ed25519", pub))
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


# --- Invitations ---------------------------------------------------------------

@dataclass
class Invitation:
    nom: str
    zone: str
    interface: str
    allow: list[str]
    cle: str              # clé publique d'invitation (jamais le secret)
    expire: datetime

    def ligne(self) -> str:
        """Ligne authorized_keys : une seule commande, jusqu'à l'expiration."""
        opts = ["restrict", f'expiry-time="{self.expire.strftime("%Y%m%d%H%M")}Z"']
        if self.allow:
            opts.append('from="' + ",".join(self.allow) + '"')
        opts.append(f'command="{INSCRIRE} {self.nom}"')
        return f"{','.join(opts)} {self.cle} auspex-invitation:{self.nom}"


def _chemin(state_dir: Path) -> Path:
    return Path(state_dir) / FICHIER_INVITATIONS


def charger(state_dir: Path, maintenant: datetime | None = None) -> list[Invitation]:
    """Invitations encore valables (les expirées sont ignorées)."""
    maintenant = maintenant or datetime.now(timezone.utc)
    try:
        brut = json.loads(_chemin(state_dir).read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return []
    out = []
    for d in brut if isinstance(brut, list) else []:
        try:
            inv = Invitation(d["nom"], d["zone"], d["interface"], list(d.get("allow") or []), d["cle"],
                             datetime.fromisoformat(d["expire"]))
        except (KeyError, TypeError, ValueError):
            continue
        if inv.expire > maintenant:
            out.append(inv)
    return out


def _enregistrer(state_dir: Path, invitations: list[Invitation]) -> None:
    from .state import _atomic_write
    _atomic_write(_chemin(state_dir), [
        {"nom": i.nom, "zone": i.zone, "interface": i.interface, "allow": i.allow, "cle": i.cle,
         "expire": i.expire.isoformat(timespec="seconds")} for i in invitations])


def inviter(cfg, empreinte_central: str, nom: str, zone: str, interface: str,
            allow: list[str], duree: timedelta = DUREE_DEFAUT,
            maintenant: datetime | None = None) -> str:
    """Crée une invitation et renvoie le code (affiché une seule fois)."""
    from .config import SENSOR_NAME
    maintenant = maintenant or datetime.now(timezone.utc)
    if not SENSOR_NAME.match(nom):
        raise InvitationError("nom de capteur : minuscules, chiffres et tirets (il devient le dossier de réception)")
    if zone not in {z.name for z in cfg.zones}:
        raise InvitationError(f"zone '{zone}' inconnue (zones : {', '.join(z.name for z in cfg.zones)})")
    if any(s.name == nom for s in cfg.sensors):
        raise InvitationError(f"un capteur « {nom} » existe déjà (auspex capteur retirer {nom} pour le remplacer)")
    for a in allow:
        import ipaddress
        try:
            if ipaddress.ip_network(a, strict=False).prefixlen == 0:
                raise ValueError
        except ValueError:
            raise InvitationError(f"adresse du capteur invalide : {a}") from None
    code = nouveau_code(empreinte_central)
    autres = [i for i in charger(cfg.state_dir, maintenant) if i.nom != nom]   # une invitation par nom
    autres.append(Invitation(nom, zone, interface, allow, cle_publique_invitation(code), maintenant + duree))
    _enregistrer(cfg.state_dir, autres)
    return code


# --- Capteurs raccordés --------------------------------------------------------

def chemin_capteurs(state_dir: Path) -> Path:
    return Path(state_dir) / FICHIER_CAPTEURS


def capteurs_raccordes(state_dir: Path) -> list[dict]:
    try:
        brut = yaml.safe_load(chemin_capteurs(state_dir).read_text(encoding="utf-8"))
    except (FileNotFoundError, yaml.YAMLError):
        return []
    return [s for s in (brut or {}).get("sensors") or [] if isinstance(s, dict)] if isinstance(brut, dict) else []


def _ecrire_capteurs(state_dir: Path, capteurs: list[dict]) -> None:
    p = chemin_capteurs(state_dir)
    tmp = p.with_suffix(".tmp")
    tmp.write_text("# Capteurs raccordés par code (auspex capteur inviter) : écrit par Auspex.\n"
                   "# Retirer un capteur : auspex capteur retirer NOM\n"
                   + yaml.safe_dump({"sensors": capteurs}, allow_unicode=True, sort_keys=False),
                   encoding="utf-8")
    tmp.replace(p)


def retirer(state_dir: Path, nom: str) -> bool:
    capteurs = capteurs_raccordes(state_dir)
    garder = [s for s in capteurs if s.get("name") != nom]
    invitations = charger(state_dir)
    reste = [i for i in invitations if i.nom != nom]
    if len(garder) == len(capteurs) and len(reste) == len(invitations):
        return False
    _ecrire_capteurs(state_dir, garder)
    _enregistrer(state_dir, reste)
    return True


def traiter_inscriptions(state_dir: Path, dossier: Path,
                         maintenant: datetime | None = None) -> list[tuple[str, str]]:
    """Inscriptions déposées par la réception → capteurs raccordés.

    Renvoie [(nom, résultat)] ; chaque fichier traité est supprimé, accepté ou non."""
    from .reception import SensorKeyError, fingerprint, parse_public_key
    dossier = Path(dossier)
    if not dossier.is_dir():
        return []
    invitations = {i.nom: i for i in charger(state_dir, maintenant)}
    capteurs = capteurs_raccordes(state_dir)
    resultats = []
    for f in sorted(dossier.glob("*.pub")):
        nom = f.stem
        try:
            texte = f.read_text(encoding="utf-8")[:2048].strip()
            f.unlink()
        except OSError:
            continue
        inv = invitations.pop(nom, None)
        if inv is None:
            resultats.append((nom, "refusé : aucune invitation valable"))
            continue
        try:
            cle = parse_public_key(texte)
        except SensorKeyError as exc:
            resultats.append((nom, f"refusé : clé invalide ({exc})"))
            continue
        capteurs = [s for s in capteurs if s.get("name") != nom]
        entree = {"name": nom, "zone": inv.zone, "interface": inv.interface, "key": cle}
        if inv.allow:
            entree["allow"] = inv.allow
        capteurs.append(entree)
        resultats.append((nom, f"raccordé ({fingerprint(cle)})"))
    if resultats:
        _ecrire_capteurs(state_dir, capteurs)
        _enregistrer(state_dir, list(invitations.values()))
    return resultats
