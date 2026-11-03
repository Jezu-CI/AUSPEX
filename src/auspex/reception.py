"""Réception des logs envoyés par les capteurs (SSH + rsync, écriture seule).

Chaque capteur déclaré avec une clé dans auspex.yaml (sensors[].key) peut
déposer ses logs Zeek, et seulement eux :

- une clé par capteur ; connexion limitée aux adresses déclarées (allow) ;
- commande imposée : rsync en écriture seule, sans suppression, cantonné au
  dossier du capteur (logs/<nom>/) ; ni shell, ni redirection de ports, ni
  lecture des dossiers des autres capteurs ;
- le service de réception tourne sans privilèges, système en lecture seule.

Le capteur, lui, vérifie l'empreinte du central avant d'envoyer quoi que ce
soit (un faux central ne reçoit rien).

Ce module produit le fichier des clés autorisées, lu à chaque connexion par
le service de réception : ajouter ou retirer un capteur dans auspex.yaml
prend effet au cycle suivant, sans redémarrage.
"""

from __future__ import annotations

import base64
import hashlib
import os
import struct
from datetime import datetime, timezone
from pathlib import Path

AUTHORIZED = "authorized_keys"
RECEIVER = "/usr/local/bin/auspex-recevoir"     # commande imposée, dans l'image de réception
HOST_KEY_PUB = "ssh_host_ed25519_key.pub"
KEY_TYPE = "ssh-ed25519"


class SensorKeyError(ValueError):
    """Clé publique de capteur refusée."""


def _read_string(blob: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(blob):
        raise SensorKeyError("clé tronquée")
    (n,) = struct.unpack(">I", blob[offset:offset + 4])
    end = offset + 4 + n
    if end > len(blob):
        raise SensorKeyError("clé tronquée")
    return blob[offset + 4:end], end


def parse_public_key(value) -> str:
    """Valide une clé publique OpenSSH Ed25519 ; renvoie « ssh-ed25519 BASE64 ».

    Tout ce qui pourrait modifier le fichier des clés autorisées (options en
    tête, saut de ligne, guillemets) est refusé : seule la forme
    « ssh-ed25519 AAAA… [commentaire] » est acceptée, et le commentaire n'est
    pas recopié.
    """
    if not isinstance(value, str):
        raise SensorKeyError("texte attendu : « ssh-ed25519 AAAA… » (affiché par le capteur)")
    if any(c in value for c in "\r\n\0"):
        raise SensorKeyError("une seule ligne attendue")
    parts = value.strip().split()
    if len(parts) < 2:
        raise SensorKeyError("forme « ssh-ed25519 AAAA… » attendue")
    if parts[0] != KEY_TYPE:
        raise SensorKeyError(f"type « {parts[0][:20]} » refusé : seules les clés {KEY_TYPE} sont acceptées "
                        "(options et autres types interdits)")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise SensorKeyError("clé illisible (base64)") from exc
    kind, off = _read_string(blob, 0)
    key, off = _read_string(blob, off)
    if kind != KEY_TYPE.encode() or len(key) != 32 or off != len(blob):
        raise SensorKeyError("clé Ed25519 invalide")
    return f"{KEY_TYPE} {parts[1]}"


def fingerprint(public_key: str) -> str:
    """Empreinte au format d'OpenSSH (« SHA256:… »), comme l'affiche ssh-keygen -l."""
    blob = base64.b64decode(public_key.split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def authorized_line(sensor) -> str:
    opts = ["restrict"]
    if sensor.allow:
        opts.append('from="' + ",".join(str(n) for n in sensor.allow) + '"')
    opts.append(f'command="{RECEIVER} {sensor.name}"')
    return f"{','.join(opts)} {sensor.key} auspex:{sensor.name}"


def render_authorized_keys(sensors) -> str:
    lines = ["# Généré par Auspex à partir de auspex.yaml (sensors[].key) : ne pas modifier à la main."]
    lines += [authorized_line(s) for s in sensors if s.key]
    return "\n".join(lines) + "\n"


def authorized_path(state_dir: Path) -> Path:
    return Path(state_dir) / "reception" / AUTHORIZED


def write_authorized_keys(state_dir: Path, sensors) -> bool:
    """Écrit le fichier s'il a changé ; renvoie True en cas de changement."""
    path = authorized_path(state_dir)
    content = render_authorized_keys(sensors)
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)
    return True


def current_lines(state_dir: Path) -> dict[str, str]:
    """Capteurs actuellement autorisés (nom → ligne du fichier écrit)."""
    path = authorized_path(state_dir)
    out = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        tail = line.rsplit(" ", 1)[-1]
        if tail.startswith("auspex:"):
            out[tail[7:]] = line
    return out


def host_key_fingerprint(reception_dir: Path) -> str | None:
    path = Path(reception_dir) / HOST_KEY_PUB
    try:
        return fingerprint(parse_public_key(path.read_text(encoding="utf-8").strip()))
    except (OSError, SensorKeyError):
        return None


def sensor_activity(logs_dir: Path, name: str, now: datetime | None = None) -> dict:
    """Dernier dépôt d'un capteur : nombre de fichiers, date du plus récent."""
    folder = Path(logs_dir) / name
    files = [p for p in folder.rglob("*") if p.is_file()] if folder.is_dir() else []
    last = max((p.stat().st_mtime for p in files), default=None)
    last_dt = datetime.fromtimestamp(last, timezone.utc) if last else None
    now = now or datetime.now(timezone.utc)
    return {"files": len(files), "last": last_dt,
            "minutes": round((now - last_dt).total_seconds() / 60) if last_dt else None}
