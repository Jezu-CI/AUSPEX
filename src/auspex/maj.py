"""Mises à jour signées de l'analyse des capteurs (côté central).

Le central signe (Ed25519, clé de mises à jour de l'organisation, distincte
de la clé des audits) un manifeste décrivant l'image d'analyse (squashfs
produit par appliance/build.sh) et la publie dans data/mises-a-jour/courant/,
que les capteurs lisent par la réception (SSH, lecture seule, même clé que
l'envoi des logs).

Côté capteur (appliance/…/maj.sh) : signature vérifiée avec MAJ_CLE, version
plus récente exigée (pas de retour en arrière imposé), empreinte de l'image,
installation dans l'emplacement libre, essai, retour automatique en cas
d'échec.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from . import audit

FORMAT = "auspex-maj-capteur/1"
KEY_FILE = "maj-capteurs-ed25519.pem"
PUBLISH_DIR = "mises-a-jour"          # sous data/ : monté en lecture seule par la réception
CURRENT, PREVIOUS = "courant", "precedent"
MANIFEST, SIGNATURE, IMAGE = "manifeste", "manifeste.sig", "image.squashfs"
MAX_IMAGE = 2 * 1024 ** 3
VERSION_RE = re.compile(r"[0-9]{1,6}(\.[0-9]{1,6}){1,4}")
NAME_RE = re.compile(r"auspex-capteur-(?P<version>[0-9.]+)\.squashfs")
SQUASHFS_MAGIC = b"hsqs"
STATUS_FILE = "auspex-etat.json"


class MajError(ValueError):
    pass


def publish_root(state_dir: Path) -> Path:
    return Path(state_dir).parent / PUBLISH_DIR


def key(state_dir: Path):
    return audit.load_or_create_key(state_dir, KEY_FILE)


def public_value(private_key) -> str:
    """Valeur de MAJ_CLE pour capteur.conf : SubjectPublicKeyInfo DER en base64."""
    from cryptography.hazmat.primitives import serialization
    der = private_key.public_key().public_bytes(serialization.Encoding.DER,
                                                serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


def fingerprint(private_key) -> str:
    return audit.fingerprint(audit.public_pem(private_key))


def version_key(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def render_manifest(version: str, sha256: str, size: int, published: datetime | None = None) -> bytes:
    published = (published or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return (f"format={FORMAT}\nversion={version}\nsha256={sha256}\ntaille={size}\n"
            f"publie_le={published}\n").encode()


def parse_manifest(data: bytes) -> dict[str, str]:
    out = {}
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise MajError("manifeste mal formé (caractères non ASCII)") from None
    for line in text.splitlines():
        m = re.fullmatch(r"([a-z0-9_]+)=([A-Za-z0-9.:/_+-]{1,128})", line)
        if not m:
            raise MajError("manifeste mal formé")
        out[m.group(1)] = m.group(2)
    if out.get("format") != FORMAT or not VERSION_RE.fullmatch(out.get("version", "")):
        raise MajError("manifeste : format ou version invalide")
    return out


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def image_version(path: Path, version: str | None = None) -> str:
    """Version de l'image : donnée, sinon tirée du nom (auspex-capteur-<version>.squashfs)."""
    if version is None:
        m = NAME_RE.fullmatch(Path(path).name)
        if not m:
            raise MajError("version introuvable : nommer l'image auspex-capteur-<version>.squashfs "
                           "ou préciser --version")
        version = m.group("version")
    if not VERSION_RE.fullmatch(version):
        raise MajError(f"version « {version} » invalide (chiffres et points, ex. 0.9.1)")
    return version


def current(state_dir: Path) -> dict | None:
    """Publication en cours, signature vérifiée avec la clé du central."""
    folder = publish_root(state_dir) / CURRENT
    try:
        data = (folder / MANIFEST).read_bytes()
        sig = (folder / SIGNATURE).read_bytes()
    except OSError:
        return None
    try:
        key(state_dir).public_key().verify(sig, data)
    except Exception:
        return {"valide": False, "raison": "signature invalide (manifeste modifié ou clé changée)"}
    try:
        info = parse_manifest(data)
    except (MajError, UnicodeDecodeError) as exc:
        return {"valide": False, "raison": str(exc)}
    return {"valide": True, **info}


def publish(state_dir: Path, image: Path, version: str | None = None, force: bool = False,
            now: datetime | None = None) -> dict:
    """Signe et publie une image d'analyse ; l'ancienne publication devient « precedent »."""
    image = Path(image)
    version = image_version(image, version)
    if not image.is_file() or image.is_symlink():
        raise MajError(f"{image} : fichier introuvable")
    size = image.stat().st_size
    if not 0 < size <= MAX_IMAGE:
        raise MajError(f"{image} : taille {size} octets hors limites (2 Gio au plus)")
    with open(image, "rb") as fh:
        if fh.read(4) != SQUASHFS_MAGIC:
            raise MajError(f"{image} : pas une image squashfs (appliance/build.sh la produit)")
    cur = current(state_dir)
    if cur and cur.get("valide") and not force and version_key(version) <= version_key(cur["version"]):
        raise MajError(f"version {version} pas plus récente que la publication en cours ({cur['version']}) ; "
                       "les capteurs ne reviennent jamais en arrière (--force pour republier quand même)")
    root = publish_root(state_dir)
    staging = root / f".{CURRENT}.nouveau"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    os.chmod(root, 0o755)
    os.chmod(staging, 0o755)
    shutil.copyfile(image, staging / IMAGE)
    digest = _sha256(staging / IMAGE)          # empreinte de la copie publiée, pas de l'original
    if (staging / IMAGE).stat().st_size != size:
        raise MajError("copie de l'image incomplète")
    manifest = render_manifest(version, digest, size, now)
    (staging / MANIFEST).write_bytes(manifest)
    (staging / SIGNATURE).write_bytes(key(state_dir).sign(manifest))
    for name in (IMAGE, MANIFEST, SIGNATURE):
        os.chmod(staging / name, 0o644)
    cur_dir, prev_dir = root / CURRENT, root / PREVIOUS
    if cur_dir.exists():
        shutil.rmtree(prev_dir, ignore_errors=True)
        os.replace(cur_dir, prev_dir)
    os.replace(staging, cur_dir)
    return {"version": version, "sha256": digest, "taille": size}


def sensor_status(logs_dir: Path, name: str) -> dict | None:
    """État déposé par le capteur avec ses logs (version d'analyse, dernière mise à jour)."""
    path = Path(logs_dir) / name / STATUS_FILE
    try:
        if path.stat().st_size > 4096:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return {k: str(data.get(k, ""))[:120] for k in ("analyse", "emplacement", "systeme", "maj", "detail", "date")}
