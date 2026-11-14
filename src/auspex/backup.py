"""Sauvegarde et restauration de l'état d'Auspex.

L'archive (tar.gz) contient :
- state/   : flux agrégés, inventaire, alertes, règles importées, modules ;
- config/  : auspex.yaml, auspex.lock et le fichier de règles de flux ;
- manifest.json : version, date, empreinte SHA-256 de chaque fichier.

La base de NetBox n'en fait pas partie : elle est sauvegardée par la
procédure de mise à jour du central (pg_dump).

La restauration vérifie chaque empreinte, refuse les chemins dangereux
(absolus, « .. », liens) et remplace l'état de façon atomique.
"""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import tarfile
import tempfile
import zlib
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from . import __version__
from .config import Config

FORMAT = 1
SKIP = {"outbox", "test-outbox"}  # files d'envoi transitoires


class BackupError(Exception):
    pass


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _config_files(cfg: Config) -> list[tuple[Path, str]]:
    files = []
    for name in ("auspex.yaml", "auspex.lock"):
        p = cfg.base_dir / name
        if p.exists():
            files.append((p, f"config/{name}"))
    if cfg.flow_rules_file and cfg.flow_rules_file.exists():
        files.append((cfg.flow_rules_file, f"config/{cfg.flow_rules_file.name}"))
    return files


def create_backup(cfg: Config, dest: Path | None = None, now: datetime | None = None) -> Path:
    now = now or datetime.now(timezone.utc)
    if dest is None:
        dest = cfg.state_dir.parent / "backups" / f"auspex-{now:%Y%m%d-%H%M%S}.tar.gz"
    dest.parent.mkdir(parents=True, exist_ok=True)
    entries: list[tuple[Path, str]] = []
    if cfg.state_dir.exists():
        for p in sorted(cfg.state_dir.rglob("*")):
            rel = p.relative_to(cfg.state_dir)
            if p.is_file() and not p.is_symlink() and not (set(rel.parts) & SKIP) and not p.name.endswith(".tmp"):
                entries.append((p, f"state/{rel.as_posix()}"))
    entries += _config_files(cfg)
    manifest = {
        "format": FORMAT, "auspex_version": __version__, "created_at": now.isoformat(),
        "files": {arc: {"sha256": _sha(p), "size": p.stat().st_size} for p, arc in entries},
    }
    tmp = dest.with_suffix(".partial")
    with tarfile.open(tmp, "w:gz") as tar:
        data = json.dumps(manifest, ensure_ascii=False, indent=1).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size, info.mtime = len(data), int(now.timestamp())
        tar.addfile(info, io.BytesIO(data))
        for p, arc in entries:
            tar.add(p, arcname=arc, recursive=False)
    tmp.replace(dest)
    return dest


def _safe_member(m: tarfile.TarInfo) -> None:
    path = PurePosixPath(m.name)
    if path.is_absolute() or ".." in path.parts or not m.name:
        raise BackupError(f"archive refusée : chemin dangereux « {m.name} »")
    if not (m.isfile() or m.isdir()):
        raise BackupError(f"archive refusée : « {m.name} » n'est pas un fichier ordinaire")
    if path.parts[0] not in {"state", "config", "manifest.json"}:
        raise BackupError(f"archive refusée : entrée inattendue « {m.name} »")


def _check_manifest(manifest) -> None:
    if not isinstance(manifest, dict):
        raise BackupError("archive refusée : manifeste illisible")
    if manifest.get("format") != FORMAT:
        raise BackupError(f"format d'archive {str(manifest.get('format'))[:20]} non pris en charge")
    files = manifest.get("files")
    if not isinstance(files, dict) or not all(
            isinstance(meta, dict) and isinstance(meta.get("sha256"), str) for meta in files.values()):
        raise BackupError("archive refusée : liste des fichiers du manifeste illisible")


def inspect_backup(archive: Path) -> dict:
    """Vérifie l'archive sans rien écrire ; renvoie son manifeste.

    Toute archive abîmée, tronquée ou forgée est refusée par une BackupError."""
    try:
        with tarfile.open(archive, "r:gz") as tar:
            members = tar.getmembers()
            for m in members:
                _safe_member(m)
            try:
                mf = tar.extractfile("manifest.json")
            except KeyError:
                mf = None
            if mf is None:
                raise BackupError("archive refusée : manifest.json absent")
            manifest = json.loads(mf.read())
            _check_manifest(manifest)
            files = {m.name: m for m in members if m.isfile() and m.name != "manifest.json"}
            if set(files) != set(manifest["files"]):
                raise BackupError("archive refusée : contenu différent du manifeste")
            for name, meta in manifest["files"].items():
                data = tar.extractfile(files[name]).read()
                if hashlib.sha256(data).hexdigest() != meta["sha256"]:
                    raise BackupError(f"archive refusée : empreinte invalide pour « {name} »")
    except (tarfile.TarError, EOFError, OSError, zlib.error, ValueError, RecursionError) as exc:
        raise BackupError(f"archive illisible ou abîmée : {str(exc)[:200]}") from exc
    return manifest


def restore_backup(cfg: Config, archive: Path, force: bool = False, with_config: bool = False) -> dict:
    manifest = inspect_backup(archive)
    if cfg.state_dir.exists() and any(cfg.state_dir.iterdir()) and not force:
        raise BackupError(f"{cfg.state_dir} n'est pas vide : utiliser --force pour le remplacer "
                          "(l'état actuel est d'abord sauvegardé)")
    previous = None
    if cfg.state_dir.exists() and any(cfg.state_dir.iterdir()):
        previous = create_backup(cfg, cfg.state_dir.parent / "backups" /
                                 f"avant-restauration-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.tar.gz")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        with tarfile.open(archive, "r:gz") as tar:
            for m in tar.getmembers():
                _safe_member(m)
                if m.isfile() and m.name != "manifest.json":
                    target = work / m.name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(m) as src, open(target, "wb") as dst:
                        shutil.copyfileobj(src, dst)
        # Le répertoire d'état peut être un volume Docker (point de montage) :
        # on remplace son contenu, pas le répertoire lui-même.
        cfg.state_dir.mkdir(parents=True, exist_ok=True)
        for child in cfg.state_dir.iterdir():
            shutil.rmtree(child) if child.is_dir() and not child.is_symlink() else child.unlink()
        new_state = work / "state"
        if new_state.exists():
            for child in new_state.iterdir():
                shutil.move(str(child), str(cfg.state_dir / child.name))
        if with_config and (work / "config").exists():
            for p in (work / "config").iterdir():
                same_rules = cfg.flow_rules_file and p.name == cfg.flow_rules_file.name
                shutil.copy2(p, cfg.flow_rules_file if same_rules else cfg.base_dir / p.name)
    return {"manifest": manifest, "previous": previous}
