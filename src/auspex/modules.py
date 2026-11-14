"""Modules communautaires.

Un module est un dépôt Git contenant un manifeste `module.yaml` :

    name: auspex-rules-schneider
    version: 0.4.1
    type: rules                  # rules | references
    auspex: ">=0.2,<0.3"         # versions d'Auspex compatibles
    license: Apache-2.0
    description: Identification des automates Schneider Electric

Il est déclaré dans auspex.yaml avec une version épinglée :

    modules:
      - github.com/exemple/auspex-rules-schneider@v0.4.1

Sécurité :
- seuls les modules de DONNÉES sont acceptés dans cette version : un module
  contenant un fichier exécutable (script, binaire...) est refusé ;
- le fichier de verrouillage `auspex.lock` (à versionner avec auspex.yaml)
  retient le commit exact de chaque module : si un tag est déplacé vers un
  autre commit (dépôt compromis), l'installation est refusée ;
- l'empreinte du module installé est vérifiée à chaque chargement : une
  modification sur le disque est détectée.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml

from . import __version__

DATA_TYPES = {"rules", "references"}
FUTURE_TYPES = {"output", "importer", "parser", "widget"}
ALLOWED_SUFFIXES = {".yaml", ".yml", ".md", ".txt", ".csv", ".json"}
ALLOWED_NAMES = {"LICENSE", "NOTICE", "AUTHORS", "CODEOWNERS", ".gitignore", ".gitattributes"}
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")


class ModuleError(Exception):
    pass


# --- Versions -----------------------------------------------------------------

def _vtuple(v: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", v)
    if not parts:
        raise ModuleError(f"version « {v} » illisible")
    return tuple(int(p) for p in parts[:3]) + (0,) * (3 - min(len(parts), 3))


def version_matches(version: str, spec: str) -> bool:
    """« >=0.1,<0.2 » ; opérateurs : >=, >, <=, <, ==, !=."""
    v = _vtuple(version)
    for clause in (c.strip() for c in spec.split(",") if c.strip()):
        m = re.match(r"^(>=|<=|==|!=|>|<)\s*([\d.]+)$", clause)
        if not m:
            raise ModuleError(f"contrainte de version « {clause} » illisible")
        op, target = m.group(1), _vtuple(m.group(2))
        ok = {">=": v >= target, ">": v > target, "<=": v <= target, "<": v < target,
              "==": v == target, "!=": v != target}[op]
        if not ok:
            return False
    return True


# --- Sources ------------------------------------------------------------------

@dataclass(frozen=True)
class Source:
    spec: str     # tel qu'écrit dans auspex.yaml
    url: str      # adresse de clonage
    ref: str      # tag ou branche épinglé

    @property
    def slug(self) -> str:
        return hashlib.sha256(self.spec.encode()).hexdigest()[:12]


def parse_source(spec: str) -> Source:
    if "@" not in spec:
        raise ModuleError(f"« {spec} » : version épinglée attendue (…@v1.2.0)")
    location, ref = spec.rsplit("@", 1)
    if not REF_RE.match(ref) or ".." in ref:
        raise ModuleError(f"« {spec} » : version « {ref} » invalide")
    if location.startswith(("https://", "file://")):
        url = location
    elif re.match(r"^github\.com/[\w.-]+/[\w.-]+$", location):
        url = f"https://{location}"
    else:
        raise ModuleError(f"« {spec} » : source attendue github.com/org/depot, https://… ou file://…")
    return Source(spec, url, ref)


# --- Contenu d'un module -----------------------------------------------------

@dataclass
class Manifest:
    name: str
    version: str
    type: str
    auspex: str
    license: str
    description: str


def read_manifest(root: Path) -> Manifest:
    path = root / "module.yaml"
    if not path.exists():
        raise ModuleError("module.yaml absent à la racine du module")
    try:
        d = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ModuleError(f"module.yaml illisible : {exc}") from exc
    missing = [k for k in ("name", "version", "type", "auspex", "license") if not d.get(k)]
    if missing:
        raise ModuleError(f"module.yaml : champ(s) manquant(s) {', '.join(missing)}")
    if not NAME_RE.match(str(d["name"])):
        raise ModuleError(f"module.yaml : nom « {d['name']} » invalide (minuscules, chiffres, tirets)")
    mtype = str(d["type"])
    if mtype in FUTURE_TYPES:
        raise ModuleError(f"type de module « {mtype} » prévu mais pas encore pris en charge : "
                          f"seuls les modules de données ({', '.join(sorted(DATA_TYPES))}) sont acceptés")
    if mtype not in DATA_TYPES:
        raise ModuleError(f"type de module « {mtype} » inconnu")
    return Manifest(str(d["name"]), str(d["version"]), mtype, str(d["auspex"]),
                    str(d["license"]), str(d.get("description", "")))


def module_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if p.is_file() and ".git" not in p.relative_to(root).parts)


def check_data_only(root: Path) -> None:
    """Refuse tout fichier qui n'est pas une donnée inerte."""
    bad = []
    for p in module_files(root):
        rel = p.relative_to(root)
        if p.is_symlink():
            bad.append(f"{rel} (lien symbolique)")
        elif p.suffix.lower() not in ALLOWED_SUFFIXES and p.name not in ALLOWED_NAMES:
            bad.append(str(rel))
        elif p.stat().st_mode & 0o111:
            bad.append(f"{rel} (exécutable)")
    if bad:
        raise ModuleError("un module de données ne peut contenir que des fichiers YAML, JSON, CSV ou "
                          f"texte ; refusé : {', '.join(bad[:5])}")


def tree_digest(root: Path) -> str:
    h = hashlib.sha256()
    for p in module_files(root):
        h.update(str(p.relative_to(root)).encode() + b"\0")
        h.update(hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest()


def validate_content(root: Path, manifest: Manifest) -> None:
    if manifest.type == "rules":
        from .fingerprint.engine import RuleError, load_normalizer, load_oui, load_rules
        rules_dir = root / "rules"
        if not rules_dir.is_dir():
            raise ModuleError("module de règles : répertoire rules/ absent")
        try:
            load_rules([rules_dir])
            if (rules_dir / "oui.yaml").exists():
                load_oui(rules_dir / "oui.yaml")
            if (rules_dir / "aliases.yaml").exists():
                load_normalizer(rules_dir / "aliases.yaml")
        except (RuleError, yaml.YAMLError, KeyError, TypeError, ValueError) as exc:
            raise ModuleError(f"règles invalides : {exc}") from exc
    elif manifest.type == "references":
        load_references(root)


def load_references(root: Path) -> dict[str, list[str]]:
    from .compliance import TITLES
    path = root / "references.yaml"
    if not path.exists():
        raise ModuleError("module de références : references.yaml absent")
    d = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    refs = d.get("references") or {}
    if not isinstance(refs, dict):
        raise ModuleError("references.yaml : dictionnaire « references » attendu")
    unknown = set(refs) - set(TITLES)
    if unknown:
        raise ModuleError(f"references.yaml : type(s) d'écart inconnu(s) {sorted(unknown)}")
    return {k: [str(x) for x in v] for k, v in refs.items()}


# --- Installation ------------------------------------------------------------

class ModuleManager:
    def __init__(self, base_dir: Path, state_dir: Path):
        self.lock_path = Path(base_dir) / "auspex.lock"
        self.root = Path(state_dir) / "modules"

    def lock(self) -> dict:
        if not self.lock_path.exists():
            return {}
        return json.loads(self.lock_path.read_text(encoding="utf-8")).get("modules", {})

    def save_lock(self, entries: dict) -> None:
        payload = {"comment": "Généré par auspex : à versionner avec auspex.yaml.", "modules": entries}
        tmp = self.lock_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(self.lock_path)

    def installed(self) -> dict[str, Path]:
        if not self.root.exists():
            return {}
        return {p.name: p for p in self.root.iterdir() if p.is_dir()}

    def plan(self, specs: list[str]) -> dict:
        sources = [parse_source(s) for s in specs]
        lock, inst = self.lock(), self.installed()
        wanted = {s.slug for s in sources}
        to_install = [s for s in sources if s.spec not in lock or s.slug not in inst]
        to_remove = [name for name in inst if name not in wanted]
        return {"install": to_install, "remove": to_remove, "unchanged": len(sources) - len(to_install)}

    def _fetch(self, src: Source, dest: Path) -> str:
        cmd = ["git", "-c", "advice.detachedHead=false", "clone", "--quiet", "--depth", "1",
               "--branch", src.ref, src.url, str(dest)]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if r.returncode:
            raise ModuleError(f"{src.spec} : téléchargement impossible ({r.stderr.strip()[:300]})")
        return subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True,
                              text=True, check=True).stdout.strip()

    def install(self, src: Source) -> dict:
        lock = self.lock()
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "m"
            commit = self._fetch(src, work)
            known = lock.get(src.spec)
            if known and known["commit"] != commit:
                raise ModuleError(
                    f"{src.spec} : le tag {src.ref} pointe désormais vers le commit {commit[:12]} au lieu "
                    f"de {known['commit'][:12]}. Possible compromission du dépôt : installation refusée. "
                    f"Pour accepter ce changement après vérification, retirer l'entrée de auspex.lock.")
            shutil.rmtree(work / ".git", ignore_errors=True)
            manifest = read_manifest(work)
            check_data_only(work)
            if not version_matches(__version__, manifest.auspex):
                raise ModuleError(f"{src.spec} : compatible avec Auspex {manifest.auspex}, "
                                  f"version installée {__version__}")
            validate_content(work, manifest)
            digest = tree_digest(work)
            self.root.mkdir(parents=True, exist_ok=True)
            target = self.root / src.slug
            staging = self.root / f".{src.slug}.new"
            shutil.rmtree(staging, ignore_errors=True)
            shutil.copytree(work, staging)
            shutil.rmtree(target, ignore_errors=True)
            staging.rename(target)
        entry = {"name": manifest.name, "version": manifest.version, "type": manifest.type,
                 "commit": commit, "sha256": digest, "dir": src.slug}
        lock[src.spec] = entry
        self.save_lock(lock)
        return entry

    def remove(self, slug: str) -> None:
        shutil.rmtree(self.root / slug, ignore_errors=True)
        lock = {k: v for k, v in self.lock().items() if v.get("dir") != slug}
        self.save_lock(lock)

    def verified(self, specs: list[str]) -> list[tuple[Manifest, Path]]:
        """Modules déclarés, installés et intacts. Lève une erreur sinon."""
        lock, out = self.lock(), []
        for spec in specs:
            src = parse_source(spec)
            entry = lock.get(spec)
            path = self.root / src.slug
            if not entry or not path.is_dir():
                raise ModuleError(f"{spec} : module déclaré mais non installé (lancer « auspex apply »)")
            if tree_digest(path) != entry["sha256"]:
                raise ModuleError(f"{spec} : le module installé a été modifié sur le disque "
                                  f"(empreinte invalide). Le réinstaller avec « auspex apply ».")
            out.append((read_manifest(path), path))
        return out
