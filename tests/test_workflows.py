"""Hygiène des workflows GitHub et des images (exigences OpenSSF Scorecard, issue #4).

- toutes les actions épinglées sur un commit (pas de tag mobile) ;
- images de base des Dockerfile et images lancées par les workflows figées par empreinte ;
- permissions en lecture seule au niveau du workflow, écriture au seul job qui en a besoin ;
- Dependabot couvre chaque écosystème figé.
"""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
DOCKERFILES = sorted(p for p in ROOT.rglob("Dockerfile") if ".venv" not in p.parts and "build" not in p.parts)


def _ids(p):
    return str(p.relative_to(ROOT))


@pytest.mark.parametrize("wf", WORKFLOWS, ids=_ids)
def test_actions_pinned_to_commit(wf):
    for line in wf.read_text(encoding="utf-8").splitlines():
        m = re.search(r"uses: (\S+)", line)
        if not m or m.group(1).startswith("./"):
            continue
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", m.group(1)), line.strip()
        assert re.search(r"# v\d+(\.\d+)*$", line), f"version lisible attendue en commentaire : {line.strip()}"


@pytest.mark.parametrize("wf", WORKFLOWS, ids=_ids)
def test_read_only_by_default(wf):
    """Aucune permission d'écriture au niveau du workflow (Token-Permissions)."""
    perms = yaml.safe_load(wf.read_text(encoding="utf-8")).get("permissions")
    assert perms is not None, "bloc permissions attendu au niveau du workflow"
    if isinstance(perms, str):
        assert perms == "read-all"
    else:
        assert all(v in ("read", "none") for v in perms.values()), perms


@pytest.mark.parametrize("wf", WORKFLOWS, ids=_ids)
def test_docker_run_images_pinned(wf):
    for line in wf.read_text(encoding="utf-8").splitlines():
        m = re.search(r"docker run .*?\b(debian|ubuntu|alpine|python):[\w.-]+(\S*)", line)
        if m:
            assert m.group(2).startswith("@sha256:"), line.strip()


@pytest.mark.parametrize("wf", WORKFLOWS, ids=_ids)
def test_service_images_pinned(wf):
    """Conteneurs de service et conteneurs de job des workflows figés par empreinte."""
    for name, job in yaml.safe_load(wf.read_text(encoding="utf-8"))["jobs"].items():
        images = [s.get("image") for s in (job.get("services") or {}).values()]
        c = job.get("container")
        images.append(c.get("image") if isinstance(c, dict) else c)
        for image in filter(None, images):
            assert re.search(r"@sha256:[0-9a-f]{64}$", image), f"{name} : {image}"


@pytest.mark.parametrize("wf", WORKFLOWS, ids=_ids)
def test_no_untrusted_expression_in_scripts(wf):
    """Injection de workflow : ni données d'événement, ni saisies, ni secrets insérés
    directement dans un script « run » ; passer par une variable d'environnement."""
    for name, job in yaml.safe_load(wf.read_text(encoding="utf-8"))["jobs"].items():
        for s in job.get("steps", []):
            for expr in re.findall(r"\$\{\{\s*([^}]+?)\s*\}\}", s.get("run", "")):
                assert not expr.startswith(("github.event", "inputs.", "secrets.", "github.head_ref")), \
                    f"{name} / {s.get('name')} : {expr}"


@pytest.mark.parametrize("wf", WORKFLOWS, ids=_ids)
def test_write_jobs_keep_no_token_on_disk(wf):
    """Un job qui peut écrire dans le dépôt ne laisse pas son jeton sur le disque
    (actions/checkout, persist-credentials: false)."""
    for name, job in yaml.safe_load(wf.read_text(encoding="utf-8"))["jobs"].items():
        perms = job.get("permissions") or {}
        if not isinstance(perms, dict) or perms.get("contents") != "write":
            continue
        for s in job.get("steps", []):
            if s.get("uses", "").startswith("actions/checkout@"):
                assert (s.get("with") or {}).get("persist-credentials") is False, name


@pytest.mark.parametrize("df", DOCKERFILES, ids=_ids)
def test_dockerfile_base_pinned(df):
    for line in df.read_text(encoding="utf-8").splitlines():
        if not line.startswith("FROM "):
            continue
        image = line.split()[1]
        if "${" in image:          # version choisie au déploiement (NetBox) : tenue à jour par Dependabot
            continue
        assert re.search(r"@sha256:[0-9a-f]{64}$", image), line


def test_dependabot_covers_pinned_ecosystems():
    cfg = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    eco = {u["package-ecosystem"]: u for u in cfg["updates"]}
    assert {"github-actions", "docker", "pip"} <= set(eco)
    dirs = set(eco["docker"]["directories"])
    assert {"/" + str(df.parent.relative_to(ROOT)) for df in DOCKERFILES} <= dirs


def test_scorecard_workflow_publishable():
    """Contraintes de publication de Scorecard : aucune écriture ni variable au niveau du
    workflow, id-token réservé au job Scorecard, actions approuvées seulement."""
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "scorecard.yml").read_text(encoding="utf-8"))
    assert wf["permissions"] == "read-all" and "env" not in wf and "defaults" not in wf
    [(name, job)] = wf["jobs"].items()
    assert "env" not in job and "defaults" not in job and "container" not in job and "services" not in job
    assert job["runs-on"].startswith("ubuntu-")
    approved = ("actions/checkout@", "actions/upload-artifact@", "github/codeql-action/upload-sarif@",
                "ossf/scorecard-action@", "step-security/harden-runner@")
    for s in job["steps"]:
        assert "uses" in s and s["uses"].startswith(approved), s
    scorecard = next(s for s in job["steps"] if s["uses"].startswith("ossf/scorecard-action@"))
    assert scorecard["with"]["publish_results"] is True
    assert scorecard["with"]["fail_on_publish_error"] is True


REQ = ROOT / "requirements"
LOCKS = sorted(REQ.glob("*.txt"))


def _pip_installs():
    files = WORKFLOWS + DOCKERFILES
    for f in files:
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            for cmd in re.findall(r"pip install[^&;|\n]*", line):
                yield f, n, cmd


def test_every_pip_install_is_pinned():
    """Pinned-Dependencies : chaque « pip install » vient d'un fichier figé vérifié par
    empreinte (--require-hashes -r requirements/…), ou installe le projet lui-même
    sans aller chercher de dépendance (--no-deps)."""
    seen = 0
    for f, n, cmd in _pip_installs():
        seen += 1
        ok = re.search(r"--require-hashes -r requirements/[a-z]+\.txt\s*$", cmd.strip()) or \
            re.search(r"--no-deps( -e)? \.\s*$", cmd.strip())
        assert ok, f"{_ids(f)}:{n} : {cmd}"
        if "-r requirements/" in cmd:
            assert (ROOT / re.search(r"requirements/[a-z]+\.txt", cmd).group(0)).exists(), cmd
    assert seen >= 10


@pytest.mark.parametrize("lock", LOCKS, ids=_ids)
def test_lock_files_fully_hashed(lock):
    """Chaque paquet figé : version exacte et au moins une empreinte SHA-256 ;
    fichier régénéré par tools/figer-dependances.sh (en-tête)."""
    text = lock.read_text(encoding="utf-8")
    assert "#    tools/figer-dependances.sh" in text
    entries = re.split(r"\n(?=[a-z0-9])", text.split("\n\n", 1)[-1] if text.startswith("#") else text)
    pkgs = [e for e in entries if re.match(r"[a-z0-9]", e)]
    assert pkgs
    for e in pkgs:
        head = e.splitlines()[0]
        assert re.match(r"^[a-z0-9_.-]+==[\w.+-]+( ;.*)? \\$", head), head
        assert re.search(r"--hash=sha256:[0-9a-f]{64}", e), head


def test_central_image_uses_locked_dependencies():
    df = (ROOT / "deploy" / "central" / "Dockerfile").read_text(encoding="utf-8")
    assert "--require-hashes -r requirements/execution.txt" in df
    assert "pip install --no-cache-dir --no-deps ." in df
    lock = (REQ / "execution.txt").read_text(encoding="utf-8")
    try:
        import tomllib
    except ImportError:          # Python 3.10
        import tomli as tomllib
    deps = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["dependencies"]
    for d in deps:   # chaque dépendance déclarée du produit est figée
        name = re.match(r"[A-Za-z0-9_.-]+", d).group(0).lower().replace("_", "-")
        assert re.search(rf"^{re.escape(name)}==", lock, re.M), name


def test_dependabot_watches_lock_files():
    cfg = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    pip = next(u for u in cfg["updates"] if u["package-ecosystem"] == "pip")
    assert "/requirements" in pip["directories"]
