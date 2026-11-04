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
