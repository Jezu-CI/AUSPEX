"""Vérification d'une version (tools/verifier-version.sh) et sa mise en œuvre dans la publication.

La vraie signature Sigstore n'est possible que dans GitHub Actions (identité
OIDC) : elle est éprouvée par le workflow de publication lui-même, contre-épreuves
comprises. Ici : logique du script (cosign simulé), identité acceptée, cohérence
entre script, site et workflow.
"""
import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "verifier-version.sh"
WF = ROOT / ".github" / "workflows" / "version.yml"


def _identity_regex() -> str:
    text = SCRIPT.read_text(encoding="utf-8")
    m = re.search(r'^IDENTITE="(.*)"$', text, re.M)
    pattern = m.group(1).replace("${DEPOT//./\\\\.}", "Jezu-CI/AUSPEX")
    return pattern


@pytest.mark.parametrize("identity, ok", [
    ("https://github.com/Jezu-CI/AUSPEX/.github/workflows/version.yml@refs/heads/main", True),
    ("https://github.com/Jezu-CI/AUSPEX/.github/workflows/version.yml@refs/tags/v0.2.0", True),
    ("https://github.com/Jezu-CI/AUSPEX/.github/workflows/version.yml@refs/heads/essai", False),
    ("https://github.com/Jezu-CI/AUSPEX/.github/workflows/ci.yml@refs/heads/main", False),
    ("https://github.com/pirate/AUSPEX/.github/workflows/version.yml@refs/heads/main", False),
    ("https://github.com/Jezu-CI/AUSPEXX/.github/workflows/version.yml@refs/heads/main", False),
    ("https://github.com/Jezu-CI/AUSPEX/.github/workflows/version.yml@refs/tags/v0.2.0-pirate", False),
    ("https://github.com/Jezu-CI/AUSPEX/.github/workflowsXversion.yml@refs/heads/main", False),
])
def test_identity(identity, ok):
    assert bool(re.search(_identity_regex(), identity)) is ok


def test_identity_documented_on_site():
    page = (ROOT / "site" / "telecharger.md").read_text(encoding="utf-8")
    assert f"--certificate-identity-regexp '{_identity_regex()}'" in page
    assert "--certificate-oidc-issuer https://token.actions.githubusercontent.com" in page


@pytest.fixture
def release(tmp_path):
    """Dossier de version factice et faux cosign (accepte si COSIGN_OK=1)."""
    d = tmp_path / "version"
    d.mkdir()
    (d / "auspex-sbom.cdx.json").write_text("{}\n")
    (d / "auspex-capteur-9.9.9.iso").write_bytes(b"iso")
    sums = "".join(f"{hashlib.sha256((d / n).read_bytes()).hexdigest()}  {n}\n"
                   for n in ("auspex-capteur-9.9.9.iso", "auspex-sbom.cdx.json"))
    (d / "SHA256SUMS").write_text(sums)
    (d / "SHA256SUMS.sigstore.json").write_text("{}")
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    cosign = bin_ / "cosign"
    cosign.write_text('#!/bin/sh\necho "$@" > "$(dirname "$0")/args"\n[ "$COSIGN_OK" = 1 ]\n')
    cosign.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}", "COSIGN_OK": "1"}
    return d, env, bin_


def _run(d, env):
    return subprocess.run(["bash", str(SCRIPT), str(d)], env=env, capture_output=True, text=True)


def test_valid_release(release):
    d, env, bin_ = release
    r = _run(d, env)
    assert r.returncode == 0, r.stderr
    args = (bin_ / "args").read_text()
    assert "verify-blob --bundle SHA256SUMS.sigstore.json" in args
    assert "--certificate-oidc-issuer https://token.actions.githubusercontent.com" in args


def test_missing_files_ignored_but_one_required(release):
    d, env, _ = release
    (d / "auspex-capteur-9.9.9.iso").unlink()
    assert _run(d, env).returncode == 0
    (d / "auspex-sbom.cdx.json").unlink()
    assert _run(d, env).returncode == 1  # aucun fichier vérifié


def test_bad_signature_refused(release):
    d, env, _ = release
    r = _run(d, {**env, "COSIGN_OK": "0"})
    assert r.returncode == 1 and "signature" in r.stderr


def test_altered_file_refused(release):
    d, env, _ = release
    with open(d / "auspex-sbom.cdx.json", "a") as f:
        f.write(" ")
    r = _run(d, env)
    assert r.returncode == 1 and "empreinte" in r.stderr


def test_unsigned_release_refused(release):
    d, env, _ = release
    (d / "SHA256SUMS.sigstore.json").unlink()
    r = _run(d, env)
    assert r.returncode == 1 and "0.2.0" in r.stderr


def test_without_cosign(release, tmp_path):
    d, env, _ = release
    path = ":".join(p for p in env["PATH"].split(":") if not (Path(p) / "cosign").exists())
    r = _run(d, {**env, "PATH": path})
    assert r.returncode == 1 and "cosign" in r.stderr


def test_publication_signs_attests_and_proves():
    wf = yaml.safe_load(WF.read_text(encoding="utf-8"))
    assert wf["permissions"] == {"contents": "write", "id-token": "write", "attestations": "write"}
    steps = wf["jobs"]["version"]["steps"]
    names = [s.get("name") or s.get("uses") for s in steps]
    i_sums = names.index("SBOM, notes et empreintes")
    i_sign = names.index("Signature de SHA256SUMS (Sigstore, sans clé)")
    i_prov = names.index("Provenance des fichiers (SLSA)")
    i_check = names.index("Vérification, comme un utilisateur")
    i_draft = names.index("Version GitHub (brouillon)")
    assert i_sums < i_sign < i_prov < i_check < i_draft
    check = steps[i_check]["run"]
    assert "tools/verifier-version.sh version" in check
    assert check.count("if tools/verifier-version.sh") == 2  # contre-épreuves
    assert "provenance acceptée pour un fichier altéré" in check
    assert steps[i_prov]["with"]["subject-checksums"] == "version/SHA256SUMS"
    assert "version/SHA256SUMS*" in steps[i_draft]["run"]


def test_shellcheck():
    if not shutil.which("shellcheck"):
        pytest.skip("shellcheck absent")
    assert subprocess.run(["shellcheck", str(SCRIPT)]).returncode == 0


def test_signing_actions_pinned_to_commit():
    """Actions qui manipulent l'identité de signature : épinglées sur un commit (pas de tag mobile)."""
    text = WF.read_text(encoding="utf-8")
    for action in ("sigstore/cosign-installer", "actions/attest"):
        assert re.search(rf"uses: {action}@[0-9a-f]{{40}} # v\d+\.\d+\.\d+", text), action


def test_release_notes_footer_runs(tmp_path):
    """Le pied des notes de version s'exécute tel quel (printf : aucun % hors des %s)."""
    run = next(s["run"] for s in yaml.safe_load(WF.read_text(encoding="utf-8"))["jobs"]["version"]["steps"]
               if s.get("name") == "SBOM, notes et empreintes")
    lines = [l for l in run.splitlines() if l.startswith(("VERIFIER=", "printf"))]
    assert len(lines) == 2
    (tmp_path / "version").mkdir()
    r = subprocess.run(["bash", "-euc", "\n".join(lines)], cwd=tmp_path, capture_output=True, text=True,
                       env={**os.environ, "GITHUB_SHA": "abc123"})
    assert r.returncode == 0, r.stderr
    notes = (tmp_path / "version" / "NOTES.md").read_text(encoding="utf-8")
    assert "(https://jezu-ci.github.io/AUSPEX/telecharger/#v%C3%A9rifier-un-fichier-t%C3%A9l%C3%A9charg%C3%A9)" in notes
    assert "Commit : abc123" in notes and "l'origine et l'intégrité" in notes
