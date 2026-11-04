"""Miroir des empreintes hors GitHub (tools/miroir-empreintes.sh, workflow miroir-empreintes.yml).

Le vrai miroir (Codeberg) n'est joignable qu'avec le jeton du workflow : ici,
le script travaille sur un dépôt git local qui tient lieu de miroir.
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "miroir-empreintes.sh"
VERIFIER = ROOT / "tools" / "verifier-version.sh"
WF = ROOT / ".github" / "workflows" / "miroir-empreintes.yml"
FICHIERS = ("SHA256SUMS", "SHA256SUMS.sigstore.json")


def _git(*args, cwd=None):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout


@pytest.fixture
def miroir(tmp_path):
    """Dépôt miroir vide (bare) et dossier de version factice.

    Branche par défaut du dépôt volontairement différente de main (comme
    « master » sur les machines de GitHub) : le script doit toujours travailler
    sur main, quelle que soit la branche par défaut du miroir.
    """
    depot = tmp_path / "miroir.git"
    _git("init", "-q", "--bare", "--initial-branch=master", str(depot))
    d = tmp_path / "version"
    d.mkdir()
    (d / "SHA256SUMS").write_text("abc  auspex-sbom.cdx.json\n")
    (d / "SHA256SUMS.sigstore.json").write_text('{"signature": 1}\n')
    return depot, d


def _run(depot, *args, **env):
    import os
    e = {k: v for k, v in os.environ.items() if k not in ("CODEBERG_TOKEN", "MIROIR_ESSAI")}
    e.update({"AUSPEX_MIROIR_GIT": str(depot), **env})
    return subprocess.run(["bash", str(SCRIPT), *map(str, args)], env=e, capture_output=True, text=True)


def _contenu(depot, chemin):
    return _git("--git-dir", str(depot), "show", f"main:{chemin}")


def _nb_commits(depot):
    return int(_git("--git-dir", str(depot), "rev-list", "--count", "main"))


def test_copie_dans_un_miroir_vide(miroir):
    depot, d = miroir
    r = _run(depot, d, "v9.9.9")
    assert r.returncode == 0, r.stderr
    for f in FICHIERS:
        assert _contenu(depot, f"v9.9.9/{f}") == (d / f).read_text()
    assert "miroir des empreintes" in _contenu(depot, "README.md")
    assert _git("--git-dir", str(depot), "log", "-1", "--format=%s", "main").strip() == "Empreintes de la version v9.9.9"


def test_versions_successives(miroir):
    depot, d = miroir
    assert _run(depot, d, "v9.9.9").returncode == 0
    (d / "SHA256SUMS").write_text("def  auspex-sbom.cdx.json\n")
    assert _run(depot, d, "v9.9.10").returncode == 0
    assert _contenu(depot, "v9.9.9/SHA256SUMS") == "abc  auspex-sbom.cdx.json\n"
    assert _contenu(depot, "v9.9.10/SHA256SUMS") == "def  auspex-sbom.cdx.json\n"
    assert _nb_commits(depot) == 2


def test_autre_branche_par_defaut_ignoree(miroir, tmp_path):
    """Miroir dont la branche par défaut (master) a déjà du contenu : main est créée seule."""
    depot, d = miroir
    w = tmp_path / "w"
    _git("init", "-q", "--initial-branch=master", str(w))
    (w / "autre.txt").write_text("x\n")
    _git("add", ".", cwd=w)
    _git("-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "a", cwd=w)
    _git("push", "-q", str(depot), "master", cwd=w)
    assert _run(depot, d, "v9.9.9").returncode == 0
    fichiers = _git("--git-dir", str(depot), "ls-tree", "-r", "--name-only", "main").split()
    assert sorted(fichiers) == ["README.md", "v9.9.9/SHA256SUMS", "v9.9.9/SHA256SUMS.sigstore.json"]
    assert _nb_commits(depot) == 1


def test_version_deja_presente_identique(miroir):
    depot, d = miroir
    assert _run(depot, d, "v9.9.9").returncode == 0
    r = _run(depot, d, "v9.9.9")
    assert r.returncode == 0 and "identique" in r.stdout
    assert _nb_commits(depot) == 1


@pytest.mark.parametrize("fichier", FICHIERS)
def test_version_deja_presente_differente_refusee(miroir, fichier):
    depot, d = miroir
    assert _run(depot, d, "v9.9.9").returncode == 0
    avant = _contenu(depot, f"v9.9.9/{fichier}")
    (d / fichier).write_text("altéré\n")
    r = _run(depot, d, "v9.9.9")
    assert r.returncode == 1 and "différent" in r.stderr
    assert _contenu(depot, f"v9.9.9/{fichier}") == avant and _nb_commits(depot) == 1


@pytest.mark.parametrize("version", ["0.2.0", "v0.2", "v0.2.0-pirate", "../v0.2.0", "v0.2.0/x"])
def test_format_de_version(miroir, version):
    depot, d = miroir
    r = _run(depot, d, version)
    assert r.returncode == 1 and "vX.Y.Z" in r.stderr


@pytest.mark.parametrize("fichier", FICHIERS)
def test_fichier_manquant(miroir, fichier):
    depot, d = miroir
    (d / fichier).unlink()
    r = _run(depot, d, "v9.9.9")
    assert r.returncode == 1 and fichier in r.stderr


def test_essai_acces_n_envoie_rien(miroir):
    depot, _ = miroir
    r = _run(depot, MIROIR_ESSAI="1")
    assert r.returncode == 0 and "OK" in r.stdout
    assert _git("--git-dir", str(depot), "branch", "--list").strip() == ""  # toujours vide


def test_miroir_inaccessible(tmp_path):
    r = _run(tmp_path / "absent.git", MIROIR_ESSAI="1")
    assert r.returncode == 1 and "inaccessible" in r.stderr


def test_jeton_jamais_en_clair():
    """Le jeton passe par GIT_ASKPASS : ni dans une URL, ni en argument, ni dans la configuration git."""
    text = SCRIPT.read_text(encoding="utf-8")
    assert "GIT_ASKPASS" in text
    assert not re.search(r"CODEBERG_TOKEN\}?@", text)
    assert text.count("$CODEBERG_TOKEN") == 1  # seulement dans l'aide à la saisie (askpass)
    assert "git config" not in text and "set-url" not in text


def test_verifier_compare_avec_le_miroir(tmp_path):
    """tools/verifier-version.sh DOSSIER VERSION : identique au miroir, différent ou absent refusés."""
    if not shutil.which("curl"):
        pytest.skip("curl absent")
    import hashlib
    import os
    d = tmp_path / "version"
    d.mkdir()
    (d / "auspex-sbom.cdx.json").write_text("{}\n")
    sums = f"{hashlib.sha256(b'{}' + bytes([10])).hexdigest()}  auspex-sbom.cdx.json\n"
    (d / "SHA256SUMS").write_text(sums)
    (d / "SHA256SUMS.sigstore.json").write_text("{}")
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    (bin_ / "cosign").write_text("#!/bin/sh\nexit 0\n")
    (bin_ / "cosign").chmod(0o755)
    m = tmp_path / "miroir"
    (m / "v9.9.9").mkdir(parents=True)
    (m / "v9.9.9" / "SHA256SUMS").write_text(sums)
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}", "AUSPEX_MIROIR_URL": f"file://{m}"}

    def run(*args):
        return subprocess.run(["bash", str(VERIFIER), str(d), *args], env=env, capture_output=True, text=True)

    r = run("v9.9.9")
    assert r.returncode == 0 and "identique au miroir" in r.stdout and "3/3" in r.stdout
    assert "3/3" not in run().stdout  # sans version : pas de comparaison
    r = run("v9.9.8")
    assert r.returncode == 1 and "absente du miroir" in r.stderr
    (m / "v9.9.9" / "SHA256SUMS").write_text("0" * 64 + "  auspex-sbom.cdx.json\n")
    r = run("v9.9.9")
    assert r.returncode == 1 and "différent de la copie du miroir" in r.stderr
    r = run("9.9.9")
    assert r.returncode == 1 and "vX.Y.Z" in r.stderr


def test_meme_miroir_partout():
    """Script de copie, script de vérification et page Télécharger désignent le même dépôt."""
    base = "codeberg.org/Jezu_CI/AUSPEX-empreintes"
    assert f"https://{base}.git" in SCRIPT.read_text(encoding="utf-8")
    assert f"https://{base}/raw/branch/main" in VERIFIER.read_text(encoding="utf-8")
    assert f"https://{base}" in (ROOT / "site" / "telecharger.md").read_text(encoding="utf-8")
    assert f"https://{base}" in (ROOT / "SECURITY.md").read_text(encoding="utf-8")


def test_workflow():
    wf = yaml.safe_load(WF.read_text(encoding="utf-8"))
    on = wf.get("on", wf.get(True))  # YAML 1.1 : « on » lu comme booléen
    assert on["release"] == {"types": ["published"]}
    assert "version" in on["workflow_dispatch"]["inputs"]
    assert wf["permissions"] == {"contents": "read"}
    steps = wf["jobs"]["miroir"]["steps"]
    names = [s.get("name") or s.get("uses") for s in steps]
    i_essai = names.index("Accès en écriture au miroir (essai)")
    i_verif = names.index("Empreintes de la version, vérifiées comme par un utilisateur")
    i_copie = names.index("Copie vers le miroir")
    i_relec = names.index("Relecture du miroir, comme un utilisateur")
    assert i_verif < i_copie < i_relec
    assert "tools/verifier-version.sh version" in steps[i_verif]["run"]
    assert 'tools/verifier-version.sh version "$V"' in steps[i_relec]["run"]
    assert steps[i_essai]["env"]["MIROIR_ESSAI"] == "1"
    # Le jeton n'est remis qu'aux deux étapes qui écrivent dans le miroir.
    avec_jeton = [i for i, s in enumerate(steps) if "CODEBERG_TOKEN" in str(s)]
    assert avec_jeton == sorted([i_essai, i_copie])
    for i in avec_jeton:
        assert steps[i]["env"]["CODEBERG_TOKEN"] == "${{ secrets.CODEBERG_TOKEN }}"
        assert steps[i]["run"].startswith("tools/miroir-empreintes.sh")


@pytest.mark.parametrize("wf", sorted((ROOT / ".github" / "workflows").glob("*.yml")), ids=lambda p: p.name)
def test_etapes_shell_syntaxe(wf):
    """Chaque étape « run » des workflows est un script bash syntaxiquement valide (bash -n)."""
    jobs = yaml.safe_load(wf.read_text(encoding="utf-8"))["jobs"]
    for job, j in jobs.items():
        for s in j.get("steps", []):
            if "run" not in s or s.get("shell", "bash") != "bash":
                continue
            r = subprocess.run(["bash", "-n"], input=s["run"], capture_output=True, text=True)
            assert r.returncode == 0, f"{job} / {s.get('name')} : {r.stderr}"


def test_workflow_actions_epinglees():
    """Workflow qui manipule un secret : toutes les actions épinglées sur un commit."""
    text = WF.read_text(encoding="utf-8")
    uses = re.findall(r"uses: (\S+)", text)
    assert uses
    for u in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", u), u
    steps = yaml.safe_load(text)["jobs"]["miroir"]["steps"]
    checkout = next(s for s in steps if s.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["persist-credentials"] is False


def test_shellcheck():
    if not shutil.which("shellcheck"):
        pytest.skip("shellcheck absent")
    assert subprocess.run(["shellcheck", str(SCRIPT)]).returncode == 0
