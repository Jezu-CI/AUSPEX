"""Sauvegarde et restauration."""

import importlib.util
import io
import json
import shutil
import tarfile
from pathlib import Path

import pytest

from auspex.cli import main

DEMO = Path(__file__).resolve().parent.parent / "examples" / "demo"


@pytest.fixture
def site(tmp_path, monkeypatch):
    work = tmp_path / "site"
    shutil.copytree(DEMO, work, ignore=shutil.ignore_patterns("state", "logs"))
    spec = importlib.util.spec_from_file_location("gen", work / "generate_logs.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    gen.generate(work / "logs", days=7)
    monkeypatch.chdir(work)
    assert main(["apply"]) == 0
    assert main(["analyze", "--logs", "logs", "--now", "logs", "--no-send"]) == 0
    return work


def snapshot(state: Path) -> dict:
    return {str(p.relative_to(state)): p.read_bytes() for p in state.rglob("*") if p.is_file()}


def test_backup_restore_roundtrip(site, capsys):
    before = snapshot(site / "state")
    assert main(["backup", "b.tar.gz"]) == 0
    assert "vérifiée" in capsys.readouterr().out
    shutil.rmtree(site / "state")
    assert main(["restore", "b.tar.gz"]) == 0
    assert snapshot(site / "state") == before
    # L'analyse reprend sans rien recompter (registre d'ingestion restauré)
    capsys.readouterr()
    assert main(["analyze", "--logs", "logs", "--now", "logs", "--no-send", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["records"] == 0


def test_restore_refuses_to_overwrite_without_force(site, capsys):
    assert main(["backup", "b.tar.gz"]) == 0
    assert main(["restore", "b.tar.gz"]) == 6
    assert "--force" in capsys.readouterr().err
    (site / "state" / "flows.json").write_text("[]")
    assert main(["restore", "b.tar.gz", "--force"]) == 0
    out = capsys.readouterr().out
    assert "État précédent sauvegardé" in out
    assert json.loads((site / "state" / "flows.json").read_text()) != []
    assert list((site / "backups").glob("avant-restauration-*.tar.gz"))


def test_with_config_restores_rules_file(site, capsys):
    original = (site / "regles-flux.csv").read_text()
    assert main(["backup", "b.tar.gz"]) == 0
    (site / "regles-flux.csv").write_text("cassé")
    assert main(["restore", "b.tar.gz", "--force", "--with-config"]) == 0
    assert (site / "regles-flux.csv").read_text() == original


def test_tampered_archive_refused(site, tmp_path, capsys):
    assert main(["backup", "b.tar.gz"]) == 0
    src = tarfile.open(site / "b.tar.gz")
    bad = tmp_path / "bad.tar.gz"
    with tarfile.open(bad, "w:gz") as out:
        for m in src.getmembers():
            data = src.extractfile(m).read()
            if m.name == "state/flows.json":
                data = b"[]"
                m.size = len(data)
            out.addfile(m, io.BytesIO(data))
    assert main(["restore", str(bad), "--check"]) == 6
    assert "empreinte invalide" in capsys.readouterr().err


@pytest.mark.parametrize("name", ["../evil.txt", "/etc/evil", "state/../../evil"])
def test_path_traversal_refused(site, tmp_path, capsys, name):
    bad = tmp_path / "bad.tar.gz"
    with tarfile.open(bad, "w:gz") as out:
        info = tarfile.TarInfo(name)
        info.size = 4
        out.addfile(info, io.BytesIO(b"evil"))
    assert main(["restore", str(bad), "--check"]) == 6
    assert "chemin dangereux" in capsys.readouterr().err
    assert not (tmp_path / "evil.txt").exists()


def test_symlink_in_archive_refused(site, tmp_path, capsys):
    bad = tmp_path / "bad.tar.gz"
    with tarfile.open(bad, "w:gz") as out:
        info = tarfile.TarInfo("state/lien")
        info.type, info.linkname = tarfile.SYMTYPE, "/etc/passwd"
        out.addfile(info)
    assert main(["restore", str(bad), "--check"]) == 6
    assert "fichier ordinaire" in capsys.readouterr().err


def test_outbox_not_backed_up(site, capsys):
    (site / "state" / "outbox").mkdir()
    (site / "state" / "outbox" / "00-syslog.jsonl").write_text("{}\n")
    assert main(["backup", "b.tar.gz"]) == 0
    names = tarfile.open(site / "b.tar.gz").getnames()
    assert not [n for n in names if "outbox" in n]
    assert "config/auspex.yaml" in names and "state/ingest.json" in names
