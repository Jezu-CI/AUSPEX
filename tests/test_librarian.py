"""Compte de service Librarian (droits restreints), contre le faux NetBox.

La vraie application des permissions par NetBox est vérifiée sur un vrai
NetBox par tests/integration/test_netbox_real.py et par la CI du central.
"""

import importlib.util
import shutil
from pathlib import Path

import pytest
import yaml

from auspex.cli import main
from auspex.netbox import LIBRARIAN, LIBRARIAN_PERMISSIONS, OBSERVED_DESCRIPTION
from fake_netbox import FakeNetBox

DEMO = Path(__file__).resolve().parent.parent / "examples" / "demo"
LIB_TOKEN = "a" * 40


@pytest.fixture
def nb():
    fake = FakeNetBox()
    yield fake
    fake.close()


@pytest.fixture
def site(tmp_path, monkeypatch, nb):
    work = tmp_path / "site"
    shutil.copytree(DEMO, work, ignore=shutil.ignore_patterns("state", "logs"))
    spec = importlib.util.spec_from_file_location("gen", work / "generate_logs.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    gen.generate(work / "logs", days=7)
    cfg = yaml.safe_load((work / "auspex.yaml").read_text())
    cfg["netbox"] = {"url": nb.url, "token_env": "NB_TOKEN"}
    (work / "auspex.yaml").write_text(yaml.safe_dump(cfg, allow_unicode=True))
    monkeypatch.chdir(work)
    monkeypatch.setenv("NB_TOKEN", "secret")  # administrateur
    monkeypatch.setenv("LIBRARIAN_TOKEN", LIB_TOKEN)
    return work


def perms(nb):
    return {p["name"]: p for p in nb.data["/api/users/permissions/"]}


def test_setup_creates_librarian_with_minimal_rights(site, nb, capsys):
    assert main(["netbox", "setup"]) == 0
    out = capsys.readouterr().out
    assert f"+ utilisateur {LIBRARIAN}" in out and "+ jeton" in out
    assert nb.data["/api/users/users/"] == []  # simulation : rien d'écrit

    assert main(["netbox", "setup", "--apply"]) == 0
    assert "droits restreints vérifiés" in capsys.readouterr().out
    user = nb.data["/api/users/users/"][0]
    assert user["username"] == "Librarian" and not user["is_superuser"]
    p = perms(nb)
    assert set(p) == {spec["name"] for spec in LIBRARIAN_PERMISSIONS}
    # Aucune permission de suppression, aucune écriture hors des adresses IP
    for perm in p.values():
        assert "delete" not in perm["actions"]
        if set(perm["actions"]) & {"add", "change"}:
            assert perm["object_types"] == ["ipam.ipaddress"]
        assert perm["users"] == [{"id": user["id"]}]
    add = next(x for x in p.values() if x["actions"] == ["add"])
    assert add["constraints"] == {"description": OBSERVED_DESCRIPTION}
    token = nb.data["/api/users/tokens/"][0]
    assert token["key"] == LIB_TOKEN and token["user"] == user["id"]

    assert main(["netbox", "setup", "--apply"]) == 0  # idempotent
    assert "Rien à faire" in capsys.readouterr().out
    assert len(nb.data["/api/users/tokens/"]) == 1


def test_sync_runs_as_librarian(site, nb, capsys, monkeypatch):
    assert main(["netbox", "setup", "--apply"]) == 0
    assert main(["apply"]) == 0  # règles de flux
    assert main(["analyze", "--logs", "logs", "--now", "logs", "--no-send"]) == 0
    monkeypatch.setenv("NB_TOKEN", LIB_TOKEN)  # le service n'a que le jeton de Librarian
    capsys.readouterr()
    assert main(["netbox", "sync", "--apply", "--now", "logs", "--no-send"]) == 0
    assert nb.ip("10.2.1.11")["description"] == OBSERVED_DESCRIPTION
    # Le service ne peut plus créer de champ : la mise en place reste à l'administrateur
    nb.data["/api/extras/custom-fields/"] = [cf for cf in nb.data["/api/extras/custom-fields/"]
                                            if cf["name"] != "auspex_firmware"]
    assert main(["apply"]) == 4
    assert "jeton administrateur" in capsys.readouterr().err


def test_permission_tampered_by_hand_is_restored(site, nb, capsys):
    assert main(["netbox", "setup", "--apply"]) == 0
    change = next(x for x in nb.data["/api/users/permissions/"] if x["actions"] == ["change"])
    change["actions"] = ["change", "delete"]          # quelqu'un élargit les droits
    change["object_types"] = ["ipam.ipaddress", "dcim.device"]
    capsys.readouterr()
    assert main(["netbox", "setup"]) == 0
    assert "~ permission" in capsys.readouterr().out
    assert main(["netbox", "setup", "--apply"]) == 0
    change = next(x for x in nb.data["/api/users/permissions/"] if x["name"] == change["name"])
    assert change["actions"] == ["change"] and change["object_types"] == ["ipam.ipaddress"]


def test_librarian_promoted_to_superuser_is_demoted(site, nb, capsys):
    assert main(["netbox", "setup", "--apply"]) == 0
    nb.data["/api/users/users/"][0]["is_superuser"] = True
    assert main(["netbox", "setup", "--apply"]) == 0
    assert nb.data["/api/users/users/"][0]["is_superuser"] is False


def test_admin_token_refused_as_librarian_token(site, nb, capsys, monkeypatch):
    monkeypatch.setenv("LIBRARIAN_TOKEN", "secret")  # copier-coller du jeton administrateur
    assert main(["netbox", "setup", "--apply"]) == 4
    assert "ne peut pas être le jeton administrateur" in capsys.readouterr().err
    assert nb.data["/api/users/users/"] == []


def test_lost_librarian_token_is_recreated(site, nb, capsys):
    assert main(["netbox", "setup", "--apply"]) == 0
    nb.data["/api/users/tokens/"].clear()  # jeton révoqué dans NetBox
    assert main(["netbox", "setup", "--apply"]) == 0
    assert [t["key"] for t in nb.data["/api/users/tokens/"]] == [LIB_TOKEN]


def test_setup_without_librarian_variable_still_works(site, nb, capsys, monkeypatch):
    monkeypatch.delenv("LIBRARIAN_TOKEN")
    assert main(["netbox", "setup", "--apply"]) == 0
    assert "non géré" in capsys.readouterr().out
    assert nb.data["/api/users/users/"] == []


def test_final_identity_check_catches_ignored_key(site, monkeypatch, capsys):
    """Si NetBox ignore la clé fournie, le service ne doit pas démarrer avec un jeton inutilisable."""
    fake = FakeNetBox(ignore_token_key=True)
    try:
        cfg = yaml.safe_load((site / "auspex.yaml").read_text())
        cfg["netbox"]["url"] = fake.url
        (site / "auspex.yaml").write_text(yaml.safe_dump(cfg, allow_unicode=True))
        assert main(["netbox", "setup", "--apply"]) == 4
        assert "« invalide » au lieu de « restreint »" in capsys.readouterr().err
    finally:
        fake.close()
