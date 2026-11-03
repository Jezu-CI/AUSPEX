"""Registre d'ingestion : aucune connexion n'est comptée deux fois."""

import gzip
import json

import pytest
import yaml

from auspex.cli import main
from auspex.zeek import file_identity, read_log
from conftest import BASE_CONFIG, T0, conn
from datetime import timedelta


@pytest.fixture
def site(tmp_path, monkeypatch):
    (tmp_path / "auspex.yaml").write_text(yaml.safe_dump(BASE_CONFIG))
    (tmp_path / "logs").mkdir()
    monkeypatch.chdir(tmp_path)
    return tmp_path


def line(i, port=22):
    return json.dumps(conn(T0 + timedelta(hours=i), "10.9.0.4", "10.1.0.10", port)) + "\n"


def ssh_count(site):
    flows = json.loads((site / "state" / "flows.json").read_text())
    return next(f["count"] for f in flows if f["port"] == 22)


def analyze(capsys):
    assert main(["analyze", "--logs", "logs", "--now", "logs", "--json"]) == 0
    return json.loads(capsys.readouterr().out)


def test_repeated_runs_count_once(site, capsys):
    (site / "logs" / "conn.log").write_text("".join(line(i) for i in range(5)))
    for _ in range(3):
        analyze(capsys)
    assert ssh_count(site) == 5


def test_growing_file_reads_only_new_lines(site, capsys):
    log = site / "logs" / "conn.log"
    log.write_text("".join(line(i) for i in range(3)))
    s1 = analyze(capsys)
    assert s1["records"] == 3 and s1["files"]["new"] == 1
    with open(log, "a") as fh:
        fh.write(line(3) + line(4))
    s2 = analyze(capsys)
    assert s2["records"] == 2 and s2["files"]["resumed"] == 1
    assert ssh_count(site) == 5


def test_line_being_written_is_read_later(site, capsys):
    log = site / "logs" / "conn.log"
    full = line(1)
    log.write_text(line(0) + full[:40])  # Zeek est en train d'écrire la 2e ligne
    assert analyze(capsys)["records"] == 1
    with open(log, "a") as fh:
        fh.write(full[40:])
    assert analyze(capsys)["records"] == 1
    assert ssh_count(site) == 2


def test_rotation_rename_is_not_reingested(site, capsys):
    log = site / "logs" / "conn.log"
    log.write_text("".join(line(i) for i in range(4)))
    analyze(capsys)
    log.rename(site / "logs" / "conn.2026-10-01-08-00-00.log")  # rotation horaire de Zeek
    s = analyze(capsys)
    assert s["records"] == 0 and s["files"]["unchanged"] == 1
    assert ssh_count(site) == 4


def test_compressed_copy_on_central_is_not_reingested(site, capsys):
    """Le même fichier, compressé puis copié sur le central : déjà lu."""
    content = "".join(line(i) for i in range(4))
    (site / "logs" / "conn.log").write_text(content)
    analyze(capsys)
    (site / "logs" / "conn.log").unlink()
    with gzip.open(site / "logs" / "conn.2026-10-01.log.gz", "wt") as fh:
        fh.write(content)
    assert analyze(capsys)["records"] == 0
    assert ssh_count(site) == 4


def test_truncated_gzip_reads_what_it_can(tmp_path):
    p = tmp_path / "conn.log.gz"
    with gzip.open(p, "wt") as fh:
        fh.write("".join(line(i) for i in range(50)))
    raw = p.read_bytes()
    p.write_bytes(raw[: len(raw) // 2])  # archive en cours d'écriture
    recs = list(read_log(p))
    assert 0 < len(recs) < 50


def test_tsv_identity_stable_as_file_grows(tmp_path):
    p = tmp_path / "conn.log"
    head = ("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n"
            "#open\t2026-10-01-08-00-00\n#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tproto\tconn_state\n"
            "#types\ttime\taddr\taddr\tport\tenum\tstring\n")
    p.write_text(head)
    assert file_identity(p) is None  # pas encore d'enregistrement
    p.write_text(head + "1790841600.0\t10.9.0.4\t10.1.0.10\t22\ttcp\tSF\n")
    first = file_identity(p)
    progress = {}
    assert len(list(read_log(p, 0, progress))) == 1
    with open(p, "a") as fh:
        fh.write("1790841700.0\t10.9.0.4\t10.1.0.20\t3389\ttcp\tSF\n")
    assert file_identity(p) == first
    # Reprise après le premier enregistrement : les en-têtes sont relus, les
    # colonnes restent justes, seul le nouvel enregistrement est renvoyé.
    resumed = list(read_log(p, progress["end"]))
    assert resumed == [{"ts": "1790841700.0", "id.orig_h": "10.9.0.4", "id.resp_h": "10.1.0.20",
                        "id.resp_p": "3389", "proto": "tcp", "conn_state": "SF"}]
