"""Exports d'audit signés : contenu par référentiel, signature, vérification, altérations."""

import csv
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import subprocess
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from auspex import audit
from auspex.cli import main
from auspex.compliance import REFERENCES as FLOW_REFERENCES
from auspex.config import AUDIT_FRAMEWORKS, ConfigError, load_config, parse_config
from auspex.netbox import REFERENCES as INVENTORY_REFERENCES
from auspex.state import AlertStore, AssetStore

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
    assert main(["daemon", "--logs", "logs", "--once"]) == 0
    return work


def cfg_of(site):
    return load_config(site / "auspex.yaml")


def bundle(zip_path) -> dict[str, bytes]:
    return audit._read_bundle(Path(zip_path))


def rezip(files, dest):
    return audit.write_zip(files, Path(dest), "x", datetime.now(timezone.utc))


# --- Référentiels ----------------------------------------------------------------------

def test_framework_catalogue_consistent():
    assert tuple(audit.FRAMEWORKS) == AUDIT_FRAMEWORKS
    known = set(FLOW_REFERENCES) | set(INVENTORY_REFERENCES)
    for fw in audit.FRAMEWORKS.values():
        refs = [c.ref for c in fw.controls]
        assert len(refs) == len(set(refs)), fw.key
        for c in fw.controls:
            assert set(c.types) <= known, (fw.key, c.ref)
            assert c.types or c.evidence == ("surveillance",)


def test_nis2_references_cite_verified_sections():
    """§12.5 (restitution des actifs au départ d'un salarié) a été cité à tort pour la revue
    de l'inventaire : seules les sections vérifiées de l'annexe du règlement 2024/2690 sont admises."""
    verified = {"3.2", "6.7", "6.8", "12.4"}
    refs = [r for table in (FLOW_REFERENCES, INVENTORY_REFERENCES) for rs in table.values() for r in rs]
    refs += [f"NIS2 CIR 2024/2690 {c.ref}" for c in audit.FRAMEWORKS["nis2"].controls]
    for r in refs:
        if "2024/2690" in r:
            sec = re.search(r"§(\d+\.\d+)", r)
            assert sec and sec.group(1) in verified, r


@pytest.mark.parametrize("fw", AUDIT_FRAMEWORKS)
def test_every_framework_exports_and_verifies(site, fw):
    dest, m = audit.export(cfg_of(site), fw, organisation="Ville de Démo")
    assert dest.name.startswith(f"auspex-audit-{fw}-") and dest.suffix == ".zip"
    v = audit.verify(dest)
    assert v.ok and not v.problems and v.fingerprint == m["cle"]
    files = bundle(dest)
    assert set(files) == {"rapport.html", "ecarts.csv", "inventaire.csv", "regles.csv", "flux-inter-zones.csv",
                          "donnees.json", "SHA256SUMS", "VERIFIER.txt", "MANIFEST.json", "MANIFEST.sig",
                          "cle-publique.pem"}
    assert set(m["synthese"]) == {c.ref for c in audit.FRAMEWORKS[fw].controls}
    html = files["rapport.html"].decode()
    assert "Ville de Démo" in html and m["cle"] in html and "<script" not in html


def test_statuses_on_demo(site):
    _, m = audit.export(cfg_of(site), "nis2")
    # Démo : flux en écart, une règle expirée utilisée ; pas de NetBox → inventaire non évalué
    assert m["synthese"] == {"§6.8": "ecarts", "§6.7": "ecarts", "§12.4": "non_evalue", "§3.2": "preuve"}
    data = json.loads(bundle(audit.export(cfg_of(site), "nis2")[0])["donnees.json"])
    seg = next(c for c in data["exigences"] if c["ref"] == "§6.8")
    assert seg["ouverts_fin"] == len(seg["ecarts"]) > 0 and seg["ouverts_fin_par_gravite"]["critical"] > 0
    inv = next(c for c in data["exigences"] if c["ref"] == "§12.4")
    assert "NetBox" in inv["raison"]


def test_no_rules_means_not_evaluated(site):
    state = Path(cfg_of(site).state_dir)
    (state / "flow_rules.json").unlink()
    _, m = audit.export(cfg_of(site), "iso27001")
    assert m["synthese"]["A.8.20"] == "ecarts"           # l'écart déjà ouvert reste rapporté
    (state / "alerts.json").write_text("{}")
    _, m = audit.export(cfg_of(site), "iso27001")
    assert m["synthese"]["A.8.20"] == "non_evalue"       # sans règles, pas de « aucun écart »


def test_csv_contents_and_counts(site):
    dest, _ = audit.export(cfg_of(site), "nis2")
    files = bundle(dest)
    assert files["ecarts.csv"].startswith("﻿".encode())          # BOM pour Excel
    rows = list(csv.DictReader(io.StringIO(files["ecarts.csv"].decode("utf-8-sig")), delimiter=";"))
    open_ids = {a["finding"]["id"] for a in AlertStore(cfg_of(site).state_dir).open_alerts()}
    assert rows and {r["Identifiant"] for r in rows} <= open_ids
    assert all(r["État en fin de période"] == "ouvert" for r in rows)
    inv = list(csv.DictReader(io.StringIO(files["inventaire.csv"].decode("utf-8-sig")), delimiter=";"))
    assert len(inv) == len(AssetStore(cfg_of(site).state_dir).load())
    flows = list(csv.DictReader(io.StringIO(files["flux-inter-zones.csv"].decode("utf-8-sig")), delimiter=";"))
    assert flows and {r["Couvert par une règle"] for r in flows} <= {"oui", "non"}
    # SHA256SUMS : format de sha256sum, cohérent avec le manifeste
    sums = dict(reversed(line.split("  ")) for line in files["SHA256SUMS"].decode().splitlines())
    manifest = json.loads(files["MANIFEST.json"])
    for name, digest in sums.items():
        assert manifest["fichiers"][name]["sha256"] == digest == hashlib.sha256(files[name]).hexdigest()


def test_network_values_neutralised(site):
    """Un nom d'hôte est choisi par n'importe quel poste du réseau : ni formule de tableur,
    ni HTML actif dans l'export."""
    cfg = cfg_of(site)
    store = AssetStore(cfg.state_dir)
    assets = store.load()
    first, second = list(assets.values())[:2]
    first.hostnames = {"=HYPERLINK(\"http://x\")"}
    second.hostnames = {"<script>alert(1)</script>"}
    store.save(assets)
    files = bundle(audit.export(cfg, "anssi")[0])
    text = files["inventaire.csv"].decode("utf-8-sig")
    assert "'=HYPERLINK" in text                      # neutralisée par une apostrophe
    for line in text.splitlines():
        for cell in next(csv.reader([line], delimiter=";")):
            assert not cell.startswith(("=", "+", "@")), cell
    html = files["rapport.html"].decode()
    assert "<script>alert" not in html and "&lt;script&gt;alert(1)" in html


# --- Période ----------------------------------------------------------------------------

def _alerts(cfg):
    return AlertStore(cfg.state_dir).load()


def test_period_boundaries(site):
    cfg = cfg_of(site)
    alerts = _alerts(cfg)
    now = datetime.now(timezone.utc)
    ids = list(alerts)
    # 1 : résolu avant la période → absent ; 2 : résolu pendant → « résolu » ; 3 : ouvert après la fin → absent
    alerts[ids[0]].update(status="resolved", opened_at=(now - timedelta(days=60)).isoformat(),
                          resolved_at=(now - timedelta(days=40)).isoformat())
    alerts[ids[1]].update(status="resolved", opened_at=(now - timedelta(days=10)).isoformat(),
                          resolved_at=(now - timedelta(days=4)).isoformat())
    alerts[ids[2]].update(opened_at=(now + timedelta(days=1)).isoformat())
    (cfg.state_dir / "alerts.json").write_text(json.dumps(alerts))
    found = {f["id"]: f for f in audit._alerts_in_period(cfg.state_dir, now - timedelta(days=30), now)}
    assert ids[0] not in found and ids[2] not in found
    assert found[ids[1]]["open_at_end"] is False and found[ids[1]]["resolved_at"]
    # Même écart vu à une fin de période antérieure à sa résolution : encore ouvert
    earlier = {f["id"]: f for f in audit._alerts_in_period(cfg.state_dir, now - timedelta(days=30),
                                                          now - timedelta(days=5))}
    assert earlier[ids[1]]["open_at_end"] is True


def test_finding_opened_just_before_export_is_included(site):
    """Régression : la fin de période arrondie à la seconde écartait un écart ouvert dans la
    seconde précédant l'export (rapport « aucun écart » à tort)."""
    cfg = cfg_of(site)
    alerts = _alerts(cfg)
    end = datetime(2026, 11, 1, 8, 8, 14, 900000, tzinfo=timezone.utc)
    for a in alerts.values():
        a["opened_at"] = "2026-11-01T08:08:14.735311+00:00"
    (cfg.state_dir / "alerts.json").write_text(json.dumps(alerts))
    _, m = audit.build_export(cfg, "nis2", end=end, key=audit.load_or_create_key(cfg.state_dir))
    assert m["synthese"]["§6.8"] == "ecarts"


def test_resolution_delay(site):
    cfg = cfg_of(site)
    alerts = _alerts(cfg)
    now = datetime.now(timezone.utc)
    seg = next(i for i, a in alerts.items() if a["finding"]["type"] == "flux_it_vers_ot_direct")
    alerts[seg].update(status="resolved", opened_at=(now - timedelta(days=6)).isoformat(),
                       resolved_at=(now - timedelta(days=3)).isoformat())
    (cfg.state_dir / "alerts.json").write_text(json.dumps(alerts))
    data = json.loads(bundle(audit.export(cfg, "iec62443")[0])["donnees.json"])
    sr52 = next(c for c in data["exigences"] if c["ref"] == "SR 5.2")
    assert sr52["resolus_periode"] >= 1 and sr52["delai_moyen_resolution_j"] == 3.0


# --- Signature et vérification ------------------------------------------------------------

def test_key_created_once_private(site):
    cfg = cfg_of(site)
    k1 = audit.load_or_create_key(cfg.state_dir)
    path = audit.key_path(cfg.state_dir)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    k2 = audit.load_or_create_key(cfg.state_dir)
    assert audit.public_pem(k1) == audit.public_pem(k2)


def test_tampering_detected(site, tmp_path):
    dest, m = audit.export(cfg_of(site), "nis2")
    files = bundle(dest)

    changed = dict(files, **{"ecarts.csv": files["ecarts.csv"].replace(b";", b",", 1)})
    v = audit.verify(rezip(changed, tmp_path / "a.zip"))
    assert not v.ok and "ecarts.csv : modifié (empreinte différente)" in v.problems

    manifest = json.loads(files["MANIFEST.json"])
    manifest["synthese"]["§6.8"] = "aucun_ecart"                  # statut maquillé
    forged = dict(files, **{"MANIFEST.json": json.dumps(manifest).encode()})
    v = audit.verify(rezip(forged, tmp_path / "b.zip"))
    assert not v.ok and "signature du manifeste invalide" in v.problems[0]

    added = dict(files, **{"complement.html": b"<p>ajout</p>"})
    v = audit.verify(rezip(added, tmp_path / "c.zip"))
    assert not v.ok and v.problems == ["complement.html : fichier ajouté, absent du manifeste"]

    removed = {k: b for k, b in files.items() if k != "regles.csv"}
    assert "regles.csv : absent" in audit.verify(rezip(removed, tmp_path / "d.zip")).problems


def test_resigned_with_other_key(site, tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ed25519
    dest, m = audit.export(cfg_of(site), "dora")
    files = bundle(dest)
    other = ed25519.Ed25519PrivateKey.generate()
    files.update({"MANIFEST.sig": other.sign(files["MANIFEST.json"]), "cle-publique.pem": audit.public_pem(other)})
    forged = rezip(files, tmp_path / "f.zip")
    assert audit.verify(forged).ok                                   # cohérent en soi...
    v = audit.verify(forged, expected_fingerprint=m["cle"])          # ...mais pas la clé attendue
    assert not v.ok and v.key_matches is False
    assert audit.verify(dest, m["cle"].lower().replace(":", " ")).key_matches is True


@pytest.mark.parametrize("name", ["../evil.txt", "x/../../evil.txt", "/etc/passwd", "x/sous/fichier"])
def test_unexpected_archive_layout_refused(tmp_path, name):
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("x/MANIFEST.json", "{}")
        zf.writestr(name, "x")
    v = audit.verify(z)
    assert not v.ok and "archive inattendue" in v.problems[0]


def test_not_a_zip(tmp_path):
    p = tmp_path / "faux.zip"
    p.write_text("bonjour")
    assert "illisible" in audit.verify(p).problems[0]


@pytest.mark.skipif(not shutil.which("openssl") or not shutil.which("sha256sum"), reason="openssl absent")
def test_verifiable_without_auspex(site, tmp_path):
    dest, _ = audit.export(cfg_of(site), "nis2")
    with zipfile.ZipFile(dest) as z:
        z.extractall(tmp_path)
    folder = tmp_path / dest.stem
    r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", "cle-publique.pem", "-rawin",
                        "-in", "MANIFEST.json", "-sigfile", "MANIFEST.sig"], cwd=folder, capture_output=True,
                       text=True)
    assert r.returncode == 0 and "Signature Verified Successfully" in r.stdout
    assert subprocess.run(["sha256sum", "-c", "--quiet", "SHA256SUMS"], cwd=folder).returncode == 0
    (folder / "regles.csv").write_bytes(b"falsifie")
    assert subprocess.run(["sha256sum", "-c", "--quiet", "SHA256SUMS"], cwd=folder,
                          capture_output=True).returncode != 0


def test_chain_and_index(site):
    cfg = cfg_of(site)
    d1, _ = audit.export(cfg, "nis2")
    d2, m2 = audit.export(cfg, "dora")
    m1 = bundle(d1)["MANIFEST.json"]
    assert m2["precedent"]["manifeste_sha256"] == hashlib.sha256(m1).hexdigest()
    assert m2["precedent"]["fichier"] == d1.name
    index = json.loads((cfg.state_dir / "tableau" / "audits" / "index.json").read_text())
    assert [e["fichier"] for e in index["exports"]] == [d2.name, d1.name]
    assert index["cle"] == m2["cle"] and index["exports"][0]["sha256"] == hashlib.sha256(d2.read_bytes()).hexdigest()


def test_same_minute_exports_not_overwritten(site):
    cfg = cfg_of(site)
    end = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
    a, _ = audit.export(cfg, "nis2", end=end)
    b, _ = audit.export(cfg, "nis2", end=end)
    assert a != b and a.exists() and b.exists()


def test_keep_prunes_oldest(site):
    cfg = cfg_of(site)
    made = [audit.export(cfg, "anssi", end=datetime(2026, 10, d, tzinfo=timezone.utc), keep=2)[0]
            for d in (1, 2, 3)]
    for p, t in zip(made, (1, 2, 3)):
        if p.exists():
            os.utime(p, (t, t))
    assert not made[0].exists() and made[1].exists() and made[2].exists()


# --- Configuration, service et commandes -------------------------------------------------

def base_raw():
    import yaml
    return yaml.safe_load((DEMO / "auspex.yaml").read_text())


def test_config_audit_section():
    raw = base_raw()
    raw["organisation"] = "Ville de Démo"
    raw["audit"] = {"referentiels": ["nis2", "iec62443"], "frequence": "hebdomadaire"}
    cfg = parse_config(raw, DEMO)
    assert cfg.organisation == "Ville de Démo"
    assert cfg.audit.frameworks == ("nis2", "iec62443") and cfg.audit.period_days == 7 and cfg.audit.keep == 24
    raw["audit"] = {"referentiels": ["nis3"], "frequence": "annuelle", "conserver": 0, "autre": 1}
    with pytest.raises(ConfigError) as exc:
        parse_config(raw, DEMO)
    text = " ".join(exc.value.problems)
    for needle in ("'nis3' inconnu", "'annuelle' inconnue", "audit.conserver", "audit.autre : clé inconnue"):
        assert needle in text


def test_daemon_exports_on_schedule(site):
    import yaml
    raw = yaml.safe_load((site / "auspex.yaml").read_text())
    raw["audit"] = {"referentiels": ["nis2", "anssi"], "frequence": "mensuelle"}
    (site / "auspex.yaml").write_text(yaml.safe_dump(raw, allow_unicode=True))
    assert main(["daemon", "--logs", "logs", "--once"]) == 0
    cfg = cfg_of(site)
    auto = [e for e in audit.journal(cfg.state_dir) if e.get("automatique")]
    assert sorted(e["referentiel"] for e in auto) == ["anssi", "nis2"]
    assert main(["daemon", "--logs", "logs", "--once"]) == 0      # pas de nouvel export avant un mois
    assert len([e for e in audit.journal(cfg.state_dir) if e.get("automatique")]) == 2
    later = datetime.now(timezone.utc) + timedelta(days=30)
    assert audit.due(cfg, later) == ["nis2", "anssi"]
    # Un export manuel ne repousse pas l'export périodique
    audit.export(cfg, "nis2")
    assert audit.due(cfg, later) == ["nis2", "anssi"]


def test_cli(site, capsys, tmp_path):
    assert main(["audit", "cle"]) == 0
    fp = capsys.readouterr().out.split("Empreinte : ")[1].strip()
    assert re.fullmatch(r"([0-9A-F]{4}:){7}[0-9A-F]{4}", fp)
    assert main(["audit", "export", "iso27001", "--jours", "7", "--sortie", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "A.8.22" in out and "écarts ouverts" in out
    z = next(tmp_path.glob("*.zip"))
    assert main(["audit", "verify", str(z)]) == 0
    assert "signé par la clé attendue" in capsys.readouterr().out
    files = bundle(z)
    files["rapport.html"] += b"<!-- -->"
    bad = rezip(files, tmp_path / "bad.zip")
    assert main(["audit", "verify", str(bad)]) == 1
    assert "NON VÉRIFIÉ" in capsys.readouterr().out
    assert main(["audit", "export", "nis2", "--fin", "pas-une-date"]) == 2
    assert main(["audit", "list"]) == 0
    assert "iso27001" in capsys.readouterr().out


def test_open_findings_reported_even_without_traffic_in_period(site):
    """Régression (CI) : export quotidien sur des logs plus anciens. Aucun trafic dans la période,
    mais les écarts ouverts avant restent ouverts : ils doivent apparaître, pas « non évalué »."""
    cfg = cfg_of(site)
    end = datetime(2026, 12, 15, tzinfo=timezone.utc)          # bien après les logs de démonstration
    _, m = audit.build_export(cfg, "nis2", end=end, days=1, key=audit.load_or_create_key(cfg.state_dir))
    assert m["synthese"]["§6.8"] == "ecarts" and m["synthese"]["§6.7"] == "ecarts"
    assert m["synthese"]["§3.2"] == "non_evalue"               # capteurs muets : pas de preuve de surveillance
    alerts = _alerts(cfg)
    for a in alerts.values():
        a.update(status="resolved", resolved_at="2026-11-01T00:00:00+00:00")
    (cfg.state_dir / "alerts.json").write_text(json.dumps(alerts))
    _, m = audit.build_export(cfg, "nis2", end=end, days=1, key=audit.load_or_create_key(cfg.state_dir))
    assert m["synthese"]["§6.8"] == "non_evalue"               # sans trafic, pas de « aucun écart »
