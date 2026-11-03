import copy

import pytest

from auspex.config import ConfigError, load_config, parse_config
from conftest import BASE_CONFIG


def cfg(**changes):
    raw = copy.deepcopy(BASE_CONFIG)
    raw.update(changes)
    return raw


def test_valid_config(tmp_path):
    c = parse_config(cfg(), tmp_path)
    assert [z.name for z in c.zones][:2] == ["T0-AD", "T1-serveurs"]
    assert c.zone_by_name("OT-N2").is_ot
    assert c.state_dir == (tmp_path / "state").resolve()


def test_all_errors_reported_at_once(tmp_path):
    raw = cfg(version=2, channel="beta",
              zones=[{"name": "A", "class": "tier9", "prefixes": ["300.1.1.0/24"]}])
    with pytest.raises(ConfigError) as exc:
        parse_config(raw, tmp_path)
    text = str(exc.value)
    assert "version" in text and "channel" in text and "tier9" in text and "300.1.1.0" in text


def test_active_mode_forbidden_in_ot(tmp_path):
    raw = cfg(sensors=[{"name": "s", "zone": "OT-N2", "interface": "eth1", "mode": "active-light"}])
    with pytest.raises(ConfigError, match="interdit en zone OT"):
        parse_config(raw, tmp_path)


def test_secret_in_file_refused(tmp_path):
    raw = cfg(alerts={"outputs": [{"type": "webhook", "url": "https://x", "token": "abc"}]})
    with pytest.raises(ConfigError, match="token_env"):
        parse_config(raw, tmp_path)


def test_plain_http_webhook_refused(tmp_path):
    raw = cfg(alerts={"outputs": [{"type": "webhook", "url": "http://x"}]})
    with pytest.raises(ConfigError, match="HTTPS"):
        parse_config(raw, tmp_path)


def test_short_output_form(tmp_path):
    c = parse_config(cfg(alerts={"outputs": ["syslog://siem:514"]}), tmp_path)
    assert c.alerts.outputs[0].type == "syslog" and c.alerts.outputs[0].format == "cef"


def test_trusted_hosts(tmp_path):
    raw = cfg(access={"trusted_hosts": [
        {"user": "user1", "allow": ["10.10.1.2/32", "172.16.20.2"]},
        {"group": "admins", "allow": ["10.0.10.0/28"]},
    ]})
    c = parse_config(raw, tmp_path)
    assert c.access.trusted_hosts[0].subject == "user1"
    assert len(c.access.trusted_hosts[0].allow) == 2


def test_break_glass_without_allow_is_local_only(tmp_path):
    """Sans liste d'adresses, le brise-glace n'est accepté que depuis la machine du central."""
    raw = cfg(auth={"break_glass": {"user": "bg", "mfa": "totp"}})
    c = parse_config(raw, tmp_path)
    assert c.access.break_glass_user == "bg" and c.access.break_glass_allow == ()
    with pytest.raises(ConfigError, match="ouvrirait le brise-glace"):
        parse_config(cfg(auth={"break_glass": {
            "user": "bg", "mfa": "totp", "allow": ["0.0.0.0/0"]}}), tmp_path)


def test_modules_must_be_pinned(tmp_path):
    with pytest.raises(ConfigError, match="épinglée"):
        parse_config(cfg(modules=["github.com/x/y"]), tmp_path)


def test_duplicate_prefix_refused(tmp_path):
    raw = cfg(zones=[
        {"name": "A", "class": "tier1", "prefixes": ["10.0.0.0/24"]},
        {"name": "B", "class": "tier2", "prefixes": ["10.0.0.0/24"]},
    ])
    with pytest.raises(ConfigError, match="déclaré dans"):
        parse_config(raw, tmp_path)


def test_load_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="introuvable"):
        load_config(tmp_path / "absent.yaml")



def test_example_config_is_valid(tmp_path):
    """Le fichier d'exemple documenté doit rester valide."""
    import pathlib
    import shutil
    from auspex.config import load_config
    root = pathlib.Path(__file__).resolve().parent.parent / "examples"
    shutil.copytree(root, tmp_path / "ex")
    (tmp_path / "ex" / "ac-siem.pem").write_text("certificat fictif")  # référencé par l'exemple
    cfg = load_config(tmp_path / "ex" / "auspex.yaml.example")
    assert cfg.access.auth_primary == "ldaps" and cfg.access.ldap.servers[0].startswith("ldaps://")
