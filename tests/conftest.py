import json
from datetime import datetime, timedelta, timezone

import pytest

from auspex.config import parse_config

BASE_CONFIG = {
    "version": 1,
    "zones": [
        {"name": "T0-AD", "class": "tier0", "prefixes": ["10.0.0.0/24"]},
        {"name": "T1-serveurs", "class": "tier1", "prefixes": ["10.1.0.0/16"]},
        {"name": "T2-postes", "class": "tier2", "prefixes": ["10.2.0.0/16"]},
        {"name": "ADMIN-bastion", "class": "admin", "prefixes": ["10.9.0.0/24"]},
        {"name": "OT-DMZ", "class": "purdue3.5", "prefixes": ["172.16.35.0/24"]},
        {"name": "OT-N2", "class": "purdue2", "prefixes": ["172.16.2.0/24"]},
    ],
    "sensors": [{"name": "capteur-ot", "zone": "OT-N2", "interface": "eth1"}],
    "alerts": {"persistent_after_days": 3, "unused_rule_after_days": 30},
}

T0 = datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)


@pytest.fixture
def config(tmp_path):
    return parse_config(json.loads(json.dumps(BASE_CONFIG)), base_dir=tmp_path)


def conn(ts, src, dst, port, proto="tcp", state="SF", service=None, ob=100, rb=200):
    rec = {"ts": ts.timestamp(), "id.orig_h": src, "id.orig_p": 50000, "id.resp_h": dst,
           "id.resp_p": port, "proto": proto, "conn_state": state, "orig_bytes": ob, "resp_bytes": rb}
    if service:
        rec["service"] = service
    return rec


def write_jsonl(path, records):
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def day():
    return lambda n, h=0: T0 + timedelta(days=n, hours=h)
