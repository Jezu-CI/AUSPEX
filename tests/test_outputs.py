import json
import socket
import ssl
import subprocess
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from auspex.compliance import Finding
from auspex.config import Output
from auspex.outputs import Dispatcher, normalize, to_cef
from auspex.state import AlertStore

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)


def finding(sev="high", ftype="nouveau_flux_non_declare", fid="CMDB-1"):
    return Finding(id=fid, type=ftype, severity=sev, message="SSH | non déclaré = test\nligne 2",
                   src="10.9.0.4", dst="10.1.0.10", src_zone="ADMIN", dst_zone="T1", proto="tcp",
                   port=22, service="SSH", first_seen=NOW.isoformat(), last_seen=NOW.isoformat(), count=3,
                   references=["ISO 27001 A.8.22"])


def ev(**kw):
    return {"event": "open", **finding(**kw).to_dict()}


def test_cef_escaping():
    cef = to_cef(normalize(ev(), NOW))
    header, ext = cef.rsplit("|", 1)[0], cef.split("|", 7)[7]
    assert header.startswith("CEF:0|auspex|auspex|")
    assert "|8|" in cef  # high → 8
    assert "msg=SSH | non déclaré \\= test\\nligne 2" in ext
    assert "dpt=22" in ext and "cs1=ADMIN" in ext and "externalId=CMDB-1" in ext


def test_ocsf_fields():
    n = normalize(ev(sev="critical"), NOW)
    assert n["severity_id"] == 5 and n["dst_endpoint"]["port"] == 22 and n["activity"] == "open"


def test_file_output_and_min_severity(tmp_path):
    out = Output(type="file", path="alerts.jsonl", min_severity="high")
    d = Dispatcher([out], tmp_path / "state", tmp_path)
    assert d.dispatch([ev(sev="medium"), ev(sev="critical", fid="CMDB-2")], NOW) == []
    lines = (tmp_path / "alerts.jsonl").read_text().splitlines()
    assert [json.loads(l)["id"] for l in lines] == ["CMDB-2"]


def test_udp_syslog(tmp_path):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(3)
    port = srv.getsockname()[1]
    d = Dispatcher([Output(type="syslog", url=f"udp://127.0.0.1:{port}", format="cef")], tmp_path, tmp_path)
    assert d.dispatch([ev()], NOW) == []
    msg = srv.recv(65535).decode()
    srv.close()
    assert msg.startswith("<131>1 2026-10-30T12:00:00+00:00 ")  # local0 + err (high)
    assert "CEF:0|auspex" in msg


def _tcp_server(ssl_ctx=None):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    got = {"data": b""}

    def run():
        conn, _ = srv.accept()
        try:
            if ssl_ctx:
                conn = ssl_ctx.wrap_socket(conn, server_side=True)
            conn.settimeout(3)
            while chunk := conn.recv(65535):
                got["data"] += chunk
        except (ssl.SSLError, OSError) as exc:
            got["error"] = exc
        finally:
            conn.close()
            srv.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return srv.getsockname()[1], t, got


def test_tcp_syslog_octet_counting(tmp_path):
    port, t, got = _tcp_server()
    d = Dispatcher([Output(type="syslog", url=f"tcp://127.0.0.1:{port}", format="json")], tmp_path, tmp_path)
    assert d.dispatch([ev(), ev(fid="CMDB-2")], NOW) == []
    t.join(5)
    data = got["data"].decode()
    length, rest = data.split(" ", 1)
    first = rest[:int(length)]
    assert first.startswith("<131>1 ") and '"id": "CMDB-1"' in first
    assert "CMDB-2" in rest[int(length):]


def test_tcp_close_is_clean_even_with_unread_server_data(tmp_path):
    """Régression : le serveur envoie des données que le client ne lit pas
    (comme les tickets de session TLS 1.3). Fermer sans les lire provoquait
    une réinitialisation TCP et la perte possible des derniers messages."""
    import time
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    got = {"data": b"", "error": None}

    def run():
        conn, _ = srv.accept()
        conn.sendall(b"x" * 4096)          # données jamais lues par un client naïf
        time.sleep(0.5)                    # le client a fini d'envoyer et fermé
        conn.settimeout(3)
        try:
            while chunk := conn.recv(65535):
                got["data"] += chunk
        except OSError as exc:
            got["error"] = exc
        finally:
            conn.close()
            srv.close()
    t = threading.Thread(target=run, daemon=True)
    t.start()
    out = Output(type="syslog", url=f"tcp://127.0.0.1:{srv.getsockname()[1]}", format="json")
    assert Dispatcher([out], tmp_path / "state", tmp_path).dispatch([ev(), ev(fid="CMDB-2")], NOW) == []
    t.join(5)
    assert got["error"] is None, f"connexion réinitialisée : {got['error']}"
    assert b"CMDB-1" in got["data"] and b"CMDB-2" in got["data"]


@pytest.fixture
def tls_cert(tmp_path):
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                        "-keyout", str(key), "-out", str(crt)], capture_output=True)
    if r.returncode:
        pytest.skip("openssl indisponible")
    return key, crt


def test_tls_syslog_verifies_certificate(tmp_path, tls_cert):
    key, crt = tls_cert
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(crt, key)

    # 1) Certificat inconnu du client : l'envoi échoue et l'événement est mis en file.
    port, t, got = _tcp_server(sctx)
    out = Output(type="syslog", url=f"tls://localhost:{port}", format="cef")
    errors = Dispatcher([out], tmp_path / "state", tmp_path).dispatch([ev()], NOW)
    t.join(5)
    assert errors and "conservé" in errors[0]
    assert got["data"] == b""  # rien n'est parti en clair
    assert (tmp_path / "state" / "outbox" / "00-syslog.jsonl").exists()

    # 2) AC du SIEM déclarée : la file est vidée avec le nouvel événement.
    port, t, got = _tcp_server(sctx)
    out = Output(type="syslog", url=f"tls://localhost:{port}", format="cef", ca_file=str(crt))
    assert Dispatcher([out], tmp_path / "state", tmp_path).dispatch([ev(fid="CMDB-2")], NOW) == []
    t.join(5)
    data = got["data"].decode()
    assert "externalId=CMDB-1" in data and "externalId=CMDB-2" in data
    assert not (tmp_path / "state" / "outbox" / "00-syslog.jsonl").exists()


def test_webhook_with_token(tmp_path, monkeypatch):
    received = {}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            received["auth"] = self.headers.get("Authorization")
            received["body"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.handle_request, daemon=True).start()
    monkeypatch.setenv("SOAR_TOKEN", "s3cret")
    out = Output(type="webhook", url=f"http://127.0.0.1:{httpd.server_port}/hook", token_env="SOAR_TOKEN")
    assert Dispatcher([out], tmp_path, tmp_path).dispatch([ev()], NOW) == []
    httpd.server_close()
    assert received["auth"] == "Bearer s3cret"
    assert received["body"]["events"][0]["id"] == "CMDB-1"


def test_webhook_missing_token_env_is_an_error(tmp_path, monkeypatch):
    monkeypatch.delenv("NOPE", raising=False)
    out = Output(type="webhook", url="https://127.0.0.1:9/x", token_env="NOPE")
    errors = Dispatcher([out], tmp_path, tmp_path).dispatch([ev()], NOW)
    assert "NOPE" in errors[0]


def test_alert_lifecycle(tmp_path):
    store = AlertStore(tmp_path)
    f = finding(sev="medium")
    assert [e["event"] for e in store.reconcile([f], NOW)] == ["open"]
    assert store.reconcile([f], NOW) == []  # rien de nouveau : pas de bruit
    f2 = finding(sev="high", ftype="flux_non_declare_persistant")
    assert [e["event"] for e in store.reconcile([f2], NOW)] == ["update"]
    assert [e["event"] for e in store.reconcile([], NOW)] == ["resolve"]
    assert [e["event"] for e in store.reconcile([f2], NOW)] == ["open"]  # réapparition


def test_alert_scopes_do_not_resolve_each_other(tmp_path):
    store = AlertStore(tmp_path)
    flow = finding(fid="AUSPEX-FLOW")
    inv = finding(fid="AUSPEX-INV", ftype="actif_inconnu")
    store.reconcile([flow], NOW, scope="flux")
    store.reconcile([inv], NOW, scope="inventaire")
    # Une analyse de flux sans écart ne résout pas l'alerte d'inventaire
    events = store.reconcile([], NOW, scope="flux")
    assert [(e["event"], e["id"]) for e in events] == [("resolve", "AUSPEX-FLOW")]
    assert [a["finding"]["id"] for a in store.open_alerts()] == ["AUSPEX-INV"]


@pytest.mark.parametrize("graceful", [True, False])
def test_close_gracefully_avoids_reset(graceful):
    """Version déterministe : les données du serveur sont bien arrivées et non
    lues au moment de la fermeture. Fermeture brute : réinitialisation (ce
    que la correction évite) ; fermeture propre : fin normale."""
    import time
    from auspex.outputs import _close_gracefully
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    client = socket.create_connection(srv.getsockname())
    conn, _ = srv.accept()
    conn.sendall(b"x" * 4096)
    time.sleep(0.2)                                   # arrivées chez le client, non lues
    client.sendall(b"message")
    if graceful:
        _close_gracefully(client)
    client.close()
    time.sleep(0.2)
    conn.settimeout(2)
    received, error = b"", None
    try:
        while chunk := conn.recv(65535):
            received += chunk
    except OSError as exc:
        error = exc
    conn.close()
    srv.close()
    if graceful:
        assert error is None and received == b"message"
    else:
        assert isinstance(error, ConnectionResetError)  # le défaut corrigé, reproduit


def test_tls_contexts_require_tls12_and_verify(tmp_path):
    """Sorties syslog TLS / webhook et client NetBox : TLS 1.2 minimum exigé explicitement,
    certificat et nom d'hôte toujours vérifiés (CodeQL py/insecure-protocol)."""
    import ssl
    from auspex.netbox import NetBoxClient
    from auspex.outputs import tls_context
    for ctx in (tls_context(), NetBoxClient("https://netbox.example", "x" * 40).ctx):
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
        assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
