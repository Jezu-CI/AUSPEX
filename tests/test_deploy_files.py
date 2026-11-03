import pytest
import json
"""Fichiers de déploiement du central : cohérence avec le code."""

from pathlib import Path

import yaml

from auspex.config import parse_config
from auspex.flowrules import import_rules

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"


def test_config_template_is_valid(tmp_path):
    raw = yaml.safe_load((DEPLOY / "auspex.yaml.template").read_text())
    cfg = parse_config(raw, base_dir=tmp_path)
    assert str(cfg.state_dir) == "/var/lib/auspex/state"
    assert cfg.netbox.url == "http://netbox:8080"
    assert str(cfg.flow_rules_file) == "/etc/auspex/regles-flux.csv"


def test_rules_template_imports(tmp_path):
    res = import_rules(DEPLOY / "regles-flux.template.csv", [])
    assert res.ok and res.rules == []


def test_compose_hardening():
    c = yaml.safe_load((DEPLOY / "docker-compose.yml").read_text())
    a = c["services"]["auspex"]
    assert a["read_only"] is True and a["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in a["security_opt"]
    assert any(v.endswith(":/var/lib/auspex/logs:ro") for v in a["volumes"])
    # NetBox n'est publié que sur la machine locale par défaut
    assert c["services"]["netbox"]["ports"][0].startswith("${NETBOX_BIND:-127.0.0.1}")
    # Aucun secret en clair dans le compose
    text = (DEPLOY / "docker-compose.yml").read_text()
    for var in ("DB_PASSWORD", "NETBOX_SECRET_KEY", "NETBOX_ADMIN_PASSWORD"):
        assert f"${{{var}" in text


def test_secrets_never_committed():
    ignored = (ROOT / ".gitignore").read_text()
    for p in ("deploy/.env", "deploy/config/", "deploy/data/", "deploy/backups/"):
        assert p in ignored


def test_scripts_never_load_env_into_shell():
    """Régression CI : une variable exportée par le shell masque celle de .env
    pour Docker Compose (le jeton NetBox d'Auspex s'est retrouvé vide)."""
    import re
    for name in ("install.sh", "update.sh"):
        text = (DEPLOY / name).read_text()
        assert not re.search(r"^\s*(set -a|\.\s+\./?\.env|source\s+\S*\.env)", text, re.M), name


def test_netbox_default_token_is_never_created():
    """Sans SUPERUSER_API_TOKEN, l'image NetBox crée un jeton admin public."""
    c = yaml.safe_load((DEPLOY / "docker-compose.yml").read_text())
    assert c["services"]["netbox"]["environment"]["SUPERUSER_API_TOKEN"].startswith("${NETBOX_ADMIN_TOKEN:?")
    install = (DEPLOY / "install.sh").read_text()
    assert "NETBOX_ADMIN_TOKEN=$(rand_hex 40)" in install


def test_auspex_container_never_gets_admin_token():
    """Le service n'a que le jeton de Librarian ; l'administrateur reste dans .env."""
    c = yaml.safe_load((DEPLOY / "docker-compose.yml").read_text())
    env = c["services"]["auspex"]["environment"]
    assert env["NETBOX_TOKEN"].startswith("${LIBRARIAN_TOKEN:?")
    assert not any("ADMIN" in str(v) for v in env.values())
    for script in ("install.sh", "update.sh"):
        assert "netbox setup --apply" in (DEPLOY / script).read_text()


def test_old_env_is_migrated(tmp_path):
    """Installation antérieure : NETBOX_TOKEN devient NETBOX_ADMIN_TOKEN, Librarian ajouté."""
    import re
    import subprocess
    src = (DEPLOY / "install.sh").read_text()
    funcs = src[src.index("rand() {"):src.index("if [ ! -f .env ]; then")]
    migration = src[src.index("# Installation antérieure"):src.index("# Répertoires montés : créés ici")]
    (tmp_path / ".env").write_text("NETBOX_VERSION=v4.4\nNETBOX_TOKEN=" + "b" * 40 + "\n")
    for _ in range(2):  # deux passages : idempotent
        r = subprocess.run(["bash", "-c", "set -euo pipefail\n" + funcs + migration], cwd=tmp_path,
                           capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr
    env = dict(l.split("=", 1) for l in (tmp_path / ".env").read_text().splitlines() if "=" in l)
    assert env["NETBOX_ADMIN_TOKEN"] == "b" * 40 and "NETBOX_TOKEN" not in env
    assert re.fullmatch(r"[a-f0-9]{40}", env["LIBRARIAN_TOKEN"])
    assert (tmp_path / ".env").read_text().count("LIBRARIAN_TOKEN=") == 1


def test_entrypoint_gates_analysis_on_apply():
    assert "daemon --apply" in (DEPLOY / "central" / "entrypoint.sh").read_text()


def test_update_rejects_unsafe_versions(tmp_path):
    """Une version est écrite dans .env par sed : « / » ou « & » le corromprait."""
    import subprocess
    for bad in ("v1/../x", "v1&rm", "x;reboot", "-v1", ""):
        if not bad:
            continue
        r = subprocess.run(["bash", str(DEPLOY / "update.sh"), "--netbox", bad],
                           capture_output=True, text=True, timeout=30)
        assert r.returncode == 2 and "invalide" in r.stderr, (bad, r.stderr)
    r = subprocess.run(["bash", str(DEPLOY / "update.sh"), "--auspex", "v0.2.0/evil"],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 2


def test_update_does_not_pull_unchanged_version():
    """Un site sans Internet doit pouvoir mettre à jour avec ses images locales."""
    text = (DEPLOY / "update.sh").read_text()
    assert '[ "$NETBOX_TARGET" != "$CURRENT_NETBOX" ]' in text
    assert 'healthy "$STARTED"' in text and "--exit-on-error" in text


def test_install_generates_private_env_and_valid_token(tmp_path):
    """Exécute la partie « création de .env » d'install.sh, sans Docker."""
    import re
    import subprocess
    src = (DEPLOY / "install.sh").read_text()
    block = src[src.index("rand() {"):src.index("# Répertoires montés : créés ici")]
    script = "set -euo pipefail\nsay(){ :; }\numask 022\n" + block + "\nstat -c '%a' .env\numask\n"
    r = subprocess.run(["bash", "-c", script], cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    perms, umask = r.stdout.split()
    assert perms == "600" and umask == "0022"  # umask limité à .env
    env = dict(l.split("=", 1) for l in (tmp_path / ".env").read_text().splitlines()
               if l and not l.startswith("#"))
    assert re.fullmatch(r"[a-f0-9]{40}", env["NETBOX_ADMIN_TOKEN"])
    assert re.fullmatch(r"[a-f0-9]{40}", env["LIBRARIAN_TOKEN"])
    assert env["LIBRARIAN_TOKEN"] != env["NETBOX_ADMIN_TOKEN"]
    assert len(env["NETBOX_SECRET_KEY"]) == 60 and len(env["DB_PASSWORD"]) == 32
    assert env["AUSPEX_UID"] != "0"           # les services ne tournent jamais en root
    # Deux installations ne partagent jamais les mêmes secrets
    r2 = subprocess.run(["bash", "-c", script], cwd=tmp_path / "..", capture_output=True, text=True)
    other = dict(l.split("=", 1) for l in (tmp_path / ".." / ".env").read_text().splitlines()
                 if l and not l.startswith("#"))
    assert other["NETBOX_ADMIN_TOKEN"] != env["NETBOX_ADMIN_TOKEN"]


def test_admin_password_never_on_command_line():
    text = (DEPLOY / "install.sh").read_text()
    assert '-e NB_PASSWORD="' not in text and "-e NB_PASSWORD auspex" in text



def test_netbox_image_carries_auspex_plugin():
    """NetBox lit auspex.yaml en lecture seule et connaît le réseau interne."""
    c = yaml.safe_load((DEPLOY / "docker-compose.yml").read_text())
    nb = c["services"]["netbox"]
    assert nb["build"]["dockerfile"] == "deploy/netbox/Dockerfile"
    assert "./config:/etc/auspex:ro" in nb["volumes"]
    assert nb["environment"]["AUSPEX_INTERNAL_SUBNET"] == "${AUSPEX_INTERNAL_SUBNET:-172.31.250.0/24}"
    assert c["networks"]["default"]["ipam"]["config"][0]["subnet"] == "${AUSPEX_INTERNAL_SUBNET:-172.31.250.0/24}"
    plugins = (DEPLOY / "netbox" / "plugins.py").read_text()
    assert '"netbox_auspex"' in plugins and "AUSPEX_INTERNAL_SUBNET" in plugins
    dockerfile = (DEPLOY / "netbox" / "Dockerfile").read_text()
    assert "pip install" not in dockerfile  # aucun téléchargement : site sans Internet


def test_template_access_defaults_are_safe(tmp_path):
    raw = yaml.safe_load((DEPLOY / "auspex.yaml.template").read_text())
    cfg = parse_config(raw, base_dir=tmp_path)
    assert cfg.access.default == "deny_if_unlisted"
    assert cfg.access.break_glass_user == "admin" and cfg.access.break_glass_allow == ()



def test_unit_forwarded_rewrite_is_removed(tmp_path):
    """Régression CI : NGINX Unit remplaçait l'adresse source par X-Forwarded-For,
    ce qui permettait d'usurper l'adresse d'un poste autorisé."""
    import json
    import subprocess
    import sys
    conf = {"listeners": {
        "0.0.0.0:8080": {"pass": "routes/main",
                         "forwarded": {"client_ip": "X-Forwarded-For", "source": ["172.16.0.0/12"]}},
        "[::]:8080": {"pass": "routes/main",
                      "client_ip": {"header": "X-Forwarded-For", "source": ["10.0.0.0/8"]}}},
        "routes": {"main": [{"action": {"pass": "applications/netbox"}}]}}
    p = tmp_path / "nginx-unit.json"
    p.write_text(json.dumps(conf))
    r = subprocess.run([sys.executable, str(DEPLOY / "netbox" / "unit_no_forwarded.py"), str(p)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    out = json.loads(p.read_text())
    assert "forwarded" not in json.dumps(out).lower() and "client_ip" not in json.dumps(out)
    assert out["routes"] == conf["routes"]  # le reste est intact
    p.write_text(json.dumps({"autre": 1}))  # format inattendu : la construction doit échouer
    assert subprocess.run([sys.executable, str(DEPLOY / "netbox" / "unit_no_forwarded.py"), str(p)],
                          capture_output=True).returncode != 0
    assert "unit_no_forwarded.py" in (DEPLOY / "netbox" / "Dockerfile").read_text()



@pytest.mark.parametrize("secret", ["AUSPEX_SMTP_PASSWORD", "AUSPEX_LDAP_BIND_PASSWORD", "AUSPEX_OIDC_CLIENT_SECRET"])
def test_auth_secrets_only_for_netbox(secret):
    """Mots de passe SMTP et LDAP : donnés à NetBox seul, jamais au conteneur Auspex."""
    compose = yaml.safe_load((DEPLOY / "docker-compose.yml").read_text())
    assert secret in compose["services"]["netbox"]["environment"]
    for name, svc in compose["services"].items():
        if name != "netbox":
            assert secret not in json.dumps(svc.get("environment", {}))


def test_ldap_config_wired_into_image():
    dockerfile = (DEPLOY / "netbox" / "Dockerfile").read_text()
    assert "/opt/netbox/netbox/netbox/ldap_config.py" in dockerfile
    src = (DEPLOY / "netbox" / "ldap_config.py").read_text()
    assert "OPT_X_TLS_DEMAND" in src and "OPT_X_TLS_NEVER" not in src and "IGNORE_CERT" not in src



def test_dashboard_snapshot_shared_read_only():
    """NetBox ne voit que l'instantané du tableau de bord, en lecture seule."""
    compose = yaml.safe_load((DEPLOY / "docker-compose.yml").read_text())
    nb = compose["services"]["netbox"]["volumes"]
    assert "./data/state/tableau:/var/lib/auspex-tableau:ro" in nb
    assert not any(v.startswith("./data:") for v in nb)          # jamais tout l'état d'Auspex
    assert "data/state/tableau" in (DEPLOY / "install.sh").read_text()
    assert "data/state/tableau" in (DEPLOY / "update.sh").read_text().split("mkdir -p", 1)[1].split("\n", 1)[0]
    plugins = (DEPLOY / "netbox" / "plugins.py").read_text()
    for w in ("FindingsWidget", "ServiceWidget", "InventoryWidget", "ZoneMatrixWidget"):
        assert f"netbox_auspex.{w}" in plugins


def test_dashboard_mount_matches_state_dir():
    """Régression CI : NetBox doit monter le répertoire où le service écrit
    vraiment l'instantané (state_dir du gabarit + montage du service)."""
    from pathlib import PurePosixPath
    tpl = yaml.safe_load((DEPLOY / "auspex.yaml.template").read_text())
    compose = yaml.safe_load((DEPLOY / "docker-compose.yml").read_text())
    container_snapshot = PurePosixPath(tpl["state_dir"]) / "tableau"
    host = None
    for v in compose["services"]["auspex"]["volumes"]:
        src, dst = v.split(":")[:2]
        if container_snapshot.is_relative_to(dst):
            host = PurePosixPath(src) / container_snapshot.relative_to(dst)
    assert host is not None
    assert f"./{host.relative_to('.')}:/var/lib/auspex-tableau:ro" in compose["services"]["netbox"]["volumes"]



def _fake_netbox(root):
    """Extraits réels des gabarits de NetBox 4.4 (inventaire de l'image)."""
    (root / "static").mkdir(parents=True)
    for f in ("logo_netbox_dark_teal.svg", "logo_netbox_bright_teal.svg", "netbox_icon.svg"):
        (root / "static" / f).write_text("<svg>netbox</svg>")
    t = root / "templates"
    (t / "base").mkdir(parents=True)
    (t / "rest_framework").mkdir()
    (t / "base" / "base.html").write_text(
        "{% load static %}<head>\n    <title>{% block title %}{% trans \"Home\" %}{% endblock %} | NetBox</title>\n</head>")
    (t / "base" / "layout.html").write_text(
        '<img src="{% static \'logo_netbox_dark_teal.svg\' %}" alt="{% trans "NetBox Logo" %}" class="navbar-brand-image hide-theme-dark">\n'
        '<img src="{% static \'logo_netbox_bright_teal.svg\' %}" alt="{% trans "NetBox Logo" %}" class="navbar-brand-image hide-theme-light">\n'
        '<a href="https://netboxlabs.com/netbox-cloud/" class="text-muted">{% trans "Get" %} Cloud</a> |\n'
        '                <a href="https://netboxlabs.com/netbox-enterprise/" class="text-muted">{% trans "Get" %} Enterprise</a>\n'
        '<a href="mailto:support@netboxlabs.com" target="_blank" class="link-secondary" rel="noopener" aria-label="x">\n'
        '  <i title="x" class="mdi mdi-lifebuoy text-primary"></i>\n                    </a>')
    (t / "login.html").write_text('<img src="x" alt="{% trans "NetBox Logo" %}" height="80">\n'
                                  '        {# SSO login #}\n        {% if auth_backends %}{% endif %}')
    (t / "rest_framework" / "api.html").write_text('<a class="navbar-brand" href="/">NetBox</a>')
    (t / "media_failure.html").write_text("<title>Static Media Failure - NetBox</title>")


def test_rebrand(tmp_path):
    import subprocess
    import sys
    root = tmp_path / "netbox"
    _fake_netbox(root)
    r = subprocess.run([sys.executable, str(DEPLOY / "netbox" / "rebrand.py"), str(root),
                        str(DEPLOY / "netbox" / "branding")], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "auspex" in (root / "static" / "logo_netbox_dark_teal.svg").read_text()
    assert (root / "static" / "auspex" / "auspex.css").exists()
    base = (root / "templates" / "base" / "base.html").read_text()
    assert "| Auspex</title>" in base and "auspex/auspex.css" in base
    layout = (root / "templates" / "base" / "layout.html").read_text()
    assert "netboxlabs.com" not in layout and "basé sur NetBox Community" in layout
    assert "logo_netbox_dark_teal" not in layout   # menu sombre : logo à texte clair dans les deux thèmes
    login = (root / "templates" / "login.html").read_text()
    assert "NetBox Logo" not in login
    assert '{% if settings.AUSPEX_CARTE_URL %}' in login and 'id="auspex-carte"' in login   # bouton carte


def test_rebrand_fails_on_unexpected_templates(tmp_path):
    import subprocess
    import sys
    root = tmp_path / "netbox"
    _fake_netbox(root)
    (root / "templates" / "base" / "base.html").write_text("<head><title>Autre</title></head>")
    r = subprocess.run([sys.executable, str(DEPLOY / "netbox" / "rebrand.py"), str(root),
                        str(DEPLOY / "netbox" / "branding")], capture_output=True, text=True)
    assert r.returncode != 0 and "| NetBox</title>" in r.stderr


def test_reception_service_hardened():
    """Réception des capteurs : sans privilèges, lecture seule, clés écrites par Auspex en lecture seule."""
    compose = yaml.safe_load((DEPLOY / "docker-compose.yml").read_text())
    svc = compose["services"]["reception"]
    assert svc["read_only"] is True and svc["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in svc["security_opt"]
    assert svc["user"].startswith("${AUSPEX_UID")
    assert "./data/state/reception:/etc/auspex-reception:ro" in svc["volumes"]
    auspex = compose["services"]["auspex"]
    assert any(v.endswith("/var/lib/auspex/logs:ro") for v in auspex["volumes"])   # Auspex lit, n'écrit pas
    sshd = (DEPLOY / "reception" / "sshd_config").read_text()
    for line in ("PasswordAuthentication no", "PermitTTY no", "DisableForwarding yes", "UsePAM no",
                 "PubkeyAcceptedAlgorithms ssh-ed25519", "AllowUsers capteur"):
        assert line in sshd
    assert "Subsystem" not in sshd                                             # pas de SFTP
    recv = (DEPLOY / "reception" / "auspex-recevoir").read_text()
    assert "rrsync -wo -no-del -munge" in recv
    assert 'test "$UID" != 0' in (DEPLOY / "reception" / "Dockerfile").read_text()


def test_front_https_hardened():
    """Front HTTPS : sans privilèges, en lecture seule, adresse fixe (proxy de confiance de NetBox),
    jamais d'en-tête de carte venu du client sur le site principal."""
    compose = yaml.safe_load((DEPLOY / "docker-compose.yml").read_text())
    svc = compose["services"]["acces"]
    assert svc["read_only"] is True and svc["cap_drop"] == ["ALL"] and svc["user"].startswith("${AUSPEX_UID")
    assert "./data/state/acces:/etc/auspex-acces:ro" in svc["volumes"] and "./config/tls:/etc/auspex/tls:ro" in svc["volumes"]
    ip = svc["networks"]["default"]["ipv4_address"]
    assert compose["services"]["netbox"]["environment"]["AUSPEX_FRONT_IP"] == ip
    assert "AUSPEX_PROXY_SECRET" in compose["services"]["netbox"]["environment"]
    nginx = (DEPLOY / "acces" / "nginx.conf").read_text()
    main = nginx.split("server {", 1)[1].split("include /tmp/carte.conf")[0]
    for header in ("X-Auspex-Proxy", "X-Auspex-Carte", "X-Auspex-Carte-Verif"):
        assert f'proxy_set_header {header} "";' in main               # effacés
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in main     # jamais recopié du client
    for script in ("install.sh", "update.sh"):
        text = (DEPLOY / script).read_text()
        assert "AUSPEX_PROXY_SECRET=$(rand_hex 64)" in text and "-keyout tls/serveur.key" in text


def test_https_private_key_out_of_netbox_reach():
    """Relevé en CI : la clé HTTPS était dans config/tls/, et NetBox monte config/ (lecture
    seule, mais lisible). Clé et certificat sont dans tls/, monté dans le seul front."""
    compose = yaml.safe_load((DEPLOY / "docker-compose.yml").read_text())
    for name, svc in compose["services"].items():
        mounts = [v.split(":")[0] for v in svc.get("volumes", [])]
        if name == "acces":
            assert "./tls" in mounts
        else:
            assert "./tls" not in mounts and not any(m in (".", "./") for m in mounts), name
    nginx = (DEPLOY / "acces" / "nginx.conf").read_text()
    assert "ssl_certificate_key /etc/auspex-front/serveur.key;" in nginx and "/etc/auspex/tls/serveur" not in nginx
    for script in ("install.sh", "update.sh"):
        text = (DEPLOY / script).read_text()
        assert "-keyout config/tls" not in text and "-keyout tls/serveur.key" in text
        assert "chmod 700 tls" in text
    assert "mv config/tls/serveur.key tls/serveur.key" in (DEPLOY / "update.sh").read_text()   # migration


def test_card_server_block(tmp_path):
    """Bloc nginx du port carte : certificat exigé, révocation, secret ; inactif sans auth.carte."""
    import copy
    from conftest import BASE_CONFIG
    from auspex.deploy import card_files
    from tests_carte_helpers import ca_and_crl
    ca, crl = ca_and_crl()
    (tmp_path / "ac.pem").write_bytes(ca)
    (tmp_path / "lcr.pem").write_bytes(crl)
    raw = copy.deepcopy(BASE_CONFIG)
    raw["auth"] = {"break_glass": {"user": "secours", "mfa": "totp"},
                   "carte": {"adresse": "https://a.fr:8443", "autorites": "ac.pem", "revocation": "lcr.pem"}}
    files = card_files(parse_config(raw, tmp_path))
    conf = files["carte.conf"].decode()
    assert "ssl_verify_client optional;" in conf and "ssl_crl /etc/auspex-acces/cartes-lcr.pem;" in conf
    assert '"@@SECRET@@"' in conf and "$ssl_client_escaped_cert" in conf and "location = /plugins/auspex/carte-a-puce/" in conf
    assert files["cartes-ac.pem"] == ca and files["cartes-lcr.pem"] == crl
    del raw["auth"]["carte"]
    assert card_files(parse_config(raw, tmp_path)) == {"carte.conf": b""}


def test_plugin_routes_unique():
    """Régression : la connexion par carte avait pris l'adresse de la carte des actifs (carte/)."""
    import re
    urls = (DEPLOY.parent / "netbox-plugin" / "netbox_auspex" / "urls.py").read_text()
    routes = re.findall(r'path\("([^"]*)"', urls)
    names = re.findall(r'name="([^"]*)"', urls)
    assert len(routes) == len(set(routes)) and len(names) == len(set(names)), routes


def test_plugins_py_publishes_card_url(tmp_path, monkeypatch):
    """plugins.py exécuté comme par l'image NetBox : avec auth.carte, l'adresse du bouton passe
    par PLUGINS_CONFIG (NetBox ignore les réglages inconnus comme AUSPEX_CARTE_URL)."""
    import copy
    import runpy
    from conftest import BASE_CONFIG
    from tests_carte_helpers import ca_and_crl
    ca, crl = ca_and_crl()
    (tmp_path / "ac.pem").write_bytes(ca)
    (tmp_path / "lcr.pem").write_bytes(crl)
    raw = copy.deepcopy(BASE_CONFIG)
    raw["auth"] = {"break_glass": {"user": "secours", "mfa": "totp"},
                   "carte": {"adresse": "https://auspex.ville.fr:8443", "autorites": "ac.pem", "revocation": "lcr.pem"}}
    (tmp_path / "auspex.yaml").write_text(yaml.safe_dump(raw))
    monkeypatch.setenv("AUSPEX_CONFIG", str(tmp_path / "auspex.yaml"))
    monkeypatch.setenv("REMOTE_AUTH_BACKEND", "")        # restauré après le test (plugins.py l'écrit)
    ns = runpy.run_path(str(DEPLOY / "netbox" / "plugins.py"))
    assert ns["PLUGINS_CONFIG"]["netbox_auspex"]["carte_url"] == \
        "https://auspex.ville.fr:8443/plugins/auspex/carte-a-puce/"
    assert "netbox_auspex.carte.CarteBackend" in ns["REMOTE_AUTH_BACKEND"]


def test_versions_consistent():
    """Publication : paquet, pyproject, plugin NetBox et journal des versions au même numéro."""
    import re
    root = DEPLOY.parent
    code = re.search(r'__version__ = "([^"]+)"', (root / "src/auspex/__init__.py").read_text()).group(1)
    assert re.search(rf'^version = "{re.escape(code)}"', (root / "pyproject.toml").read_text(), re.M)
    assert f'version = "{code}"' in (root / "netbox-plugin/netbox_auspex/__init__.py").read_text()
    assert f"## [{code}]" in (root / "CHANGELOG.md").read_text()
