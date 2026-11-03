"""Restriction des connexions par IP source (trusted hosts)."""

import copy

import pytest

from auspex.access import AccessPolicy
from auspex.config import ConfigError, parse_config
from conftest import BASE_CONFIG

INTERNAL = "172.31.250.0/24"   # réseau Docker du central ; .1 = la machine elle-même
GATEWAY = "172.31.250.1"
AUSPEX_CONTAINER = "172.31.250.7"
PROXY = "192.0.2.10"           # reverse proxy TLS déclaré


def policy(tmp_path, access=None, auth=None, internal=INTERNAL):
    raw = copy.deepcopy(BASE_CONFIG)
    raw["access"] = access if access is not None else {
        "default": "deny_if_unlisted",
        "trusted_proxies": [PROXY, GATEWAY],
        "trusted_hosts": [
            {"user": "user1", "allow": ["10.10.1.2/32", "172.16.20.2"]},
            {"group": "admins-t0", "allow": ["10.0.10.0/28"]},
            {"user": "v6user", "allow": ["2001:db8:1::/64"]},
        ],
    }
    raw["auth"] = auth if auth is not None else {
        "break_glass": {"user": "admin", "mfa": "totp", "allow": ["10.0.10.5/32"]}}
    return AccessPolicy(parse_config(raw, tmp_path).access, internal)


# --- Le critère de sortie du jalon : user1 et ses deux adresses ----------------

@pytest.mark.parametrize("ip,ok", [
    ("10.10.1.2", True), ("172.16.20.2", True),
    ("10.10.1.3", False), ("172.16.20.1", False), ("8.8.8.8", False), (AUSPEX_CONTAINER, False),
])
def test_user1_only_from_its_two_addresses(tmp_path, ip, ok):
    assert policy(tmp_path).decide("user1", [], ip).allowed is ok


def test_user1_through_declared_proxy(tmp_path):
    p = policy(tmp_path)
    assert p.decide("user1", [], PROXY, "10.10.1.2").allowed
    assert not p.decide("user1", [], PROXY, "10.10.1.99").allowed
    assert p.decide("user1", [], PROXY, "10.10.1.2").client_ip == "10.10.1.2"


# --- X-Forwarded-For ne se croit que s'il vient d'un proxy déclaré -------------

def test_forged_forwarded_for_is_ignored(tmp_path):
    """Un attaquant en 10.66.0.9 se fait passer pour 10.10.1.2 : refusé."""
    d = policy(tmp_path).decide("user1", [], "10.66.0.9", "10.10.1.2")
    assert not d.allowed and d.client_ip == "10.66.0.9"


def test_client_prepending_entries_cannot_spoof(tmp_path):
    """Le client écrit lui-même « 10.10.1.2 » à gauche ; le proxy ajoute sa vraie IP à droite."""
    d = policy(tmp_path).decide("user1", [], PROXY, "10.10.1.2, 10.66.0.9")
    assert not d.allowed and d.client_ip == "10.66.0.9"


def test_chain_of_trusted_proxies(tmp_path):
    """Client → reverse proxy (déclaré) → passerelle (déclarée) → NetBox."""
    assert policy(tmp_path).decide("user1", [], GATEWAY, f"10.10.1.2, {PROXY}").allowed


def test_chain_made_only_of_trusted_proxies(tmp_path):
    """Poste → passerelle (proxy déclaré) → front HTTPS d'Auspex → NetBox : le client est la
    passerelle, pas le front (sinon toute règle par adresse échoue derrière le front)."""
    from auspex.access import AccessPolicy
    p = policy(tmp_path)          # passerelle déclarée dans trusted_proxies
    front = AccessPolicy(p.access, front_proxy="172.31.250.250")
    ip, forwarded = front.client_ip("172.31.250.250", GATEWAY)
    assert str(ip) == GATEWAY and forwarded
    ip, forwarded = front.client_ip("172.31.250.250", f"10.10.1.2, {GATEWAY}")
    assert str(ip) == "10.10.1.2" and forwarded
    # Sans en-tête : l'adresse de la connexion, sans proxy traversé
    ip, forwarded = front.client_ip("172.31.250.250", None)
    assert str(ip) == "172.31.250.250" and not forwarded


def test_garbage_forwarded_for_is_not_trusted(tmp_path):
    d = policy(tmp_path).decide("user1", [], PROXY, "10.10.1.2, n'importe-quoi")
    assert not d.allowed and d.client_ip == PROXY


# --- Groupes, politique par défaut, IPv6 ------------------------------------------

def test_group_rule(tmp_path):
    p = policy(tmp_path)
    assert p.decide("alice", ["admins-t0"], "10.0.10.3").allowed
    assert not p.decide("alice", ["admins-t0"], "10.0.11.3").allowed
    assert not p.decide("alice", ["autre"], "10.0.10.3").allowed  # pas de règle → refus par défaut


def test_rules_from_user_and_group_combine(tmp_path):
    p = policy(tmp_path)
    assert p.decide("user1", ["admins-t0"], "10.0.10.3").allowed
    assert p.decide("user1", ["admins-t0"], "10.10.1.2").allowed


def test_default_allow_if_unlisted(tmp_path):
    p = policy(tmp_path, access={"default": "allow_if_unlisted",
                                 "trusted_hosts": [{"user": "user1", "allow": ["10.10.1.2/32"]}]})
    assert p.decide("bob", [], "10.99.0.1").allowed
    assert not p.decide("user1", [], "10.99.0.1").allowed  # une règle existe : elle s'applique


def test_ipv6_and_ipv4_mapped(tmp_path):
    p = policy(tmp_path)
    assert p.decide("v6user", [], "2001:db8:1::42").allowed
    assert not p.decide("v6user", [], "2001:db8:2::42").allowed
    assert p.decide("user1", [], "::ffff:10.10.1.2").allowed


def test_anonymous_requests_untouched(tmp_path):
    assert policy(tmp_path).decide(None, [], "8.8.8.8").allowed


def test_unreadable_source_refused(tmp_path):
    assert not policy(tmp_path).decide("user1", [], "pas-une-ip").allowed


# --- Brise-glace -----------------------------------------------------------------

@pytest.mark.parametrize("peer,fwd,ok", [
    (GATEWAY, None, True),             # depuis la machine du central (tunnel SSH)
    ("127.0.0.1", None, True),
    (AUSPEX_CONTAINER, None, True),    # scripts d'installation et de mise à jour
    ("10.0.10.5", None, True),         # adresse déclarée
    ("10.0.10.6", None, False),
    (PROXY, "10.0.10.5", True),        # via le reverse proxy, depuis l'adresse déclarée
    (PROXY, "10.0.10.6", False),       # via le reverse proxy : ce n'est PLUS un accès local
    (GATEWAY, "10.0.10.6", False),     # idem par la passerelle : X-Forwarded-For fait foi
])
def test_break_glass(tmp_path, peer, fwd, ok):
    assert policy(tmp_path).decide("admin", [], peer, fwd).allowed is ok


def test_break_glass_without_allow_is_local_only(tmp_path):
    p = policy(tmp_path, auth={"break_glass": {"user": "admin", "mfa": "totp"}})
    assert p.decide("admin", [], GATEWAY).allowed
    assert not p.decide("admin", [], "10.0.10.5").allowed


# --- Compte de service Librarian ----------------------------------------------------

@pytest.mark.parametrize("peer,fwd,ok", [
    (AUSPEX_CONTAINER, None, True),
    (GATEWAY, None, False),            # même depuis la machine : seul le service l'utilise
    ("10.10.1.2", None, False),
    (PROXY, AUSPEX_CONTAINER, False),  # se faire passer pour le conteneur via un en-tête : refusé
])
def test_librarian_only_from_internal_network(tmp_path, peer, fwd, ok):
    assert policy(tmp_path).decide("Librarian", [], peer, fwd).allowed is ok


def test_librarian_refused_without_internal_network(tmp_path):
    assert not policy(tmp_path, internal=None).decide("Librarian", [], AUSPEX_CONTAINER).allowed


# --- Configuration illisible : verrouillage -----------------------------------------

def test_lockdown_when_config_unreadable():
    p = AccessPolicy(None, INTERNAL)
    assert p.decide("admin", [], GATEWAY).allowed
    assert p.decide("Librarian", [], AUSPEX_CONTAINER).allowed
    d = p.decide("user1", [], "10.10.1.2")
    assert not d.allowed and "verrouillage" in d.reason
    # Régression CI : en verrouillage, un utilisateur ordinaire relayé par la
    # machine du central (reverse proxy local, port publié) restait accepté.
    assert not p.decide("user1", [], GATEWAY).allowed
    assert not p.decide("user1", [], GATEWAY, "10.10.1.2").allowed
    assert not p.decide("user1", [], "127.0.0.1").allowed
    assert not p.decide("Librarian", [], GATEWAY).allowed
    assert not p.decide("admin", [], "10.10.1.2").allowed


# --- Validation de la configuration -------------------------------------------------

def test_wildcard_refused(tmp_path):
    raw = copy.deepcopy(BASE_CONFIG)
    raw["access"] = {"trusted_proxies": ["0.0.0.0/0"]}
    with pytest.raises(ConfigError, match="n'importe qui"):
        parse_config(raw, tmp_path)
    raw = copy.deepcopy(BASE_CONFIG)
    raw["auth"] = {"break_glass": {"user": "admin", "mfa": "totp", "allow": ["::/0"]}}
    with pytest.raises(ConfigError, match="ouvrirait le brise-glace"):
        parse_config(raw, tmp_path)


def test_local_admin_without_break_glass_config(tmp_path):
    """Sans section auth, les scripts (compte admin) fonctionnent toujours, mais
    admin reste refusé depuis l'extérieur."""
    raw = copy.deepcopy(BASE_CONFIG)
    raw["access"] = {"default": "deny_if_unlisted", "trusted_proxies": [GATEWAY]}
    p = AccessPolicy(parse_config(raw, tmp_path).access, INTERNAL)
    assert p.decide("admin", [], AUSPEX_CONTAINER).allowed   # scripts d'installation
    assert p.decide("admin", [], GATEWAY).allowed            # machine du central
    assert not p.decide("admin", [], GATEWAY, "8.8.8.8").allowed
    assert not p.decide("admin", [], "10.0.10.5").allowed


def test_humans_not_trusted_just_for_being_internal(tmp_path):
    """Un utilisateur ordinaire depuis un conteneur du central n'est pas accepté pour autant."""
    assert not policy(tmp_path).decide("user1", [], AUSPEX_CONTAINER, "10.10.1.2").allowed
