"""Méthode de connexion principale (LDAPS) : validation et réglages NetBox."""

import copy

import pytest

from auspex import netbox_auth as na
from auspex.config import ConfigError, parse_config
from conftest import BASE_CONFIG

AD = {
    "servers": ["ldaps://dc01.ville.local", "ldaps://dc02.ville.local"],
    "bind_dn": "CN=svc-auspex,OU=Services,DC=ville,DC=local",
    "user_search_base": "OU=Utilisateurs,DC=ville,DC=local",
    "group_search_base": "OU=Groupes,DC=ville,DC=local",
    "require_group": "CN=Auspex,OU=Groupes,DC=ville,DC=local",
}


def access(tmp_path, ldaps=AD, primary="ldaps", **auth):
    raw = copy.deepcopy(BASE_CONFIG)
    raw["auth"] = {"break_glass": {"user": "secours", "mfa": "totp"}, **auth}
    if primary:
        raw["auth"]["primary"] = primary
    if ldaps is not None:
        raw["auth"]["ldaps"] = copy.deepcopy(ldaps)
    return parse_config(raw, tmp_path).access


def test_active_directory_plan(tmp_path):
    a = access(tmp_path)
    assert na.remote_backend(a) == "netbox.authentication.LDAPBackend"
    plan = na.ldap_plan(a)
    assert plan["server_uri"] == "ldaps://dc01.ville.local ldaps://dc02.ville.local"
    assert plan["user_search"] == ("OU=Utilisateurs,DC=ville,DC=local", "(sAMAccountName=%(user)s)")
    assert plan["group_search"] == ("OU=Groupes,DC=ville,DC=local", "(objectClass=group)")
    assert plan["group_type"] == "NestedActiveDirectoryGroupType"
    assert plan["user_attr_map"] == {"first_name": "givenName", "last_name": "sn", "email": "mail"}
    assert plan["bind_password_env"] == "AUSPEX_LDAP_BIND_PASSWORD" and "password" not in str(a.ldap)


def test_openldap_plan(tmp_path):
    a = access(tmp_path, {"server": "ldap://annuaire.ville.local", "start_tls": True,
                          "user_search_base": "ou=people,dc=ville,dc=local", "user_attribute": "uid",
                          "group_search_base": "ou=groups,dc=ville,dc=local", "group_type": "group_of_names",
                          "attributes": {"email": "courriel"}})
    plan = na.ldap_plan(a)
    assert plan["start_tls"] and plan["user_search"][1] == "(uid=%(user)s)"
    assert plan["group_type"] == "GroupOfNamesType" and plan["user_attr_map"]["email"] == "courriel"


def test_without_primary_local_only(tmp_path):
    a = access(tmp_path, ldaps=None, primary=None)
    assert na.remote_backend(a) == "netbox.authentication.RemoteUserBackend"
    assert na.ldap_plan(a) is None and na.ldap_plan(None) is None
    assert na.local_login_allowed(a, "user1")


def test_local_login_reserved_to_break_glass(tmp_path):
    a = access(tmp_path)
    assert na.local_login_allowed(a, "secours") and na.local_login_allowed(a, "admin")
    assert not na.local_login_allowed(a, "user1")
    assert na.local_login_allowed(None, "user1")  # configuration illisible : le plugin verrouille déjà


@pytest.mark.parametrize("ldaps,message", [
    ({**AD, "servers": ["ldap://dc01.ville.local"]}, "en clair"),
    ({**AD, "bind_password": "x"}, "AUSPEX_LDAP_BIND_PASSWORD"),
    ({**AD, "ignore_cert_errors": True}, "ne se désactive pas"),
    ({**AD, "user_search_base": "Utilisateurs"}, "user_search_base : DN attendu"),
    ({**AD, "user_attribute": "uid)(objectClass=*"}, "user_attribute"),
    ({**AD, "group_type": "nis"}, "group_type"),
    ({k: v for k, v in AD.items() if k != "group_search_base"}, "group_search_base : obligatoire"),
    ({**AD, "attributes": {"email": "mail)("}}, "attributes"),
    ({**AD, "ca_file": "absent.pem"}, "ca_file : fichier introuvable"),
    ({**AD, "servers": []}, "au moins un serveur"),
    (None, "section obligatoire"),
])
def test_ldaps_errors(tmp_path, ldaps, message):
    with pytest.raises(ConfigError, match=message):
        access(tmp_path, ldaps)


def test_ldaps_block_without_primary(tmp_path):
    with pytest.raises(ConfigError, match="n'est pas 'ldaps'"):
        access(tmp_path, primary=None)


# --- SAML -------------------------------------------------------------------------------

CERT = "MIIC" + "A" * 60 + "=="
METADATA = f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sso.ville.local/realms/r">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="encryption"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:X509Data><ds:X509Certificate>CHIFFREMENT</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:X509Data><ds:X509Certificate>
        {CERT[:30]}
        {CERT[30:]}
      </ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sso.ville.local/post"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sso.ville.local/saml"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""
SAML = {"sp_entity_id": "https://netbox.ville.local", "idp_metadata": "idp.xml", "label": "ADFS",
        "attributes": {"permanent_id": "uid", "username": "uid", "email": "mail"},
        "groups_attribute": "memberOf", "require_group": "auspex-utilisateurs"}


def saml(tmp_path, block=SAML, metadata=METADATA):
    (tmp_path / "idp.xml").write_text(metadata)
    raw = copy.deepcopy(BASE_CONFIG)
    raw["auth"] = {"primary": "saml", "break_glass": {"user": "secours", "mfa": "totp"}, "saml": copy.deepcopy(block)}
    return parse_config(raw, tmp_path).access


def test_metadata_parsing():
    md = na.parse_idp_metadata(METADATA)
    assert md == {"entity_id": "https://sso.ville.local/realms/r", "sso_url": "https://sso.ville.local/saml",
                  "x509cert": CERT}   # certificat de SIGNATURE, espaces retirés


@pytest.mark.parametrize("xml,message", [
    ("<pas-du-xml", "illisible"),
    (METADATA.replace("IDPSSODescriptor", "SPSSODescriptor"), "IDPSSODescriptor absent"),
    (METADATA.replace("HTTP-Redirect", "SOAP"), "HTTP-Redirect"),
    (METADATA.replace('use="signing"', 'use="encryption"'), "certificat de signature"),
    ('<!DOCTYPE x [<!ENTITY a "b">]>' + METADATA.split("?>", 1)[1], "entités interdites"),
])
def test_metadata_errors(xml, message):
    with pytest.raises(ValueError, match=message):
        na.parse_idp_metadata(xml)


def test_saml_settings(tmp_path):
    a = saml(tmp_path)
    assert na.remote_backend(a) == "social_core.backends.saml.SAMLAuth"
    s = na.social_settings(a, {})
    idp = s["SOCIAL_AUTH_SAML_ENABLED_IDPS"]["idp"]
    assert idp["entity_id"] == "https://sso.ville.local/realms/r" and idp["x509cert"] == CERT
    assert idp["attr_user_permanent_id"] == "uid" and idp["attr_email"] == "mail"
    assert "attr_first_name" not in idp and "attr_last_name" not in idp  # non configurés : absents
    assert s["SOCIAL_AUTH_SAML_SECURITY_CONFIG"]["wantAssertionsSigned"] is True
    assert s["SOCIAL_AUTH_SAML_SECURITY_CONFIG"]["rejectDeprecatedAlgorithm"] is True
    assert s["SOCIAL_AUTH_SAML_ASSOCIATE_BY_EMAIL"] is False
    assert na.sso_config(a).groups_claim == "memberOf" and na.sso_config(a).require_group == "auspex-utilisateurs"
    assert not na.local_login_allowed(a, "user1")


@pytest.mark.parametrize("block,metadata,message", [
    ({**SAML, "idp_metadata": "absent.xml"}, METADATA, "fichier introuvable"),
    ({k: v for k, v in SAML.items() if k != "idp_metadata"}, METADATA, "métadonnées du fournisseur obligatoire"),
    (SAML, METADATA.replace("https://sso.ville.local/saml", "http://sso.ville.local/saml"), "non chiffrée"),
    (SAML, METADATA.replace("https://sso.ville.local/saml", "https://sso:8443/saml"), "nom complet"),
    ({**SAML, "attributes": {"email": "mail"}}, METADATA, "permanent_id et username"),
    ({**SAML, "want_assertions_signed": False}, METADATA, "ne se désactive pas"),
    ({k: v for k, v in SAML.items() if k != "sp_entity_id"}, METADATA, "sp_entity_id"),
])
def test_saml_errors(tmp_path, block, metadata, message):
    with pytest.raises(ConfigError, match=message):
        saml(tmp_path, block, metadata)


# --- OIDC -------------------------------------------------------------------------------

ENTRA = {"issuer": "https://login.microsoftonline.com/0000-tenant/v2.0", "client_id": "auspex-netbox",
         "require_group": "auspex-utilisateurs", "label": "Microsoft"}


def oidc(tmp_path, block=ENTRA):
    raw = copy.deepcopy(BASE_CONFIG)
    raw["auth"] = {"primary": "oidc", "break_glass": {"user": "secours", "mfa": "totp"}, "oidc": copy.deepcopy(block)}
    return parse_config(raw, tmp_path).access


def test_oidc_settings(tmp_path):
    a = oidc(tmp_path)
    assert na.remote_backend(a) == "social_core.backends.open_id_connect.OpenIdConnectAuth"
    s = na.social_settings(a, {"AUSPEX_OIDC_CLIENT_SECRET": "s3cr3t"})
    assert s["SOCIAL_AUTH_OIDC_OIDC_ENDPOINT"] == ENTRA["issuer"]
    assert s["SOCIAL_AUTH_OIDC_KEY"] == "auspex-netbox" and s["SOCIAL_AUTH_OIDC_SECRET"] == "s3cr3t"
    assert s["SOCIAL_AUTH_OIDC_VERIFY_SSL"] is True                  # certificat vérifié
    assert s["SOCIAL_AUTH_OIDC_ASSOCIATE_BY_EMAIL"] is False
    pipeline = s["SOCIAL_AUTH_PIPELINE"]
    # Le refus hors du groupe exigé vient AVANT toute création de compte.
    assert pipeline.index("netbox_auspex.pipeline.require_group") < pipeline.index("social_core.pipeline.user.create_user")
    assert pipeline[-1] == "netbox_auspex.pipeline.sync_groups"
    assert not any("associate_by_email" in step for step in pipeline)
    assert s["SOCIAL_AUTH_BACKEND_ATTRS"]["oidc"][0] == "Microsoft"
    assert na.ldap_plan(a) is None and na.social_settings(access(tmp_path), {}) == {}
    assert not na.local_login_allowed(a, "user1") and na.local_login_allowed(a, "secours")


def test_oidc_internal_ca(tmp_path):
    (tmp_path / "ca.pem").write_text("x")
    s = na.social_settings(oidc(tmp_path, {**ENTRA, "ca_file": "ca.pem"}), {})
    assert s["SOCIAL_AUTH_OIDC_VERIFY_SSL"] == str(tmp_path / "ca.pem")


@pytest.mark.parametrize("block,message", [
    ({**ENTRA, "issuer": "http://idp.ville.local"}, "https://"),
    ({k: v for k, v in ENTRA.items() if k != "client_id"}, "client_id : obligatoire"),
    ({**ENTRA, "client_secret": "x"}, "AUSPEX_OIDC_CLIENT_SECRET"),
    ({**ENTRA, "verify_ssl": False}, "ne se désactive pas"),
    ({**ENTRA, "scopes": "groups"}, "scopes"),
    ({**ENTRA, "ca_file": "absent.pem"}, "ca_file : fichier introuvable"),
    (None, "section obligatoire"),
])
def test_oidc_errors(tmp_path, block, message):
    with pytest.raises(ConfigError, match=message):
        oidc(tmp_path, block)


def test_oidc_block_without_primary(tmp_path):
    raw = copy.deepcopy(BASE_CONFIG)
    raw["auth"] = {"break_glass": {"user": "secours", "mfa": "totp"}, "oidc": ENTRA}
    with pytest.raises(ConfigError, match="n'est pas 'oidc'"):
        parse_config(raw, tmp_path)


def test_ca_file(tmp_path):
    (tmp_path / "ca-ad.pem").write_text("x")
    assert na.ldap_plan(access(tmp_path, {**AD, "ca_file": "ca-ad.pem"}))["ca_file"] == str(tmp_path / "ca-ad.pem")
