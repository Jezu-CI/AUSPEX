"""Traduction de la section `auth` d'auspex.yaml en réglages NetBox.

Lu au démarrage de NetBox (deploy/netbox/plugins.py et ldap_config.py) : ce
module ne dépend ni de NetBox ni de django-auth-ldap, et se teste seul.
Après une modification de `auth`, NetBox doit être redémarré.
"""

from __future__ import annotations

from .config import AccessConfig

LOCAL_BACKEND = "netbox.authentication.ObjectPermissionBackend"  # toujours présent (brise-glace)
DEFAULT_REMOTE_BACKEND = "netbox.authentication.RemoteUserBackend"  # valeur par défaut de NetBox, inerte
LDAP_BACKEND = "netbox.authentication.LDAPBackend"
LDAP_PASSWORD_ENV = "AUSPEX_LDAP_BIND_PASSWORD"
OIDC_BACKEND = "social_core.backends.open_id_connect.OpenIdConnectAuth"
OIDC_SECRET_ENV = "AUSPEX_OIDC_CLIENT_SECRET"
SAML_BACKEND = "social_core.backends.saml.SAMLAuth"
SAML_IDP_NAME = "idp"  # nom interne du fournisseur (?idp=idp)
CARD_BACKEND = "netbox_auspex.carte.CarteBackend"  # carte à puce (certificat vérifié par le front HTTPS)

# Chaîne de connexion SSO de NetBox, avec deux étapes Auspex : refus hors du
# groupe exigé (avant toute création de compte), puis recopie des groupes.
SOCIAL_PIPELINE = (
    "social_core.pipeline.social_auth.social_details",
    "social_core.pipeline.social_auth.social_uid",
    "netbox_auspex.pipeline.require_group",
    "social_core.pipeline.social_auth.social_user",
    "social_core.pipeline.user.get_username",
    "social_core.pipeline.user.create_user",
    "social_core.pipeline.social_auth.associate_user",
    "netbox.authentication.user_default_groups_handler",
    "social_core.pipeline.social_auth.load_extra_data",
    "social_core.pipeline.user.user_details",
    "netbox_auspex.pipeline.sync_groups",
)

# Backends qui authentifient un compte LOCAL de NetBox (mot de passe en base).
LOCAL_BACKENDS = {LOCAL_BACKEND, "django.contrib.auth.backends.ModelBackend"}

_GROUP_FILTERS = {
    "active_directory": "(objectClass=group)",
    "group_of_names": "(objectClass=groupOfNames)",
    "posix": "(objectClass=posixGroup)",
}
_GROUP_TYPES = {
    "active_directory": "NestedActiveDirectoryGroupType",   # groupes imbriqués d'AD
    "group_of_names": "GroupOfNamesType",
    "posix": "PosixGroupType",
}


def remote_backend(access: AccessConfig | None) -> str:
    """REMOTE_AUTH_BACKEND de NetBox (le backend local reste toujours actif)."""
    if access is not None and access.auth_primary == "ldaps" and access.ldap is not None:
        return LDAP_BACKEND
    if access is not None and access.auth_primary == "oidc" and access.oidc is not None:
        return OIDC_BACKEND
    if access is not None and access.auth_primary == "saml" and access.saml is not None:
        return SAML_BACKEND
    return DEFAULT_REMOTE_BACKEND


def auth_backends(access: AccessConfig | None) -> list[str]:
    """REMOTE_AUTH_BACKEND de NetBox : méthode principale, plus la carte à puce si configurée."""
    backends = [remote_backend(access)]
    if access is not None and access.card is not None:
        backends.append(CARD_BACKEND)
    return backends


def sso_config(access: AccessConfig | None):
    """Configuration du fournisseur d'identité actif (OIDC ou SAML), ou None."""
    if access is None:
        return None
    return {"oidc": access.oidc, "saml": access.saml}.get(access.auth_primary)


_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
_DS = "http://www.w3.org/2000/09/xmldsig#"
_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"


def parse_idp_metadata(xml_text: str) -> dict:
    """Métadonnées SAML du fournisseur (fichier exporté d'ADFS, Entra, Keycloak...)
    → identifiant, adresse de connexion, certificat de signature.

    Lève ValueError si un de ces éléments manque.
    """
    import xml.etree.ElementTree as ET
    if "<!ENTITY" in xml_text or "<!DOCTYPE" in xml_text:
        raise ValueError("DTD ou entités interdites dans les métadonnées")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"XML illisible ({exc})") from None
    entity = root if root.tag == f"{{{_MD}}}EntityDescriptor" else root.find(f".//{{{_MD}}}EntityDescriptor")
    if entity is None or not entity.get("entityID"):
        raise ValueError("EntityDescriptor/entityID absent")
    idp = entity.find(f"{{{_MD}}}IDPSSODescriptor")
    if idp is None:
        raise ValueError("ce n'est pas un fournisseur d'identité (IDPSSODescriptor absent)")
    sso = [e.get("Location") for e in idp.findall(f"{{{_MD}}}SingleSignOnService") if e.get("Binding") == _REDIRECT]
    if not sso or not sso[0]:
        raise ValueError("adresse de connexion (SingleSignOnService, liaison HTTP-Redirect) absente")
    certs = [k.findtext(f".//{{{_DS}}}X509Certificate") for k in idp.findall(f"{{{_MD}}}KeyDescriptor")
             if k.get("use") in (None, "signing")]
    certs = ["".join(c.split()) for c in certs if c and c.strip()]
    if not certs:
        raise ValueError("certificat de signature (KeyDescriptor use=signing) absent")
    return {"entity_id": entity.get("entityID"), "sso_url": sso[0], "x509cert": certs[0]}


def social_settings(access: AccessConfig | None, environ: dict) -> dict:
    """Réglages SOCIAL_AUTH_* de NetBox pour OIDC ou SAML (vide sinon)."""
    if access is not None and access.auth_primary == "saml" and access.saml is not None:
        return _saml_settings(access.saml)
    if access is None or access.auth_primary != "oidc" or access.oidc is None:
        return {}
    c = access.oidc
    out = {
        "SOCIAL_AUTH_OIDC_OIDC_ENDPOINT": c.issuer,
        "SOCIAL_AUTH_OIDC_KEY": c.client_id,
        "SOCIAL_AUTH_OIDC_SECRET": environ.get(OIDC_SECRET_ENV, ""),
        "SOCIAL_AUTH_OIDC_SCOPE": list(c.scopes),
        # Certificat du fournisseur : toujours vérifié ; autorité interne possible.
        "SOCIAL_AUTH_OIDC_VERIFY_SSL": c.ca_file or True,
        "SOCIAL_AUTH_BACKEND_ATTRS": {"oidc": (c.label, "login")},
        "SOCIAL_AUTH_PIPELINE": SOCIAL_PIPELINE,
        # Jamais de rattachement d'un compte existant par l'adresse e-mail.
        "SOCIAL_AUTH_OIDC_ASSOCIATE_BY_EMAIL": False,
    }
    return out


def ldap_plan(access: AccessConfig | None) -> dict | None:
    """Réglages django-auth-ldap, en valeurs simples (ldap_config.py les traduit
    en objets). None si l'annuaire n'est pas la méthode principale."""
    if access is None or access.auth_primary != "ldaps" or access.ldap is None:
        return None
    c = access.ldap
    plan = {
        "server_uri": " ".join(c.servers),
        "start_tls": c.start_tls,
        "bind_dn": c.bind_dn or "",
        "bind_password_env": LDAP_PASSWORD_ENV,
        "ca_file": c.ca_file,
        "user_search": (c.user_search_base, f"({c.user_attribute}=%(user)s)"),
        "user_attr_map": dict(c.attributes),
        "group_search": None,
        "group_type": None,
        "require_group": c.require_group,
        "superuser_group": c.superuser_group,
    }
    if c.group_search_base:
        plan["group_search"] = (c.group_search_base, _GROUP_FILTERS[c.group_type])
        plan["group_type"] = _GROUP_TYPES[c.group_type]
    return plan


def local_login_allowed(access: AccessConfig | None, username: str, local_admins=("admin",)) -> bool:
    """Avec une méthode principale, seuls le brise-glace et l'administrateur
    local peuvent encore se connecter avec un compte local de NetBox."""
    if access is None or access.auth_primary is None:
        return True
    return username in set(local_admins) | ({access.break_glass_user} if access.break_glass_user else set())


def _saml_settings(c) -> dict:
    contact = {"givenName": "Auspex", "emailAddress": c.contact}
    a = c.attributes
    return {
        "SOCIAL_AUTH_SAML_SP_ENTITY_ID": c.sp_entity_id,
        # Demandes non signées : la sécurité repose sur la signature des
        # assertions du fournisseur, exigée et vérifiée ci-dessous.
        "SOCIAL_AUTH_SAML_SP_PUBLIC_CERT": "",
        "SOCIAL_AUTH_SAML_SP_PRIVATE_KEY": "",
        "SOCIAL_AUTH_SAML_ORG_INFO": {"en-US": {"name": "auspex", "displayname": "Auspex", "url": c.sp_entity_id}},
        "SOCIAL_AUTH_SAML_TECHNICAL_CONTACT": contact,
        "SOCIAL_AUTH_SAML_SUPPORT_CONTACT": contact,
        "SOCIAL_AUTH_SAML_ENABLED_IDPS": {SAML_IDP_NAME: {
            "entity_id": c.idp_entity_id, "url": c.idp_sso_url, "x509cert": c.idp_cert,
            "attr_user_permanent_id": a["permanent_id"], "attr_username": a["username"],
            # Attributs facultatifs : seulement s'ils sont configurés (un attribut
            # déclaré mais absent de l'assertion fait échouer la connexion).
            **{f"attr_{k}": a[k] for k in ("email", "first_name", "last_name") if a.get(k)},
        }},
        "SOCIAL_AUTH_SAML_SECURITY_CONFIG": {
            "wantAssertionsSigned": True,           # assertion signée par le fournisseur, sinon refus
            "rejectDeprecatedAlgorithm": True,      # pas de SHA-1
            "requestedAuthnContext": False,
        },
        "SOCIAL_AUTH_BACKEND_ATTRS": {"saml": (c.label, "login")},
        "SOCIAL_AUTH_PIPELINE": SOCIAL_PIPELINE,
        "SOCIAL_AUTH_SAML_ASSOCIATE_BY_EMAIL": False,
    }
