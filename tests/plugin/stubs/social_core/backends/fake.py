"""Doublure d'un fournisseur d'identité (OIDC/SAML) : la MFA est la sienne."""
from django.contrib.auth.backends import ModelBackend


class FakeSSO(ModelBackend):
    pass
