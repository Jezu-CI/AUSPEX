"""Doublure du backend LDAP de NetBox (pour simuler une session ouverte par l'annuaire)."""
from django.contrib.auth.backends import ModelBackend


class LDAPBackend(ModelBackend):
    def authenticate(self, request, **kwargs):  # jamais utilisé pour se connecter dans les tests
        return None
