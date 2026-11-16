"""Plugin NetBox : identification des jetons d'API pour le contrôle des adresses
(trusted hosts), comme NetBox 4.7 (jetons v2 « nbt_CLÉ.SECRET » et v1)."""

import sys
import types

import pytest

pytest.importorskip("django")

import django_harness  # noqa: E402,F401  (configure Django)
from netbox_auspex import middleware  # noqa: E402

V2_KEY, V2_SECRET, V1 = "AbCdEfGh1234", "s" * 40, "0123456789abcdef0123456789abcdef01234567"


class _Token:
    def __init__(self, version, user, key=None, plaintext=None, secret=None):
        self.version, self.user, self.key, self.plaintext, self._secret = version, user, key, plaintext, secret

    def validate(self, secret):
        return secret == self._secret


class _QS:
    def __init__(self, items):
        self.items = items

    def select_related(self, *a):
        return self

    def filter(self, **kw):
        return _QS([t for t in self.items if all(getattr(t, k) == v for k, v in kw.items())])

    def first(self):
        return self.items[0] if self.items else None


@pytest.fixture
def jetons(monkeypatch):
    tokens = [_Token(2, "user-v2", key=V2_KEY, secret=V2_SECRET), _Token(1, "user-v1", plaintext=V1)]
    module = types.ModuleType("users.models")
    module.Token = type("Token", (), {"objects": _QS(tokens)})
    monkeypatch.setitem(sys.modules, "users", types.ModuleType("users"))
    monkeypatch.setitem(sys.modules, "users.models", module)
    return tokens


@pytest.mark.parametrize("header, user", [
    (f"Bearer nbt_{V2_KEY}.{V2_SECRET}", "user-v2"),
    (f"bearer   nbt_{V2_KEY}.{V2_SECRET}", "user-v2"),
    (f"Token {V1}", "user-v1"),
    (f"Bearer {V1}", "user-v1"),          # NetBox : la version vient du préfixe, pas du mot-clé
    ("Basic dXNlcjpwYXNz", None),         # autre schéma : ignoré par NetBox comme ici
])
def test_token_identified_like_netbox(jetons, header, user):
    assert middleware._token_user(header) == user


@pytest.mark.parametrize("header", [
    f"Bearer nbt_{V2_KEY}.mauvais-secret",   # bonne clé, mauvais secret
    f"Bearer nbt_{V2_KEY}",                  # sans secret
    f"Token {V1[:-1]}x",
    f"Token nbt_{V2_KEY}.{V2_SECRET} de-trop",
    "Token",
])
def test_unknown_or_malformed_token_is_refused(jetons, header):
    """Refus par défaut : un jeton non identifié ici ne passe jamais sans contrôle d'adresse."""
    with pytest.raises(middleware._UnknownToken):
        middleware._token_user(header)
