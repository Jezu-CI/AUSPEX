"""Tests du plugin NetBox avec un vrai Django (sans NetBox : doublures dans stubs/).

Importé par les fichiers de test après pytest.importorskip("django").
"""
import pathlib
import sys

import django

if True:
    HERE = pathlib.Path(__file__).parent
    sys.path[:0] = [str(HERE / "stubs"), str(HERE.parent.parent / "netbox-plugin")]
    from django.conf import settings

    if not settings.configured:
        settings.configure(
            SECRET_KEY="tests-seulement",
            ALLOWED_HOSTS=["testserver"],
            INSTALLED_APPS=["django.contrib.auth", "django.contrib.contenttypes", "django.contrib.sessions",
                            "netbox_auspex.AuspexConfig"],
            DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
            MIDDLEWARE=["django.contrib.sessions.middleware.SessionMiddleware",
                        "django.middleware.csrf.CsrfViewMiddleware",
                        "django.contrib.auth.middleware.AuthenticationMiddleware",
                        "netbox_auspex.mfa.MFARequiredMiddleware"],
            ROOT_URLCONF="plugin_urls",
            TEMPLATES=[{"BACKEND": "django.template.backends.django.DjangoTemplates", "APP_DIRS": True,
                        "DIRS": [str(HERE / "stubs" / "templates")]}],
            AUTHENTICATION_BACKENDS=["django.contrib.auth.backends.ModelBackend",
                                     "social_core.backends.fake.FakeSSO",
                                     "netbox.authentication.LDAPBackend",
                                     "netbox_auspex.carte.CarteBackend"],
            DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
            STATIC_URL="/static/",
            USE_TZ=True,
            PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"],
        )
        django.setup()
