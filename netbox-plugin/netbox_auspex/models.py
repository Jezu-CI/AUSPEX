"""Données du plugin : inscription MFA de chaque utilisateur, clés de sécurité."""

from django.conf import settings
from django.db import models


class TOTPDevice(models.Model):
    """Inscription à la double authentification d'un utilisateur : application
    (TOTP) ou code par e-mail.

    Le secret est en base, comme les empreintes de mots de passe de NetBox :
    la base est déjà l'élément à protéger. Les codes de secours ne sont
    conservés que sous forme d'empreinte.
    """

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                                related_name="auspex_totp")
    method = models.CharField(max_length=8, default="totp",
                              choices=[("totp", "application"), ("email", "e-mail"),
                                       ("webauthn", "clé de sécurité")])
    secret = models.CharField(max_length=64, blank=True)               # vide pour l'e-mail
    last_counter = models.BigIntegerField(null=True, blank=True)   # anti-rejeu
    failures = models.PositiveSmallIntegerField(default=0)
    locks = models.PositiveSmallIntegerField(default=0)            # verrouillages successifs
    locked_until = models.FloatField(null=True, blank=True)        # horodatage Unix
    recovery_hashes = models.JSONField(default=list, blank=True)
    created = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "appareil TOTP"

    def __str__(self):
        return f"TOTP de {self.user}"


class WebAuthnKey(models.Model):
    """Clé de sécurité (FIDO2, Windows Hello, Touch ID) d'un utilisateur.

    Seule la clé publique est conservée : la base ne contient rien qui permette
    de se faire passer pour l'utilisateur."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="auspex_webauthn")
    credential_id = models.CharField(max_length=1400, unique=True)      # base64url
    public_key = models.TextField()                                      # COSE, base64url
    sign_count = models.BigIntegerField(default=0)
    name = models.CharField(max_length=64, default="clé de sécurité")
    created = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "clé de sécurité"
        ordering = ("created",)

    def __str__(self):
        return f"{self.name} ({self.user})"
