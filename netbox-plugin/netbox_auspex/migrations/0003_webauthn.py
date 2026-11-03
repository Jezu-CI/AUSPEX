from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("netbox_auspex", "0002_method"), migrations.swappable_dependency(settings.AUTH_USER_MODEL)]

    operations = [
        migrations.AlterField(
            model_name="totpdevice",
            name="method",
            field=models.CharField(choices=[("totp", "application"), ("email", "e-mail"),
                                            ("webauthn", "clé de sécurité")], default="totp", max_length=8),
        ),
        migrations.CreateModel(
            name="WebAuthnKey",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("credential_id", models.CharField(max_length=1400, unique=True)),
                ("public_key", models.TextField()),
                ("sign_count", models.BigIntegerField(default=0)),
                ("name", models.CharField(default="clé de sécurité", max_length=64)),
                ("created", models.DateTimeField(auto_now_add=True)),
                ("last_used", models.DateTimeField(blank=True, null=True)),
                ("user", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="auspex_webauthn",
                                           to=settings.AUTH_USER_MODEL)),
            ],
            options={"verbose_name": "clé de sécurité", "ordering": ("created",)},
        ),
    ]
