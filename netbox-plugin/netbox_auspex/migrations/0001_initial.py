from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [migrations.swappable_dependency(settings.AUTH_USER_MODEL)]

    operations = [
        migrations.CreateModel(
            name="TOTPDevice",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("secret", models.CharField(max_length=64)),
                ("last_counter", models.BigIntegerField(blank=True, null=True)),
                ("failures", models.PositiveSmallIntegerField(default=0)),
                ("locks", models.PositiveSmallIntegerField(default=0)),
                ("locked_until", models.FloatField(blank=True, null=True)),
                ("recovery_hashes", models.JSONField(blank=True, default=list)),
                ("created", models.DateTimeField(auto_now_add=True)),
                ("last_used", models.DateTimeField(blank=True, null=True)),
                ("user", models.OneToOneField(on_delete=models.deletion.CASCADE, related_name="auspex_totp",
                                              to=settings.AUTH_USER_MODEL)),
            ],
            options={"verbose_name": "appareil TOTP"},
        ),
    ]
