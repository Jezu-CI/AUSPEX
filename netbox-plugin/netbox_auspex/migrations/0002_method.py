from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("netbox_auspex", "0001_initial")]

    operations = [
        migrations.AddField(
            model_name="totpdevice",
            name="method",
            field=models.CharField(choices=[("totp", "application"), ("email", "e-mail")], default="totp",
                                   max_length=8),
        ),
        migrations.AlterField(
            model_name="totpdevice",
            name="secret",
            field=models.CharField(blank=True, max_length=64),
        ),
    ]
