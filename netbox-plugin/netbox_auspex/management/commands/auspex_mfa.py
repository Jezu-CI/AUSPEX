"""Administration de la double authentification (dans le conteneur NetBox) :

    manage.py auspex_mfa status              qui est inscrit, qui est verrouillé
    manage.py auspex_mfa reset  <utilisateur> téléphone ou clé perdus : nouvelle inscription
                                              (les clés de sécurité inscrites sont révoquées)
    manage.py auspex_mfa unlock <utilisateur> lever un verrouillage après échecs
"""

import json
import logging
import time

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from netbox_auspex.models import TOTPDevice, WebAuthnKey

logger = logging.getLogger("netbox_auspex")


class Command(BaseCommand):
    help = "Double authentification Auspex : status, reset <utilisateur>, unlock <utilisateur>"

    def add_arguments(self, parser):
        parser.add_argument("action", choices=["status", "reset", "unlock"])
        parser.add_argument("username", nargs="?")

    def handle(self, *args, action, username=None, **options):
        if action == "status":
            now = time.time()
            for d in TOTPDevice.objects.select_related("user").order_by("user__username"):
                state = "verrouillé" if d.locked_until and d.locked_until > now else "actif"
                keys = WebAuthnKey.objects.filter(user=d.user).count()
                self.stdout.write(f"{d.user.username}\t{d.get_method_display()}\tinscrit le {d.created:%Y-%m-%d}\t"
                                  f"{state}\t{len(d.recovery_hashes)} code(s) de secours"
                                  + (f"\t{keys} clé(s) de sécurité" if keys else ""))
            return
        if not username:
            raise CommandError(f"{action} : nom d'utilisateur attendu")
        user = get_user_model().objects.filter(username=username).first()
        if user is None:
            raise CommandError(f"utilisateur inconnu : {username}")
        device = TOTPDevice.objects.filter(user=user).first()
        if device is None:
            raise CommandError(f"{username} n'est pas inscrit à la double authentification")
        if action == "reset":
            # Les clés de sécurité aussi : une clé perdue ne doit plus jamais servir.
            keys, _ = WebAuthnKey.objects.filter(user=user).delete()
            device.delete()
            msg = (f"{username} : double authentification réinitialisée"
                   + (f", {keys} clé(s) de sécurité révoquée(s)" if keys else "")
                   + ", nouvelle inscription à la prochaine connexion")
        else:
            device.failures, device.locks, device.locked_until = 0, 0, None
            device.save()
            msg = f"{username} : verrouillage levé"
        logger.warning(json.dumps({"event": f"auspex_mfa_{action}", "user": username, "by": "manage.py"},
                                  ensure_ascii=False))
        self.stdout.write(msg)
