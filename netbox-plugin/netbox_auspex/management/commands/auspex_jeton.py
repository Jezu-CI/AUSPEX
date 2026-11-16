"""Met en place un jeton d'API dont la valeur est imposée (dans le conteneur NetBox) :

    printf '%s' "$JETON" | manage.py auspex_jeton admin
    printf '%s' "$JETON" | manage.py auspex_jeton Librarian --creer

La valeur est lue sur l'entrée standard, jamais en argument (elle serait
visible dans la liste des processus). Utilisé par install.sh et update.sh :
depuis NetBox 4.7, l'API crée elle-même la valeur des jetons, et Auspex doit
connaître d'avance ceux de l'administrateur et de Librarian (rangés dans
.env).

- « nbt_CLÉ.SECRET » : jeton v2 (NetBox ne garde qu'une empreinte du secret,
  calculée avec le poivre API_TOKEN_PEPPER_1) ;
- 40 caractères hexadécimaux : jeton v1, celui des installations antérieures,
  toujours accepté par NetBox 4.7.

Sans effet si le jeton est déjà en place pour cet utilisateur. --creer crée
l'utilisateur s'il n'existe pas (compte de service sans mot de passe
utilisable, sans droit : ses permissions sont posées par
« auspex netbox setup --apply »).
"""

import json
import logging
import re
import sys

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

logger = logging.getLogger("netbox_auspex")

V2 = re.compile(r"^nbt_([A-Za-z0-9]{12})\.([A-Za-z0-9]{40,})$")
V1 = re.compile(r"^[0-9a-f]{40}$")
DESCRIPTIONS = {"Librarian": "Auspex : compte de service Librarian"}


class Command(BaseCommand):
    help = "Jeton d'API à valeur imposée (lue sur l'entrée standard) pour un utilisateur"

    def add_arguments(self, parser):
        parser.add_argument("username")
        parser.add_argument("--creer", action="store_true",
                            help="créer l'utilisateur (compte de service, sans droit) s'il n'existe pas")

    def handle(self, *args, username, creer=False, **options):
        from users.choices import TokenVersionChoices
        from users.models import Token

        valeur = sys.stdin.readline().strip()
        v2, v1 = V2.match(valeur), V1.match(valeur)
        if not (v2 or v1):
            raise CommandError("jeton attendu sur l'entrée standard : « nbt_CLÉ.SECRET » (v2) "
                               "ou 40 caractères hexadécimaux (v1)")
        User = get_user_model()
        with transaction.atomic():
            user = User.objects.filter(username=username).first()
            if user is None:
                if not creer:
                    raise CommandError(f"utilisateur inconnu : {username}")
                user = User(username=username, first_name=username, last_name="(compte de service Auspex)",
                            is_active=True, is_superuser=False)
                user.set_unusable_password()
                user.save()
                self.stdout.write(f"{username} : utilisateur créé (sans droit)")
            if v2:
                cle, secret = v2.groups()
                existant = Token.objects.filter(version=TokenVersionChoices.V2, key=cle).first()
            else:
                existant = Token.objects.filter(version=TokenVersionChoices.V1, plaintext=valeur).first()
            if existant is not None:
                if existant.user_id != user.pk:
                    raise CommandError(f"ce jeton appartient à un autre utilisateur que {username} : refusé")
                if existant.is_active and existant.validate(secret if v2 else valeur):
                    self.stdout.write(f"{username} : jeton déjà en place")
                    return
                existant.delete()   # même clé, autre secret, ou jeton désactivé : remplacé
            jeton = Token(user=user, version=TokenVersionChoices.V2 if v2 else TokenVersionChoices.V1,
                          key=cle if v2 else None, token=secret if v2 else valeur, write_enabled=True,
                          description=DESCRIPTIONS.get(username, "Auspex : mise en place"))
            jeton.full_clean()
            jeton.save()
        logger.warning(json.dumps({"event": "auspex_jeton", "user": username, "version": 2 if v2 else 1,
                                   "by": "manage.py"}, ensure_ascii=False))
        self.stdout.write(f"{username} : jeton v{2 if v2 else 1} en place")
