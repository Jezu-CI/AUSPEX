# Image NetBox du central : NetBox officiel + plugin Auspex.
# Construite depuis la racine du dépôt :
#   docker build -f deploy/netbox/Dockerfile .
#
# Base : la version de NetBox livrée et testée avec Auspex, figée par son
# empreinte (tenue à jour par Dependabot, vérifiée par la CI). Une autre
# version choisie par l'administrateur (update.sh --netbox vX.Y.Z) est passée
# dans NETBOX_BASE et prise à son étiquette, sous sa responsabilité.
#
# Le plugin et le moteur Auspex sont du Python pur : ils sont copiés tels
# quels, sans téléchargement, pour qu'une mise à jour fonctionne aussi sur un
# site sans accès à Internet.
ARG NETBOX_BASE=netbox-livree
FROM netboxcommunity/netbox:v4.7@sha256:a521748a89c8966565bbf7832fd01caef2a122f46a21ccf7a7b7682dd3428839 AS netbox-livree
FROM ${NETBOX_BASE}

COPY src/auspex /opt/auspex-lib/auspex
COPY netbox-plugin/netbox_auspex /opt/auspex-lib/netbox_auspex
RUN SITE=$(/opt/netbox/venv/bin/python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])') \
 && echo /opt/auspex-lib > "$SITE/auspex.pth" \
 && /opt/netbox/venv/bin/python -c 'import yaml, auspex.access, auspex.mfa, auspex.netbox_auth, auspex.qrcode, netbox_auspex; print("plugin Auspex installé")'

COPY deploy/netbox/plugins.py /etc/netbox/config/plugins.py

# Annuaire (LDAPS) : la configuration vient d'auspex.yaml. NetBox lit le
# module netbox/ldap_config.py ; on remplace celui de l'image (fichier ou lien).
COPY deploy/netbox/ldap_config.py /opt/auspex-lib/ldap_config.py
RUN rm -f /opt/netbox/netbox/netbox/ldap_config.py \
 && cp /opt/auspex-lib/ldap_config.py /opt/netbox/netbox/netbox/ldap_config.py \
 && mkdir -p /etc/netbox/config/ldap \
 && cp /opt/auspex-lib/ldap_config.py /etc/netbox/config/ldap/ldap_config.py \
 && /opt/netbox/venv/bin/python -c 'import ldap, django_auth_ldap.config; print("LDAP disponible")' \
 && /opt/netbox/venv/bin/python -c 'import social_core.backends.open_id_connect, netbox_auspex.pipeline; print("OIDC disponible")'

# Marque Auspex : logos, titre, charte « Scanner Auspex », mention « basé sur
# NetBox Community » (licence Apache 2.0). Échoue si les gabarits ont changé.
COPY deploy/netbox/branding /opt/auspex-lib/branding
COPY deploy/netbox/rebrand.py /opt/auspex-lib/rebrand.py
RUN /opt/netbox/venv/bin/python /opt/auspex-lib/rebrand.py /opt/netbox/netbox /opt/auspex-lib/branding
# Fichiers statiques du plugin (carte) : collectstatic de l'image a déjà eu lieu.
RUN cp -r /opt/auspex-lib/netbox_auspex/static/netbox_auspex /opt/netbox/netbox/static/

# SÉCURITÉ : le serveur web de l'image (Granian) remplace l'adresse source par
# le contenu de X-Forwarded-For pour toute machine des plages privées : un
# poste du réseau interne pourrait usurper l'adresse d'un poste autorisé. Son
# point d'entrée est remplacé par un point d'entrée sans cette réécriture : le
# plugin voit l'adresse réelle et n'accepte l'en-tête que des proxys déclarés
# dans auspex.yaml. La construction échoue si l'image n'a plus la forme
# attendue : mieux vaut une image en erreur qu'un contournement silencieux.
COPY deploy/netbox/granian.py /opt/auspex-lib/granian.py
RUN grep -q 'netbox.granian:application' /opt/netbox/launch-netbox.sh \
 && grep -q 'wrap_wsgi_with_proxy_headers' /opt/netbox/netbox/netbox/granian.py \
 && cp /opt/auspex-lib/granian.py /opt/netbox/netbox/netbox/granian.py \
 && ! grep -qi 'proxy\|forwarded' /opt/netbox/launch-netbox.sh \
 && ! grep -v '^#' /opt/netbox/netbox/netbox/granian.py | grep -qi 'proxy\|forwarded' \
 && echo "Granian : réécriture par X-Forwarded-For supprimée"

LABEL org.opencontainers.image.title="auspex-netbox" \
      org.opencontainers.image.description="Interface Auspex : NetBox Community avec le plugin et la marque Auspex"
