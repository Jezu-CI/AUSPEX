# Image NetBox du central : NetBox officiel + plugin Auspex.
# Construite depuis la racine du dépôt :
#   docker build -f deploy/netbox/Dockerfile --build-arg NETBOX_VERSION=v4.4 .
#
# Le plugin et le moteur Auspex sont du Python pur : ils sont copiés tels
# quels, sans téléchargement, pour qu'une mise à jour fonctionne aussi sur un
# site sans accès à Internet.
ARG NETBOX_VERSION=v4.4
FROM netboxcommunity/netbox:${NETBOX_VERSION}

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

# SÉCURITÉ : le serveur web de l'image (NGINX Unit) remplace l'adresse source
# par le contenu de X-Forwarded-For pour les sources qu'il juge de confiance.
# Toute machine de ces plages pourrait alors usurper l'adresse d'un poste
# autorisé. On supprime cette réécriture : le plugin voit l'adresse réelle et
# n'accepte l'en-tête que depuis les proxys déclarés dans auspex.yaml.
# Marque Auspex : logos, titre, charte « Scanner Auspex », mention « basé sur
# NetBox Community » (licence Apache 2.0). Échoue si les gabarits ont changé.
COPY deploy/netbox/branding /opt/auspex-lib/branding
COPY deploy/netbox/rebrand.py /opt/auspex-lib/rebrand.py
RUN /opt/netbox/venv/bin/python /opt/auspex-lib/rebrand.py /opt/netbox/netbox /opt/auspex-lib/branding
# Fichiers statiques du plugin (carte) : collectstatic de l'image a déjà eu lieu.
RUN cp -r /opt/auspex-lib/netbox_auspex/static/netbox_auspex /opt/netbox/netbox/static/

COPY deploy/netbox/unit_no_forwarded.py /opt/auspex-lib/unit_no_forwarded.py
RUN /opt/netbox/venv/bin/python /opt/auspex-lib/unit_no_forwarded.py /etc/unit/nginx-unit.json

LABEL org.opencontainers.image.title="auspex-netbox" \
      org.opencontainers.image.description="Interface Auspex : NetBox Community avec le plugin et la marque Auspex"
