# Point d'entrée WSGI de Granian (serveur web de l'image NetBox depuis la 4.7),
# remplace celui de l'image (voir deploy/netbox/Dockerfile).
#
# SÉCURITÉ : celui de l'image enveloppe l'application dans
# wrap_wsgi_with_proxy_headers, qui remplace l'adresse source par le contenu
# de X-Forwarded-For pour toute machine des plages privées. N'importe quel
# poste du réseau interne pourrait alors usurper l'adresse d'un poste
# autorisé. Ici, aucune réécriture : le plugin Auspex voit l'adresse réelle et
# n'accepte l'en-tête que des proxys déclarés dans auspex.yaml.
from netbox.wsgi import application  # noqa: F401
