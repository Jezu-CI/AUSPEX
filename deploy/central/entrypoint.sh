#!/bin/sh
# Point d'entrée du central Auspex.
#   daemon       (défaut) service : à chaque cycle, rend le déploiement
#                conforme à auspex.yaml, puis analyse, met NetBox à jour et
#                alerte. Tant que le déploiement n'est pas conforme (NetBox
#                pas encore démarré, jeton absent...), l'analyse est suspendue
#                et la cause est visible dans « auspex health ».
#   <commande>   toute autre commande auspex (plan, findings, backup...)
set -eu
CONFIG="${AUSPEX_CONFIG:-/etc/auspex/auspex.yaml}"

if [ "${1:-daemon}" = "daemon" ]; then
    exec auspex -c "$CONFIG" daemon --apply \
        --logs "${AUSPEX_LOGS:-/var/lib/auspex/logs}" --interval "${AUSPEX_INTERVAL:-300}"
fi

exec auspex -c "$CONFIG" "$@"
