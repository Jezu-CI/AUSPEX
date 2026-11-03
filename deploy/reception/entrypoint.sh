#!/bin/sh
# Réception des logs des capteurs.
#   - clé d'hôte créée au premier démarrage (data/reception/), son empreinte
#     est à donner aux capteurs : « auspex capteur empreinte » ;
#   - purge des logs reçus plus anciens que AUSPEX_LOGS_RETENTION_DAYS (30 j).
set -eu
D=/var/lib/reception
KEY="$D/ssh_host_ed25519_key"
if [ ! -f "$KEY" ]; then
    ssh-keygen -q -t ed25519 -N '' -C auspex-reception -f "$KEY"
fi
chmod 600 "$KEY"
echo "auspex-reception : clé d'hôte $(ssh-keygen -l -f "$KEY.pub" | cut -d' ' -f2)" >&2
[ -f /etc/auspex-reception/authorized_keys ] \
    || echo "auspex-reception : aucun capteur autorisé pour l'instant (sensors[].key dans auspex.yaml)" >&2

# Purge limitée aux dossiers des capteurs déclarés : les logs déposés à la
# main ailleurs dans logs/ ne sont jamais touchés.
DAYS="${AUSPEX_LOGS_RETENTION_DAYS:-30}"
( while true; do
      for name in $(sed -n 's/.* auspex:\([a-z0-9-]*\)$/\1/p' /etc/auspex-reception/authorized_keys 2>/dev/null); do
          [ -d "/logs/$name" ] && find "/logs/$name" -type f -mtime +"$DAYS" -delete 2>/dev/null || true
      done
      sleep 3600
  done ) &

exec /usr/sbin/sshd -D -e -f /etc/auspex-reception-sshd/sshd_config
