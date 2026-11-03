#!/bin/sh
# Front HTTPS d'Auspex : configuration rendue dans /tmp (système en lecture
# seule), puis rechargée quand Auspex réécrit le bloc carte (auth.carte).
set -eu
SRC=/etc/auspex-acces             # écrit par Auspex (auspex apply / service)
PORT="${AUSPEX_HTTPS_PORT:-443}"
SUFFIX=""
[ "$PORT" = 443 ] || SUFFIX=":$PORT"

if [ "${#AUSPEX_PROXY_SECRET}" -lt 32 ]; then
    echo "auspex-acces : AUSPEX_PROXY_SECRET absent ou trop court (.env)" >&2
    exit 1
fi
case "$AUSPEX_PROXY_SECRET" in *[!0-9a-f]*) echo "auspex-acces : AUSPEX_PROXY_SECRET : hexadécimal attendu" >&2; exit 1 ;; esac
for f in serveur.crt serveur.key; do
    [ -r "/etc/auspex-front/$f" ] || { echo "auspex-acces : tls/$f introuvable ou illisible" >&2; exit 1; }
done

render() {
    sed "s/@@HTTPS_SUFFIX@@/$SUFFIX/g" /etc/auspex-acces-image/nginx.conf > /tmp/nginx.conf
    if [ -s "$SRC/carte.conf" ]; then
        sed -e "s/@@SECRET@@/$AUSPEX_PROXY_SECRET/g" -e "s/@@HTTPS_SUFFIX@@/$SUFFIX/g" "$SRC/carte.conf" > /tmp/carte.conf
    else
        : > /tmp/carte.conf
    fi
}
signature() { cat "$SRC"/* 2>/dev/null | md5sum | cut -d' ' -f1; }

render
nginx -t -q -c /tmp/nginx.conf
( last=$(signature)
  while sleep 20; do
      now=$(signature)
      [ "$now" = "$last" ] && continue
      render
      if nginx -t -q -c /tmp/nginx.conf; then
          nginx -s reload -c /tmp/nginx.conf
          echo "auspex-acces : configuration rechargée (port carte $([ -s /tmp/carte.conf ] && echo actif || echo inactif))" >&2
      else
          echo "auspex-acces : nouvelle configuration refusée par nginx, ancienne conservée" >&2
      fi
      last=$now
  done ) &
echo "auspex-acces : HTTPS prêt (port carte $([ -s /tmp/carte.conf ] && echo actif || echo inactif))" >&2
exec nginx -c /tmp/nginx.conf -g 'daemon off;'
