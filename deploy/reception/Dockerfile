# Réception des logs des capteurs : SSH + rsync en écriture seule.
#
# Tourne sans privilèges (compte « capteur », même UID que le service Auspex
# pour partager le dossier des logs), système en lecture seule. Chaque
# capteur est cantonné à son dossier par la commande imposée de sa clé
# (fichier généré par Auspex depuis auspex.yaml).

FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3

ARG UID=10001
ARG GID=10001
RUN test "$UID" != 0 || { echo "UID 0 refusé : la réception ne tourne jamais en root" >&2; exit 1; }

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server rsync python3 \
 && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* \
 && test -x /usr/bin/rrsync \
 && (getent group "$GID" >/dev/null || groupadd -g "$GID" capteur) \
 && useradd -o -u "$UID" -g "$GID" -d /var/lib/reception -M -s /bin/sh capteur \
 && usermod -p '*' capteur

COPY deploy/reception/sshd_config /etc/auspex-reception-sshd/sshd_config
COPY deploy/reception/auspex-recevoir deploy/reception/entrypoint.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/auspex-recevoir /usr/local/bin/entrypoint.sh

LABEL org.opencontainers.image.title="auspex-reception" \
      org.opencontainers.image.description="Réception des logs des capteurs Auspex (SSH, rsync en écriture seule)" \
      org.opencontainers.image.licenses="Apache-2.0"

USER capteur
EXPOSE 2222
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
