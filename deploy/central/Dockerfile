# Image du central Auspex : moteur d'analyse, synchronisation NetBox, alertes.
# Construite depuis la racine du dépôt :
#   docker build -f deploy/central/Dockerfile -t auspex-central .
FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30

# git : installation des modules communautaires (versions épinglées)
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/auspex
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY rules ./rules
RUN pip install --no-cache-dir . && rm -rf /root/.cache

COPY deploy/central/entrypoint.sh /usr/local/bin/auspex-entrypoint
RUN chmod 0755 /usr/local/bin/auspex-entrypoint

ENV AUSPEX_RULES_DIR=/opt/auspex/rules \
    AUSPEX_CONFIG=/etc/auspex/auspex.yaml \
    HOME=/tmp \
    PYTHONUNBUFFERED=1

# Utilisateur non privilégié par défaut ; le compose le remplace par
# l'utilisateur qui a installé Auspex, propriétaire des répertoires montés.
USER 10001:10001
VOLUME ["/etc/auspex", "/var/lib/auspex"]

HEALTHCHECK --interval=60s --timeout=20s --start-period=10m --retries=3 \
  CMD auspex -c "$AUSPEX_CONFIG" health || exit 1

LABEL org.opencontainers.image.title="auspex-central" \
      org.opencontainers.image.description="Central Auspex : analyse, NetBox, alertes SIEM" \
      org.opencontainers.image.licenses="Apache-2.0"

ENTRYPOINT ["auspex-entrypoint"]
CMD ["daemon"]
