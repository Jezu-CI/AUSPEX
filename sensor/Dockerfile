# Image du capteur Auspex : Zeek + parsers industriels ICSNPP.
#
# Le capteur ne fait qu'écouter : aucune adresse IP n'est nécessaire sur
# l'interface de capture, et le conteneur peut tourner avec --network none
# en lecture de captures. Les logs JSON sont écrits dans /logs ; en écoute
# continue, ils sont envoyés au central (SSH + rsync) si AUSPEX_CENTRAL est
# défini. Clé du capteur et réglages : /etc/auspex-capteur.

FROM zeek/zeek:lts@sha256:524cb0ce29f26a6a954fb9c357a8f92b95812476d8240f0ece26617ace249dd0

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential cmake git ca-certificates libpcap-dev \
      rsync openssh-client \
 && rm -rf /var/lib/apt/lists/*

# Parsers industriels de la CISA / INL. EtherNet/IP-CIP et S7comm sont
# indispensables (échec = image refusée) ; les autres enrichissent l'identification
# et leur absence est consignée (/opt/icsnpp-absents), sans bloquer la construction.
RUN zkg autoconfig --force \
 && zkg install --force --skiptests https://github.com/cisagov/icsnpp-enip \
 && zkg install --force --skiptests https://github.com/cisagov/icsnpp-s7comm
RUN for p in modbus dnp3 bacnet opcua-binary omron-fins hart-ip ge-srtp profinet-io-cm; do \
      zkg install --force --skiptests "https://github.com/cisagov/icsnpp-$p" >/dev/null 2>&1 \
        || echo "icsnpp-$p" >> /opt/icsnpp-absents; \
    done; touch /opt/icsnpp-absents

# JA4+ (FoxIO) n'est PAS embarqué : hors JA4 lui-même (BSD), les méthodes JA4+
# relèvent de la FoxIO License 1.1, qui interdit l'usage monétisé sans licence OEM.
# Aucune règle d'Auspex ne s'en servait ; à réévaluer avec une licence compatible.

COPY auspex.zeek live.zeek entrypoint.sh /opt/auspex/
RUN chmod 0755 /opt/auspex/entrypoint.sh

LABEL org.opencontainers.image.title="auspex-sensor" \
      org.opencontainers.image.description="Capteur passif Auspex : Zeek + ICSNPP" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /logs
ENTRYPOINT ["/opt/auspex/entrypoint.sh"]
CMD ["help"]
