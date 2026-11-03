# Composants tiers

Auspex est publié sous licence GNU AGPL v3 (voir [LICENSE](LICENSE) et
[NOTICE](NOTICE)). Toutes les licences ci-dessous sont compatibles avec elle. Il
s'appuie sur des composants tiers, chacun sous sa propre licence, qui reste
la leur. Ce dépôt ne contient le code d'aucun d'eux : les images Docker et
l'ISO du capteur les téléchargent depuis leurs sources officielles à la
construction.

## Bibliothèques Python (paquet `auspex`)

| Composant | Licence | Usage |
| --- | --- | --- |
| PyYAML | MIT | lecture de `auspex.yaml` et des règles |
| openpyxl | MIT | import des règles de flux XLSX |
| cryptography | Apache 2.0 ou BSD | signatures Ed25519, certificats |

Tests seulement : pytest (MIT), Django (BSD), zxing-cpp (Apache 2.0),
NumPy (BSD).

## Central (docker compose)

| Composant | Licence | Image |
| --- | --- | --- |
| NetBox | Apache 2.0 | `netboxcommunity/netbox` (netbox-docker, Apache 2.0) |
| PostgreSQL | PostgreSQL License | `postgres:16-alpine` |
| Valkey | BSD 3-Clause | `valkey/valkey:8-alpine` |
| nginx | BSD 2-Clause | `nginxinc/nginx-unprivileged:1.27-alpine` |
| OpenSSH, rsync | BSD / GPL v3 | paquets Debian de l'image de réception |
| Python | PSF | `python:3.12-slim` |

## Capteur et appliance

| Composant | Licence | Usage |
| --- | --- | --- |
| Zeek | BSD 3-Clause | analyse du trafic (`zeek/zeek:lts`) |
| Parsers ICSNPP (CISA / INL) | BSD 3-Clause | EtherNet/IP-CIP, S7comm, Modbus, DNP3, BACnet, OPC UA, FINS, HART-IP, GE-SRTP, PROFINET |
| Debian 12 et live-build | licences libres de la distribution | système de l'appliance |

**JA4+ n'est pas embarqué.** Hors JA4 (BSD 3-Clause), les méthodes JA4+ de
FoxIO (JA4S, JA4H, JA4X, JA4SSH…) relèvent de la FoxIO License 1.1, qui
n'autorise pas l'usage monétisé sans licence OEM : incompatible avec l'usage
libre, y compris commercial, que permet la licence d'Auspex.

## Données

- Préfixes MAC (`rules/oui.yaml`) : sous-ensemble du registre public de
  l'IEEE.
- Captures industrielles publiques utilisées par la CI (dépôt
  automayt/ICS-pcap : 4SICS / Netresec, digitalbond, Wireshark…) :
  **téléchargées au moment du test, non redistribuées**.
- Logs de démonstration (`examples/demo`) : générés, aucune donnée réelle.
