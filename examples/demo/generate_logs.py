#!/usr/bin/env python3
"""Génère des logs Zeek synthétiques (JSON) pour un petit site IT/OT.

Scénario sur 7 jours :
- un contrôleur de domaine, un serveur de fichiers, un serveur web Ubuntu ;
- des postes Windows (dont un VM Hyper-V) qui naviguent et s'authentifient ;
- un bastion d'administration ;
- un atelier : automate Siemens S7, automate Rockwell (EtherNet/IP), IHM ;
- un SSH ouvert depuis le bastion vers le serveur web pour un dépannage,
  jamais refermé (flux non déclaré persistant) ;
- un poste qui fait du RDP vers le contrôleur de domaine (violation du modèle en tiers) ;
- un serveur qui interroge directement l'automate en Modbus (contournement de la DMZ OT) ;
- un accès prestataire SSH vers l'atelier couvert par une règle expirée.

Usage : python generate_logs.py RÉPERTOIRE_DE_SORTIE [--days 7]
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

START = datetime(2026, 10, 20, 7, 0, tzinfo=timezone.utc)

DC, FILES, WEB = "10.0.0.5", "10.1.0.20", "10.1.0.80"
APP = "10.1.0.30"
PCS = ["10.2.1.11", "10.2.1.12", "10.2.1.13"]
BASTION = "10.9.0.4"
SCADA_DMZ = "172.16.35.5"
HMI, PLC_S7, PLC_AB = "172.16.2.50", "172.16.2.10", "172.16.2.20"
PRESTA = "10.9.0.7"

MACS = {
    PCS[0]: "00:15:5d:0a:11:01",  # VM Hyper-V
    PCS[1]: "3c:52:82:aa:12:02",
    PCS[2]: "3c:52:82:aa:13:03",
    PLC_S7: "00:1b:1b:10:20:30",  # Siemens
    PLC_AB: "00:00:bc:44:55:66",  # Rockwell
}
HOSTNAMES = {PCS[0]: "PC-COMPTA-01", PCS[1]: "PC-RH-02", PCS[2]: "PC-DIR-03"}


class Writer:
    def __init__(self, out: Path):
        self.out = out
        self.files: dict[str, list[str]] = {}
        self.uid = 0

    def add(self, log: str, rec: dict) -> None:
        self.files.setdefault(log, []).append(json.dumps(rec))

    def conn(self, ts, src, dst, port, proto="tcp", service=None, state="SF", ob=400, rb=1200):
        self.uid += 1
        rec = {"ts": ts.timestamp(), "uid": f"C{self.uid:08d}", "id.orig_h": src,
               "id.orig_p": random.randint(49152, 65535), "id.resp_h": dst, "id.resp_p": port,
               "proto": proto, "conn_state": state, "orig_bytes": ob, "resp_bytes": rb}
        if service:
            rec["service"] = service
        self.add("conn", rec)
        return rec

    def flush(self) -> None:
        self.out.mkdir(parents=True, exist_ok=True)
        for log, lines in self.files.items():
            (self.out / f"{log}.log").write_text("\n".join(lines) + "\n", encoding="utf-8")


def generate(out: Path, days: int = 7, seed: int = 42) -> None:
    random.seed(seed)
    w = Writer(out)
    for d in range(days):
        day = START + timedelta(days=d)
        t = lambda h, m=0: day + timedelta(hours=h, minutes=m, seconds=random.randint(0, 59))

        # DHCP du matin
        for pc in PCS:
            w.add("dhcp", {"ts": t(7, 30).timestamp(), "client_addr": pc, "assigned_addr": pc,
                           "server_addr": DC, "mac": MACS[pc], "host_name": HOSTNAMES[pc]})

        # Activité bureautique
        for pc in PCS:
            for port, proto, svc in ((88, "tcp", "krb_tcp"), (389, "tcp", "ldap"), (445, "tcp", "smb"),
                                     (135, "tcp", "dce_rpc"), (53, "udp", "dns"), (3268, "tcp", "ldap")):
                w.conn(t(8), pc, DC, port, proto, svc)
            w.conn(t(9), pc, FILES, 445, service="smb", rb=250_000)
            w.conn(t(10), pc, WEB, 443, service="ssl")
            w.conn(t(10, 5), pc, APP, 1433, service=None)
            w.add("http", {"ts": t(11).timestamp(), "id.orig_h": pc, "id.resp_h": WEB,
                           "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
            w.add("http", {"ts": t(11, 2).timestamp(), "id.orig_h": pc, "id.resp_h": WEB,
                           "user_agent": "Microsoft-CryptoAPI/10.0"})
        w.conn(t(9, 30), FILES, DC, 88, service="krb_tcp")
        w.conn(t(9, 31), FILES, DC, 445, service="smb")
        w.conn(t(9, 40), WEB, DC, 53, proto="udp", service="dns")

        # Administration légitime depuis le bastion
        w.conn(t(14), BASTION, FILES, 3389)
        w.conn(t(14, 10), BASTION, APP, 3389)

        # Le serveur web se met à jour : bannière SSH et User-Agent APT
        w.add("ssh", {"ts": t(3).timestamp(), "id.orig_h": BASTION, "id.resp_h": WEB,
                      "server": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", "client": "SSH-2.0-OpenSSH_9.6"})
        w.add("http", {"ts": t(3, 5).timestamp(), "id.orig_h": WEB, "id.resp_h": "185.125.190.36",
                       "user_agent": "Debian APT-HTTP/1.3 (2.4.11)"})

        # Le SSH de dépannage jamais refermé : du bastion vers le serveur web, tous les jours
        w.conn(t(16), BASTION, WEB, 22, service="ssh")

        # Atelier : IHM ↔ automates, et supervision depuis la DMZ industrielle
        for h in range(7, 19, 2):
            w.conn(t(h), HMI, PLC_S7, 102, service="s7comm")
            w.conn(t(h, 1), HMI, PLC_AB, 44818, service="enip")
            w.conn(t(h, 2), SCADA_DMZ, PLC_S7, 502, service="modbus")
        w.add("cip_identity", {"ts": t(7, 5).timestamp(), "id.orig_h": HMI, "id.resp_h": PLC_AB,
                               "socket_address": PLC_AB, "vendor_name": "Rockwell Automation/Allen-Bradley",
                               "product_name": "1769-L33ER/A LOGIX5333ER", "revision": "32.11",
                               "device_type_name": "Programmable Logic Controller"})
        for plc in (PLC_S7, PLC_AB):
            w.add("conn", {"ts": t(7, 6).timestamp(), "id.orig_h": HMI, "id.resp_h": plc,
                           "id.resp_p": 102 if plc == PLC_S7 else 44818, "proto": "tcp",
                           "conn_state": "SF", "orig_l2_addr": "00:1b:1b:aa:bb:cc", "resp_l2_addr": MACS[plc]})

        # Violations ponctuelles
        if d == 2:
            w.conn(t(11), PCS[2], DC, 3389)  # RDP d'un poste vers le DC
        if d >= 4:
            w.conn(t(13), APP, PLC_S7, 502, service="modbus")  # serveur applicatif → automate en direct
        if d == 6:
            w.conn(t(10), PRESTA, PLC_S7, 22, service="ssh")  # accès prestataire, règle expirée

        # Bruit : scans sans réponse, ne doivent rien inventorier
        w.conn(t(2), PCS[1], "10.1.0.250", 445, state="S0", rb=0)

    w.flush()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("out", type=Path)
    ap.add_argument("--days", type=int, default=7)
    a = ap.parse_args()
    generate(a.out, a.days)
    print(f"Logs générés dans {a.out}")
