#!/usr/bin/env python3
"""Générateur de captures réseau (pcap) en Python pur, sans dépendance.

Sert à tester le capteur avec le vrai Zeek sans disposer d'un lab : chaque
scénario produit des échanges protocolaires réalistes (poignée de main TCP,
sommes de contrôle valides, numéros de séquence cohérents).

Usage : python tools/pcapgen.py SORTIE.pcap
"""

from __future__ import annotations

import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import IPv4Address

LINKTYPE_ETHERNET = 1
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def _mac(m: str) -> bytes:
    return bytes(int(x, 16) for x in m.split(":"))


def _ip(a: str) -> bytes:
    return IPv4Address(a).packed


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int, ttl: int = 64) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF, 0x4000,
                      ttl, proto, 0, _ip(src), _ip(dst))
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    return hdr + payload


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    return _ip(src) + _ip(dst) + struct.pack("!BBH", 0, proto, length)


def tcp_segment(src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
                flags: int, payload: bytes = b"", window: int = 64240) -> bytes:
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                      5 << 4, flags, window, 0, 0)
    csum = checksum(_pseudo(src, dst, 6, len(hdr) + len(payload)) + hdr + payload)
    return hdr[:16] + struct.pack("!H", csum) + hdr[18:] + payload


def udp_datagram(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", sport, dport, length, 0)
    csum = checksum(_pseudo(src, dst, 17, length) + hdr + payload) or 0xFFFF
    return hdr[:6] + struct.pack("!H", csum) + payload


def ethernet(src_mac: str, dst_mac: str, payload: bytes) -> bytes:
    return _mac(dst_mac) + _mac(src_mac) + struct.pack("!H", 0x0800) + payload


FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


@dataclass
class Host:
    ip: str
    mac: str


@dataclass
class Capture:
    """Accumule des trames horodatées puis écrit un fichier pcap."""
    t: float = datetime(2026, 10, 20, 8, 0, tzinfo=timezone.utc).timestamp()
    frames: list[tuple[float, bytes]] = field(default_factory=list)
    ident: int = 1
    port: int = 49200

    def tick(self, seconds: float = 0.001) -> None:
        self.t += seconds

    def ephemeral(self) -> int:
        self.port += 1
        return self.port

    def frame(self, src: Host, dst_mac: str, dst_ip: str, proto: int, l4: bytes, src_ip: str | None = None):
        self.ident += 1
        self.frames.append((self.t, ethernet(src.mac, dst_mac, ipv4(src_ip or src.ip, dst_ip, proto, l4, self.ident))))
        self.tick()

    def tcp(self, client: Host, server: Host, dport: int, exchanges: list[tuple[str, bytes]]) -> None:
        """Session TCP complète : poignée de main, échanges ('c' ou 's', données), fermeture."""
        sport = self.ephemeral()
        cseq, sseq = 1000, 5000

        def c2s(flags, data=b""):
            self.frame(client, server.mac, server.ip, 6,
                       tcp_segment(client.ip, server.ip, sport, dport, cseq, sseq, flags, data))

        def s2c(flags, data=b""):
            self.frame(server, client.mac, client.ip, 6,
                       tcp_segment(server.ip, client.ip, dport, sport, sseq, cseq, flags, data))

        self.frame(client, server.mac, server.ip, 6,
                   tcp_segment(client.ip, server.ip, sport, dport, cseq, 0, SYN))
        cseq += 1
        s2c(SYN | ACK)
        sseq += 1
        c2s(ACK)
        for side, data in exchanges:
            if side == "c":
                c2s(PSH | ACK, data)
                cseq += len(data)
                s2c(ACK)
            else:
                s2c(PSH | ACK, data)
                sseq += len(data)
                c2s(ACK)
        c2s(FIN | ACK)
        cseq += 1
        s2c(FIN | ACK)
        sseq += 1
        c2s(ACK)

    def tcp_refused(self, client: Host, server: Host, dport: int) -> None:
        sport = self.ephemeral()
        self.frame(client, server.mac, server.ip, 6, tcp_segment(client.ip, server.ip, sport, dport, 1000, 0, SYN))
        self.frame(server, client.mac, client.ip, 6, tcp_segment(server.ip, client.ip, dport, sport, 0, 1001, RST | ACK))

    def udp(self, client: Host, server: Host, sport: int, dport: int, request: bytes, response: bytes | None):
        self.frame(client, server.mac, server.ip, 17, udp_datagram(client.ip, server.ip, sport, dport, request))
        if response is not None:
            self.frame(server, client.mac, client.ip, 17, udp_datagram(server.ip, client.ip, dport, sport, response))

    def write(self, path: str) -> None:
        with open(path, "wb") as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
            for ts, data in sorted(self.frames, key=lambda f: f[0]):
                sec = int(ts)
                usec = int(round((ts - sec) * 1_000_000))
                fh.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
                fh.write(data)


# --- Charges utiles protocolaires -----------------------------------------

def dns_query(qid: int, name: str) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def dns_answer(qid: int, name: str, ip: str) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return (struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0) + q + struct.pack("!HH", 1, 1)
            + struct.pack("!HHHIH", 0xC00C, 1, 1, 300, 4) + _ip(ip))


def dhcp(op: int, msg_type: int, xid: int, mac: str, yiaddr: str = "0.0.0.0", siaddr: str = "0.0.0.0",
         hostname: str | None = None, server_id: str | None = None, requested: str | None = None) -> bytes:
    bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", op, 1, 6, 0, xid, 0, 0x8000,
                        _ip("0.0.0.0"), _ip(yiaddr), _ip(siaddr), _ip("0.0.0.0"),
                        _mac(mac) + b"\0" * 10, b"\0" * 64, b"\0" * 128)
    opts = b"\x63\x82\x53\x63" + bytes([53, 1, msg_type])
    if hostname:
        opts += bytes([12, len(hostname)]) + hostname.encode()
    if requested:
        opts += bytes([50, 4]) + _ip(requested)
    if server_id:
        opts += bytes([54, 4]) + _ip(server_id)
    if op == 2:
        opts += bytes([51, 4]) + struct.pack("!I", 86400) + bytes([1, 4]) + _ip("255.255.0.0")
    else:
        opts += bytes([55, 4, 1, 3, 6, 15])
    return bootp + opts + b"\xff"


def http_request(host: str, path: str, ua: str) -> bytes:
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n"
            f"Accept: */*\r\nConnection: close\r\n\r\n").encode()


def http_response(body: str = "<html>ok</html>") -> bytes:
    return (f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n{body}").encode()


def modbus_read_request(tid: int, unit: int = 1, addr: int = 0, qty: int = 10) -> bytes:
    pdu = struct.pack("!BHH", 3, addr, qty)
    return struct.pack("!HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def modbus_read_response(tid: int, unit: int = 1, qty: int = 10) -> bytes:
    pdu = struct.pack("!BB", 3, qty * 2) + b"\x00\x2a" * qty
    return struct.pack("!HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def tpkt(payload: bytes) -> bytes:
    return struct.pack("!BBH", 3, 0, 4 + len(payload)) + payload


COTP_CR = bytes.fromhex("11e00000000100c1020100c2020102c0010a")
COTP_CC = bytes.fromhex("11d00001000100c0010ac1020100c2020102")
COTP_DT = bytes.fromhex("02f080")
S7_SETUP_JOB = bytes.fromhex("32010000000000080000f0000001000101e0")
S7_SETUP_ACK = bytes.fromhex("320300000000000800000000f0000001000101e0")


def enip_list_identity_request() -> bytes:
    return struct.pack("<HHII8sI", 0x0063, 0, 0, 0, b"\0" * 8, 0)


def enip_list_identity_response(ip: str, vendor: int, device_type: int, product_code: int,
                                revision: tuple[int, int], serial: int, name: str) -> bytes:
    sockaddr = struct.pack(">HH4s8s", 2, 44818, _ip(ip), b"\0" * 8)
    item = (struct.pack("<H", 1) + sockaddr
            + struct.pack("<HHHBBHI", vendor, device_type, product_code, revision[0], revision[1], 0x0030, serial)
            + bytes([len(name)]) + name.encode() + b"\x03")
    data = struct.pack("<HHH", 1, 0x000C, len(item)) + item
    return struct.pack("<HHII8sI", 0x0063, len(data), 0, 0, b"\0" * 8, 0) + data


# --- Scénario de lab -------------------------------------------------------

DC = Host("10.0.0.5", "00:15:5d:00:00:05")
WEB = Host("10.1.0.80", "00:15:5d:01:00:80")
APP = Host("10.1.0.30", "00:15:5d:01:00:30")
PC1 = Host("10.2.1.11", "00:15:5d:0a:11:01")
PC3 = Host("10.2.1.13", "3c:52:82:aa:13:03")
SCANNER = Host("10.2.1.66", "3c:52:82:aa:66:06")
BASTION = Host("10.9.0.4", "00:15:5d:09:00:04")
SCADA = Host("172.16.35.5", "00:15:5d:35:00:05")
HMI = Host("172.16.2.50", "00:1b:1b:aa:bb:cc")
PLC_S7 = Host("172.16.2.10", "00:1b:1b:10:20:30")
PLC_AB = Host("172.16.2.20", "00:00:bc:44:55:66")
GATEWAY_MAC = "00:15:5d:ff:ff:01"


def lab_scenario() -> Capture:
    """Petit site IT/OT : les mêmes acteurs que la démonstration."""
    c = Capture()

    # DHCP : le poste PC-COMPTA-01 (VM Hyper-V) obtient son adresse
    xid = 0x3903F326
    unconf = Host("0.0.0.0", PC1.mac)
    c.udp(unconf, Host("255.255.255.255", BROADCAST_MAC), 68, 67,
          dhcp(1, 1, xid, PC1.mac, hostname="PC-COMPTA-01"), None)
    c.frame(DC, BROADCAST_MAC, "255.255.255.255", 17, udp_datagram(
        DC.ip, "255.255.255.255", 67, 68, dhcp(2, 2, xid, PC1.mac, yiaddr=PC1.ip, siaddr=DC.ip, server_id=DC.ip)))
    c.udp(unconf, Host("255.255.255.255", BROADCAST_MAC), 68, 67,
          dhcp(1, 3, xid, PC1.mac, hostname="PC-COMPTA-01", requested=PC1.ip, server_id=DC.ip), None)
    c.frame(DC, BROADCAST_MAC, "255.255.255.255", 17, udp_datagram(
        DC.ip, "255.255.255.255", 67, 68, dhcp(2, 5, xid, PC1.mac, yiaddr=PC1.ip, siaddr=DC.ip, server_id=DC.ip)))
    c.tick(1)

    # DNS vers le contrôleur de domaine
    c.udp(PC1, DC, c.ephemeral(), 53, dns_query(0x1A2B, "intranet.lab.local"),
          dns_answer(0x1A2B, "intranet.lab.local", WEB.ip))

    # Trafic Active Directory (Kerberos, LDAP, catalogue global) : données opaques
    for port in (88, 389, 3268):
        c.tcp(PC1, DC, port, [("c", b"\x00\x00\x00\x10" + b"\x6a" * 16), ("s", b"\x00\x00\x00\x08" + b"\x6b" * 8)])

    # Navigation HTTP depuis un poste Windows
    c.tcp(PC1, WEB, 80, [("c", http_request("intranet.lab.local", "/", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                             "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36")),
                         ("s", http_response())])
    c.tcp(PC1, WEB, 80, [("c", http_request("crl.lab.local", "/root.crl", "Microsoft-CryptoAPI/10.0")),
                         ("s", http_response("crl"))])

    # SSH du bastion vers le serveur web Ubuntu
    c.tcp(BASTION, WEB, 22, [("s", b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"),
                             ("c", b"SSH-2.0-OpenSSH_9.6\r\n")])

    # RDP d'un poste vers le contrôleur de domaine (violation du modèle en tiers)
    c.tcp(PC3, DC, 3389, [("c", bytes.fromhex("0300002b26e00000000000436f6f6b69653a206d737473686173683d7573657231"
                                               "0d0a0100080003000000")),
                          ("s", bytes.fromhex("0300001300d000001234000200080002000000"))])

    # Tentative refusée (scan) : ne doit rien inventorier
    c.tcp_refused(PC3, Host("10.1.0.250", GATEWAY_MAC), 445)

    # Balayage : un poste tente 120 cibles (10 adresses × 12 ports), toutes
    # refusées ; alerte « balayage du réseau » attendue, cibles non inventoriées
    for i in range(120):
        c.tcp_refused(SCANNER, Host(f"10.1.0.{200 + i % 10}", GATEWAY_MAC),
                      (21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 3389, 8080)[i // 10])

    # OT : supervision Modbus depuis la DMZ industrielle
    for tid in (1, 2):
        c.tcp(SCADA, PLC_S7, 502, [("c", modbus_read_request(tid)), ("s", modbus_read_response(tid))])
    # OT : serveur applicatif qui interroge l'automate en direct (contournement de la DMZ)
    c.tcp(APP, PLC_S7, 502, [("c", modbus_read_request(9)), ("s", modbus_read_response(9))])

    # OT : IHM ↔ automate Siemens en S7comm
    c.tcp(HMI, PLC_S7, 102, [("c", tpkt(COTP_CR)), ("s", tpkt(COTP_CC)),
                             ("c", tpkt(COTP_DT + S7_SETUP_JOB)), ("s", tpkt(COTP_DT + S7_SETUP_ACK))])

    # OT : IHM ↔ automate Rockwell, identité EtherNet/IP
    c.tcp(HMI, PLC_AB, 44818, [("c", enip_list_identity_request()),
                               ("s", enip_list_identity_response(PLC_AB.ip, vendor=1, device_type=0x0E,
                                                                 product_code=166, revision=(32, 11),
                                                                 serial=0x00C0FFEE,
                                                                 name="1769-L33ER/A LOGIX5333ER"))])
    return c


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    cap = lab_scenario()
    cap.write(sys.argv[1])
    print(f"{len(cap.frames)} trames écrites dans {sys.argv[1]}")
