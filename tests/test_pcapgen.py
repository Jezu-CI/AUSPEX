"""Relit les captures générées et vérifie leur validité, indépendamment du générateur."""

import importlib.util
import struct
import sys
from collections import defaultdict
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "tools" / "pcapgen.py"
spec = importlib.util.spec_from_file_location("pcapgen", TOOLS)
pcapgen = importlib.util.module_from_spec(spec)
sys.modules["pcapgen"] = pcapgen
spec.loader.exec_module(pcapgen)


def ones_complement_ok(data: bytes) -> bool:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF  # somme incluant la somme de contrôle elle-même


def read_pcap(path):
    raw = Path(path).read_bytes()
    magic, vmaj, vmin, _, _, snap, link = struct.unpack("<IHHiIII", raw[:24])
    assert (magic, vmaj, vmin, link) == (0xA1B2C3D4, 2, 4, 1)
    off, out, last_ts = 24, [], 0
    while off < len(raw):
        sec, usec, incl, orig = struct.unpack("<IIII", raw[off:off + 16])
        assert incl == orig and usec < 1_000_000
        ts = sec + usec / 1e6
        assert ts >= last_ts, "horodatages non croissants"
        last_ts = ts
        out.append(raw[off + 16: off + 16 + incl])
        off += 16 + incl
    assert off == len(raw)
    return out


def test_lab_capture_is_valid(tmp_path):
    p = tmp_path / "lab.pcap"
    pcapgen.lab_scenario().write(str(p))
    frames = read_pcap(p)
    assert len(frames) > 100

    streams = defaultdict(list)
    for f in frames:
        assert struct.unpack("!H", f[12:14])[0] == 0x0800
        ip = f[14:]
        ihl = (ip[0] & 0x0F) * 4
        total = struct.unpack("!H", ip[2:4])[0]
        assert ip[0] >> 4 == 4 and total == len(ip)
        assert ones_complement_ok(ip[:ihl]), "somme IP invalide"
        proto, src, dst = ip[9], ip[12:16], ip[16:20]
        l4 = ip[ihl:]
        pseudo = src + dst + struct.pack("!BBH", 0, proto, len(l4))
        assert ones_complement_ok(pseudo + l4), f"somme L4 invalide (proto {proto})"
        if proto == 6:
            sport, dport, seq, ack, offs, flags = struct.unpack("!HHIIBB", l4[:14])
            payload = l4[(offs >> 4) * 4:]
            streams[(src, sport, dst, dport)].append((seq, flags, len(payload)))

    # Continuité des numéros de séquence dans chaque sens de chaque session
    for key, segs in streams.items():
        expected = None
        for seq, flags, plen in segs:
            if expected is not None:
                assert seq == expected, f"trou de séquence dans {key}"
            expected = seq + plen + (1 if flags & 0x03 else 0)  # SYN et FIN consomment 1
    assert len(streams) == 26  # 13 sessions TCP, chacune dans les deux sens


def test_modbus_and_enip_payloads():
    req = pcapgen.modbus_read_request(7)
    tid, pid, length, unit = struct.unpack("!HHHB", req[:7])
    assert (tid, pid, length, unit) == (7, 0, len(req) - 6, 1)
    rsp = pcapgen.enip_list_identity_response("172.16.2.20", 1, 14, 166, (32, 11), 1, "1769-L33ER")
    cmd, length = struct.unpack("<HH", rsp[:4])
    assert cmd == 0x63 and length == len(rsp) - 24
