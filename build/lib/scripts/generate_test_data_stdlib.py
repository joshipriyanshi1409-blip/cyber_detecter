#!/usr/bin/env python3
"""
Generate Test PCAP Files (stdlib-only fallback)

scripts/generate_test_data.py builds its demo traffic with Scapy
(`from scapy.all import ...`). Scapy is not installed in every
environment (it wasn't installed in the sandbox this fallback was
written in — see docs/AUDIT_PROGRESS.md), which is exactly why
demo/ddos.pcap, demo/dga.pcap, and demo/normal.pcap were still 0 bytes
even though demo/port_scan.pcap had content.

This script builds the same three scenarios by hand-assembling classic
(libpcap) format bytes with nothing but the Python standard library
(struct, socket, random) — no scapy, no nfstream, no network access
required. It is NOT a drop-in replacement for generate_test_data.py:
it covers fewer protocol variations and does not use Scapy's
randomized field helpers. Treat it as "good enough to exercise the
detectors and pcap_reader.py path", not as a permanent substitute.
Prefer scripts/generate_test_data.py on any machine where scapy is
actually installed.

Usage:
    python3 scripts/generate_test_data_stdlib.py
"""

import random
import socket
import struct
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
DEMO_DIR = PROJECT_ROOT / "demo"

# ---------------------------------------------------------------------------
# Minimal classic-pcap (libpcap) writer -- no external dependencies.
# Format reference: https://wiki.wireshark.org/Development/LibpcapFileFormat
# ---------------------------------------------------------------------------

PCAP_MAGIC = 0xA1B2C3D4  # microsecond resolution, native/little-endian on
                          # disk matches the header already shipped in
                          # demo/port_scan.pcap (bytes d4 c3 b2 a1).
LINKTYPE_ETHERNET = 1


def write_pcap(path: Path, packets):
    """packets: list of (timestamp_float, bytes) tuples, Ethernet frames."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        # Global header
        f.write(struct.pack(
            "<IHHiIII",
            PCAP_MAGIC, 2, 4,       # magic, version_major, version_minor
            0, 0,                    # thiszone, sigfigs
            0xFFFF,                  # snaplen
            LINKTYPE_ETHERNET,
        ))
        for ts, data in packets:
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            f.write(data)


# ---------------------------------------------------------------------------
# Minimal Ethernet/IP/TCP/UDP/ICMP/DNS frame builders.
# ---------------------------------------------------------------------------

def mac_bytes(s="02:00:00:00:00:01"):
    return bytes(int(b, 16) for b in s.split(":"))


def ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_ip_header(src: str, dst: str, proto: int, payload_len: int, ident: int) -> bytes:
    ver_ihl = (4 << 4) | 5
    total_len = 20 + payload_len
    flags_frag = 0
    ttl = 64
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, 0, total_len, ident, flags_frag,
        ttl, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    checksum = ip_checksum(header)
    return header[:10] + struct.pack("!H", checksum) + header[12:]


def build_tcp_header(sport: int, dport: int, seq: int, flags: int,
                      src: str, dst: str, payload: bytes = b"") -> bytes:
    ack = 0
    offset_res = (5 << 4)
    window = 8192
    header = struct.pack(
        "!HHIIBBHHH",
        sport, dport, seq, ack, offset_res, flags, window, 0, 0,
    )
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src), socket.inet_aton(dst), 0, 6, len(header) + len(payload),
    )
    checksum = ip_checksum(pseudo + header + payload)
    return header[:16] + struct.pack("!H", checksum) + header[18:]


def build_udp_header(sport: int, dport: int, src: str, dst: str, payload: bytes) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = struct.pack("!4s4sBBH", socket.inet_aton(src), socket.inet_aton(dst), 0, 17, length)
    checksum = ip_checksum(pseudo + header + payload)
    if checksum == 0:
        checksum = 0xFFFF
    return header[:6] + struct.pack("!H", checksum)


def build_icmp_echo(icmp_type: int, icmp_code: int, ident: int, seq: int) -> bytes:
    header = struct.pack("!BBHHH", icmp_type, icmp_code, 0, ident, seq)
    checksum = ip_checksum(header)
    return header[:2] + struct.pack("!H", checksum) + header[4:]


def build_dns_query(qname: str, qid: int) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    parts = qname.strip(".").split(".")
    qname_bytes = b"".join(bytes([len(p)]) + p.encode() for p in parts) + b"\x00"
    question = qname_bytes + struct.pack("!HH", 1, 1)  # A, IN
    return header + question


def eth_frame(src_mac: bytes, dst_mac: bytes, ip_payload: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", 0x0800) + ip_payload


_ident_counter = [1]


def tcp_packet(src, dst, sport, dport, flags, seq=1000, payload=b""):
    _ident_counter[0] += 1
    tcp_hdr = build_tcp_header(sport, dport, seq, flags, src, dst, payload)
    ip_hdr = build_ip_header(src, dst, 6, len(tcp_hdr) + len(payload), _ident_counter[0])
    return eth_frame(mac_bytes(), mac_bytes("02:00:00:00:00:02"), ip_hdr + tcp_hdr + payload)


def udp_packet(src, dst, sport, dport, payload):
    _ident_counter[0] += 1
    udp_hdr = build_udp_header(sport, dport, src, dst, payload)
    ip_hdr = build_ip_header(src, dst, 17, len(udp_hdr) + len(payload), _ident_counter[0])
    return eth_frame(mac_bytes(), mac_bytes("02:00:00:00:00:02"), ip_hdr + udp_hdr + payload)


def icmp_packet(src, dst, icmp_type=8, icmp_code=0, ident=1, seq=1):
    _ident_counter[0] += 1
    icmp_hdr = build_icmp_echo(icmp_type, icmp_code, ident, seq)
    ip_hdr = build_ip_header(src, dst, 1, len(icmp_hdr), _ident_counter[0])
    return eth_frame(mac_bytes(), mac_bytes("02:00:00:00:00:02"), ip_hdr + icmp_hdr)


# TCP flags
FLAG_SYN = 0x02
FLAG_ACK = 0x10
FLAG_SYN_ACK = FLAG_SYN | FLAG_ACK
FLAG_RST = 0x04
FLAG_FIN = 0x01
FLAG_PSH_ACK = 0x18


# ---------------------------------------------------------------------------
# Scenario generators
# ---------------------------------------------------------------------------

def generate_normal_traffic(num_flows=40, seed=1):
    """A handful of ordinary clients doing HTTP/HTTPS/DNS against a few
    servers. Meant to be a low/no-alert baseline for regression checks,
    not a large-scale capture."""
    rng = random.Random(seed)
    servers = ["93.184.216.34", "142.250.72.14", "1.1.1.1"]
    clients = [f"192.168.1.{n}" for n in range(100, 106)]
    packets = []
    t = time.time() - 60

    for i in range(num_flows):
        client = rng.choice(clients)
        sport = rng.randint(1024, 65535)
        kind = i % 3

        if kind == 0:  # HTTP-ish TCP handshake + small request/response
            server, dport = rng.choice(servers), 80
            seq = rng.randint(1000, 90000)
            packets.append((t, tcp_packet(client, server, sport, dport, FLAG_SYN, seq)))
            t += 0.01
            packets.append((t, tcp_packet(server, client, dport, sport, FLAG_SYN_ACK, seq + 5000)))
            t += 0.01
            packets.append((t, tcp_packet(client, server, sport, dport, FLAG_ACK, seq + 1)))
            t += 0.02
            packets.append((t, tcp_packet(client, server, sport, dport, FLAG_PSH_ACK, seq + 1,
                                           payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")))
            t += 0.05
            packets.append((t, tcp_packet(server, client, dport, sport, FLAG_FIN | FLAG_ACK, seq + 5001)))
        elif kind == 1:  # HTTPS-ish handshake only (encrypted-metadata style)
            server, dport = rng.choice(servers), 443
            seq = rng.randint(1000, 90000)
            packets.append((t, tcp_packet(client, server, sport, dport, FLAG_SYN, seq)))
            t += 0.01
            packets.append((t, tcp_packet(server, client, dport, sport, FLAG_SYN_ACK, seq + 5000)))
            t += 0.01
            packets.append((t, tcp_packet(client, server, sport, dport, FLAG_ACK, seq + 1)))
        else:  # ordinary DNS lookup for a legitimate-looking name
            names = ["example.com", "www.example.org", "mail.example.net", "cdn.example.com"]
            packets.append((t, udp_packet(client, "8.8.8.8", sport, 53,
                                           build_dns_query(rng.choice(names), rng.randint(1, 65535)))))
        t += rng.uniform(0.05, 0.3)

    packets.sort(key=lambda p: p[0])
    return packets


def generate_ddos_traffic(num_sources=60, packets_per_source=25, seed=2):
    """Many distinct source IPs sending a burst of SYNs at a single
    victim IP:port in a short window -- a volumetric SYN-flood-style
    pattern intended to trip src/detectors/ddos.py and
    src/detectors/syn_flood.py."""
    rng = random.Random(seed)
    victim = "10.0.0.1"
    victim_port = 80
    packets = []
    t = time.time() - 5

    for _ in range(num_sources):
        # Vary the source /24 rather than reusing one range, so
        # source-diversity features (source_stats.py, spoofing_likelihood.py)
        # see plausible-looking distinct attackers.
        src_ip = f"198.51.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        sport = rng.randint(1024, 65535)
        for _ in range(packets_per_source):
            seq = rng.randint(1, 2**32 - 1)
            packets.append((t, tcp_packet(src_ip, victim, sport, victim_port, FLAG_SYN, seq)))
            t += rng.uniform(0.0005, 0.003)  # high rate, no time for a handshake

    packets.sort(key=lambda p: p[0])
    return packets


def generate_dga_traffic(num_domains=50, seed=3):
    """DNS queries for algorithmically-generated-looking domain names
    (long, high-entropy, consonant-heavy labels) mixed with a few
    ordinary lookups, to exercise src/detectors/dga.py and
    src/features/entropy.py."""
    rng = random.Random(seed)
    client = "192.168.1.150"
    consonants = "bcdfghjklmnpqrstvwxyz"
    vowels = "aeiou"
    tlds = [".com", ".net", ".info", ".biz"]
    packets = []
    t = time.time() - 30

    def random_label(length):
        out = []
        for i in range(length):
            out.append(rng.choice(consonants) if i % 2 == 0 else rng.choice(vowels))
        rng.shuffle(out)
        return "".join(out)

    for i in range(num_domains):
        if i % 8 == 0:
            # sprinkle a couple of ordinary lookups among the DGA traffic
            name = "example.com"
        else:
            label = random_label(rng.randint(14, 22))
            name = label + rng.choice(tlds)
        sport = rng.randint(1024, 65535)
        packets.append((t, udp_packet(client, "8.8.8.8", sport, 53,
                                       build_dns_query(name, rng.randint(1, 65535)))))
        t += rng.uniform(0.1, 0.6)

    return packets


def main():
    scenarios = {
        "normal.pcap": generate_normal_traffic(),
        "ddos.pcap": generate_ddos_traffic(),
        "dga.pcap": generate_dga_traffic(),
    }
    for filename, packets in scenarios.items():
        out_path = DEMO_DIR / filename
        write_pcap(out_path, packets)
        print(f"Wrote {len(packets)} packets to {out_path} ({out_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
