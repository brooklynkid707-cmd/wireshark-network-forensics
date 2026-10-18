"""Pure-stdlib pcap writer and packet builders.

These helpers produce byte-accurate Ethernet / ARP / IPv4 / TCP / UDP / ICMP /
DNS frames with correct checksums, so the generated captures open cleanly in
Wireshark and tshark without "bad checksum" noise.
"""

from __future__ import annotations

import random
import struct
from pathlib import Path
from typing import BinaryIO

from netforensics.parsers import (
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    IPPROTO_ICMP,
    IPPROTO_TCP,
    IPPROTO_UDP,
)

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def mac_bytes(mac: str) -> bytes:
    """``aa:bb:cc:dd:ee:ff`` -> 6 raw bytes."""
    return bytes(int(part, 16) for part in mac.split(":"))


def ip_bytes(ip: str) -> bytes:
    """Dotted-quad -> 4 raw bytes."""
    return bytes(int(part) for part in ip.split("."))


def checksum(data: bytes) -> int:
    """RFC 1071 ones-complement checksum."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_ethernet(src: str, dst: str, ethertype: int, payload: bytes) -> bytes:
    """Ethernet II frame."""
    return mac_bytes(dst) + mac_bytes(src) + struct.pack("!H", ethertype) + payload


def build_arp(opcode: int, sender_mac: str, sender_ip: str, target_mac: str, target_ip: str) -> bytes:
    """ARP packet for Ethernet/IPv4 (without the Ethernet header)."""
    return (struct.pack("!HHBBH", 1, ETHERTYPE_IPV4, 6, 4, opcode)
            + mac_bytes(sender_mac) + ip_bytes(sender_ip)
            + mac_bytes(target_mac) + ip_bytes(target_ip))


def build_ipv4(src: str, dst: str, protocol: int, payload: bytes, ttl: int = 64,
               identification: int | None = None) -> bytes:
    """IPv4 header (no options) with checksum, followed by payload."""
    if identification is None:
        identification = random.randint(0, 0xFFFF)
    total_length = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_length, identification, 0x4000,
                         ttl, protocol, 0, ip_bytes(src), ip_bytes(dst))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def _pseudo_header(src: str, dst: str, protocol: int, length: int) -> bytes:
    return ip_bytes(src) + ip_bytes(dst) + struct.pack("!BBH", 0, protocol, length)


def build_tcp(src: str, dst: str, sport: int, dport: int, flags: int, seq: int = 0,
              ack: int = 0, payload: bytes = b"", window: int = 64240) -> bytes:
    """TCP segment with pseudo-header checksum (no options)."""
    header = struct.pack("!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | flags, window, 0, 0)
    csum = checksum(_pseudo_header(src, dst, IPPROTO_TCP, len(header) + len(payload)) + header + payload)
    header = header[:16] + struct.pack("!H", csum) + header[18:]
    return header + payload


def build_udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    """UDP datagram with pseudo-header checksum."""
    length = 8 + len(payload)
    header = struct.pack("!HHHH", sport, dport, length, 0)
    csum = checksum(_pseudo_header(src, dst, IPPROTO_UDP, length) + header + payload) or 0xFFFF
    return header[:6] + struct.pack("!H", csum) + payload


def build_icmp(icmp_type: int, code: int, identifier: int, sequence: int, payload: bytes) -> bytes:
    """ICMP message (echo request/reply layout) with checksum."""
    header = struct.pack("!BBHHH", icmp_type, code, 0, identifier, sequence)
    csum = checksum(header + payload)
    return header[:2] + struct.pack("!H", csum) + header[4:] + payload


def encode_dns_name(name: str) -> bytes:
    """Encode ``a.b.c`` as DNS labels."""
    out = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".") if label)
    return out + b"\x00"


def build_dns_query(txid: int, qname: str, qtype: int = 1) -> bytes:
    """Standard recursive DNS query with a single question."""
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + encode_dns_name(qname) + struct.pack("!HH", qtype, 1)


def build_dns_response(txid: int, qname: str, answer_ip: str | None, qtype: int = 1,
                       rcode: int = 0, txt: bytes | None = None) -> bytes:
    """DNS response. ``answer_ip`` adds an A record; ``txt`` adds a TXT record."""
    answers = b""
    ancount = 0
    if answer_ip and rcode == 0:
        answers += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ip_bytes(answer_ip)
        ancount += 1
    if txt is not None and rcode == 0:
        rdata = bytes([len(txt)]) + txt
        answers += b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(rdata)) + rdata
        ancount += 1
    flags = 0x8180 | rcode
    return (struct.pack("!HHHHHH", txid, flags, 1, ancount, 0, 0)
            + encode_dns_name(qname) + struct.pack("!HH", qtype, 1) + answers)


class PcapWriter:
    """Write classic little-endian microsecond pcap files (link type Ethernet).

    Example::

        with PcapWriter("out.pcap") as w:
            w.write(frame_bytes, timestamp=1_700_000_000.0)
    """

    def __init__(self, path: str | Path, snaplen: int = 65535) -> None:
        self.path = Path(path)
        self.snaplen = snaplen
        self._fh: BinaryIO | None = None
        self.count = 0

    def __enter__(self) -> PcapWriter:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("wb")
        self._fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, self.snaplen, 1))
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

    def write(self, frame: bytes, timestamp: float) -> None:
        """Append one frame with the given epoch timestamp (seconds, float)."""
        if self._fh is None:
            raise RuntimeError("PcapWriter must be used as a context manager")
        sec = int(timestamp)
        usec = int(round((timestamp - sec) * 1_000_000))
        if usec >= 1_000_000:
            sec, usec = sec + 1, usec - 1_000_000
        data = frame[: self.snaplen]
        self._fh.write(struct.pack("<IIII", sec, usec, len(data), len(frame)))
        self._fh.write(data)
        self.count += 1
