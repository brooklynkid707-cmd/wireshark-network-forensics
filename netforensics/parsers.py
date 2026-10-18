"""Protocol decoders built on :mod:`struct` only.

Every function is defensive: a truncated or malformed layer returns ``None``
instead of raising, because a forensics tool must keep going when it meets
garbage on the wire.
"""

from __future__ import annotations

import struct

from netforensics.packets import ARP, DNS, HTTP, ICMP, TCP, UDP, Ethernet, IPv4, Packet

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ")


def mac_str(raw: bytes) -> str:
    """Format 6 raw bytes as ``aa:bb:cc:dd:ee:ff``."""
    return ":".join(f"{b:02x}" for b in raw)


def ip_str(raw: bytes) -> str:
    """Format 4 raw bytes as dotted-quad."""
    return ".".join(str(b) for b in raw)


def parse_ethernet(data: bytes) -> tuple[Ethernet, bytes] | None:
    """Decode an Ethernet II header. Returns (header, payload)."""
    if len(data) < 14:
        return None
    dst, src, ethertype = struct.unpack("!6s6sH", data[:14])
    offset = 14
    # 802.1Q VLAN tag: skip it and use the inner ethertype.
    if ethertype == 0x8100 and len(data) >= 18:
        ethertype = struct.unpack("!H", data[16:18])[0]
        offset = 18
    return Ethernet(mac_str(dst), mac_str(src), ethertype), data[offset:]


def parse_arp(data: bytes) -> ARP | None:
    """Decode an ARP packet for Ethernet/IPv4 (hardware len 6, proto len 4)."""
    if len(data) < 28:
        return None
    htype, ptype, hlen, plen, opcode = struct.unpack("!HHBBH", data[:8])
    if hlen != 6 or plen != 4:
        return None
    sha, spa, tha, tpa = struct.unpack("!6s4s6s4s", data[8:28])
    return ARP(opcode, mac_str(sha), ip_str(spa), mac_str(tha), ip_str(tpa))


def parse_ipv4(data: bytes) -> tuple[IPv4, bytes] | None:
    """Decode an IPv4 header. Returns (header, payload)."""
    if len(data) < 20:
        return None
    ver_ihl = data[0]
    if ver_ihl >> 4 != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total_length, identification, flags_frag, ttl, proto = struct.unpack("!HHHBB", data[2:10])
    src, dst = data[12:16], data[16:20]
    flags = flags_frag >> 13
    frag_offset = flags_frag & 0x1FFF
    payload_end = min(len(data), total_length) if total_length >= ihl else len(data)
    header = IPv4(ip_str(src), ip_str(dst), proto, ttl, identification,
                  total_length, ihl, flags, frag_offset)
    return header, data[ihl:payload_end]


def parse_tcp(data: bytes) -> TCP | None:
    """Decode a TCP header (options are skipped) plus payload."""
    if len(data) < 20:
        return None
    sport, dport, seq, ack, offset_flags, window = struct.unpack("!HHIIHH", data[:16])
    data_offset = (offset_flags >> 12) * 4
    flags = offset_flags & 0x01FF
    if data_offset < 20 or len(data) < data_offset:
        return None
    return TCP(sport, dport, seq, ack, flags, window, data[data_offset:])


def parse_udp(data: bytes) -> UDP | None:
    """Decode a UDP header plus payload."""
    if len(data) < 8:
        return None
    sport, dport, length, _checksum = struct.unpack("!HHHH", data[:8])
    return UDP(sport, dport, length, data[8:])


def parse_icmp(data: bytes) -> ICMP | None:
    """Decode an ICMP header. Identifier/sequence are meaningful for echo."""
    if len(data) < 8:
        return None
    icmp_type, code, _checksum, identifier, sequence = struct.unpack("!BBHHH", data[:8])
    return ICMP(icmp_type, code, identifier, sequence, data[8:])


def _read_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Read a DNS name handling compression pointers. Returns (name, next_offset)."""
    labels: list[str] = []
    if depth > 10:
        raise ValueError("DNS compression loop")
    while True:
        if offset >= len(data):
            raise ValueError("truncated DNS name")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated DNS pointer")
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            suffix, _ = _read_name(data, pointer, depth + 1)
            labels.append(suffix)
            offset += 2
            break
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(label for label in labels if label), offset


def parse_dns(data: bytes) -> DNS | None:
    """Decode the DNS header and question section."""
    if len(data) < 12:
        return None
    txid, flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    is_response = bool(flags & 0x8000)
    rcode = flags & 0x000F
    offset = 12
    questions: list[tuple[str, int]] = []
    try:
        for _ in range(min(qdcount, 16)):
            name, offset = _read_name(data, offset)
            if offset + 4 > len(data):
                break
            qtype, _qclass = struct.unpack("!HH", data[offset:offset + 4])
            offset += 4
            questions.append((name, qtype))
    except ValueError:
        if not questions:
            return None
    return DNS(txid, is_response, rcode, tuple(questions), ancount)


def parse_http_request(payload: bytes) -> HTTP | None:
    """Decode an HTTP/1.x request line, headers and (partial) body."""
    if not payload.startswith(HTTP_METHODS):
        return None
    head, sep, body = payload.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    request_line = lines[0].decode("latin-1", errors="replace").split(" ")
    if len(request_line) < 3 or not request_line[2].startswith("HTTP/"):
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, colon, value = line.decode("latin-1", errors="replace").partition(":")
        if colon:
            headers[name.strip().lower()] = value.strip()
    return HTTP(request_line[0], request_line[1], request_line[2], headers, body if sep else b"")


def decode_packet(number: int, timestamp: float, raw: bytes) -> Packet:
    """Decode a raw Ethernet frame into a :class:`Packet` with all known layers."""
    pkt = Packet(number=number, timestamp=timestamp, raw=raw)
    eth = parse_ethernet(raw)
    if eth is None:
        return pkt
    pkt.eth, payload = eth

    if pkt.eth.ethertype == ETHERTYPE_ARP:
        pkt.arp = parse_arp(payload)
        return pkt
    if pkt.eth.ethertype != ETHERTYPE_IPV4:
        return pkt

    ip = parse_ipv4(payload)
    if ip is None:
        return pkt
    pkt.ip, l4 = ip

    if pkt.ip.protocol == IPPROTO_TCP:
        pkt.tcp = parse_tcp(l4)
        if pkt.tcp and pkt.tcp.payload:
            pkt.http = parse_http_request(pkt.tcp.payload)
    elif pkt.ip.protocol == IPPROTO_UDP:
        pkt.udp = parse_udp(l4)
        if pkt.udp and 53 in (pkt.udp.sport, pkt.udp.dport):
            pkt.dns = parse_dns(pkt.udp.payload)
    elif pkt.ip.protocol == IPPROTO_ICMP:
        pkt.icmp = parse_icmp(l4)
    return pkt
