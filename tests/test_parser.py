"""Parser and pcap round-trip correctness."""

from __future__ import annotations

from pathlib import Path

import pytest

from netforensics.packets import TCP
from netforensics.parsers import decode_packet, parse_dns, parse_http_request
from netforensics.pcap import PcapError, PcapReader, read_pcap
from netforensics.writer import (
    PcapWriter,
    build_dns_query,
    build_ethernet,
    build_ipv4,
    build_tcp,
    build_udp,
    checksum,
)
from netforensics.parsers import ETHERTYPE_IPV4, IPPROTO_TCP, IPPROTO_UDP


def test_checksum_known_value() -> None:
    # A zeroed buffer has checksum 0xFFFF (ones-complement of 0).
    assert checksum(b"\x00\x00\x00\x00") == 0xFFFF


def test_pcap_roundtrip(tmp_path: Path) -> None:
    """Frames written by PcapWriter are read back byte-identical with timestamps."""
    frame = build_ethernet("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", ETHERTYPE_IPV4,
                           build_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_TCP,
                                      build_tcp("10.0.0.1", "10.0.0.2", 1234, 80, TCP.SYN, 1, 0)))
    path = tmp_path / "rt.pcap"
    with PcapWriter(path) as w:
        w.write(frame, 1_700_000_000.5)
        w.write(frame, 1_700_000_001.25)
    packets = read_pcap(path)
    assert len(packets) == 2
    assert packets[0].raw == frame
    assert packets[0].timestamp == pytest.approx(1_700_000_000.5, abs=1e-6)
    assert packets[1].timestamp == pytest.approx(1_700_000_001.25, abs=1e-6)


def test_decode_tcp_layers() -> None:
    frame = build_ethernet("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", ETHERTYPE_IPV4,
                           build_ipv4("192.0.2.1", "192.0.2.2", IPPROTO_TCP,
                                      build_tcp("192.0.2.1", "192.0.2.2", 40000, 443,
                                                TCP.SYN | TCP.ACK, 10, 11, b"hello")))
    pkt = decode_packet(1, 0.0, frame)
    assert pkt.eth and pkt.ip and pkt.tcp
    assert pkt.ip.src == "192.0.2.1" and pkt.ip.dst == "192.0.2.2"
    assert pkt.tcp.sport == 40000 and pkt.tcp.dport == 443
    assert pkt.tcp.is_syn_ack and not pkt.tcp.is_syn_only
    assert pkt.tcp.flag_names == "SYN/ACK"
    assert pkt.tcp.payload == b"hello"
    assert pkt.protocol_path == ["ETH", "IP", "TCP"]


def test_decode_dns_question() -> None:
    frame = build_ethernet("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", ETHERTYPE_IPV4,
                           build_ipv4("10.0.0.5", "10.0.0.53", IPPROTO_UDP,
                                      build_udp("10.0.0.5", "10.0.0.53", 55000, 53,
                                                build_dns_query(0x1234, "www.example.com", 1))))
    pkt = decode_packet(1, 0.0, frame)
    assert pkt.dns is not None
    assert pkt.dns.qname == "www.example.com"
    assert pkt.dns.qtype == 1
    assert not pkt.dns.is_response


def test_parse_http_request() -> None:
    payload = (b"POST /login HTTP/1.1\r\nHost: intranet.example\r\n"
               b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\n"
               b"user=a&p=b")
    http = parse_http_request(payload)
    assert http is not None
    assert http.method == "POST" and http.uri == "/login"
    assert http.host == "intranet.example"
    assert http.body == b"user=a&p=b"


def test_parse_dns_pointer_compression() -> None:
    # name 'a.example.com' with the 'example.com' part via a pointer at offset 12.
    msg = build_dns_query(1, "example.com", 1)
    # Append a second question 'a' + pointer to offset of 'example.com' (0x0c).
    extra = b"\x01a\xc0\x0c\x00\x01\x00\x01"
    header = msg[:4] + b"\x00\x02" + msg[6:12]  # qdcount = 2
    dns = parse_dns(header + msg[12:] + extra)
    assert dns is not None
    names = [q[0] for q in dns.questions]
    assert "example.com" in names
    assert "a.example.com" in names


def test_bad_magic_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.pcap"
    path.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)  # pcapng block type
    with pytest.raises(PcapError):
        with PcapReader(path) as r:
            list(r)


def test_truncated_record_stops_cleanly(tmp_path: Path) -> None:
    frame = build_ethernet("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", ETHERTYPE_IPV4,
                           build_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_TCP,
                                      build_tcp("10.0.0.1", "10.0.0.2", 1, 2, TCP.SYN, 1, 0)))
    path = tmp_path / "trunc.pcap"
    with PcapWriter(path) as w:
        w.write(frame, 1.0)
    data = bytearray(path.read_bytes())
    data += b"\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x50\x00\x00\x00\x50"  # header promising 80 bytes
    data += b"\x00" * 10  # but only 10 present
    path.write_bytes(bytes(data))
    assert len(read_pcap(path)) == 1  # the complete frame survives, the stub is dropped


def test_generated_pcaps_parse(pcap_dir: Path, scenarios: dict[str, str]) -> None:
    """Every generated capture reads back with plausible packet counts."""
    for name in list(scenarios) + ["baseline"]:
        packets = read_pcap(pcap_dir / f"{name}.pcap")
        assert len(packets) > 20, f"{name} produced too few packets"
        assert all(p.eth is not None for p in packets), f"{name} has undecodable frames"
