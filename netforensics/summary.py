"""Capture statistics: the equivalent of Wireshark's Statistics menu.

Produces top talkers (Statistics > Endpoints), conversations
(Statistics > Conversations), protocol hierarchy (Statistics > Protocol
Hierarchy) and a few capture-wide facts.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any

from netforensics.packets import Packet


@dataclass
class CaptureSummary:
    """Aggregate statistics for one capture."""

    packets: int = 0
    bytes: int = 0
    first_timestamp: float = 0.0
    last_timestamp: float = 0.0
    duration_s: float = 0.0
    protocol_hierarchy: dict[str, int] = field(default_factory=dict)
    top_talkers: list[dict[str, Any]] = field(default_factory=list)
    conversations: list[dict[str, Any]] = field(default_factory=list)
    top_ports: list[dict[str, Any]] = field(default_factory=list)
    dns_queries: int = 0
    unique_dns_names: int = 0
    arp_packets: int = 0
    http_requests: int = 0

    def to_dict(self) -> dict[str, Any]:
        """JSON-friendly dictionary."""
        return asdict(self)


def summarize(packets: list[Packet], top_n: int = 10) -> CaptureSummary:
    """Compute endpoint, conversation and protocol statistics."""
    summary = CaptureSummary(packets=len(packets))
    if not packets:
        return summary

    hierarchy: Counter[str] = Counter()
    endpoint_pkts: Counter[str] = Counter()
    endpoint_bytes: Counter[str] = Counter()
    conv_pkts: Counter[tuple[str, str]] = Counter()
    conv_bytes: Counter[tuple[str, str]] = Counter()
    conv_protos: dict[tuple[str, str], set[str]] = defaultdict(set)
    ports: Counter[str] = Counter()
    dns_names: set[str] = set()

    for pkt in packets:
        summary.bytes += pkt.length
        hierarchy["/".join(pkt.protocol_path) or "RAW"] += 1
        if pkt.arp:
            summary.arp_packets += 1
        if pkt.http:
            summary.http_requests += 1
        if pkt.dns and not pkt.dns.is_response:
            summary.dns_queries += 1
            dns_names.add(pkt.dns.qname)
        if not pkt.ip:
            continue
        src, dst = pkt.ip.src, pkt.ip.dst
        endpoint_pkts[src] += 1
        endpoint_pkts[dst] += 1
        endpoint_bytes[src] += pkt.length
        endpoint_bytes[dst] += pkt.length
        key = (src, dst) if src <= dst else (dst, src)
        conv_pkts[key] += 1
        conv_bytes[key] += pkt.length
        layer = pkt.tcp or pkt.udp
        if layer:
            proto = "TCP" if pkt.tcp else "UDP"
            conv_protos[key].add(proto)
            ports[f"{proto}/{min(layer.sport, layer.dport)}"] += 1
        elif pkt.icmp:
            conv_protos[key].add("ICMP")

    summary.first_timestamp = packets[0].timestamp
    summary.last_timestamp = packets[-1].timestamp
    summary.duration_s = round(packets[-1].timestamp - packets[0].timestamp, 6)
    summary.protocol_hierarchy = dict(hierarchy.most_common())
    summary.top_talkers = [
        {"address": addr, "packets": count, "bytes": endpoint_bytes[addr]}
        for addr, count in endpoint_pkts.most_common(top_n)
    ]
    summary.conversations = [
        {"a": a, "b": b, "packets": count, "bytes": conv_bytes[(a, b)],
         "protocols": sorted(conv_protos[(a, b)])}
        for (a, b), count in conv_pkts.most_common(top_n)
    ]
    summary.top_ports = [{"port": port, "packets": count} for port, count in ports.most_common(top_n)]
    summary.unique_dns_names = len(dns_names)
    return summary
