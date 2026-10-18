"""Detection analyzers. Each exposes ``analyze(packets) -> list[Finding]``."""

from __future__ import annotations

from collections.abc import Callable

from netforensics.analyzers import (
    arpspoof,
    beacon,
    credentials,
    dnstunnel,
    icmpexfil,
    portscan,
    smb,
)
from netforensics.findings import Finding
from netforensics.packets import Packet

Analyzer = Callable[[list[Packet]], list[Finding]]

ANALYZERS: dict[str, Analyzer] = {
    "port_scan": portscan.analyze,
    "arp_spoof": arpspoof.analyze,
    "dns_tunnel": dnstunnel.analyze,
    "beacon": beacon.analyze,
    "credentials": credentials.analyze,
    "icmp_exfil": icmpexfil.analyze,
    "smb_lateral": smb.analyze,
}


def run_all(packets: list[Packet]) -> list[Finding]:
    """Run every analyzer and return findings sorted by severity (highest first)."""
    findings: list[Finding] = []
    for analyzer in ANALYZERS.values():
        findings.extend(analyzer(packets))
    findings.sort(key=lambda f: (-int(f.severity), f.analyzer, f.title))
    return findings


__all__ = ["ANALYZERS", "Analyzer", "run_all"]
