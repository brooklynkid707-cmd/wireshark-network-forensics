"""ICMP data exfiltration / tunnel detector (MITRE ATT&CK T1048 / T1095).

Logic
-----
A normal ``ping`` sends a fixed-size payload (56 bytes on Linux, 32 on
Windows) with a predictable pattern (``abcdefghijklmnop...`` or ``08 09 0a``).
ICMP tunnels (ptunnel, icmpsh, custom loaders) abuse the payload to carry
arbitrary data, so we look for echo requests whose payloads are:

* **oversized** (> 64 bytes) and/or
* **varying** from packet to packet (a real ping repeats the same pattern) and/or
* **high entropy** (compressed or encrypted data).

The volume of payload bytes sent to a destination is reported so the analyst
can estimate how much left the network.
"""

from __future__ import annotations

from collections import defaultdict

from netforensics.analyzers.dnstunnel import shannon_entropy
from netforensics.findings import Finding, Severity
from netforensics.packets import Packet

MIN_ECHO_REQUESTS = 5
LARGE_PAYLOAD = 64
HIGH_ENTROPY = 4.0             # bits/byte; ping patterns sit near 4.0 or lower, data sits > 5
MIN_UNIQUE_PAYLOAD_RATIO = 0.5


def analyze(packets: list[Packet]) -> list[Finding]:
    """Flag src->dst ICMP echo streams carrying variable or oversized payloads."""
    streams: dict[tuple[str, str], list[bytes]] = defaultdict(list)
    for pkt in packets:
        if pkt.ip and pkt.icmp and pkt.icmp.type == 8:
            streams[(pkt.ip.src, pkt.ip.dst)].append(pkt.icmp.payload)

    findings: list[Finding] = []
    for (src, dst), payloads in streams.items():
        if len(payloads) < MIN_ECHO_REQUESTS:
            continue
        unique_ratio = len(set(payloads)) / len(payloads)
        avg_size = sum(len(p) for p in payloads) / len(payloads)
        avg_entropy = sum(shannon_entropy(p.decode("latin-1")) for p in payloads) / len(payloads)
        large = avg_size > LARGE_PAYLOAD
        varying = unique_ratio >= MIN_UNIQUE_PAYLOAD_RATIO
        random_looking = avg_entropy >= HIGH_ENTROPY
        reasons = [r for r, hit in (("oversized payloads", large), ("payload changes every packet", varying),
                                    ("high-entropy payload", random_looking)) if hit]
        if len(reasons) < 2:
            continue
        total_bytes = sum(len(p) for p in payloads)
        findings.append(Finding(
            analyzer="icmp_exfil",
            title=f"ICMP tunnel / exfiltration {src} -> {dst} ({total_bytes} payload bytes)",
            severity=Severity.HIGH if random_looking else Severity.MEDIUM,
            technique="T1048",
            description=(
                f"{len(payloads)} echo requests from {src} to {dst}: {'; '.join(reasons)}. "
                f"Mean payload {avg_size:.0f} bytes, {unique_ratio:.0%} unique payloads, mean "
                f"entropy {avg_entropy:.2f} bits/byte. A real ping repeats a fixed 32/56-byte pattern."
            ),
            indicators={"source": src, "destination": dst},
            evidence={"echo_requests": len(payloads), "payload_bytes": total_bytes,
                      "mean_payload_size": round(avg_size, 1), "unique_payload_ratio": round(unique_ratio, 3),
                      "mean_entropy": round(avg_entropy, 3)},
            wireshark_filter=f"icmp.type == 8 && ip.src == {src} && data.len > {LARGE_PAYLOAD}",
        ))
    return findings
