"""TCP SYN port-scan detector (MITRE ATT&CK T1046 Network Service Discovery).

Logic
-----
For every source IP we count the number of *distinct* destination ports it
sent a pure SYN (no ACK) to, inside a sliding time window. Legitimate hosts
talk to a handful of ports; a scanner touches dozens or hundreds in seconds.
We also count how many of those probes were answered with RST (closed port)
versus SYN/ACK (open port): a high RST ratio is a strong scan signature
because normal clients rarely connect to closed ports.
"""

from __future__ import annotations

from collections import defaultdict

from netforensics.findings import Finding, Severity
from netforensics.packets import Packet

WINDOW_SECONDS = 10.0
MIN_UNIQUE_PORTS = 15        # distinct dst ports from one src within a window
HIGH_SEVERITY_PORTS = 50     # escalate to HIGH beyond this many ports


def analyze(packets: list[Packet]) -> list[Finding]:
    """Detect hosts probing many distinct TCP ports inside a short window."""
    # src -> list of (timestamp, dst_ip, dst_port) for pure SYNs
    syns: dict[str, list[tuple[float, str, int]]] = defaultdict(list)
    # (src, dst, dport) -> response flags seen back
    responses: dict[tuple[str, str, int], set[str]] = defaultdict(set)

    for pkt in packets:
        if not (pkt.ip and pkt.tcp):
            continue
        if pkt.tcp.is_syn_only:
            syns[pkt.ip.src].append((pkt.timestamp, pkt.ip.dst, pkt.tcp.dport))
        elif pkt.tcp.is_syn_ack:
            responses[(pkt.ip.dst, pkt.ip.src, pkt.tcp.sport)].add("SYN/ACK")
        elif pkt.tcp.is_rst:
            responses[(pkt.ip.dst, pkt.ip.src, pkt.tcp.sport)].add("RST")

    findings: list[Finding] = []
    for src, probes in syns.items():
        probes.sort()
        best_count, best_start = 0, 0.0
        start = 0
        window_ports: dict[int, int] = defaultdict(int)
        for end, (ts, _dst, port) in enumerate(probes):
            window_ports[port] += 1
            while probes[start][0] < ts - WINDOW_SECONDS:
                old_port = probes[start][2]
                window_ports[old_port] -= 1
                if window_ports[old_port] == 0:
                    del window_ports[old_port]
                start += 1
            if len(window_ports) > best_count:
                best_count, best_start = len(window_ports), probes[start][0]
        if best_count < MIN_UNIQUE_PORTS:
            continue

        all_ports = sorted({p for _, _, p in probes})
        targets = sorted({d for _, d, _ in probes})
        open_ports = sorted({p for (s, d, p), flags in responses.items()
                             if s == src and "SYN/ACK" in flags})
        closed = sum(1 for (s, _d, _p), flags in responses.items() if s == src and flags == {"RST"})
        severity = Severity.HIGH if best_count >= HIGH_SEVERITY_PORTS else Severity.MEDIUM
        findings.append(Finding(
            analyzer="port_scan",
            title=f"TCP SYN scan from {src} ({best_count} ports in {WINDOW_SECONDS:.0f}s)",
            severity=severity,
            technique="T1046",
            description=(
                f"{src} sent SYN probes to {len(all_ports)} distinct TCP ports on "
                f"{len(targets)} host(s); peak of {best_count} unique ports inside a "
                f"{WINDOW_SECONDS:.0f} second window. {closed} probes were answered with RST "
                f"(closed) and {len(open_ports)} with SYN/ACK (open), which is the classic "
                "half-open scan signature."
            ),
            indicators={"scanner_ip": src, "targets": targets, "open_ports": open_ports},
            evidence={
                "total_syn_probes": len(probes),
                "unique_ports": len(all_ports),
                "peak_ports_in_window": best_count,
                "window_start": best_start,
                "rst_responses": closed,
                "port_range": f"{all_ports[0]}-{all_ports[-1]}" if all_ports else "",
            },
            wireshark_filter=f"ip.src == {src} && tcp.flags.syn == 1 && tcp.flags.ack == 0",
        ))
    return findings
