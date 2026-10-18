"""C2 beaconing detector (MITRE ATT&CK T1071.001 Web Protocols / T1573).

Logic
-----
Malware implants "phone home" on a timer. We group new TCP connections
(pure SYNs) by ``src -> dst:port`` and look at the gaps between them. Human
browsing has wildly variable gaps; a beacon has a tight distribution. We use
the coefficient of variation (standard deviation / mean) of the intervals.
Real beacons with jitter still land well below 0.3-0.4; bursts of scripted
updates or NTP also look regular, so the finding lists the destination so an
analyst can rule those out. A near-identical request size on every
connection strengthens the verdict.
"""

from __future__ import annotations

import statistics
from collections import defaultdict

from netforensics.findings import Finding, Severity
from netforensics.packets import Packet

MIN_CONNECTIONS = 8
MIN_INTERVAL = 1.0            # ignore sub-second chatter (retransmits, keepalives)
MAX_CV = 0.35                 # std-dev / mean below this => regular
IGNORE_PORTS = {53, 123}      # DNS and NTP are legitimately periodic


def analyze(packets: list[Packet]) -> list[Finding]:
    """Flag src->dst:port pairs whose new-connection intervals are suspiciously regular."""
    sessions: dict[tuple[str, str, int], list[float]] = defaultdict(list)
    request_sizes: dict[tuple[str, str, int], list[int]] = defaultdict(list)
    hosts: dict[tuple[str, str, int], set[str]] = defaultdict(set)
    uris: dict[tuple[str, str, int], set[str]] = defaultdict(set)

    for pkt in packets:
        if not (pkt.ip and pkt.tcp):
            continue
        key = (pkt.ip.src, pkt.ip.dst, pkt.tcp.dport)
        if pkt.tcp.is_syn_only and pkt.tcp.dport not in IGNORE_PORTS:
            sessions[key].append(pkt.timestamp)
        if pkt.tcp.payload and key in sessions:
            request_sizes[key].append(len(pkt.tcp.payload))
        if pkt.http and key in sessions:
            hosts[key].add(pkt.http.host)
            uris[key].add(pkt.http.uri)

    findings: list[Finding] = []
    for key, times in sessions.items():
        if len(times) < MIN_CONNECTIONS:
            continue
        times.sort()
        intervals = [b - a for a, b in zip(times, times[1:]) if b - a >= MIN_INTERVAL]
        if len(intervals) < MIN_CONNECTIONS - 1:
            continue
        mean = statistics.fmean(intervals)
        stdev = statistics.pstdev(intervals)
        cv = stdev / mean if mean else 1.0
        if cv > MAX_CV:
            continue
        src, dst, dport = key
        sizes = request_sizes.get(key, [])
        size_cv = (statistics.pstdev(sizes) / statistics.fmean(sizes)) if len(sizes) > 1 and statistics.fmean(sizes) else None
        severity = Severity.HIGH if cv < 0.15 else Severity.MEDIUM
        findings.append(Finding(
            analyzer="beacon",
            title=f"Periodic beacon {src} -> {dst}:{dport} every ~{mean:.1f}s ({len(times)} connections)",
            severity=severity,
            technique="T1071.001",
            description=(
                f"{len(times)} new TCP connections from {src} to {dst}:{dport} with a mean gap of "
                f"{mean:.2f}s and standard deviation {stdev:.2f}s (coefficient of variation "
                f"{cv:.3f}). Human-driven traffic does not keep a schedule this tight; this "
                "matches a malware implant polling its command-and-control server."
                + (f" Hosts: {', '.join(sorted(h for h in hosts[key] if h))}." if hosts.get(key) else "")
                + (f" URIs: {', '.join(sorted(uris[key]))}." if uris.get(key) else "")
            ),
            indicators={"source": src, "c2_server": dst, "port": dport,
                        "http_hosts": sorted(hosts.get(key, ())), "uris": sorted(uris.get(key, ()))},
            evidence={
                "connections": len(times),
                "mean_interval_s": round(mean, 3),
                "stdev_interval_s": round(stdev, 3),
                "coefficient_of_variation": round(cv, 4),
                "request_size_cv": round(size_cv, 4) if size_cv is not None else None,
                "first_seen": times[0],
                "last_seen": times[-1],
            },
            wireshark_filter=f"ip.src == {src} && ip.dst == {dst} && tcp.dstport == {dport} && tcp.flags.syn == 1 && tcp.flags.ack == 0",
        ))
    return findings
