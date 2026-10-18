"""DNS tunneling detector (MITRE ATT&CK T1071.004 / T1048).

Logic
-----
DNS tunnels (iodine, dnscat2, dns2tcp) smuggle data in the *question name*:
the client encodes outbound bytes as base32/base64 subdomains of a domain the
attacker controls, and the server answers with TXT/NULL/CNAME records. Three
properties separate that from real lookups:

* **Label length** - real hostnames are short; encoded chunks hit the 63-byte
  label limit and the 253-byte name limit.
* **Shannon entropy** - encoded data is close to random (entropy > 3.5 bits
  per character for base32/base64); English-ish names sit around 2.5-3.
* **Unique subdomains per registered domain** - a tunnel never repeats a
  query because each one carries fresh data; normal clients hit the same few
  names repeatedly and cache them.

A domain is flagged when it accumulates many unique, long, high-entropy
subdomains. TXT/NULL query types and high query rate raise the severity.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict

from netforensics.findings import Finding, Severity
from netforensics.packets import Packet

MIN_UNIQUE_SUBDOMAINS = 10
LONG_LABEL = 30               # characters in the longest label
HIGH_ENTROPY = 3.5            # bits/char over the subdomain portion
MIN_SUSPICIOUS_RATIO = 0.5    # share of queries that look encoded
TUNNEL_QTYPES = {16: "TXT", 10: "NULL", 5: "CNAME", 15: "MX"}


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def registered_domain(name: str) -> str:
    """Crude eTLD+1: last two labels (``a.b.example.com`` -> ``example.com``)."""
    labels = name.lower().strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else name.lower()


def analyze(packets: list[Packet]) -> list[Finding]:
    """Flag domains receiving many long, high-entropy, non-repeating subdomain queries."""
    per_domain: dict[str, list[tuple[float, str, int, str]]] = defaultdict(list)  # ts, qname, qtype, src
    for pkt in packets:
        if not (pkt.dns and pkt.ip) or pkt.dns.is_response or not pkt.dns.qname:
            continue
        qname = pkt.dns.qname.lower()
        per_domain[registered_domain(qname)].append((pkt.timestamp, qname, pkt.dns.qtype, pkt.ip.src))

    findings: list[Finding] = []
    for domain, queries in per_domain.items():
        unique_names = {q for _, q, _, _ in queries}
        if len(unique_names) < MIN_UNIQUE_SUBDOMAINS:
            continue
        suspicious = 0
        entropies: list[float] = []
        longest_label = 0
        for name in unique_names:
            sub = name[: -len(domain) - 1] if name.endswith("." + domain) else ""
            if not sub:
                continue
            labels = sub.split(".")
            longest = max(len(label) for label in labels)
            longest_label = max(longest_label, longest)
            ent = shannon_entropy(sub.replace(".", ""))
            entropies.append(ent)
            if longest >= LONG_LABEL or ent >= HIGH_ENTROPY:
                suspicious += 1
        ratio = suspicious / len(unique_names)
        if ratio < MIN_SUSPICIOUS_RATIO:
            continue

        timestamps = sorted(ts for ts, _, _, _ in queries)
        span = max(timestamps[-1] - timestamps[0], 1e-6)
        rate = len(queries) / span
        qtypes = Counter(TUNNEL_QTYPES.get(qt, str(qt)) for _, _, qt, _ in queries)
        tunnel_types = sum(c for name, c in qtypes.items() if name in TUNNEL_QTYPES.values())
        clients = sorted({src for _, _, _, src in queries})
        avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
        severity = Severity.HIGH if (tunnel_types or rate > 1.0) else Severity.MEDIUM
        example = max(unique_names, key=len)
        findings.append(Finding(
            analyzer="dns_tunnel",
            title=f"Probable DNS tunnel to {domain} ({len(unique_names)} unique subdomains)",
            severity=severity,
            technique="T1071.004",
            description=(
                f"{len(queries)} queries from {', '.join(clients)} produced {len(unique_names)} "
                f"distinct subdomains of {domain}; {ratio:.0%} of them have labels >= {LONG_LABEL} "
                f"chars or entropy >= {HIGH_ENTROPY} bits/char (mean entropy {avg_entropy:.2f}, "
                f"longest label {longest_label}). Query rate {rate:.2f}/s; record types "
                f"{dict(qtypes)}. Example: {example}"
            ),
            indicators={"domain": domain, "clients": clients, "example_query": example},
            evidence={
                "queries": len(queries),
                "unique_subdomains": len(unique_names),
                "suspicious_ratio": round(ratio, 3),
                "mean_entropy": round(avg_entropy, 3),
                "longest_label": longest_label,
                "queries_per_second": round(rate, 3),
                "qtypes": dict(qtypes),
            },
            wireshark_filter=f'dns.qry.name contains "{domain}" && dns.flags.response == 0',
        ))
    return findings
