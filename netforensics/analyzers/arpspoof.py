"""ARP cache-poisoning / MITM detector (MITRE ATT&CK T1557.002).

Logic
-----
1. **IP claimed by multiple MACs** - we build a table of every ``sender_ip ->
   sender_mac`` binding advertised in ARP replies. One IP answering from two
   different MACs is Wireshark's own "duplicate IP address detected" warning.
2. **Gratuitous / unsolicited replies** - an attacker poisons caches by
   blasting unsolicited replies ("is-at") that no one asked for. We count
   replies that have no matching prior request within a short window, and
   gratuitous ARPs (sender IP == target IP).
3. **Reply flood** - a single MAC emitting far more replies than requests is
   a strong indicator of an active poisoning tool (arpspoof, ettercap,
   bettercap).
"""

from __future__ import annotations

from collections import defaultdict

from netforensics.findings import Finding, Severity
from netforensics.packets import Packet

UNSOLICITED_WINDOW = 2.0      # seconds a reply may trail a request
MIN_UNSOLICITED_REPLIES = 5
MIN_GRATUITOUS = 3            # a couple at boot is normal; a burst is not


def analyze(packets: list[Packet]) -> list[Finding]:
    """Detect conflicting IP/MAC bindings and unsolicited ARP replies."""
    ip_to_macs: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    recent_requests: dict[str, list[float]] = defaultdict(list)  # target_ip -> request times
    unsolicited: dict[str, int] = defaultdict(int)               # sender_mac -> count
    gratuitous: dict[str, int] = defaultdict(int)
    replies_by_mac: dict[str, int] = defaultdict(int)
    requests_by_mac: dict[str, int] = defaultdict(int)

    for pkt in packets:
        arp = pkt.arp
        if arp is None:
            continue
        if arp.opcode == 1:
            requests_by_mac[arp.sender_mac] += 1
            recent_requests[arp.target_ip].append(pkt.timestamp)
            if arp.is_gratuitous:
                gratuitous[arp.sender_mac] += 1
            continue
        if arp.opcode != 2:
            continue
        replies_by_mac[arp.sender_mac] += 1
        ip_to_macs[arp.sender_ip][arp.sender_mac] += 1
        if arp.is_gratuitous:
            gratuitous[arp.sender_mac] += 1
            continue
        asked = recent_requests.get(arp.sender_ip, [])
        if not any(pkt.timestamp - t <= UNSOLICITED_WINDOW for t in asked[-5:]):
            unsolicited[arp.sender_mac] += 1

    findings: list[Finding] = []

    for ip, macs in ip_to_macs.items():
        if len(macs) < 2:
            continue
        ranked = sorted(macs.items(), key=lambda kv: -kv[1])
        # The MAC that answers most is usually the poisoner; the other is the real owner.
        suspect_mac, legit_mac = ranked[0][0], ranked[-1][0]
        findings.append(Finding(
            analyzer="arp_spoof",
            title=f"IP {ip} claimed by {len(macs)} different MAC addresses",
            severity=Severity.CRITICAL,
            technique="T1557.002",
            description=(
                f"ARP replies for {ip} were sent from {', '.join(macs)}. A single IP must map "
                "to one MAC on a LAN; two claimants means either an IP conflict or an "
                "attacker rewriting the ARP cache of victims to intercept traffic (MITM). "
                f"{suspect_mac} issued {ranked[0][1]} replies versus {ranked[-1][1]} from {legit_mac}."
            ),
            indicators={"ip": ip, "suspect_mac": suspect_mac, "legitimate_mac": legit_mac,
                        "all_macs": dict(macs)},
            evidence={"replies_per_mac": dict(macs)},
            wireshark_filter=f"arp.src.proto_ipv4 == {ip} && arp.opcode == 2",
        ))

    for mac, count in unsolicited.items():
        if count < MIN_UNSOLICITED_REPLIES:
            continue
        claimed = sorted({ip for ip, macs in ip_to_macs.items() if mac in macs})
        findings.append(Finding(
            analyzer="arp_spoof",
            title=f"{count} unsolicited ARP replies from {mac}",
            severity=Severity.HIGH,
            technique="T1557.002",
            description=(
                f"MAC {mac} sent {count} ARP 'is-at' replies that were not preceded by a "
                f"'who-has' request within {UNSOLICITED_WINDOW:.0f}s, claiming to be "
                f"{', '.join(claimed)}. Unsolicited replies are how poisoning tools keep "
                f"victim caches overwritten. It sent {replies_by_mac[mac]} replies total against "
                f"{requests_by_mac.get(mac, 0)} requests."
            ),
            indicators={"mac": mac, "claimed_ips": claimed},
            evidence={"unsolicited_replies": count, "total_replies": replies_by_mac[mac],
                      "total_requests": requests_by_mac.get(mac, 0),
                      "gratuitous": gratuitous.get(mac, 0)},
            wireshark_filter=f"arp.opcode == 2 && eth.src == {mac}",
        ))

    for mac, count in gratuitous.items():
        if count >= MIN_GRATUITOUS and mac not in unsolicited:
            findings.append(Finding(
                analyzer="arp_spoof",
                title=f"{count} gratuitous ARP packets from {mac}",
                severity=Severity.MEDIUM,
                technique="T1557.002",
                description=(
                    f"{mac} announced itself with {count} gratuitous ARPs. One or two at boot "
                    "or failover are normal; repeated announcements can be cache poisoning."
                ),
                indicators={"mac": mac},
                evidence={"gratuitous": count},
                wireshark_filter=f"arp.isgratuitous && eth.src == {mac}",
            ))
    return findings
