"""SMB lateral-movement burst detector (MITRE ATT&CK T1021.002 SMB/Windows Admin Shares).

Logic
-----
Workstations talk SMB (TCP 445) to a few file servers, over and over. A
compromised host spreading laterally (PsExec, wmiexec, SMB worms, ransomware
deploying via admin shares) opens SMB sessions to *many distinct peers* in a
short burst, often workstation-to-workstation. We count distinct TCP/445
destinations per source inside a window and, when SMB2 headers are visible,
note the commands (SESSION_SETUP, TREE_CONNECT to ``ADMIN$`` / ``C$`` /
``IPC$``) which are the signature of remote service creation.
"""

from __future__ import annotations

from collections import defaultdict

from netforensics.findings import Finding, Severity
from netforensics.packets import Packet

SMB_PORT = 445
WINDOW_SECONDS = 60.0
MIN_DISTINCT_PEERS = 5
SMB2_MAGIC = b"\xfeSMB"
ADMIN_SHARES = ("ADMIN$", "C$", "IPC$")


def _smb2_command(payload: bytes) -> int | None:
    """Return the SMB2 command code if the payload is an SMB2 message (NetBIOS framed)."""
    body = payload[4:] if len(payload) > 4 and payload[0] == 0 else payload
    if body.startswith(SMB2_MAGIC) and len(body) >= 16:
        return int.from_bytes(body[12:14], "little")
    return None


def analyze(packets: list[Packet]) -> list[Finding]:
    """Flag sources opening SMB sessions to many distinct hosts in a short burst."""
    syns: dict[str, list[tuple[float, str]]] = defaultdict(list)
    tree_connects: dict[str, set[str]] = defaultdict(set)
    session_setups: dict[str, int] = defaultdict(int)

    for pkt in packets:
        if not (pkt.ip and pkt.tcp and pkt.tcp.dport == SMB_PORT):
            continue
        if pkt.tcp.is_syn_only:
            syns[pkt.ip.src].append((pkt.timestamp, pkt.ip.dst))
        if not pkt.tcp.payload:
            continue
        if _smb2_command(pkt.tcp.payload) == 1:
            session_setups[pkt.ip.src] += 1
        # A TREE_CONNECT carries the share path (\\host\ADMIN$) as UTF-16-LE; scan the
        # whole segment because multiple SMB2 messages may be pipelined into one PDU.
        text = pkt.tcp.payload.decode("utf-16-le", errors="ignore")
        for share in ADMIN_SHARES:
            if share in text:
                tree_connects[pkt.ip.src].add(share)

    findings: list[Finding] = []
    for src, events in syns.items():
        events.sort()
        best, best_peers = 0, set()
        start = 0
        for end, (ts, _dst) in enumerate(events):
            while events[start][0] < ts - WINDOW_SECONDS:
                start += 1
            peers = {d for _, d in events[start:end + 1]}
            if len(peers) > best:
                best, best_peers = len(peers), peers
        if best < MIN_DISTINCT_PEERS:
            continue
        shares = sorted(tree_connects.get(src, ()))
        severity = Severity.CRITICAL if shares else Severity.HIGH
        findings.append(Finding(
            analyzer="smb_lateral",
            title=f"SMB lateral-movement burst from {src} to {best} hosts",
            severity=severity,
            technique="T1021.002",
            description=(
                f"{src} opened TCP/445 sessions to {best} distinct hosts within {WINDOW_SECONDS:.0f}s "
                f"({len(events)} SYNs total). {session_setups.get(src, 0)} SMB2 SESSION_SETUP "
                f"requests were seen"
                + (f" and TREE_CONNECT to administrative shares {', '.join(shares)}" if shares else "")
                + ". Workstations do not normally fan out over SMB like this; it matches PsExec-style "
                "remote execution or worm propagation."
            ),
            indicators={"source": src, "targets": sorted(best_peers), "admin_shares": shares},
            evidence={"distinct_peers_in_window": best, "total_syns": len(events),
                      "session_setups": session_setups.get(src, 0)},
            wireshark_filter=f"ip.src == {src} && tcp.dstport == 445 && tcp.flags.syn == 1 && tcp.flags.ack == 0",
        ))
    return findings
