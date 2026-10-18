"""Cleartext credential finder (MITRE ATT&CK T1040 Network Sniffing / T1552).

Logic
-----
Anything an attacker with a sniffer could read, we read too:

* HTTP ``Authorization: Basic`` headers (base64 of ``user:pass``).
* HTTP form POSTs whose body contains password-like field names.
* FTP ``USER`` / ``PASS`` commands on port 21.
* Any other TCP payload that looks like a login command (SMTP ``AUTH PLAIN``,
  POP3 ``PASS``, IMAP ``LOGIN``).

Captured secrets are masked in the report (only the first two characters are
kept) because a forensics report must not become a second leak.
"""

from __future__ import annotations

import base64
import re
from urllib.parse import parse_qsl

from netforensics.findings import Finding, Severity
from netforensics.packets import Packet

PASSWORD_FIELDS = re.compile(r"^(pass(word|wd|phrase)?|pwd|secret|token|api[_-]?key)$", re.I)
USER_FIELDS = re.compile(r"^(user(name)?|login|email|uid|account)$", re.I)
FTP_USER = re.compile(rb"^USER (\S+)\r?\n", re.M)
FTP_PASS = re.compile(rb"^PASS (\S+)\r?\n", re.M)
MAIL_LOGIN = re.compile(rb"^(AUTH PLAIN|AUTH LOGIN|PASS|[A-Za-z0-9]+ LOGIN) ?(\S*)", re.M)


def mask(secret: str) -> str:
    """Keep the first two characters, mask the rest."""
    if len(secret) <= 2:
        return "*" * len(secret)
    return secret[:2] + "*" * (len(secret) - 2)


def _finding(pkt: Packet, proto: str, user: str, secret: str, where: str, wf: str) -> Finding:
    assert pkt.ip and pkt.tcp
    return Finding(
        analyzer="credentials",
        title=f"Cleartext {proto} credential from {pkt.ip.src} to {pkt.ip.dst}:{pkt.tcp.dport}",
        severity=Severity.HIGH,
        technique="T1040",
        description=(
            f"Frame {pkt.number}: {where}. Username '{user}' and a secret ('{mask(secret)}', "
            f"{len(secret)} chars) crossed the network unencrypted; anyone on the path "
            "(or a MITM) can harvest them."
        ),
        indicators={"client": pkt.ip.src, "server": pkt.ip.dst, "port": pkt.tcp.dport,
                    "username": user, "protocol": proto},
        evidence={"frame": pkt.number, "secret_masked": mask(secret), "secret_length": len(secret)},
        wireshark_filter=wf,
    )


def analyze(packets: list[Packet]) -> list[Finding]:
    """Find credentials transmitted in cleartext over HTTP, FTP and mail protocols."""
    findings: list[Finding] = []
    pending_ftp_user: dict[tuple[str, str], str] = {}

    for pkt in packets:
        if not (pkt.ip and pkt.tcp and pkt.tcp.payload):
            continue
        payload = pkt.tcp.payload

        if pkt.http:
            auth = pkt.http.headers.get("authorization", "")
            if auth.lower().startswith("basic "):
                try:
                    decoded = base64.b64decode(auth[6:].strip() + "==").decode("latin-1")
                    user, _, secret = decoded.partition(":")
                except (ValueError, UnicodeDecodeError):
                    user, secret = "?", "?"
                findings.append(_finding(
                    pkt, "HTTP Basic", user, secret,
                    f"HTTP {pkt.http.method} {pkt.http.uri} on host {pkt.http.host} carried an "
                    "Authorization: Basic header (base64 is encoding, not encryption)",
                    'http.authorization contains "Basic"'))
            if pkt.http.method == "POST" and pkt.http.body:
                ctype = pkt.http.headers.get("content-type", "")
                if "x-www-form-urlencoded" in ctype or b"=" in pkt.http.body:
                    fields = dict(parse_qsl(pkt.http.body.decode("latin-1", errors="replace")))
                    user = next((v for k, v in fields.items() if USER_FIELDS.match(k)), "")
                    secret = next((v for k, v in fields.items() if PASSWORD_FIELDS.match(k)), "")
                    if secret:
                        findings.append(_finding(
                            pkt, "HTTP form POST", user or "(no user field)", secret,
                            f"HTTP POST {pkt.http.uri} to host {pkt.http.host} submitted a form with "
                            f"a password field ({', '.join(fields)})",
                            'http.request.method == "POST" && urlencoded-form.key contains "pass"'))
            continue

        key = (pkt.ip.src, pkt.ip.dst)
        if pkt.tcp.dport == 21:
            m_user = FTP_USER.search(payload)
            if m_user:
                pending_ftp_user[key] = m_user.group(1).decode("latin-1")
            m_pass = FTP_PASS.search(payload)
            if m_pass:
                findings.append(_finding(
                    pkt, "FTP", pending_ftp_user.get(key, "?"), m_pass.group(1).decode("latin-1"),
                    "FTP login (USER/PASS) on port 21", "ftp.request.command == \"PASS\""))
            continue

        if pkt.tcp.dport in (25, 110, 143, 587):
            m = MAIL_LOGIN.search(payload)
            if m and m.group(2):
                findings.append(_finding(
                    pkt, "mail", "(see payload)", m.group(2).decode("latin-1"),
                    f"{m.group(1).decode('latin-1')} on port {pkt.tcp.dport}",
                    f"tcp.port == {pkt.tcp.dport} && tcp.payload contains \"LOGIN\""))
    return findings
