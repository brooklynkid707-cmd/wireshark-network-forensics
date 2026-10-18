#!/usr/bin/env python3
"""Generate synthetic PCAP captures for each attack scenario plus a benign baseline.

All traffic is fabricated with a seeded RNG so the output is reproducible.
Addresses follow RFC 1918 (10.10.0.0/16 corporate LAN) and RFC 5737
documentation ranges (203.0.113.0/24, 198.51.100.0/24) for "internet" hosts.
Nothing here touches a real network.

Usage::

    python scripts/generate_pcaps.py             # writes pcaps/*.pcap
    python scripts/generate_pcaps.py --out /tmp  # elsewhere

If scapy happens to be installed it is used only to re-read each file as a
sanity check; the frames themselves are built with the standard library.
"""

from __future__ import annotations

import argparse
import base64
import os
import random
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netforensics.packets import TCP  # noqa: E402
from netforensics.writer import (  # noqa: E402
    BROADCAST_MAC,
    PcapWriter,
    build_arp,
    build_dns_query,
    build_dns_response,
    build_ethernet,
    build_icmp,
    build_ipv4,
    build_tcp,
    build_udp,
)
from netforensics.parsers import ETHERTYPE_ARP, ETHERTYPE_IPV4, IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP  # noqa: E402

START = 1_773_478_800.0  # 2026-03-14 09:00:00 UTC

# --- Lab network --------------------------------------------------------------
GATEWAY = ("10.10.0.1", "00:1c:73:aa:00:01")
DNS_SERVER = ("10.10.0.53", "00:1c:73:aa:00:53")
FILE_SERVER = ("10.10.0.20", "00:50:56:b1:00:20")
WEB_INTRANET = ("10.10.0.80", "00:50:56:b1:00:80")
WORKSTATIONS = [
    ("10.10.1.11", "3c:52:82:11:11:11"),
    ("10.10.1.12", "3c:52:82:12:12:12"),
    ("10.10.1.13", "3c:52:82:13:13:13"),
    ("10.10.1.14", "3c:52:82:14:14:14"),
    ("10.10.1.15", "3c:52:82:15:15:15"),
]
ATTACKER = ("10.10.1.66", "de:ad:be:ef:00:66")
VICTIM = WORKSTATIONS[0]
INTERNET = {
    "www.example.com": "203.0.113.10",
    "cdn.example.net": "203.0.113.25",
    "mail.example.org": "203.0.113.40",
    "updates.example.com": "203.0.113.55",
    "pool.ntp.example.org": "198.51.100.123",
}
C2_SERVER = "198.51.100.77"
TUNNEL_DOMAIN = "t1.exfil-example.net"
TUNNEL_RESOLVER = "198.51.100.53"

BENIGN_NAMES = list(INTERNET)


class Net:
    """Tiny stateful helper that emits frames with monotonically increasing time."""

    def __init__(self, writer: PcapWriter, rng: random.Random) -> None:
        self.w = writer
        self.rng = rng
        self.t = START
        self.ip_id = rng.randint(1, 60000)

    # -- timing --------------------------------------------------------------
    def tick(self, seconds: float) -> None:
        """Advance the clock."""
        self.t += seconds

    def jitter(self, lo: float = 0.0005, hi: float = 0.004) -> None:
        """Advance by a tiny random amount (LAN latency)."""
        self.t += self.rng.uniform(lo, hi)

    def _id(self) -> int:
        self.ip_id = (self.ip_id + 1) & 0xFFFF
        return self.ip_id

    # -- layer-2 emitters -----------------------------------------------------
    def _mac_for(self, ip: str) -> str:
        for host in (GATEWAY, DNS_SERVER, FILE_SERVER, WEB_INTRANET, ATTACKER, *WORKSTATIONS):
            if host[0] == ip:
                return host[1]
        return GATEWAY[1]  # off-subnet traffic goes via the gateway

    def ip_frame(self, src: str, dst: str, proto: int, l4: bytes, ttl: int = 64,
                 src_mac: str | None = None, dst_mac: str | None = None) -> None:
        """Emit Ethernet/IPv4 frame around a layer-4 payload."""
        frame = build_ethernet(src_mac or self._mac_for(src), dst_mac or self._mac_for(dst), ETHERTYPE_IPV4,
                               build_ipv4(src, dst, proto, l4, ttl=ttl, identification=self._id()))
        self.w.write(frame, self.t)
        self.jitter()

    def arp(self, opcode: int, sender: tuple[str, str], target_ip: str, target_mac: str = "00:00:00:00:00:00",
            dst_mac: str = BROADCAST_MAC) -> None:
        """Emit an ARP packet."""
        frame = build_ethernet(sender[1], dst_mac, ETHERTYPE_ARP,
                               build_arp(opcode, sender[1], sender[0], target_mac, target_ip))
        self.w.write(frame, self.t)
        self.jitter()

    # -- protocol helpers -----------------------------------------------------
    def tcp(self, src: str, dst: str, sport: int, dport: int, flags: int, seq: int, ack: int,
            payload: bytes = b"", **kw: object) -> None:
        """Emit one TCP segment."""
        self.ip_frame(src, dst, IPPROTO_TCP, build_tcp(src, dst, sport, dport, flags, seq, ack, payload), **kw)

    def tcp_session(self, client: str, server: str, dport: int, request: bytes = b"",
                    response: bytes = b"", sport: int | None = None, rtt: float = 0.02,
                    close: bool = True) -> None:
        """Full three-way handshake, optional request/response, FIN teardown."""
        sport = sport or self.rng.randint(49152, 65535)
        cseq, sseq = self.rng.randint(1, 2**31), self.rng.randint(1, 2**31)
        self.tcp(client, server, sport, dport, TCP.SYN, cseq, 0)
        self.tick(rtt)
        self.tcp(server, client, dport, sport, TCP.SYN | TCP.ACK, sseq, cseq + 1)
        self.tcp(client, server, sport, dport, TCP.ACK, cseq + 1, sseq + 1)
        cseq, sseq = cseq + 1, sseq + 1
        if request:
            self.tcp(client, server, sport, dport, TCP.PSH | TCP.ACK, cseq, sseq, request)
            cseq += len(request)
            self.tick(rtt)
            self.tcp(server, client, dport, sport, TCP.ACK, sseq, cseq)
        if response:
            self.tcp(server, client, dport, sport, TCP.PSH | TCP.ACK, sseq, cseq, response)
            sseq += len(response)
            self.tcp(client, server, sport, dport, TCP.ACK, cseq, sseq)
        if close:
            self.tcp(client, server, sport, dport, TCP.FIN | TCP.ACK, cseq, sseq)
            self.tcp(server, client, dport, sport, TCP.FIN | TCP.ACK, sseq, cseq + 1)
            self.tcp(client, server, sport, dport, TCP.ACK, cseq + 1, sseq + 1)

    def dns(self, client: str, name: str, answer: str | None, qtype: int = 1,
            resolver: str | None = None, txt: bytes | None = None, rcode: int = 0) -> None:
        """DNS query + response."""
        resolver = resolver or DNS_SERVER[0]
        txid = self.rng.randint(0, 0xFFFF)
        sport = self.rng.randint(49152, 65535)
        self.ip_frame(client, resolver, IPPROTO_UDP, build_udp(client, resolver, sport, 53, build_dns_query(txid, name, qtype)))
        self.tick(self.rng.uniform(0.005, 0.03))
        self.ip_frame(resolver, client, IPPROTO_UDP,
                      build_udp(resolver, client, 53, sport, build_dns_response(txid, name, answer, qtype, rcode, txt)))

    def ping(self, src: str, dst: str, ident: int, seq: int, payload: bytes) -> None:
        """ICMP echo request + reply."""
        self.ip_frame(src, dst, IPPROTO_ICMP, build_icmp(8, 0, ident, seq, payload))
        self.tick(self.rng.uniform(0.001, 0.01))
        self.ip_frame(dst, src, IPPROTO_ICMP, build_icmp(0, 0, ident, seq, payload))


LINUX_PING = bytes(range(0x08, 0x08 + 56))


def http_get(host: str, path: str = "/") -> bytes:
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            f"Accept: text/html\r\nConnection: close\r\n\r\n").encode()


def http_200(body: bytes = b"<html><body>ok</body></html>") -> bytes:
    return (f"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n").encode() + body


TLS_CLIENT_HELLO = bytes.fromhex("160301") + bytes([0, 200]) + bytes.fromhex("010000c40303") + bytes(194)
TLS_SERVER_HELLO = bytes.fromhex("160303") + bytes([0, 90]) + bytes.fromhex("020000560303") + bytes(84)


# --- Background traffic -------------------------------------------------------

def background(net: Net, seconds: float, intensity: float = 1.0) -> None:
    """Emit realistic, benign office traffic for roughly ``seconds`` of capture time."""
    end = net.t + seconds
    while net.t < end:
        ws = net.rng.choice(WORKSTATIONS)
        roll = net.rng.random()
        if roll < 0.35:
            name = net.rng.choice(BENIGN_NAMES)
            net.dns(ws[0], name, INTERNET[name])
            net.tcp_session(ws[0], INTERNET[name], 443, TLS_CLIENT_HELLO, TLS_SERVER_HELLO)
        elif roll < 0.5:
            net.tcp_session(ws[0], WEB_INTRANET[0], 80, http_get("intranet.corp.example", "/news"), http_200())
        elif roll < 0.65:
            net.tcp_session(ws[0], FILE_SERVER[0], 445, smb2_negotiate(), smb2_negotiate(response=True))
        elif roll < 0.75:
            # ARP refresh: who-has gateway, gateway replies (solicited, single MAC)
            net.arp(1, ws, GATEWAY[0])
            net.arp(2, GATEWAY, ws[0], ws[1], dst_mac=ws[1])
        elif roll < 0.82:
            ident = net.rng.randint(1, 65535)
            for seq in range(1, 4):
                net.ping(ws[0], GATEWAY[0], ident, seq, LINUX_PING)
                net.tick(1.0)
        else:
            ntp = INTERNET["pool.ntp.example.org"]
            net.ip_frame(ws[0], ntp, IPPROTO_UDP, build_udp(ws[0], ntp, 123, 123, b"\x23" + bytes(47)))
            net.ip_frame(ntp, ws[0], IPPROTO_UDP, build_udp(ntp, ws[0], 123, 123, b"\x24" + bytes(47)))
        net.tick(net.rng.uniform(0.5, 6.0) / intensity)


def smb2_negotiate(response: bool = False) -> bytes:
    """Minimal SMB2 NEGOTIATE (command 0) framed in NetBIOS session service."""
    hdr = b"\xfeSMB" + bytes(60)
    hdr = hdr[:12] + (0).to_bytes(2, "little") + hdr[14:]
    flags = (1).to_bytes(4, "little") if response else bytes(4)
    hdr = hdr[:16] + flags + hdr[20:]
    body = hdr + bytes(36)
    return b"\x00" + len(body).to_bytes(3, "big") + body


def smb2_message(command: int, payload: bytes = b"") -> bytes:
    hdr = b"\xfeSMB" + bytes(60)
    hdr = hdr[:12] + command.to_bytes(2, "little") + hdr[14:]
    body = hdr + payload
    return b"\x00" + len(body).to_bytes(3, "big") + body


# --- Scenarios ----------------------------------------------------------------

def scenario_baseline(net: Net) -> None:
    """Five minutes of ordinary office traffic: nothing should fire."""
    background(net, 300, intensity=1.2)


def scenario_port_scan(net: Net) -> None:
    """Attacker runs a SYN scan of the top 200 ports against the file server (nmap -sS style)."""
    background(net, 40)
    target = FILE_SERVER[0]
    open_ports = {22, 80, 139, 445, 3389}
    ports = sorted(net.rng.sample(range(1, 1024), 180) + [22, 80, 139, 445, 3389, 8080, 8443, 3306, 5432, 1433])
    net.rng.shuffle(ports)
    sport = 41337
    for port in ports:
        seq = net.rng.randint(1, 2**31)
        net.tcp(ATTACKER[0], target, sport, port, TCP.SYN, seq, 0)
        net.tick(net.rng.uniform(0.002, 0.01))
        if port in open_ports:
            net.tcp(target, ATTACKER[0], port, sport, TCP.SYN | TCP.ACK, net.rng.randint(1, 2**31), seq + 1)
            net.tcp(ATTACKER[0], target, sport, port, TCP.RST, seq + 1, 0)
        else:
            net.tcp(target, ATTACKER[0], port, sport, TCP.RST | TCP.ACK, 0, seq + 1)
        net.tick(net.rng.uniform(0.005, 0.03))
    background(net, 30)


def scenario_arp_spoof(net: Net) -> None:
    """Attacker poisons victim and gateway caches, then relays the victim's HTTP traffic."""
    background(net, 30)
    # Legitimate exchange first so the real binding is on record.
    net.arp(1, VICTIM, GATEWAY[0])
    net.arp(2, GATEWAY, VICTIM[0], VICTIM[1], dst_mac=VICTIM[1])
    net.tick(5)
    fake_gw = (GATEWAY[0], ATTACKER[1])   # attacker claims to be the gateway
    fake_victim = (VICTIM[0], ATTACKER[1])  # ...and the victim
    for _ in range(25):
        net.arp(2, fake_gw, VICTIM[0], VICTIM[1], dst_mac=VICTIM[1])      # to victim: gateway is-at attacker
        net.arp(2, fake_victim, GATEWAY[0], GATEWAY[1], dst_mac=GATEWAY[1])  # to gateway: victim is-at attacker
        if net.rng.random() < 0.3:
            # the victim's periodic refresh still gets the legitimate answer, creating the conflict
            net.arp(1, VICTIM, GATEWAY[0])
            net.arp(2, GATEWAY, VICTIM[0], VICTIM[1], dst_mac=VICTIM[1])
        # Relayed traffic: victim -> "gateway" MAC is actually the attacker
        net.tcp(VICTIM[0], INTERNET["www.example.com"], 50123, 80, TCP.PSH | TCP.ACK, 1000, 2000,
                http_get("www.example.com", "/account"), dst_mac=ATTACKER[1])
        net.tcp(VICTIM[0], INTERNET["www.example.com"], 50123, 80, TCP.PSH | TCP.ACK, 1000, 2000,
                http_get("www.example.com", "/account"), src_mac=ATTACKER[1], dst_mac=GATEWAY[1])
        net.tick(net.rng.uniform(1.5, 2.5))
    background(net, 20)




def _rand_b32(rng: random.Random, n: int) -> str:
    """A random lowercase base32-ish label used to simulate encoded tunnel data."""
    alphabet = string.ascii_lowercase + "234567"
    return "".join(rng.choice(alphabet) for _ in range(n))


def scenario_dns_tunnel(net: Net) -> None:
    """Workstation runs a DNS tunnel: long, high-entropy, non-repeating subdomains."""
    background(net, 30)
    client = WORKSTATIONS[1][0]
    for i in range(60):
        # Two 40-char encoded labels under the attacker domain, TXT record answers.
        label = f"{_rand_b32(net.rng, 40)}.{_rand_b32(net.rng, 30)}.{TUNNEL_DOMAIN}"
        txt = base64.b64encode(os.urandom(24))
        net.dns(client, label, None, qtype=16, resolver=TUNNEL_RESOLVER, txt=txt)
        net.tick(net.rng.uniform(0.3, 0.9))
    background(net, 20)


def scenario_http_credentials(net: Net) -> None:
    """A user logs into an intranet app over cleartext HTTP (form POST + Basic auth)."""
    background(net, 25)
    user = WORKSTATIONS[2][0]
    form = b"username=jscirica&password=Sup3rS3cret!&submit=Log+In"
    post = (f"POST /login HTTP/1.1\r\nHost: intranet.corp.example\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(form)}\r\n"
            f"Connection: close\r\n\r\n").encode() + form
    net.tcp_session(user, WEB_INTRANET[0], 80, post, http_200(b"Welcome"))
    net.tick(3)
    creds = base64.b64encode(b"admin:Password123").decode()
    basic = (f"GET /admin HTTP/1.1\r\nHost: intranet.corp.example\r\n"
             f"Authorization: Basic {creds}\r\nConnection: close\r\n\r\n").encode()
    net.tcp_session(user, WEB_INTRANET[0], 80, basic, http_200(b"admin panel"))
    background(net, 20)


def scenario_c2_beacon(net: Net) -> None:
    """Implant beacons to its C2 every 30s (+/- small jitter) over HTTP."""
    background(net, 20)
    host = WORKSTATIONS[3][0]
    net.dns(host, "cdn.example.net", C2_SERVER)  # resolves to the C2 the first time
    interval = 30.0
    for i in range(15):
        get = (f"GET /api/v2/status?id={net.rng.randint(1000,9999)} HTTP/1.1\r\n"
               f"Host: cdn.example.net\r\nUser-Agent: Mozilla/4.0\r\nConnection: close\r\n\r\n").encode()
        net.tcp_session(host, C2_SERVER, 80, get, http_200(b"c2-ack-noop"))
        net.tick(interval + net.rng.uniform(-1.5, 1.5))  # small jitter, CV stays low
    background(net, 15)


def scenario_icmp_exfil(net: Net) -> None:
    """Host exfiltrates a file in oversized, high-entropy ICMP echo payloads."""
    background(net, 20)
    src = WORKSTATIONS[4][0]
    ident = net.rng.randint(1, 65535)
    for seq in range(1, 31):
        payload = os.urandom(net.rng.randint(400, 900))  # random == encrypted chunk
        net.ping(src, C2_SERVER, ident, seq, payload)
        net.tick(net.rng.uniform(0.1, 0.4))
    background(net, 15)


def scenario_smb_lateral(net: Net) -> None:
    """Compromised workstation sprays SMB/445 across the subnet (PsExec-style)."""
    background(net, 20)
    attacker = WORKSTATIONS[0][0]
    targets = [f"10.10.1.{n}" for n in range(20, 45)]
    for ip in targets:
        net.tcp(attacker, ip, net.rng.randint(49152, 65535), 445, TCP.SYN, net.rng.randint(1, 2**31), 0,
                dst_mac=GATEWAY[1])
        net.tick(net.rng.uniform(0.05, 0.3))
    # Follow up on a few that "answered" with session setup + TREE_CONNECT to ADMIN$.
    for ip in targets[:6]:
        setup = smb2_message(1)
        tree = smb2_message(3, ("\\\\" + ip + "\\ADMIN$").encode("utf-16-le"))
        net.tcp_session(attacker, ip, 445, setup + tree, smb2_message(3), rtt=0.01)
        net.tick(net.rng.uniform(0.2, 0.6))
    background(net, 15)


SCENARIOS = {
    "baseline": scenario_baseline,
    "port_scan": scenario_port_scan,
    "arp_spoof": scenario_arp_spoof,
    "dns_tunnel": scenario_dns_tunnel,
    "http_credentials": scenario_http_credentials,
    "c2_beacon": scenario_c2_beacon,
    "icmp_exfil": scenario_icmp_exfil,
    "smb_lateral": scenario_smb_lateral,
}


def generate(out_dir: Path, seed: int = 1337) -> list[Path]:
    """Write every scenario to ``out_dir`` and return the paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, fn in SCENARIOS.items():
        path = out_dir / f"{name}.pcap"
        rng = random.Random(seed + sum(name.encode()))
        with PcapWriter(path) as writer:
            fn(Net(writer, rng))
        written.append(path)
        print(f"  {path.name:<22} {writer.count:>5} packets  {path.stat().st_size:>8} bytes")
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic attack PCAPs.")
    parser.add_argument("--out", default=str(Path(__file__).resolve().parent.parent / "pcaps"),
                        help="output directory (default: ./pcaps)")
    parser.add_argument("--seed", type=int, default=1337, help="RNG seed")
    args = parser.parse_args(argv)
    print(f"Generating synthetic captures into {args.out}")
    paths = generate(Path(args.out), args.seed)
    print(f"Done: {len(paths)} captures.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
