"""Decoded packet layers.

Each layer is a small frozen dataclass. A :class:`Packet` holds the capture
timestamp, the raw bytes, and whichever layers were successfully decoded.
Layers that are absent are ``None`` so callers can simply test ``if pkt.tcp``.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Ethernet:
    """Ethernet II header."""

    dst: str
    src: str
    ethertype: int


@dataclass(frozen=True)
class ARP:
    """ARP packet (Ethernet / IPv4 only)."""

    opcode: int  # 1 = request, 2 = reply
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str

    @property
    def is_reply(self) -> bool:
        """True for ARP replies."""
        return self.opcode == 2

    @property
    def is_gratuitous(self) -> bool:
        """Gratuitous ARP: sender and target IP are identical."""
        return self.sender_ip == self.target_ip


@dataclass(frozen=True)
class IPv4:
    """IPv4 header."""

    src: str
    dst: str
    protocol: int
    ttl: int
    identification: int
    total_length: int
    header_length: int
    flags: int
    fragment_offset: int


@dataclass(frozen=True)
class TCP:
    """TCP header plus payload."""

    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    window: int
    payload: bytes

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20

    @property
    def flag_names(self) -> str:
        """Compact flag string such as ``SYN``, ``SYN/ACK``, ``PSH/ACK``."""
        names = []
        for bit, name in ((self.SYN, "SYN"), (self.ACK, "ACK"), (self.FIN, "FIN"),
                          (self.RST, "RST"), (self.PSH, "PSH"), (self.URG, "URG")):
            if self.flags & bit:
                names.append(name)
        return "/".join(names) or "NONE"

    @property
    def is_syn_only(self) -> bool:
        """True for a pure SYN (new connection attempt, no ACK)."""
        return bool(self.flags & self.SYN) and not self.flags & self.ACK

    @property
    def is_syn_ack(self) -> bool:
        """True for SYN/ACK (open port response)."""
        return bool(self.flags & self.SYN) and bool(self.flags & self.ACK)

    @property
    def is_rst(self) -> bool:
        """True when the RST bit is set."""
        return bool(self.flags & self.RST)


@dataclass(frozen=True)
class UDP:
    """UDP header plus payload."""

    sport: int
    dport: int
    length: int
    payload: bytes


@dataclass(frozen=True)
class ICMP:
    """ICMP header plus payload."""

    type: int
    code: int
    identifier: int
    sequence: int
    payload: bytes


@dataclass(frozen=True)
class DNS:
    """DNS message (only the fields the analyzers care about)."""

    transaction_id: int
    is_response: bool
    rcode: int
    questions: tuple[tuple[str, int], ...]  # (name, qtype)
    answer_count: int

    @property
    def qname(self) -> str:
        """First question name, or empty string."""
        return self.questions[0][0] if self.questions else ""

    @property
    def qtype(self) -> int:
        """First question type, or 0."""
        return self.questions[0][1] if self.questions else 0


@dataclass(frozen=True)
class HTTP:
    """HTTP/1.x request (only requests are decoded)."""

    method: str
    uri: str
    version: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    @property
    def host(self) -> str:
        """Host header value (lower-case lookup)."""
        return self.headers.get("host", "")


@dataclass
class Packet:
    """A single captured frame with decoded layers."""

    number: int
    timestamp: float
    raw: bytes
    eth: Ethernet | None = None
    arp: ARP | None = None
    ip: IPv4 | None = None
    tcp: TCP | None = None
    udp: UDP | None = None
    icmp: ICMP | None = None
    dns: DNS | None = None
    http: HTTP | None = None

    @property
    def length(self) -> int:
        """Captured frame length in bytes."""
        return len(self.raw)

    @property
    def highest_layer(self) -> str:
        """Name of the top-most decoded protocol (``DNS``, ``TCP`` ...)."""
        for name in ("http", "dns", "tcp", "udp", "icmp", "arp", "ip", "eth"):
            if getattr(self, name) is not None:
                return name.upper()
        return "RAW"

    @property
    def protocol_path(self) -> list[str]:
        """Ordered list of decoded layers, e.g. ``['ETH', 'IP', 'UDP', 'DNS']``."""
        path = []
        for name in ("eth", "arp", "ip", "tcp", "udp", "icmp", "dns", "http"):
            if getattr(self, name) is not None:
                path.append(name.upper())
        return path
