"""Classic libpcap (``.pcap``) file reader.

Supports both byte orders, microsecond and nanosecond timestamp magics, and
only link-layer type 1 (Ethernet), which is what Wireshark writes for a
normal NIC capture. pcapng is intentionally out of scope: convert with
``editcap -F pcap in.pcapng out.pcap`` if needed.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from netforensics.packets import Packet
from netforensics.parsers import decode_packet

# Magic as read with a little-endian unpack of the first 4 bytes on disk.
# A file written little-endian yields 0xA1B2C3D4; big-endian yields 0xD4C3B2A1.
MAGIC_USEC_LE = 0xA1B2C3D4
MAGIC_USEC_BE = 0xD4C3B2A1
MAGIC_NSEC_LE = 0x4D3CB2A1
MAGIC_NSEC_BE = 0xA1B23C4D
LINKTYPE_ETHERNET = 1


class PcapError(ValueError):
    """Raised for malformed pcap files."""


@dataclass(frozen=True)
class PcapHeader:
    """Global pcap header fields."""

    endian: str
    nanosecond: bool
    version_major: int
    version_minor: int
    snaplen: int
    linktype: int


class PcapReader:
    """Iterate over decoded packets in a pcap file.

    Example::

        with PcapReader("capture.pcap") as reader:
            for pkt in reader:
                if pkt.dns:
                    print(pkt.dns.qname)
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._fh: BinaryIO | None = None
        self.header: PcapHeader | None = None

    def __enter__(self) -> PcapReader:
        self._fh = self.path.open("rb")
        self.header = self._read_global_header(self._fh)
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

    @staticmethod
    def _read_global_header(fh: BinaryIO) -> PcapHeader:
        raw = fh.read(24)
        if len(raw) < 24:
            raise PcapError("file too short for pcap global header")
        magic = struct.unpack("<I", raw[:4])[0]
        if magic in (MAGIC_USEC_LE, MAGIC_NSEC_LE):
            endian, nanosecond = "<", magic == MAGIC_NSEC_LE
        elif magic in (MAGIC_USEC_BE, MAGIC_NSEC_BE):
            endian, nanosecond = ">", magic == MAGIC_NSEC_BE
        else:
            raise PcapError(f"unknown pcap magic 0x{magic:08x} (pcapng is not supported)")
        major, minor, _tz, _sig, snaplen, linktype = struct.unpack(endian + "HHiIII", raw[4:24])
        if linktype != LINKTYPE_ETHERNET:
            raise PcapError(f"unsupported link type {linktype}; only Ethernet (1) is decoded")
        return PcapHeader(endian, nanosecond, major, minor, snaplen, linktype)

    def __iter__(self) -> Iterator[Packet]:
        if self._fh is None or self.header is None:
            raise PcapError("PcapReader must be used as a context manager")
        fmt = self.header.endian + "IIII"
        divisor = 1_000_000_000 if self.header.nanosecond else 1_000_000
        number = 0
        while True:
            rec = self._fh.read(16)
            if len(rec) < 16:
                return
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(fmt, rec)
            data = self._fh.read(incl_len)
            if len(data) < incl_len:
                return  # truncated final record: stop quietly like Wireshark does
            number += 1
            yield decode_packet(number, ts_sec + ts_frac / divisor, data)


def read_pcap(path: str | Path) -> list[Packet]:
    """Read an entire pcap into a list of decoded packets."""
    with PcapReader(path) as reader:
        return list(reader)
