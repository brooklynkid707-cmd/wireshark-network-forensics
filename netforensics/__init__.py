"""netforensics - a zero-dependency PCAP parser and network forensics toolkit.

The package reads classic libpcap files (``.pcap``) with nothing but the
Python standard library, decodes Ethernet / ARP / IPv4 / TCP / UDP / ICMP /
DNS / HTTP, and runs a set of detectors that model the kind of triage a SOC
analyst performs in Wireshark: port scans, ARP cache poisoning, DNS
tunneling, C2 beaconing, cleartext credentials, and traffic summaries.
"""

from netforensics.findings import Finding, Severity
from netforensics.pcap import PcapReader, read_pcap
from netforensics.writer import PcapWriter

__version__ = "1.0.0"

__all__ = [
    "Finding",
    "PcapReader",
    "PcapWriter",
    "Severity",
    "read_pcap",
    "__version__",
]
