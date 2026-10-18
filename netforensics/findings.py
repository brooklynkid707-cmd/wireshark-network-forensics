"""Finding and severity data types shared by every analyzer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Ordered severity levels. Higher value means more urgent."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        """Human readable label."""
        return self.name


@dataclass
class Finding:
    """A single detection produced by an analyzer.

    Attributes:
        analyzer: Short machine name of the analyzer (``port_scan``).
        title: One-line summary suitable for a report heading.
        severity: :class:`Severity` of the finding.
        description: Longer explanation of what was observed and why it matters.
        technique: MITRE ATT&CK technique ID(s), e.g. ``T1046``.
        indicators: Structured IOCs (IPs, MACs, domains, ports...).
        evidence: Supporting metrics used by the detector (counts, ratios...).
        wireshark_filter: A display filter that reproduces the view in Wireshark.
    """

    analyzer: str
    title: str
    severity: Severity
    description: str
    technique: str = ""
    indicators: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    wireshark_filter: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-friendly dictionary."""
        data = asdict(self)
        data["severity"] = self.severity.label
        return data
