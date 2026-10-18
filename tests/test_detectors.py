"""Each detector must fire on its own scenario and stay silent on the baseline."""

from __future__ import annotations

from pathlib import Path

import pytest

from netforensics.analyzers import ANALYZERS, run_all
from netforensics.analyzers.dnstunnel import shannon_entropy
from netforensics.findings import Severity
from netforensics.pcap import read_pcap


def test_each_detector_fires_on_its_scenario(pcap_dir: Path, scenarios: dict[str, str]) -> None:
    for scenario, analyzer in scenarios.items():
        packets = read_pcap(pcap_dir / f"{scenario}.pcap")
        findings = ANALYZERS[analyzer](packets)
        assert findings, f"{analyzer} did not fire on {scenario}"
        assert all(f.technique for f in findings), f"{analyzer} finding missing ATT&CK id"
        assert max(f.severity for f in findings) >= Severity.MEDIUM


def test_baseline_is_clean(pcap_dir: Path) -> None:
    """No analyzer may raise a MEDIUM+ finding on benign traffic (false-positive guard)."""
    packets = read_pcap(pcap_dir / "baseline.pcap")
    findings = [f for f in run_all(packets) if f.severity >= Severity.MEDIUM]
    assert not findings, f"false positives on baseline: {[f.title for f in findings]}"


@pytest.mark.parametrize("scenario,foreign", [
    ("port_scan", ["arp_spoof", "dns_tunnel", "icmp_exfil"]),
    ("dns_tunnel", ["port_scan", "credentials"]),
    ("arp_spoof", ["dns_tunnel", "icmp_exfil"]),
    ("icmp_exfil", ["port_scan", "arp_spoof"]),
])
def test_detectors_are_specific(pcap_dir: Path, scenario: str, foreign: list[str]) -> None:
    """A capture should not trip unrelated detectors."""
    packets = read_pcap(pcap_dir / f"{scenario}.pcap")
    for analyzer in foreign:
        assert not ANALYZERS[analyzer](packets), f"{analyzer} false-fired on {scenario}"


def test_port_scan_details(pcap_dir: Path) -> None:
    findings = ANALYZERS["port_scan"](read_pcap(pcap_dir / "port_scan.pcap"))
    f = findings[0]
    assert f.indicators["scanner_ip"] == "10.10.1.66"
    assert f.evidence["unique_ports"] >= 50
    assert set(f.indicators["open_ports"]) >= {22, 80, 445}


def test_arp_spoof_identifies_conflict(pcap_dir: Path) -> None:
    findings = ANALYZERS["arp_spoof"](read_pcap(pcap_dir / "arp_spoof.pcap"))
    titles = " ".join(f.title for f in findings)
    assert "10.10.0.1" in titles or any("10.10.0.1" in str(f.indicators) for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_dns_tunnel_entropy_and_domain(pcap_dir: Path) -> None:
    findings = ANALYZERS["dns_tunnel"](read_pcap(pcap_dir / "dns_tunnel.pcap"))
    f = findings[0]
    assert "exfil-example.net" in f.indicators["domain"]
    assert f.evidence["mean_entropy"] > 3.5
    assert f.evidence["unique_subdomains"] >= 10


def test_beacon_interval(pcap_dir: Path) -> None:
    findings = ANALYZERS["beacon"](read_pcap(pcap_dir / "c2_beacon.pcap"))
    f = findings[0]
    assert f.indicators["c2_server"] == "198.51.100.77"
    assert 25 <= f.evidence["mean_interval_s"] <= 35
    assert f.evidence["coefficient_of_variation"] < 0.35


def test_credentials_masked(pcap_dir: Path) -> None:
    findings = ANALYZERS["credentials"](read_pcap(pcap_dir / "http_credentials.pcap"))
    assert findings
    joined = " ".join(str(f.evidence) + str(f.indicators) for f in findings)
    assert "Sup3rS3cret" not in joined and "Password123" not in joined  # secrets masked
    assert any(f.indicators.get("username") == "jscirica" for f in findings)


def test_shannon_entropy_bounds() -> None:
    assert shannon_entropy("aaaaaa") == 0.0
    assert shannon_entropy("abcdefgh") == pytest.approx(3.0, abs=0.01)


def test_run_all_sorted_by_severity(pcap_dir: Path) -> None:
    findings = run_all(read_pcap(pcap_dir / "arp_spoof.pcap"))
    severities = [int(f.severity) for f in findings]
    assert severities == sorted(severities, reverse=True)
