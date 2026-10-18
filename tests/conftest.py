"""Shared fixtures: generate the scenario pcaps once into a temp dir per session."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import generate_pcaps  # noqa: E402


@pytest.fixture(scope="session")
def pcap_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Generate every scenario capture once and return the directory."""
    out = tmp_path_factory.mktemp("pcaps")
    generate_pcaps.generate(out)
    return out


@pytest.fixture(scope="session")
def scenarios() -> dict[str, str]:
    """Map scenario name -> primary analyzer expected to fire."""
    return {
        "port_scan": "port_scan",
        "arp_spoof": "arp_spoof",
        "dns_tunnel": "dns_tunnel",
        "http_credentials": "credentials",
        "c2_beacon": "beacon",
        "icmp_exfil": "icmp_exfil",
        "smb_lateral": "smb_lateral",
    }
