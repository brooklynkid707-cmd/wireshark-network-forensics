"""CLI, JSON and HTML report smoke tests."""

from __future__ import annotations

import json
from pathlib import Path

from netforensics.cli import main
from netforensics.report import CaptureResult, render_html, write_json
from netforensics.summary import summarize
from netforensics.analyzers import run_all
from netforensics.pcap import read_pcap


def test_cli_analyze_json_html(pcap_dir: Path, tmp_path: Path, capsys) -> None:
    out_json = tmp_path / "out.json"
    out_html = tmp_path / "out.html"
    rc = main(["analyze", str(pcap_dir / "port_scan.pcap"),
               "--json", str(out_json), "--html", str(out_html)])
    assert rc == 0
    captured = capsys.readouterr().out
    assert "TCP SYN scan" in captured
    doc = json.loads(out_json.read_text())
    assert doc["captures"][0]["findings"]
    assert doc["captures"][0]["max_severity"] in {"HIGH", "MEDIUM", "CRITICAL"}
    html = out_html.read_text()
    assert "<!DOCTYPE html>" in html and "Network Forensics Report" in html


def test_cli_fail_on(pcap_dir: Path) -> None:
    assert main(["analyze", str(pcap_dir / "baseline.pcap"), "-q", "--fail-on", "high"]) == 0
    assert main(["analyze", str(pcap_dir / "smb_lateral.pcap"), "-q", "--fail-on", "high"]) == 1


def test_cli_summary(pcap_dir: Path, capsys) -> None:
    rc = main(["summary", str(pcap_dir / "baseline.pcap")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Protocol hierarchy" in out and "Top talkers" in out


def test_cli_glob_multiple(pcap_dir: Path, tmp_path: Path, capsys) -> None:
    rc = main(["analyze", str(pcap_dir / "*.pcap"), "-q", "--json", str(tmp_path / "all.json")])
    assert rc == 0
    doc = json.loads((tmp_path / "all.json").read_text())
    assert len(doc["captures"]) == 8


def test_html_escapes_values(pcap_dir: Path) -> None:
    packets = read_pcap(pcap_dir / "port_scan.pcap")
    res = CaptureResult(path="<script>evil</script>", summary=summarize(packets), findings=run_all(packets))
    html = render_html([res])
    assert "<script>evil</script>" not in html
    assert "&lt;script&gt;" in html
