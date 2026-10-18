"""Report rendering: console text, JSON and a self-contained HTML page.

The HTML uses :class:`string.Template` from the standard library; there is no
templating engine dependency and every user-controlled value is escaped with
:func:`html.escape`.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from typing import Any

from netforensics.findings import Finding, Severity
from netforensics.summary import CaptureSummary


@dataclass
class CaptureResult:
    """Everything produced for one pcap."""

    path: str
    summary: CaptureSummary
    findings: list[Finding] = field(default_factory=list)

    @property
    def max_severity(self) -> Severity:
        """Highest severity among the findings (INFO if none)."""
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def to_dict(self) -> dict[str, Any]:
        """JSON-friendly dictionary."""
        return {
            "pcap": self.path,
            "max_severity": self.max_severity.label,
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
        }


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ----------------------------------------------------------------------------
# Console
# ----------------------------------------------------------------------------

def render_summary_text(summary: CaptureSummary, path: str) -> str:
    """Wireshark-Statistics-style text block for one capture."""
    lines = [
        f"Capture: {path}",
        f"  Packets: {summary.packets}   Bytes: {summary.bytes}   Duration: {summary.duration_s:.2f}s",
    ]
    if summary.packets:
        lines.append(f"  First: {_fmt_ts(summary.first_timestamp)}   Last: {_fmt_ts(summary.last_timestamp)}")
    lines.append(f"  DNS queries: {summary.dns_queries} ({summary.unique_dns_names} unique names)   "
                 f"ARP: {summary.arp_packets}   HTTP requests: {summary.http_requests}")
    lines.append("  Protocol hierarchy:")
    for proto, count in summary.protocol_hierarchy.items():
        pct = 100.0 * count / summary.packets if summary.packets else 0
        lines.append(f"    {proto:<24} {count:>7}  ({pct:5.1f}%)")
    lines.append("  Top talkers:")
    for row in summary.top_talkers:
        lines.append(f"    {row['address']:<18} {row['packets']:>7} pkts {row['bytes']:>10} bytes")
    lines.append("  Top conversations:")
    for row in summary.conversations:
        lines.append(f"    {row['a']:<16} <-> {row['b']:<16} {row['packets']:>6} pkts "
                     f"{row['bytes']:>9} bytes  {','.join(row['protocols'])}")
    lines.append("  Top ports:")
    for row in summary.top_ports:
        lines.append(f"    {row['port']:<12} {row['packets']:>7} pkts")
    return "\n".join(lines)


def render_findings_text(findings: list[Finding]) -> str:
    """Numbered list of findings for the console."""
    if not findings:
        return "  No findings - capture looks benign under the current thresholds."
    lines = []
    for i, f in enumerate(findings, 1):
        lines.append(f"  [{i}] {f.severity.label:<8} {f.analyzer:<12} {f.technique:<10} {f.title}")
        lines.append(f"      {f.description}")
        if f.wireshark_filter:
            lines.append(f"      Wireshark: {f.wireshark_filter}")
    return "\n".join(lines)


def render_console(results: list[CaptureResult]) -> str:
    """Full console report for one or more captures."""
    blocks = []
    for res in results:
        blocks.append("=" * 78)
        blocks.append(render_summary_text(res.summary, res.path))
        blocks.append(f"\nFindings ({len(res.findings)}), max severity {res.max_severity.label}:")
        blocks.append(render_findings_text(res.findings))
    blocks.append("=" * 78)
    total = sum(len(r.findings) for r in results)
    by_sev: dict[str, int] = {}
    for r in results:
        for f in r.findings:
            by_sev[f.severity.label] = by_sev.get(f.severity.label, 0) + 1
    sev_text = ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items(), key=lambda kv: -Severity[kv[0]]))
    blocks.append(f"Analyzed {len(results)} capture(s): {total} finding(s) [{sev_text or 'none'}]")
    return "\n".join(blocks)


# ----------------------------------------------------------------------------
# JSON
# ----------------------------------------------------------------------------

def write_json(results: list[CaptureResult], path: str | Path) -> None:
    """Write all results to a JSON document."""
    doc = {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "tool": "netforensics",
        "captures": [r.to_dict() for r in results],
    }
    Path(path).write_text(json.dumps(doc, indent=2), encoding="utf-8")


# ----------------------------------------------------------------------------
# HTML
# ----------------------------------------------------------------------------

_PAGE = Template("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network Forensics Report</title>
<style>
  :root { --bg:#f6f7f9; --fg:#1b1f24; --card:#fff; --line:#d9dde3; --muted:#5b6470;
          --crit:#b3261e; --high:#d9480f; --med:#b8860b; --low:#2b6cb0; --info:#4a5568; }
  body { margin:0; padding:24px 16px; font:15px/1.5 system-ui, -apple-system, Segoe UI, sans-serif;
         background:var(--bg); color:var(--fg); }
  main { max-width:1080px; margin:0 auto; }
  h1 { margin:0 0 4px; font-size:26px; } h2 { font-size:20px; margin:32px 0 8px; }
  h3 { font-size:16px; margin:0 0 6px; }
  .muted { color:var(--muted); }
  .card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:16px; margin:12px 0; }
  .badge { display:inline-block; padding:2px 8px; border-radius:4px; color:#fff; font-size:12px; font-weight:600; }
  .CRITICAL{background:var(--crit)} .HIGH{background:var(--high)} .MEDIUM{background:var(--med)}
  .LOW{background:var(--low)} .INFO{background:var(--info)}
  table { border-collapse:collapse; width:100%; font-size:14px; }
  th, td { text-align:left; padding:4px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
  code { background:#eef1f5; padding:1px 4px; border-radius:3px; font-size:13px; word-break:break-all; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:12px; }
  dl { margin:8px 0 0; } dt { font-weight:600; } dd { margin:0 0 6px 0; }
</style>
</head>
<body>
<main>
<h1>Network Forensics Report</h1>
<p class="muted">Generated $generated by netforensics. $capture_count capture(s), $finding_count finding(s).</p>
<h2>Overview</h2>
<div class="card">
<table>
<tr><th>Capture</th><th>Packets</th><th>Duration</th><th>Findings</th><th>Max severity</th></tr>
$overview_rows
</table>
</div>
$capture_sections
</main>
</body>
</html>
""")

_CAPTURE = Template("""
<h2 id="$anchor">$path</h2>
<div class="grid">
  <div class="card"><h3>Capture facts</h3>
    <table>
    <tr><td>Packets</td><td>$packets</td></tr>
    <tr><td>Bytes</td><td>$bytes</td></tr>
    <tr><td>Duration</td><td>$duration s</td></tr>
    <tr><td>DNS queries</td><td>$dns_queries ($dns_unique unique)</td></tr>
    <tr><td>ARP packets</td><td>$arp</td></tr>
    <tr><td>HTTP requests</td><td>$http</td></tr>
    </table></div>
  <div class="card"><h3>Protocol hierarchy</h3><table>$hierarchy_rows</table></div>
  <div class="card"><h3>Top talkers</h3><table><tr><th>Address</th><th>Packets</th><th>Bytes</th></tr>$talker_rows</table></div>
  <div class="card"><h3>Top conversations</h3><table><tr><th>A</th><th>B</th><th>Pkts</th><th>Bytes</th><th>Proto</th></tr>$conv_rows</table></div>
</div>
<h3 style="margin-top:16px">Findings ($finding_count)</h3>
$finding_cards
""")

_FINDING = Template("""
<div class="card">
  <span class="badge $severity">$severity</span>
  <strong>$title</strong> <span class="muted">&middot; $analyzer &middot; $technique</span>
  <p>$description</p>
  <dl>
    <dt>Indicators</dt><dd><code>$indicators</code></dd>
    <dt>Evidence</dt><dd><code>$evidence</code></dd>
    <dt>Wireshark display filter</dt><dd><code>$wfilter</code></dd>
  </dl>
</div>
""")


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def render_html(results: list[CaptureResult]) -> str:
    """Render all results as a single HTML document."""
    overview_rows = []
    sections = []
    for idx, res in enumerate(results):
        anchor = f"cap{idx}"
        overview_rows.append(
            f'<tr><td><a href="#{anchor}">{_e(res.path)}</a></td><td>{res.summary.packets}</td>'
            f"<td>{res.summary.duration_s:.2f}s</td><td>{len(res.findings)}</td>"
            f'<td><span class="badge {res.max_severity.label}">{res.max_severity.label}</span></td></tr>'
        )
        hierarchy_rows = "".join(f"<tr><td>{_e(p)}</td><td>{c}</td></tr>"
                                 for p, c in res.summary.protocol_hierarchy.items())
        talker_rows = "".join(f"<tr><td>{_e(r['address'])}</td><td>{r['packets']}</td><td>{r['bytes']}</td></tr>"
                              for r in res.summary.top_talkers)
        conv_rows = "".join(
            f"<tr><td>{_e(r['a'])}</td><td>{_e(r['b'])}</td><td>{r['packets']}</td><td>{r['bytes']}</td>"
            f"<td>{_e(','.join(r['protocols']))}</td></tr>" for r in res.summary.conversations)
        cards = "".join(_FINDING.substitute(
            severity=f.severity.label, title=_e(f.title), analyzer=_e(f.analyzer),
            technique=_e(f.technique or "-"), description=_e(f.description),
            indicators=_e(json.dumps(f.indicators)), evidence=_e(json.dumps(f.evidence)),
            wfilter=_e(f.wireshark_filter or "-"),
        ) for f in res.findings) or '<p class="muted">No findings.</p>'
        sections.append(_CAPTURE.substitute(
            anchor=anchor, path=_e(res.path), packets=res.summary.packets, bytes=res.summary.bytes,
            duration=f"{res.summary.duration_s:.2f}", dns_queries=res.summary.dns_queries,
            dns_unique=res.summary.unique_dns_names, arp=res.summary.arp_packets,
            http=res.summary.http_requests, hierarchy_rows=hierarchy_rows, talker_rows=talker_rows,
            conv_rows=conv_rows, finding_count=len(res.findings), finding_cards=cards,
        ))
    return _PAGE.substitute(
        generated=_e(datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")),
        capture_count=len(results),
        finding_count=sum(len(r.findings) for r in results),
        overview_rows="\n".join(overview_rows),
        capture_sections="\n".join(sections),
    )


def write_html(results: list[CaptureResult], path: str | Path) -> None:
    """Write the HTML report to disk."""
    Path(path).write_text(render_html(results), encoding="utf-8")
