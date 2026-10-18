"""Command-line interface: ``python -m netforensics analyze|summary``."""

from __future__ import annotations

import argparse
import glob
import sys
from pathlib import Path

from netforensics import __version__
from netforensics.analyzers import ANALYZERS, run_all
from netforensics.findings import Severity
from netforensics.pcap import PcapError, read_pcap
from netforensics.report import (
    CaptureResult,
    render_console,
    render_summary_text,
    write_html,
    write_json,
)
from netforensics.summary import summarize


def _expand(paths: list[str]) -> list[str]:
    """Expand shell globs (Windows shells do not) and keep order, dropping duplicates."""
    out: list[str] = []
    for p in paths:
        matches = sorted(glob.glob(p)) or [p]
        for m in matches:
            if m not in out:
                out.append(m)
    return out


def analyze_file(path: str, analyzers: list[str] | None = None) -> CaptureResult:
    """Read one pcap, summarise it and run the selected (default: all) analyzers."""
    packets = read_pcap(path)
    if analyzers:
        findings = []
        for name in analyzers:
            findings.extend(ANALYZERS[name](packets))
        findings.sort(key=lambda f: (-int(f.severity), f.analyzer, f.title))
    else:
        findings = run_all(packets)
    return CaptureResult(path=path, summary=summarize(packets), findings=findings)


def cmd_analyze(args: argparse.Namespace) -> int:
    """``analyze`` sub-command."""
    results: list[CaptureResult] = []
    for path in _expand(args.pcaps):
        try:
            results.append(analyze_file(path, args.analyzer))
        except (OSError, PcapError) as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            return 2
    if args.min_severity:
        floor = Severity[args.min_severity.upper()]
        for res in results:
            res.findings = [f for f in res.findings if f.severity >= floor]
    if not args.quiet:
        print(render_console(results))
    if args.json:
        write_json(results, args.json)
        print(f"JSON report written to {args.json}")
    if args.html:
        write_html(results, args.html)
        print(f"HTML report written to {args.html}")
    worst = max((r.max_severity for r in results), default=Severity.INFO)
    return 1 if (args.fail_on and worst >= Severity[args.fail_on.upper()]) else 0


def cmd_summary(args: argparse.Namespace) -> int:
    """``summary`` sub-command: statistics only, no detectors."""
    for path in _expand(args.pcaps):
        try:
            packets = read_pcap(path)
        except (OSError, PcapError) as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            return 2
        print(render_summary_text(summarize(packets, top_n=args.top), path))
        print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser."""
    parser = argparse.ArgumentParser(
        prog="python -m netforensics",
        description="Zero-dependency PCAP analysis: port scans, ARP spoofing, DNS tunnels, "
                    "C2 beacons, cleartext credentials, ICMP exfil, SMB lateral movement.",
    )
    parser.add_argument("--version", action="version", version=f"netforensics {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_an = sub.add_parser("analyze", help="run all detectors and print/write a report")
    p_an.add_argument("pcaps", nargs="+", help="pcap file(s); shell globs are accepted")
    p_an.add_argument("--json", metavar="FILE", help="write a JSON report")
    p_an.add_argument("--html", metavar="FILE", help="write an HTML report")
    p_an.add_argument("--analyzer", action="append", choices=sorted(ANALYZERS),
                      help="run only this analyzer (repeatable)")
    p_an.add_argument("--min-severity", choices=[s.name.lower() for s in Severity],
                      help="hide findings below this severity")
    p_an.add_argument("--fail-on", choices=[s.name.lower() for s in Severity],
                      help="exit 1 if any finding reaches this severity (for CI / pipelines)")
    p_an.add_argument("-q", "--quiet", action="store_true", help="suppress the console report")
    p_an.set_defaults(func=cmd_analyze)

    p_sum = sub.add_parser("summary", help="print capture statistics (endpoints, conversations, protocols)")
    p_sum.add_argument("pcaps", nargs="+", help="pcap file(s)")
    p_sum.add_argument("--top", type=int, default=10, help="rows per table (default 10)")
    p_sum.set_defaults(func=cmd_summary)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
