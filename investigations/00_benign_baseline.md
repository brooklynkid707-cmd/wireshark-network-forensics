# Case notes — benign baseline (control)

**Capture:** `pcaps/baseline.pcap`
**Verdict:** No findings — this is the control used to tune thresholds and prove the detectors are specific, not trigger-happy.

---

## Why a baseline matters

A detector that fires on everything is useless. Before trusting any rule, you
need to know it stays quiet on normal traffic. This capture is five minutes of
ordinary office activity on the same network: HTTPS browsing, intranet HTTP,
SMB to the file server, solicited ARP refreshes, short pings, and NTP.

## What normal looks like here

- **Protocol mix** (`Statistics > Protocol Hierarchy`): mostly TCP/443 (TLS),
  some HTTP, SMB, a little DNS/UDP and ARP. No single internal host fanning out.
- **ARP:** every reply is *solicited* — each `is-at` follows a `who-has`, and
  each IP maps to exactly one MAC. No duplicates, no unsolicited flood.
- **DNS:** a handful of names (`www.example.com`, `cdn.example.net`, …) that
  **repeat** and resolve to A records. Short, low-entropy, cacheable.
- **ICMP:** a few echoes with the standard fixed 56-byte Linux padding.
- **Timing:** connection intervals are irregular (human-driven), so the beacon
  detector's coefficient-of-variation test never trips.

## Result

`python -m netforensics analyze pcaps/baseline.pcap` → **0 findings**. Every
analyzer ran and none reached even MEDIUM. The pytest suite enforces this as a
false-positive guard (`test_baseline_is_clean`): if a threshold is ever loosened
too far, that test fails and the regression is caught before it ships.

This is the single most important file in the repo for credibility — detections
are only meaningful next to a clean control.
