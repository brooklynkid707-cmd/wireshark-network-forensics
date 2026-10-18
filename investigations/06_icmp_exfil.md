# Case notes — ICMP tunnelling / exfiltration

**Capture:** `pcaps/icmp_exfil.pcap`
**ATT&CK:** T1048.003 Exfil Over Unencrypted Non-C2 Protocol · T1095 Non-Application Layer Protocol · **Security+:** 2.4, 4.4
**Verdict:** True positive — data smuggled inside oversized, high-entropy ICMP echo payloads.

---

## 1. Triage

"It's just ping" is how ICMP tunnels survive. Filtered to echo requests:

```
icmp.type == 8
```

and immediately noticed the **Length** column: these echoes are 400–900 bytes,
not the 32 (Windows) or 56 (Linux) bytes a normal `ping` sends.

## 2. Confirmation

- **Oversized:** `icmp.type == 8 && data.len > 64` keeps every packet — all 30
  echoes carry large payloads (mean **651 bytes**).
- **Varying payload:** click the ICMP **Data** field on consecutive packets. A
  real ping repeats a fixed pattern (`08 09 0a 0b …`); here the bytes change
  every single packet (`netforensics`: unique-payload ratio **1.0**).
- **Random-looking:** mean Shannon entropy **7.68 bits/byte** (max is 8.0) —
  consistent with encrypted/compressed data, not padding.

```bash
tshark -r pcaps/icmp_exfil.pcap -Y "icmp.type==8" \
  -T fields -e ip.src -e ip.dst -e data.len | sort | uniq -c
tshark -r pcaps/icmp_exfil.pcap -Y "icmp.type==8 && ip.dst==198.51.100.77" \
  -T fields -e data.len | awk '{s+=$1} END{print s}'      # -> 19526 bytes
```

Two of three indicators (oversized + varying + high-entropy) are required to
fire; all three are present.

## 3. IOCs

| Type | Value |
|------|-------|
| Source | `10.10.1.15` |
| Destination | `198.51.100.77` (external) |
| Volume | 30 echo requests, **19,526** payload bytes |
| Signature | 651-byte mean payload, 100% unique, entropy 7.68 |

## 4. Assessment & response

~19 KB left the network disguised as ping to an external host — enough for
keys, a config dump, or a document. ICMP is frequently allowed outbound without
inspection. Severity: **high**.

**Recommended response**
1. Block/rate-limit outbound ICMP echo to the internet at the perimeter; drop
   echo payloads over a sane size.
2. Isolate and investigate `10.10.1.15` for the tunnelling tool (ptunnel/icmpsh).
3. Assume data loss; identify what the host had access to and notify as policy requires.
4. Add detection: ICMP echo payload length and entropy thresholds; alert on
   sustained echo volume to a single external destination.
