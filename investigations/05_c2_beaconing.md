# Case notes — C2 beaconing

**Capture:** `pcaps/c2_beacon.pcap`
**ATT&CK:** T1071.001 Application Layer Protocol: Web Protocols · T1573 (if encrypted) · **Security+:** 2.4, 4.4
**Verdict:** True positive — implant beaconing to an external C2 on a fixed interval.

---

## 1. Triage

Beaconing hides in plain HTTP; the tell is *timing*, not content. In
**Statistics > Conversations > TCP** I added the **Duration** column and spotted
a conversation to an external host, **198.51.100.77**, that kept reopening on a
metronome. Isolated the new connections:

```
ip.dst == 198.51.100.77 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

15 connections, evenly spaced.

## 2. Confirmation

Measured the inter-arrival gaps (Wireshark: add a *delta time displayed* column,
or tshark):

```bash
tshark -r pcaps/c2_beacon.pcap \
  -Y "ip.dst==198.51.100.77 && tcp.flags.syn==1 && tcp.flags.ack==0" \
  -T fields -e frame.time_relative | awk 'NR>1{printf "%.1f\n",$1-p} {p=$1}'
```

Gaps cluster tightly around **30 s**. `netforensics` quantifies it:
mean **29.97 s**, std-dev **0.97 s**, **coefficient of variation 0.032**. Human
browsing has a CV well above 1; a value this low is machine-scheduled.

Content corroborates:
- Same URI pattern every time: `GET /api/v2/status?id=NNNN` (`http.request.uri contains "/api/v2/status"`).
- Tiny, antique user-agent `Mozilla/4.0` (`http.user_agent`).
- Request size identical every beacon (request-size CV = 0.0).
- **Statistics > I/O Graph** with the conversation filter draws an even comb.

## 3. IOCs

| Type | Value |
|------|-------|
| Infected host | `10.10.1.14` |
| C2 server | `198.51.100.77:80` (resolved via `cdn.example.net`) |
| URI | `/api/v2/status?id=<rand>` |
| User-Agent | `Mozilla/4.0` |
| Cadence | ~30 s interval, CV 0.032 (very low jitter) |

## 4. Assessment & response

A host checking in with external infrastructure on a schedule is an active
implant. The `id=` parameter and fixed cadence are the poll loop. Severity:
**high** (escalate to critical if tasking/exfil is seen on the same channel).

**Recommended response**
1. Block `198.51.100.77` and the `cdn.example.net` resolution at the proxy/firewall.
2. Isolate `10.10.1.14`; capture volatile memory, then image for IR.
3. Hunt the fleet for the same beacon pattern (interval + URI + UA) — one
   implant usually means more.
4. Add detection: low inter-arrival CV per external destination, rare/legacy
   user-agents, and uniform request sizes.
