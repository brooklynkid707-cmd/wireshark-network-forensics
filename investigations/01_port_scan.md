# Case notes — TCP SYN port scan

**Capture:** `pcaps/port_scan.pcap`
**ATT&CK:** T1046 Network Service Discovery · **Security+ SY0-701:** 2.4 (recon), 4.4 (monitoring)
**Verdict:** True positive — internal host conducting a half-open TCP port scan.

---

## 1. Triage — what first caught my eye

Opened the capture and sorted **Statistics > Conversations > TCP**. Instead of
a handful of long conversations, there were ~190 conversations between a single
pair of hosts, almost all 1–2 packets long, to sequential/scattered ports. That
shape — one source, one destination, many tiny connections — is a scan, not an
application.

Applied the connection-attempt filter:

```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

The packet list filled with lone SYNs from **10.10.1.66**, source port fixed at
41337, destination port climbing. Classic `nmap -sS` behaviour.

## 2. Confirmation

- **Scanner → target:** `ip.src == 10.10.1.66 && tcp.flags.syn==1 && tcp.flags.ack==0`
  → 190 unique destination ports on **10.10.0.20**, all inside a ~10-second window.
- **Closed ports:** `ip.dst == 10.10.1.66 && tcp.flags.reset == 1` → 185 RST/ACKs
  came back. Normal clients rarely touch closed ports; a wall of RSTs is the scan's echo.
- **Open ports:** `ip.src == 10.10.0.20 && tcp.flags.syn==1 && tcp.flags.ack==1`
  → SYN/ACK from ports **22, 80, 139, 445, 3389**. The scanner answered each with a
  RST (half-open — never completes the handshake, so the service logs nothing).

tshark cross-check:

```bash
tshark -r pcaps/port_scan.pcap -Y "ip.src==10.10.1.66 && tcp.flags.syn==1 && tcp.flags.ack==0" \
  -T fields -e tcp.dstport | sort -un | wc -l      # -> 190
```

`netforensics` reports the same: *190 ports in 10s, 185 RST, 5 open.*

## 3. IOCs

| Type | Value |
|------|-------|
| Scanner (internal) | `10.10.1.66` |
| Target | `10.10.0.20` (file server) |
| Open services found by attacker | 22/tcp, 80/tcp, 139/tcp, 445/tcp, 3389/tcp |
| Pattern | fixed source port 41337, 190 SYNs in ~10 s, half-open (SYN→RST) |

## 4. Assessment & response

A host on the user VLAN enumerating the file server's services is
reconnaissance — the step before exploitation or lateral movement. RDP (3389)
and SMB (445) being open and discovered is the immediate risk.

**Recommended response**
1. Isolate/quarantine `10.10.1.66`; identify the logged-in user and whether the
   scan was authorised (pentest? rogue tool? compromised host?).
2. On `10.10.0.20`, review auth logs for follow-on connection attempts to 3389/445.
3. Trigger an IDS rule for high unique-port-per-source rates; alert the SOC.
4. If unauthorised, image the scanning host for IR and rotate any credentials it held.
