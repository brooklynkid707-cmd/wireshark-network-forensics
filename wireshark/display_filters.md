# Wireshark display filter cheat sheet (by investigation task)

Display filters change *what you see*, not what is captured. Type them into the
filter bar (green = valid). These are organised the way a SOC analyst actually
works a capture: start broad, isolate a host or conversation, then confirm a
hypothesis. Every filter here maps to one of the scenarios this toolkit
generates and detects.

> Capture filters (BPF, set before capture) use a different syntax — a few are
> listed at the end. Everything above the divider is a **display** filter.

---

## 0. First five minutes with an unknown capture

| Goal | Filter |
|------|--------|
| Strip ARP/STP/LLDP noise, see only IP | `ip` |
| Only traffic to/from one host | `ip.addr == 10.10.1.66` |
| One conversation (both directions) | `ip.addr == 10.10.1.66 && ip.addr == 10.10.0.20` |
| Everything on a port | `tcp.port == 445` |
| Drop a chatty host while triaging | `!(ip.addr == 10.10.0.53)` |
| Only packets with a TCP payload | `tcp.len > 0` |
| Anything Wireshark flagged as an "expert" problem | `tcp.analysis.flags` |

`ip.addr ==` matches source **or** destination. Use `ip.src ==` / `ip.dst ==`
when direction matters (it almost always does in an investigation).

---

## 1. Port scanning / host discovery (T1046)

A SYN scan is a flood of lone SYNs; open ports answer SYN/ACK, closed ports
answer RST/ACK.

| Goal | Filter |
|------|--------|
| All connection *attempts* (lone SYN, no ACK) | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| SYNs from one suspected scanner | `ip.src == 10.10.1.66 && tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| Open-port responses (services that answered) | `tcp.flags.syn == 1 && tcp.flags.ack == 1` |
| Closed-port responses (the scan's RST storm) | `tcp.flags.reset == 1` |
| Likely scanner: resets it received | `ip.dst == 10.10.1.66 && tcp.flags.reset == 1` |

Confirm in **Statistics > Conversations > TCP**: a scanner shows hundreds of
one- or two-packet conversations to sequential ports on a single host.

---

## 2. ARP spoofing / MITM (T1557.002)

| Goal | Filter |
|------|--------|
| All ARP | `arp` |
| ARP replies only ("is-at") | `arp.opcode == 2` |
| Gratuitous ARP (sender IP == target IP) | `arp.isgratuitous` |
| Replies claiming a specific IP | `arp.src.proto_ipv4 == 10.10.0.1 && arp.opcode == 2` |
| Replies from a suspected poisoner MAC | `arp.opcode == 2 && eth.src == de:ad:be:ef:00:66` |
| Wireshark's own duplicate-address detector | `arp.duplicate-address-detected` |

Wireshark adds a yellow "duplicate IP address configured" expert note when one
IP answers from two MACs — the single clearest sign of poisoning. Confirm with
**Statistics > Endpoints > Ethernet** (one MAC sending a disproportionate
number of ARP replies) and by watching the victim's gateway entry flip MACs.

---

## 3. DNS tunnelling / DNS exfil (T1071.004)

| Goal | Filter |
|------|--------|
| All DNS | `dns` |
| Only queries (hide responses) | `dns.flags.response == 0` |
| TXT / NULL queries (classic tunnel carriers) | `dns.qry.type == 16 || dns.qry.type == 10` |
| Queries to one suspect domain | `dns.qry.name contains "exfil-example.net"` |
| Very long query names (encoded data) | `frame.len > 250 && dns` |
| Server failures / NXDOMAIN bursts | `dns.flags.rcode != 0` |

Confirm with **Statistics > DNS** (huge query count, mostly TXT) and
**Statistics > DNS > Query Name** — a tunnel shows thousands of unique,
never-repeated subdomains under one parent. Real browsing repeats a small set
of names.

---

## 4. Cleartext credentials (T1040 / T1552.001)

| Goal | Filter |
|------|--------|
| HTTP Basic auth headers | `http.authorization` |
| Any HTTP form POST | `http.request.method == "POST"` |
| POST bodies containing a password field | `urlencoded-form.key == "password"` |
| FTP password command | `ftp.request.command == "PASS"` |
| FTP user command | `ftp.request.command == "USER"` |
| Telnet (entirely cleartext) | `telnet` |
| IMAP/POP/SMTP login verbs | `imap.request.command == "LOGIN" || pop.request.command == "PASS"` |

Right-click the packet > **Follow > HTTP Stream** (or TCP Stream) to read the
whole exchange, credentials included. This is exactly what an attacker with a
tap or a successful ARP spoof sees.

---

## 5. C2 beaconing (T1071.001)

Beacons are periodic, small, and identical. Display filters isolate the
candidate; the *timing* is the proof.

| Goal | Filter |
|------|--------|
| New connections to a suspected C2 | `ip.dst == 198.51.100.77 && tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| HTTP requests to one host | `http.host == "cdn.example.net"` |
| One repeated URI | `http.request.uri contains "/api/v2/status"` |
| Suspicious short/odd user-agents | `http.user_agent == "Mozilla/4.0"` |
| Hide everything but one conversation | `ip.addr == 198.51.100.77` |

Confirm with **Statistics > Conversations > TCP**, add the **Duration** column,
and eyeball the inter-arrival time; or **Statistics > I/O Graph** with the C2
filter — a beacon draws an evenly spaced comb. Also add a custom time column:
right-click a column header > **Column Preferences** > *Delta time displayed*.

---

## 6. ICMP tunnelling / exfil (T1048 / T1095)

| Goal | Filter |
|------|--------|
| All ICMP | `icmp` |
| Echo requests only | `icmp.type == 8` |
| Oversized echo payloads (real ping is 32–56 B) | `icmp.type == 8 && data.len > 64` |
| Echo to an external host | `icmp.type == 8 && ip.dst == 198.51.100.77` |

A normal ping repeats the same padding (`08 09 0a 0b …`). Click into the ICMP
**Data** field across several packets: if it changes every packet and looks
random, it is a tunnel. **Statistics > Conversations** shows the surprising
byte volume riding on "ping".

---

## 7. SMB lateral movement (T1021.002)

| Goal | Filter |
|------|--------|
| All SMB2 | `smb2` |
| New SMB sessions (fan-out) | `tcp.dstport == 445 && tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| Session setup (authentication) | `smb2.cmd == 1` |
| Tree connect (share access) | `smb2.cmd == 3` |
| Connections to admin shares | `smb2.tree contains "ADMIN$" || smb2.tree contains "IPC$"` |
| SMB from one suspected source | `ip.src == 10.10.1.11 && tcp.port == 445` |

A workstation that opens 445 to many *other workstations* in seconds — and
reaches `ADMIN$`/`C$` — is doing PsExec-style remote execution. Confirm with
**Statistics > Conversations > TCP** filtered to port 445.

---

## Handy building blocks

| Need | Filter |
|------|--------|
| Time window | `frame.time >= "2026-03-14 09:00:00" && frame.time <= "2026-03-14 09:05:00"` |
| Seconds since capture start | `frame.time_relative < 30` |
| Payload byte search (hex) | `tcp contains 50:41:53:53` (`PASS`) |
| Payload text search | `frame contains "password"` |
| TCP retransmissions | `tcp.analysis.retransmission` |
| Out-of-subnet traffic | `!(ip.addr == 10.10.0.0/16)` |
| Combine | use `&&`, `||`, `!`, parentheses |

## A few matching capture filters (BPF, set before capture)

| Need | Capture filter |
|------|----------------|
| Only one host | `host 10.10.1.66` |
| Only a port | `tcp port 445` |
| Only ARP | `arp` |
| Only DNS | `udp port 53` |
| Exclude SSH management noise | `not tcp port 22` |
