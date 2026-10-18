# tshark recipes — reproduce every analyzer finding from the command line

`tshark` is Wireshark's CLI. Each recipe below reproduces, by hand, what the
matching `netforensics` analyzer concludes — useful for grepping large
captures, scripting triage, or sanity-checking the tool. Replace the file name
as needed. `-r` reads a file, `-Y` is a display filter, `-T fields -e` prints
chosen fields, `-q -z` runs a statistics tap.

> These are written for real `tshark`. The pcaps in `pcaps/` open in it
> directly. `netforensics` itself needs no tshark — it is pure Python.

---

## Capture overview (Statistics equivalents)

```bash
# Protocol hierarchy  (Statistics > Protocol Hierarchy)
tshark -r pcaps/baseline.pcap -q -z io,phs

# Endpoints / top talkers  (Statistics > Endpoints)
tshark -r pcaps/baseline.pcap -q -z endpoints,ip

# Conversations  (Statistics > Conversations)
tshark -r pcaps/baseline.pcap -q -z conv,tcp
```

---

## 1. TCP SYN port scan (T1046)

Count distinct destination ports each source sent a lone SYN to — a scanner
stands out with dozens to hundreds.

```bash
tshark -r pcaps/port_scan.pcap \
  -Y "tcp.flags.syn==1 && tcp.flags.ack==0" \
  -T fields -e ip.src -e tcp.dstport | sort | uniq -c | sort -rn | head

# Distinct ports per scanner:
tshark -r pcaps/port_scan.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" \
  -T fields -e ip.src -e tcp.dstport | awk '{print $1}' | sort | uniq -c
# ...or count unique ports for the suspected scanner:
tshark -r pcaps/port_scan.pcap -Y "ip.src==10.10.1.66 && tcp.flags.syn==1 && tcp.flags.ack==0" \
  -T fields -e tcp.dstport | sort -un | wc -l

# Which ports were actually open (answered SYN/ACK)?
tshark -r pcaps/port_scan.pcap -Y "ip.src==10.10.0.20 && tcp.flags.syn==1 && tcp.flags.ack==1" \
  -T fields -e tcp.srcport | sort -un
```

---

## 2. ARP spoofing / MITM (T1557.002)

Find any IP advertised by more than one MAC (the poisoning signature).

```bash
# IP -> MAC bindings seen in ARP replies; any IP with >1 MAC is suspect.
tshark -r pcaps/arp_spoof.pcap -Y "arp.opcode==2" \
  -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac | sort -u

# Count replies per source MAC (a poisoner floods replies):
tshark -r pcaps/arp_spoof.pcap -Y "arp.opcode==2" -T fields -e eth.src \
  | sort | uniq -c | sort -rn

# Gratuitous ARP:
tshark -r pcaps/arp_spoof.pcap -Y "arp.isgratuitous" -T fields -e arp.src.hw_mac
```

---

## 3. DNS tunnelling (T1071.004)

List query names, measure their length, count unique subdomains per domain.

```bash
# Longest query names first (encoded data hits the 63/253-byte limits):
tshark -r pcaps/dns_tunnel.pcap -Y "dns.flags.response==0" \
  -T fields -e dns.qry.name | awk '{print length, $0}' | sort -rn | head

# Unique subdomains under the suspect domain:
tshark -r pcaps/dns_tunnel.pcap -Y 'dns.qry.name contains "exfil-example.net"' \
  -T fields -e dns.qry.name | sort -u | wc -l

# Record types (tunnels love TXT=16 / NULL=10):
tshark -r pcaps/dns_tunnel.pcap -Y "dns.flags.response==0" \
  -T fields -e dns.qry.type | sort | uniq -c
```

---

## 4. Cleartext credentials (T1040)

```bash
# HTTP Basic auth headers:
tshark -r pcaps/http_credentials.pcap -Y "http.authorization" \
  -T fields -e ip.src -e http.host -e http.authorization

# Form POST bodies (decode later with: base64 -d / urldecode):
tshark -r pcaps/http_credentials.pcap -Y 'http.request.method=="POST"' \
  -T fields -e ip.src -e http.host -e http.file_data

# FTP credentials, if present:
tshark -r pcaps/http_credentials.pcap -Y 'ftp.request.command=="USER" || ftp.request.command=="PASS"' \
  -T fields -e ftp.request.command -e ftp.request.arg
```

---

## 5. C2 beaconing (T1071.001)

Print the relative time of each new connection to the suspect, then look at the
gaps — a beacon keeps a near-constant interval.

```bash
# Inter-arrival times of new connections to the C2:
tshark -r pcaps/c2_beacon.pcap \
  -Y "ip.dst==198.51.100.77 && tcp.flags.syn==1 && tcp.flags.ack==0" \
  -T fields -e frame.time_relative \
  | awk 'NR>1{printf "%.2f\n", $1-prev} {prev=$1}'

# Repeated URI / tiny user-agent that gives the beacon away:
tshark -r pcaps/c2_beacon.pcap -Y "http.request" \
  -T fields -e http.host -e http.request.uri -e http.user_agent | sort | uniq -c
```

---

## 6. ICMP exfiltration (T1048)

```bash
# Echo-request payload sizes (real ping is a constant 32/56 bytes):
tshark -r pcaps/icmp_exfil.pcap -Y "icmp.type==8" \
  -T fields -e ip.src -e ip.dst -e data.len | sort | uniq -c

# Total payload bytes smuggled to the destination:
tshark -r pcaps/icmp_exfil.pcap -Y "icmp.type==8 && ip.dst==198.51.100.77" \
  -T fields -e data.len | awk '{s+=$1} END{print s" bytes"}'
```

---

## 7. SMB lateral movement (T1021.002)

```bash
# Distinct SMB targets a source opened (fan-out):
tshark -r pcaps/smb_lateral.pcap \
  -Y "tcp.dstport==445 && tcp.flags.syn==1 && tcp.flags.ack==0" \
  -T fields -e ip.src -e ip.dst | sort -u | awk '{print $1}' | uniq -c

# Tree connects to administrative shares:
tshark -r pcaps/smb_lateral.pcap -Y 'smb2.cmd==3' \
  -T fields -e ip.src -e ip.dst -e smb2.tree
```

---

## Bulk export for a report

```bash
# Dump a filtered view to a new, smaller pcap for evidence:
tshark -r pcaps/port_scan.pcap -Y "ip.addr==10.10.1.66" -w evidence_scanner.pcap

# CSV of a conversation for a ticket:
tshark -r pcaps/c2_beacon.pcap -Y "ip.addr==198.51.100.77" \
  -T fields -E separator=, -E header=y \
  -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e tcp.dstport -e http.request.uri
```
