# Case notes — cleartext credential exposure

**Capture:** `pcaps/http_credentials.pcap`
**ATT&CK:** T1040 Network Sniffing · T1552.001 Unsecured Credentials · **Security+:** 1.4 (encryption), 4.1
**Verdict:** True positive — credentials submitted over plain HTTP, readable by anyone on-path.

---

## 1. Triage

Anything on port 80 carrying a login is a finding. I started with:

```
http.authorization || http.request.method == "POST"
```

Two hits to the intranet app at **10.10.0.80**.

## 2. Confirmation

**Form POST** — `http.request.method == "POST"`, then right-click >
**Follow > HTTP Stream**. The request body is right there in the clear:

```
POST /login HTTP/1.1
Host: intranet.corp.example
Content-Type: application/x-www-form-urlencoded

username=jscirica&password=Sup3rS3cret!&submit=Log+In
```

**HTTP Basic** — `http.authorization` shows:

```
Authorization: Basic YWRtaW46UGFzc3dvcmQxMjM=
```

Base64 is *encoding, not encryption*. Decode it:

```bash
echo YWRtaW46UGFzc3dvcmQxMjM= | base64 -d      # admin:Password123
```

tshark one-liners:

```bash
tshark -r pcaps/http_credentials.pcap -Y "http.authorization" \
  -T fields -e ip.src -e http.host -e http.authorization
tshark -r pcaps/http_credentials.pcap -Y 'http.request.method=="POST"' \
  -T fields -e http.host -e http.file_data
```

> `netforensics` reports both but **masks** the secrets (`Su**********`,
> `Pa*********`) so the report itself is not a second leak — it still shows the
> username (`jscirica`, `admin`), server, port and frame number for pivoting.

## 3. IOCs

| Type | Value |
|------|-------|
| Client | `10.10.1.13` |
| Server | `10.10.0.80:80` (intranet app) |
| Exposed accounts | `jscirica` (form), `admin` (Basic) |
| Protocols | HTTP form POST, HTTP Basic auth — both cleartext |

## 4. Assessment & response

Every credential here is recoverable by any passive sniffer or an ARP-spoofing
MITM (see case 02 — that attacker would harvest exactly these). The `admin`
Basic-auth account is the priority. Severity: **high**.

**Recommended response**
1. Force TLS on the intranet app (redirect 80→443, HSTS); disable plain HTTP.
2. Rotate `admin` and `jscirica` immediately; review the app's access logs for
   misuse during the exposure window.
3. Replace HTTP Basic with a session-token/SSO flow.
4. Add a monitoring rule for `http.authorization` and password-field POSTs on
   the wire — credentials should never appear in cleartext at all.
