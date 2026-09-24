# Switch adapters

Falcon is a decision service. The switch keeps signaling and media. Falcon
scores the SIP request and returns an action. There are two ways to ask:

1. `POST /v1/screen` over HTTP from a script hook in the switch.
2. Send the INVITE to Falcon over SIP. Falcon answers as a redirect server:
   302 to continue, 603 to drop. This is for switches with no script hook.

Fail open if Falcon does not answer. Every adapter here does.

## Which adapter for which platform

| Platform | Adapter | Tested |
| --- | --- | --- |
| Asterisk 16 to 21, FreePBX, Issabel, VitalPBX, PBX in a Flash, Wazo | `asterisk/falcon.agi` (AGI) or `asterisk/falcon_ari.py` (ARI) | Real Asterisk 20 container in CI, plus an AGI harness |
| FreeSWITCH 1.10, FusionPBX | `freeswitch/falcon.lua` | Real FreeSWITCH 1.10 container with `mod_curl` in CI, plus a Lua harness |
| Kamailio 5.x | `kamailio/falcon.cfg`, or `kamailio/falcon_async.cfg` for a busy proxy | Real Kamailio 5.5 container in CI, both routes |
| OpenSIPS 3.x | `opensips/falcon.cfg`, or `opensips/falcon_async.cfg` for a busy proxy | Real OpenSIPS 3.6 container in CI, both routes |
| ConnexCS | `connexcs/falcon.js` (ScriptForge App) for INVITE, `connexcs/falcon-live.xml` (ConneXML) for live voice | Node harness in CI, all three enforcement postures |
| Sansay VSXi, Sippy, PortaSwitch, Telinta, Metaswitch, Ribbon, Oracle SBC, AudioCodes, Cisco CUBE, TelcoBridges, BroadWorks, VOS3000, and any switch that can route to a SIP redirect server | SIP redirect listener, no adapter file | UDP and TCP tests, `sipsend` in CI |
| Telnyx Call Control (Voice API v2) | `telnyx/falcon.js` in your webhook handler | Node harness in CI: signed webhooks, all three enforcement postures, outbound, outcome |
| Telnyx SIP connection | The adapter of the switch it points at; see [Telnyx](#sip-connection) for the connection settings | Through that switch's tests |
| 2600Hz Kazoo | HTTP from a Pivot callflow | Not yet |
| Twilio, Bandwidth, Vonage, Plivo, SignalWire | HTTP from your voice webhook | Not yet |

Platforms with no call hook and no redirect routing cannot use Falcon
in line. 3CX and Yeastar are in that group.

## HTTP request

```http
POST /v1/screen HTTP/1.1
Host: 127.0.0.1:8090
Content-Type: application/json
X-Falcon-Token: replace-me
```

```json
{
  "switch": "asterisk",
  "source_ip": "203.0.113.10",
  "raw_sip": "INVITE sip:+15551212@carrier.example SIP/2.0\r\n..."
}
```

You can send selected headers instead of the raw message:

```json
{
  "switch": "kamailio",
  "method": "INVITE",
  "request_uri": "sip:+15551212@carrier.example",
  "source_ip": "203.0.113.10",
  "headers": {
    "From": "<sip:+14155550100@origin.example>;tag=1",
    "To": "<sip:+15551212@carrier.example>",
    "Call-ID": "abc@host",
    "User-Agent": "Asterisk PBX 20",
    "Identity": ""
  }
}
```

You can also POST the raw SIP body with `Content-Type: application/sip`.

`source_ip` may carry a port (`203.0.113.10:5060`). Falcon strips it.
Numbers must be inside a `sip:`, `sips:`, or `tel:` URI. A bare
`user@host` is not parsed.

## HTTP response

```json
{
  "action": "reject",
  "risk_score": 90,
  "risk_band": "high",
  "sip_status": 603,
  "sip_reason": "Decline",
  "reasons": [
    {"code": "scanner_user_agent", "weight": 90, "detail": "User-Agent matches a known SIP scanner", "category": "ua"}
  ],
  "signals": {
    "verstat": "TN-Validation-Passed",
    "signer_spc": "1234",
    "signer_name": "Example Carrier LLC",
    "ip_provider": "Example Wholesale"
  },
  "headers_to_set": {
    "X-Falcon-Score": "90",
    "X-Falcon-Action": "reject",
    "X-Falcon-Reasons": "scanner_user_agent",
    "X-Falcon-Verstat": "TN-Validation-Passed",
    "X-Falcon-Signer": "1234",
    "X-Falcon-Provider": "Example Wholesale"
  },
  "switch_hints": {
    "asterisk_hangup_cause": 21,
    "freeswitch_hangup_cause": "CALL_REJECTED",
    "kamailio_reply": "603 Decline"
  }
}
```

Actions:

1. `allow` - continue the call.
2. `flag` - continue the call and attach the `X-Falcon-*` headers.
3. `challenge` - treat as a reject, or send 407 if you own that policy.
4. `reject` - drop the call.

`X-Falcon-Block` is present on a hard reject and names the source:
`denylist`, `spam_feed`, `ip_intel`, `caller_id`, or `bcid`. Send the
`Identity` header when the switch has it. Without it Falcon cannot verify
STIR/SHAKEN or name the signer.

When Business Caller ID returns a name, Falcon also sets `bcid`,
`bcid_name`, `X-Falcon-BCID`, `X-Falcon-BCID-Name`, and
`Remote-Party-ID`. Apply those headers when the switch can inject them.
Show `bcid_name` as the caller display name.

## SIP redirect listener

For a switch or SBC that cannot run a script. The switch routes the INVITE
to Falcon first, as it would to any redirect server or ENUM style policy
hop. Falcon replies and is out of the dialog.

```
FALCON_SIP_LISTEN=0.0.0.0:5060
FALCON_SIP_PEERS=203.0.113.10,198.51.100.0/24
FALCON_SIP_REDIRECT_HOST=
FALCON_SIP_TIMEOUT=2s
```

`FALCON_SIP_PEERS` lists the switch IPs and CIDRs that may send. Anything
else is dropped without a reply. A listen address that is not loopback
with an empty peer list refuses to start. SIP has no token, so the peer
list is the gate.

What comes back:

| Falcon action | SIP answer |
| --- | --- |
| `allow`, `flag` | `302 Moved Temporarily`, `Contact: <Request-URI>`, `X-Falcon-*` headers |
| `reject` | `603 Decline` (or the `sip_status` Falcon chose), `X-Falcon-*` headers |
| `challenge` | `603 Decline`. A redirect server owns no authentication |
| `OPTIONS` | `200 OK`. Use it as the health probe from the switch |

`FALCON_SIP_REDIRECT_HOST=10.0.0.5:5080` replaces the host and port in the
Contact of the 302, so the switch continues to your real egress. Empty
echoes the Request-URI. Most switches only read the 302 as "continue" and
ignore the Contact host.

Source IP: Falcon reads `X-Source-IP` from the INVITE when the switch adds
it. Otherwise it reads the hop below the switch in `Via`. Otherwise it
uses the peer address. A B2BUA sends one Via, so add `X-Source-IP` with
the remote address in its header manipulation rules.

UDP and TCP on the same port. Retransmitted INVITEs get the same final
response for 32 seconds. Falcon sends `100 Trying` at once, so a slow
STIR/SHAKEN fetch never triggers a switch retransmit storm.

Switch side, in one line each:

- Kamailio or OpenSIPS: `$du = "sip:falcon:5060"; t_relay();` and in the
  failure route on 3xx call `get_redirects()` from `uac_redirect` (or use
  the HTTP cfg below).
- Sansay VSXi, Sippy, PortaSwitch, Telinta: define Falcon as a SIP
  redirect server route and put it first.
- Ribbon, Oracle, AudioCodes, Metaswitch, Cisco CUBE: a routing policy
  that sends the INVITE to Falcon first and route-advances on 302. The
  vendor name for this differs. Reject codes pass through as they are.

Test from any host with the bundled tool:

```bash
go run ./adapters/e2e/sipsend -to falcon:5060 -from +13125550188
```

## Asterisk

AGI is the default path. It uses the Python standard library only.

1. Copy `asterisk/falcon.agi` and `asterisk/falcon_hangup.agi` to
   `/var/lib/asterisk/agi-bin/` and make them executable. Asterisk logs
   `Permission denied` and continues the call when they are not.
2. Include `asterisk/extensions.conf` in the inbound context. The patterns
   are `_[+0-9]X.`, so E.164 destinations with a plus match.
3. Set `FALCON_URL` and `FALCON_TOKEN` in the Asterisk environment
   (`/etc/default/asterisk` or the systemd unit).

FreePBX, Issabel, VitalPBX, and PBX in a Flash: put the context in
`extensions_custom.conf` and point the trunk's inbound context at
`from-trunk-falcon`. Wazo: the same, in a custom dialplan file.

The ARI app is `asterisk/falcon_ari.py`. Install `ari` from
`asterisk/requirements-ari.txt`. Point `Stasis(falcon,from-internal,${EXTEN},1)` at it.

## FreeSWITCH

1. `load mod_curl` in `modules.conf.xml`.
2. Copy `freeswitch/falcon.lua` and `freeswitch/falcon_hangup.lua` to the
   scripts directory.
3. Include `freeswitch/dialplan.xml` in the inbound dialplan.
4. Set `FALCON_URL` and `FALCON_TOKEN` in the FreeSWITCH environment.

The script hangs up when the action is `reject` or `challenge`.
FusionPBX: add a dialplan entry with `lua falcon.lua` as the first action
of the inbound route.

## Kamailio

1. Load `http_client.so` and `jansson.so`.
2. Define `FALCON_URL` and `FALCON_TOKEN`, then import `kamailio/falcon.cfg`.
3. Call `route(FALCON_SCREEN)` from `request_route` on INVITE.

```
#!define FALCON_URL "http://127.0.0.1:8090/v1/screen"
#!define FALCON_TOKEN "replace-me"
import_file "falcon.cfg"
```

The screen holds a worker for up to 2 s. On a busy proxy use
`kamailio/falcon_async.cfg` instead: load `tm.so`, `http_async_client.so`,
and `jansson.so`, import the async file, and define `route[FALCON_CONTINUE]`
with what you did after the screen. The transaction is suspended while
Falcon answers and workers keep serving other calls. Reply with `t_reply()`
and relay with `t_relay()` inside it.

## OpenSIPS

1. Load `cfgutils.so`, `sl.so`, `sipmsgops.so`, `rest_client.so`, and
   `json.so`.
2. Set the two shared variables, then include `opensips/falcon.cfg`.
3. Call `route(falcon_screen);` from the main route on INVITE.

```
modparam("cfgutils", "shvset", "falcon_url=s:http://127.0.0.1:8090/v1/screen")
modparam("cfgutils", "shvset", "falcon_token=s:replace-me")
include_file "falcon.cfg"
```

On a busy proxy include `opensips/falcon_async.cfg` instead, load `tm.so`
as well, and define `route[falcon_continue]` with what you did after the
screen. `rest_post()` runs inside `async()`, so the worker is free while
Falcon answers.

## Carrier profile

Falcon's default scoring is tuned for an inbound trunk into a PBX, where
one IP sending 30 calls a minute is a scanner. On a class 4 or wholesale
ingress that is one normal customer. With the defaults, a call center CLI
that reaches 30 numbers in an hour scores `challenge`, and the adapters
turn `challenge` into a 603. Run every carrier ingress with:

```
FALCON_PROFILE=carrier
```

The profile turns the per-IP and per-CLI velocity rules off and raises the
challenge and reject thresholds above the score cap. Scores can only flag.
Hard blocks still reject: an operator deny rule, a spam feed hit, an IP
intel `block` row, and a caller id a registered customer does not own. Each
variable the profile sets can still be overridden by name. The Traffic view
shows what a lower threshold would have done to your traffic before you
lower it.

## ConnexCS

ConnexCS runs in the cloud, so Falcon needs a public HTTPS URL and a token.
Two parts: screening at INVITE, and live voice.

### Screening at INVITE (ScriptForge)

1. Developer > ScriptForge. Add a script of type App. Name it Falcon.
2. Paste `connexcs/falcon.js`. Set `FALCON_URL` and `FALCON_TOKEN` at the
   top. Leave `DIRECTION` at `outbound` for a customer Route. Set it to
   `inbound` for a DID.
3. Leave `MODE` at `monitor`. Nothing is rejected. Every call is screened
   and recorded, and the Traffic view shows what enforce would have done.
4. Save. Click Save and Run once against a real log. Check that
   `data.routing` carries the source IP, User-Agent, and Call-ID under one
   of the keys in `IP_KEYS`, `UA_KEYS`, and `CALLID_KEYS`. Add the key if
   your build names it differently. An unknown key is an empty field,
   never a wrong one.
5. Management > Customer > Routing > [Route] > ScriptForge. Select Falcon.
   Set Timeout to `3000`. Set Timeout Action to `200 OK`, so a slow Falcon
   lets the call through.
6. For inbound: Management > Customer > DID > [DID] > ScriptForge.
7. After a week in monitor, set `MODE` to `enforce`. Only hard blocks
   reject: the deny list, the spam feed, IP intel `block`, and a caller
   id the customer does not own. Set `ENFORCE_HARD_BLOCKS_ONLY` to false
   only after the Traffic view shows the thresholds fit your traffic.

A reject throws `603 Decline` and ConnexCS answers the caller with it.
Allow and flag return the routing object unchanged. `ADD_HEADERS` puts
the `X-Falcon-*` headers on the egress INVITEs once you have confirmed the
header shape on your build.

The e2e harness runs all three postures against a live Falcon: monitor
never throws, enforce with hard blocks only throws on the deny list and
not on a scanner score, full enforce throws on both.

### Live voice (ConneXML)

CallerAPI listens to the call as it happens. ConnexCS forks the audio to
`wss://api.callerapi.com/api/voice/filter/stream`. CallerAPI transcribes,
runs the scam rules on every line, runs the model when the rules cannot
phrase it, and posts a verdict to Falcon the moment the score changes.
Falcon receives it at `POST /v1/voice/verdict`, ties it to the INVITE it
screened by Call-ID, shows it in the event drawer, pages your webhook with
`kind: voice_scam, live: true`, and blocks the next call from that number.

1. Set `CALLERAPI_API_KEY` on Falcon. The webhook is signed with that key
   and Falcon refuses anything else.
2. Class 5 > Apps > + > ConneXML. Paste `connexcs/falcon-live.xml`. Fill
   in the key and your Falcon host.
3. Route the calls you want listened to through the app. Start with one
   route or a sampled share.

Cost is per listened minute on CallerAPI. The keyword rules run on every
line for free; the model runs at most twice a minute per call. Every call
through the app is a Class 5 call on ConnexCS.

Two things the ConnexCS docs do not state. Confirm them with ConnexCS
support before go-live. The audio format on the socket: CallerAPI accepts
Twilio style JSON frames, its own JSON start line, or bare mu-law or PCM16
frames with the call id on the URL, so the likely formats all work. The
ConneXML variable names for caller, destination, and call id: the template
uses placeholders.

Ending the live call: ConnexCS has no documented API for it. The Control
Panel has End Calls under Global Dialogs and the terminal has
`calls kill <CallID>`. Falcon's page arrives within seconds of the verdict
with `call_id`, `customer_id`, `calling_number`, and `suggested_action`,
so your automation can end the call, unassign the DID, and open the case.
Ask ConnexCS for a hangup API and Falcon will call it.

## Telnyx

Two ways in. A Call Control application sends webhooks, and
`telnyx/falcon.js` screens them. A SIP connection (IP, credential, or FQDN)
sends the INVITE to your own switch, and that switch's adapter screens it
with no Telnyx code. The SIP connection gives Falcon the full request,
including the Identity header, so Falcon verifies STIR/SHAKEN itself.

### Call Control

Telnyx runs in the cloud, so Falcon needs a public HTTPS URL and a token, as
with ConnexCS. The adapter is a Node module with no dependencies that runs
in the webhook handler you already have.

1. Copy `telnyx/falcon.js` next to your handler. Set `FALCON_URL`,
   `FALCON_TOKEN`, `TELNYX_API_KEY`, and `TELNYX_PUBLIC_KEY` (Portal > Keys
   & Credentials > Public Key), or pass them to `create()`.
2. Read the webhook body as raw text, verify it, acknowledge, then handle:

   ```js
   const falcon = require('./falcon').create();

   app.post('/telnyx', express.text({ type: '*/*' }), async (req, res) => {
     let event;
     try {
       event = falcon.verify(req.body, req.headers);
     } catch (e) {
       return res.sendStatus(400);
     }
     res.sendStatus(200);
     const out = await falcon.handle(event);
     if (out.rejected) return;
     // your answer, transfer, or gather logic
   });
   ```

   Telnyx parks the call until your first command, so screening after the
   acknowledgement delays nothing. On `call.initiated` the adapter screens
   the call; on `call.answered` and `call.hangup` it reports the outcome to
   `/v1/outcome`. The leg id (`call_leg_id`) is the Call-ID in Falcon.
3. Leave `FALCON_MODE` at `monitor`. Nothing is rejected. After a week, set
   it to `enforce`. Only hard blocks reject, with the `reject` command
   (`CALL_REJECTED`), before the call is answered. Set
   `FALCON_HARD_BLOCKS_ONLY=false` only after the Traffic view shows the
   thresholds fit your traffic.
4. Outbound: pass `customerFor(payload)` to `create()` and return the
   account id of the customer placing the call, for example from the `tags`
   you set on `dial`. Falcon hangs up a caller id that customer does not
   own. Legs with no customer, such as transfer legs, are not screened.
5. Enable "SHAKEN/STIR" on the application. Falcon cannot verify it from a
   webhook, but Telnyx's attestation and call screening result are returned
   in `out.telnyx` for your logs.

A webhook carries no source IP, User-Agent, Identity header, or SDP, so
every call starts at 30 points (`missing_user_agent`, `missing_identity`,
`invite_no_sdp`). Lists, the spam feed, the customer caller id check,
honeypots, and the behaviour rules all apply. With more than one process
behind the webhook URL, pass a shared `store` with async `get`, `set`, and
`delete` so the outcome finds the answered time.

### SIP connection

Point the connection at your Asterisk, FreeSWITCH, Kamailio, or OpenSIPS
and install that switch's adapter as above. On the connection's inbound
settings:

1. Enable SHAKEN/STIR (`shaken_stir_enabled`). It is off by default, and
   without it Telnyx does not forward the Identity header and every call
   scores `missing_identity`.
2. Set the ANI number format (`ani_number_format`) to `+E.164`. The default,
   `E.164-national`, can present domestic callers without the country code.
   Deny rules written in E.164 then miss them, and a correctly signed call
   scores `shaken_orig_mismatch` because the PASSporT carries the full
   number.

Run Falcon with `FALCON_PROFILE=carrier` on a busy connection. Every INVITE
comes from a few Telnyx signaling IPs, so the per-IP velocity rules of the
default profile fire on normal traffic. Do not add those IPs as allow rules;
an allow rule ends scoring and nothing from the connection would be screened.
IP intel and the fingerprint name Telnyx's edge, not the caller. Lists,
STIR/SHAKEN, the spam feed, honeypots, the behaviour rules, and voice
sampling work as on any trunk. Mark outbound calls with `falcon_direction`
and `falcon_customer` as usual.

## curl

```bash
curl -sS -X POST http://127.0.0.1:8090/v1/screen \
  -H 'Content-Type: application/json' \
  -H "X-Falcon-Token: $FALCON_TOKEN" \
  -d '{"switch":"curl","source_ip":"198.51.100.20","raw_sip":"INVITE sip:+15551212@ex SIP/2.0\r\nVia: SIP/2.0/UDP 198.51.100.20;branch=z9hG4bK1\r\nFrom: <sip:+14155550100@ex>;tag=1\r\nTo: <sip:+15551212@ex>\r\nCall-ID: demo\r\nUser-Agent: friendly-scanner\r\nMax-Forwards: 70\r\n\r\n"}'
```

## Test everything

```bash
bash adapters/e2e/run.sh
ASTERISK_E2E=1 FREESWITCH_IMAGE=safarov/freeswitch:latest \
  KAMAILIO_IMAGE=kamailio/kamailio-ci:5.5.2 OPENSIPS_IMAGE=opensips/opensips:3.6 \
  bash adapters/e2e/run.sh
```

The script starts a Falcon with a token and one deny rule, then drives the
SIP listener, the AGI, the Lua script, the ScriptForge app, the Telnyx
webhook adapter, and with Docker
a real Asterisk, a real FreeSWITCH, a real Kamailio (sync and async), and a
real OpenSIPS (sync and async). Each adapter must reject the denied number
and pass the clean one, and must send the token. Works on Linux and on
Docker Desktop for macOS.
