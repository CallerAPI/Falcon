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
| Asterisk 16 to 21, FreePBX, Issabel, VitalPBX, PBX in a Flash, Wazo | `asterisk/falcon.agi` (AGI) or `asterisk/falcon_ari.py` (ARI) | AGI harness in CI |
| FreeSWITCH 1.10, FusionPBX | `freeswitch/falcon.lua` | Lua harness with the real `mod_curl` argument rules in CI |
| Kamailio 5.x | `kamailio/falcon.cfg` | Real Kamailio 5.5 container in CI |
| OpenSIPS 3.x | `opensips/falcon.cfg` | Real OpenSIPS 3.6 container in CI |
| ConnexCS | `connexcs/falcon.js` (ScriptForge App) | Node harness in CI |
| Sansay VSXi, Sippy, PortaSwitch, Telinta, Metaswitch, Ribbon, Oracle SBC, AudioCodes, Cisco CUBE, TelcoBridges, BroadWorks, VOS3000, and any switch that can route to a SIP redirect server | SIP redirect listener, no adapter file | UDP and TCP tests, `sipsend` in CI |
| 2600Hz Kazoo | HTTP from a Pivot callflow | Not yet |
| Twilio, Telnyx, Bandwidth, Vonage, Plivo, SignalWire | HTTP from your voice webhook | Not yet |

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
`denylist`, `spam_feed`, `ip_intel`, or `caller_id`. Send the `Identity`
header when the switch has it. Without it Falcon cannot verify STIR/SHAKEN
or name the signer.

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
   `/var/lib/asterisk/agi-bin/` and make them executable.
2. Include `asterisk/extensions.conf` in the inbound context.
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

## ConnexCS

ConnexCS runs in the cloud, so Falcon needs a public HTTPS URL and a token.

1. Developer > ScriptForge. Add a script of type App. Name it Falcon.
2. Paste `connexcs/falcon.js`. Set `FALCON_URL` and `FALCON_TOKEN` at the
   top. Leave `DIRECTION` at `outbound` for a customer Route. Set it to
   `inbound` for a DID.
3. Save. Click Save and Run once against a real log. Check that
   `data.routing` carries the source IP and User-Agent under one of the
   keys in `IP_KEYS` and `UA_KEYS`. Add the key if your build names it
   differently.
4. Management > Customer > Routing > [Route] > ScriptForge. Select Falcon.
   Set Timeout to 3000 ms. Leave Timeout Action empty.
5. For inbound: Management > Customer > DID > [DID] > ScriptForge.

A reject throws `603 Decline` and ConnexCS answers the caller with it.
Allow and flag return the routing object and add the `X-Falcon-*` headers
to every destination.

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
KAMAILIO_IMAGE=kamailio/kamailio-ci:5.5.2 OPENSIPS_IMAGE=opensips/opensips:3.6 bash adapters/e2e/run.sh
```

The script starts a Falcon with a token and one deny rule, then drives the
SIP listener, the AGI, the Lua script, the ScriptForge app, and with Docker
a real Kamailio and a real OpenSIPS. Each adapter must reject the denied
number and pass the clean one, and must send the token.
