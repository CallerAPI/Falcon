# Switch adapters

Falcon is an HTTP decision service. The switch keeps signaling. Falcon only scores the SIP request and returns an action.

Send `POST /v1/screen` before you create media. Fail open if Falcon does not answer.

## Request

JSON:

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

## Response

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
`denylist`, `spam_feed`, or `ip_intel`. Send the `Identity` header when the
switch has it. Without it Falcon cannot verify STIR/SHAKEN or name the signer.

## Asterisk

AGI is the default path. It uses the Python standard library only.

1. Copy `asterisk/falcon.agi` to `/var/lib/asterisk/agi-bin/falcon.agi`.
2. Run `chmod +x /var/lib/asterisk/agi-bin/falcon.agi`.
3. Include `asterisk/extensions.conf` in the inbound context.

The ARI app is `asterisk/falcon_ari.py`. Install `ari` from `asterisk/requirements-ari.txt`. Point `Stasis(falcon,from-internal,${EXTEN},1)` at it.

## FreeSWITCH

1. Copy `freeswitch/falcon.lua` to the FreeSWITCH scripts directory.
2. Include `freeswitch/dialplan.xml` in the inbound dialplan.
3. The script hangs up when the action is `reject` or `challenge`.

## Kamailio

1. Load `http_client.so` and `jansson.so`.
2. Include `kamailio/falcon.cfg`.
3. Call `route(FALCON_SCREEN)` from `request_route` on INVITE.

## curl

```bash
curl -sS -X POST http://127.0.0.1:8090/v1/screen \
  -H 'Content-Type: application/json' \
  -H "X-Falcon-Token: $FALCON_TOKEN" \
  -d '{"switch":"curl","source_ip":"198.51.100.20","raw_sip":"INVITE sip:+15551212@ex SIP/2.0\r\nVia: SIP/2.0/UDP 198.51.100.20;branch=z9hG4bK1\r\nFrom: <sip:+14155550100@ex>;tag=1\r\nTo: <sip:+15551212@ex>\r\nCall-ID: demo\r\nUser-Agent: friendly-scanner\r\nMax-Forwards: 70\r\n\r\n"}'
```
