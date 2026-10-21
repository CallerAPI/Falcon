# Falcon for AI agents

This file is for a coding agent (Cursor, Claude Code, Codex, or any other)
that has been asked to stand up, configure, test, or change Falcon. Follow
it in order. Every step has a command and an expected result. Do not guess
at configuration; every value is in `.env.example` with a comment.

## What Falcon is

A SIP risk engine that runs next to a telecom switch. The switch asks
Falcon about each INVITE over local HTTP or SIP. Falcon answers allow,
flag, challenge, or reject with reasons. It verifies STIR/SHAKEN, names the
signer, scores behaviour, screens the operator's own outbound customers for
spoofed caller ids, and shares redacted telemetry with CallerAPI by default.
In bridge mode it also carries suspicious calls, records both sides, and
catches false answer supervision (FAS). One Go binary, one SQLite file, an
embedded dashboard. Apache 2.0.

## Stand it up in five minutes

Requirements: Go 1.23 or Docker. No database server, no other service.

```
# 1. Build and run (Go). VERSION is required. A binary without it says dev.
make build VERSION=0.9.23
FALCON_TOKEN=change-me ./bin/falcon
# expected: "Falcon 0.9.23 listening on 127.0.0.1:8090" and a telemetry line

# 1. or Docker. FALCON_VERSION is required. Without it the image is not built.
cp .env.example .env && sed -i 's/^FALCON_TOKEN=.*/FALCON_TOKEN=change-me/' .env
FALCON_VERSION=0.9.23 docker compose up -d --build
# expected: container up, http://127.0.0.1:8090/v1/health returns {"status":"ok"}

# 2. Prove it screens
curl -s -X POST -H 'X-Falcon-Token: change-me' -H 'Content-Type: application/json' \
  -d '{"method":"INVITE","request_uri":"sip:+14155550100@x","source_ip":"203.0.113.9","headers":{"From":"<sip:+13125550188@203.0.113.9>;tag=1","To":"<sip:+14155550100@x>","Call-ID":"agent-1","CSeq":"1 INVITE","User-Agent":"friendly-scanner"}}' \
  http://127.0.0.1:8090/v1/screen
# expected: {"action":"reject", ... "scanner_user_agent" ...}

# 3. Open the dashboard
# http://127.0.0.1:8090/?token=change-me  (Overview shows the state, four numbers, and what needs a decision)
```

If step 2 does not return JSON, read `/tmp/falcon.log` or the container
logs. The two failures seen in practice: the token header is missing (401)
or the body is not JSON (415).

## Connect a switch

Pick the adapter for the switch and copy it in. Each adapter posts the
INVITE to `/v1/screen`. The Asterisk and FreeSWITCH adapters also report
the outcome at hangup. The Kamailio and OpenSIPS files show an optional
outcome hook in their comments. CI runs every adapter against a live
Falcon and a real switch.

| Switch | Files | Where |
| --- | --- | --- |
| Asterisk | `adapters/asterisk/falcon.agi`, `falcon_hangup.agi`, `extensions.conf` | agi-bin and the inbound and outbound contexts |
| FreeSWITCH | `adapters/freeswitch/falcon.lua`, `falcon_hangup.lua`, `dialplan.xml` | scripts and the inbound dialplan |
| Kamailio | `adapters/kamailio/falcon.cfg` | `import_file` and `route(FALCON_SCREEN)` on INVITE |
| OpenSIPS | `adapters/opensips/falcon.cfg` | `include_file` and `route(falcon_screen)` on INVITE |
| No script hook | none | `FALCON_SIP_LISTEN` and `FALCON_SIP_PEERS`. The switch routes the INVITE to Falcon as a redirect server |
| Call bridge | none | `FALCON_SIP_MODE=bridge`. Add Falcon as a carrier and as a customer. See `adapters/README.md` |

For outbound calls (the operator's own customers), set `falcon_direction=outbound`
and `falcon_customer=<account id>` on the channel before the adapter runs,
and register each customer's numbers:

```
curl -s -X PUT -H 'X-Falcon-Token: change-me' -H 'Content-Type: application/json' \
  -d '{"id":"acme","name":"Acme","dids":["+13125550100","+1312555*"]}' http://127.0.0.1:8090/v1/customers
```

Verify with `bash adapters/e2e/run.sh` (needs python3 and curl; lua5.4 for
the FreeSWITCH harness; Docker and `KAMAILIO_IMAGE=kamailio/kamailio-ci:5.5.2`
for Kamailio). Expected: `sip bridge: PASS`, `asterisk agi adapter: PASS`,
and `adapters: PASS` at the end.

## Configuration that matters first

| Variable | Set it when | Default |
| --- | --- | --- |
| `FALCON_TOKEN` | Always. An empty token on a non-loopback listen refuses to start. | empty |
| `FALCON_PROFILE` | `carrier` on a class 4 or wholesale ingress. Default scoring rejects normal call center traffic there. | `trunk` |
| `FALCON_LISTEN` | The switch is on another host. Keep it on a private network. | `127.0.0.1:8090` |
| `FALCON_SIP_LISTEN`, `FALCON_SIP_PEERS` | The switch cannot run a script and routes INVITEs to Falcon over SIP. Peers are required off loopback. | empty |
| `FALCON_SIP_MODE` | `bridge` when Falcon should carry suspicious calls, record them, and run the FAS guard. `redirect` answers 302 or 603 and steps out. | `redirect` |
| `FALCON_MEDIA_IP` | The bridge host has more than one address. Falcon puts this one in SDP. | empty |
| `FALCON_FAS_MODE` | `enforce` holds a bridged answer until a person speaks. `monitor` only records. Settings changes it at runtime. | `monitor` |
| `FALCON_FCC_MODE` | `enforce` adds deny rules for every upstream under an FCC order, matched by RMD number or FRN. `monitor` alerts only. Settings changes it at runtime. `FALCON_FCC=false` turns the autopilot off. `FALCON_FCC_FILE` reads the list from disk. | `monitor` |
| `FALCON_SHARE` | The operator opts out of redacted telemetry. The environment is the only switch. Demo mode never shares. | `true` |
| `CALLERAPI_API_KEY` | The operator has a CallerAPI account: credits telemetry, enables the paid feed, live reputation, Business Caller ID, number check, the voice scan provider, and the assistant. | empty |
| `FALCON_VOICE_PROVIDER` | Recordings should be transcribed by speaker and classified: `openai` (any OpenAI-compatible speech and chat pair) or `callerapi`. | `off` |
| `FALCON_ASSISTANT_PROVIDER` | "Ask Falcon" should answer questions: `openai` or `callerapi`. The value card works without it. | `off` |
| `FALCON_SHAKEN_PA_PIN` | Policy requires the STI-PA list-signing key pinned. | empty |

Everything else has a safe default. Read `.env.example` top to bottom once.

## Verify a change

```
gofmt -l . && go vet ./... && go test -race ./...
go test -run '^$' -fuzz=FuzzRedact -fuzztime=20s ./internal/share/
bash adapters/e2e/run.sh
```

All three must pass before a commit. The fuzz target on the redactor is the
one that protects subscribers; never weaken it.

## Rules for changing Falcon

- The called party never leaves the host. Any new field that could carry
  it goes through `internal/share.Redact` and gets a test.
- On the HTTP and redirect paths Falcon never sits in the call and never
  holds the switch longer than the configured budget. Fail open is the
  default for a reason.
- The bridge sits in the call only for the calls it carries, and it must
  never create FAS. It never answers the caller before the far end
  answers. Any hangup ends both legs. A call it cannot carry gets 503
  before answer, so the switch routes it. `internal/bridge` tests prove
  each of these. Keep them passing.
- Add-ons are built in. Falcon does not load or run code from a catalog.
- No new external service. One binary, one SQLite file. Horizontal scale
  is one Falcon per switch.
- Reputation and fingerprints are corroboration, not verdicts. A hard
  reject needs a fact: a list, a failed verification, a spoofed caller id,
  or an operator setting enforce on purpose.
- Every mutation through the API writes an audit row. Keep it that way.
- Read `SECURITY.md` before touching `internal/safehttp`, `internal/shaken`,
  or the telemetry path.

## Where things are

| Path | What |
| --- | --- |
| `cmd/falcon` | Entry point, wiring, boot log |
| `internal/score` | The scoring rules and thresholds |
| `internal/shaken` | STIR/SHAKEN verification and the STI-PA trust store |
| `internal/share` | Telemetry redaction |
| `internal/voice` | Clip analysis, sampler, transcription by speaker, classification providers |
| `internal/bridge` | The SIP call bridge: policy, call state, vendor routes, the FAS hold |
| `internal/media` | RTP relay, G.711, SDP rewrite, the port allocator, the stereo recorder |
| `internal/fas` | The tone and speech detector behind the FAS guard |
| `internal/sipserver` | The SIP redirect listener |
| `internal/numbercheck` | The number check client for CallerAPI |
| `internal/httpapi` | The API, the overview and its insights, the assistant, the embedded dashboard under `web/` |
| `internal/store` | SQLite schema and queries |
| `adapters/` | Switch integrations and the end-to-end harness |

## Support

Issues on GitHub. Security findings to security@callerapi.com.
