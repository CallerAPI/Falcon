# Security

Falcon runs inside carrier networks next to the switch. This page states what
it trusts, what it refuses, what leaves the host, and how to run it safely.
Read it before the first install. Send findings to security@callerapi.com.

## Threat model

Falcon reads SIP requests that strangers wrote. Every header is hostile input.
The switch that sends them is trusted. The operator's dashboard is trusted
after authentication. Nothing else is.

| Input | Source | Trust |
| --- | --- | --- |
| SIP message body and headers | Any caller on the public network | None |
| `x5u` certificate URL inside the PASSporT | The signer, or an attacker | None |
| `source_ip`, `switch` fields | The switch adapter | Trusted |
| Dashboard and API calls | Holder of the token or dashboard password | Trusted |
| STI-PA trust list and CRL | Public iconectiv endpoints over TLS | Trusted for content, see Known limits |
| IP intel table | Operator file or operator URL | Trusted |

## What Falcon refuses

**Outbound fetches from untrusted URLs.** The `x5u` is the only URL Falcon
follows that an outsider chose. Before a packet leaves the host, the URL must
be `https`, carry no credentials, and name no `localhost`, `.local`,
`.internal`, or literal private address. At dial time the resolved address is
checked again against loopback, RFC 1918, link-local, carrier NAT
(100.64/10), cloud metadata (169.254/16), multicast, documentation, and
reserved ranges, so DNS rebinding fails. Redirects are re-validated and capped
at two. Environment proxies are ignored. Compression is off. The body is
capped at 64 KB. Chains are capped at eight certificates. Fetches are bounded
to 32 in flight and 50 new per second. A burst of unique `x5u` values yields
`No-TN-Validation`, never a flood from your network.

**Holding the switch.** A cold certificate fetch returns after the budget
(400 ms by default) and completes in the background. Verification never adds
more than the budget to a call. Parse failures fail open and the switch
continues.

**Oversized input.** Screened messages are capped at 64 KB
(`FALCON_MAX_BODY_BYTES`). Rule bodies at 4 KB. Settings at 1 KB. Request
headers at 64 KB. Read and idle timeouts are set. The event stream is the one
response that stays open on purpose.

**Cross-site mutation.** A browser attaches Basic credentials to a form
submission from any origin. Mutations refuse the content types a form can
send (`urlencoded`, `multipart`, `text/plain`, or none). JSON and
`application/sip` need a CORS preflight the dashboard never grants. The
`?token=` query form authorises reads only, so a token that lands in a log or
a referrer cannot change rules.

**Script injection in the dashboard.** Every value is escaped before it is
placed in the page. The Content Security Policy allows scripts from the host
only and forbids framing. No third-party script, font, or image is loaded.

**Running open by accident.** An empty `FALCON_TOKEN` on a listen address
other than loopback stops startup unless `FALCON_ALLOW_OPEN=true`. The SIP
listener has no token: a `FALCON_SIP_LISTEN` off loopback with an empty
`FALCON_SIP_PEERS` stops startup, and a request from a peer outside the
list gets no reply at all, so Falcon cannot be used as a reflector.

**SQL injection.** Every query is parameterised. Column names in aggregate
queries come from a fixed list.

## What leaves the host

The System view lists the live destinations. In full:

| Destination | When | What |
| --- | --- | --- |
| `authenticate-api.iconectiv.com` | Every 6 hours (roots), every hour (CRL) | A GET. Nothing about your traffic. Off with `FALCON_SHAKEN_CA_URL=off` and a PEM file. |
| The `x5u` host of each signer | On the first sight of a certificate URL, then hourly | A GET for the certificate. The signer learns that some verifier fetched their certificate. This is inherent to STIR/SHAKEN verification and every verification service does it. Nothing about the called party is sent. |
| `api.callerapi.com` (feed) | Hourly | A signed GET for the network reputation feed. Nothing about your traffic; the signature carries the install id and a timestamp. Off with `FALCON_REPUTATION=false`. |
| Your voice provider | Per sampled clip, within the budget | The first seconds of audio and the calling number. Only with `FALCON_VOICE_PROVIDER` set. The transcript comes back and stays here. |
| Your alert webhook | When an alert fires | The alert title, detail, install id, and version. Only if you set one. |
| Your IP intel URL | On the refresh timer | A GET. Only if you set one. |
| `api.callerapi.com` (feed) | On the refresh timer | A GET for the spam list. Only with a key and `FALCON_SPAM_FEED=true`. |
| `api.callerapi.com` (live lookup) | Per screened INVITE | The calling number. Only with a key and `FALCON_VOICE_FIREWALL=true`. |
| `api.callerapi.com` (BCID verify) | Per screened INVITE | The calling number, the called number, and an optional in-band assertion. Only with a key and `FALCON_BCID=true` (the default). Off with `FALCON_BCID=false`. |
| `api.callerapi.com` (telemetry) | Every 30 seconds | Redacted screening events: decision, score, reasons, calling number, source IP, User-Agent, signer, verification result, SIP headers with the called party replaced by `REDACTED`, no `Identity` header, no SDP. On by default. Off with `FALCON_SHARE=false` or the System view. See the README section "Telemetry". |
| Your S3 endpoint | Every 30 seconds | Screened events as JSONL, unredacted. Only with your credentials. |

Nothing else. No update check, no crash reporting.

### Telemetry redaction

The called party is the operator's subscriber. Before an event leaves the
host, `internal/share` replaces the called number with `REDACTED` in the
`to` field, the Request-URI, the `To`, `P-Called-Party-ID`, `Diversion`,
`History-Info`, `Referred-By`, and `Target-Dialog` headers including display
names, and then removes any remaining digit run that ends with the same
seven digits from every other header, the Call-ID, and reason text. The
`Identity` header is removed because the PASSporT carries the called number
in its `dest` claim; the verification booleans are sent instead. The SDP
body is dropped. A calling number equal to the called number is redacted
too. A keyed hash of the called number replaces it, with a per-install
random key that is never sent.

Tests in `internal/share` assert that the full number, the national form,
the last seven digits, the display name, the PASSporT, and the SDP are
absent from the shared payload.

## Data at rest

Events live in one SQLite file at `FALCON_DB_PATH`. The raw SIP message is
the one field with subscriber numbers in the clear. It has its own retention
(7 days by default) and is scrubbed while the decision row stays for the full
window (30 days by default). Both are editable at runtime. Set
`FALCON_STORE_RAW_SIP=false` to never write it.

Protect the file like you protect CDRs: a dedicated user, `0600`, an
encrypted volume where policy asks for it. Falcon does not encrypt at rest on
its own.

Audio clips are analysed in memory and not written to disk by Falcon. The
adapters record to a temporary file and delete it after upload. Transcripts
are stored in `voice_samples` under the same retention and protection as
events and are never shared.

Logs name no phone numbers.

## Hardening checklist

1. Set `FALCON_TOKEN` to a long random value. Set `FALCON_DASHBOARD_PASSWORD`.
2. Listen on loopback or a management VLAN. Put TLS in front for the
   dashboard (a reverse proxy). Falcon speaks plain HTTP to the switch on
   purpose so the adapter path stays simple; keep that path on a private
   network.
3. Leave `FALCON_SHAKEN_ALLOW_HTTP` off. It is lab mode and it logs when on.
4. Decide retention with your DPO. Shorten raw SIP first.
5. Decide on telemetry with your DPO. It is on by default and the called
   party never leaves the host. `FALCON_SHARE=false` turns it off. Turn it
   off on any switch that screens outbound calls, because there the calling
   number is your subscriber.
6. Run as a non-root user. The container image is distroless and runs as
   `nonroot`.
7. Pin a version. Read the changelog before upgrading.
8. Give Prometheus the token in an `Authorization: Bearer` header.

## Known limits

- The STI-PA CA list JWS is verified against the certificate the list names,
  which must come from the STI-PA host, name the STI-PA, and be within its
  validity period; expiry and sequence rollback are checked. Without
  `FALCON_SHAKEN_PA_PIN` or `FALCON_SHAKEN_PA_ROOT_FILE` the binding to the
  STI-PA is by origin and name, not by a pinned key. Set one of them where
  policy asks for it.
- The network feed scores are built from telemetry other installs sent.
  Installs are identified by a signed key and rate limited, and a score
  needs several independent installs before it can move a call past flag,
  but a determined actor with many installs could try to shape a score.
  Reputation never rejects on its own unless the operator turns enforce on.
- Falcon does not sign calls and does not manage certificates or SPC tokens.
  It verifies.
- There is no built-in TLS listener. Use a reverse proxy for the dashboard.
- The `source_ip` field is trusted from the adapter. A compromised switch can
  lie to Falcon about where a call came from.

## Reporting

Email security@callerapi.com. Include the version, the configuration with
secrets removed, and a reproduction. We answer within two business days and
credit reporters in the changelog unless asked not to.
