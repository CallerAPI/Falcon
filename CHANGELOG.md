# Changelog

## Unreleased

Added

- `FALCON_PROFILE=carrier` for class 4 and wholesale ingress: velocity
  rules off, scores only flag, hard blocks still reject. The trunk defaults
  rejected a normal call center CLI within its first hour.
- Live voice verdicts: `POST /v1/voice/verdict` receives the CallerAPI live
  filter webhook, verifies the HMAC with the account key, ties the verdict
  to the screened INVITE by Call-ID, keeps the worst score, shows it in the
  event drawer, and pages `voice_scam` with `live: true` and a suggested
  action. Falcon never hears the audio.
- ConnexCS: `MODE` (`monitor` default, `enforce`), `ENFORCE_HARD_BLOCKS_ONLY`,
  `ADD_HEADERS` off by default, Timeout Action `200 OK`, and a ConneXML
  template that forks audio to the CallerAPI live filter.
- Kamailio and OpenSIPS asynchronous routes (`falcon_async.cfg`) that
  suspend the transaction while Falcon answers.
- Real Asterisk 20 and real FreeSWITCH 1.10 containers in CI, next to the
  real Kamailio and OpenSIPS ones.

- SIP redirect listener (`FALCON_SIP_LISTEN`, `FALCON_SIP_PEERS`,
  `FALCON_SIP_REDIRECT_HOST`, `FALCON_SIP_TIMEOUT`). Falcon answers INVITE
  over UDP and TCP with 302 to continue or 603 to drop, 200 to OPTIONS,
  and drops peers outside the allowlist. For switches with no script hook.
- OpenSIPS 3.x adapter (`adapters/opensips/falcon.cfg`), tested against a
  real OpenSIPS 3.6 container.
- ConnexCS ScriptForge App (`adapters/connexcs/falcon.js`), tested with a
  Node harness.
- Adapter platform matrix in `adapters/README.md`.
- `adapters/e2e/run.sh` runs every adapter against a Falcon with a token,
  so an adapter that drops the token fails the build.

Fixed

- Telemetry drained 100 events per 30 s and nothing more, so a carrier
  ingress fell behind for the life of the process. One tick now drains up
  to 50 batches and stops at the first failure.
- Asterisk dialplan patterns were `_X.`, which does not match an E.164
  destination with a plus. Calls to `+1...` got 404 before the AGI ran.
  Now `_[+0-9]X.`. The AGI files are shipped executable.
- FreeSWITCH adapter logs a warning when Falcon gives no decision instead
  of allowing silently.
- FreeSWITCH adapter used a `mod_curl` grammar that does not exist.
  `headers` prints response headers; request headers are `append_headers`
  and the type is `content-type`. With a token set, every screen failed
  open. The body is now percent-encoded, so quotes and `%` in a display
  name survive `mod_curl`'s split and decode. The fallback JSON encoder
  now escapes quotes and control characters.
- Kamailio adapter: `httpcon` (not `connection`), a `{}` seed and a
  `headers` object for `jansson_set`, unquoted `$var(falcon)` for
  `jansson_get`, and `http_client_query` with a header block so the token
  is sent. `http_connect` cannot add headers.
- `source_ip` with a port (`203.0.113.9:5060`, what Asterisk
  `CHANNEL(pjsip,remote_addr)` returns) made every IP intel and IP rule
  lookup miss. The port is stripped.
- Data race in the outbound spoof test. Telemetry redaction: From is
  scrubbed when it contains the called digits as a run.

## 0.9.0

First release under the Falcon name. Formerly sipari.

Added

- STIR/SHAKEN verification: x5u fetch, ES256 signature, chain to the STI-PA
  trusted CA list, STI-PA CRL, iat freshness, orig and dest claims, signer
  SPC from the TNAuthList extension. Per-call budget with background cache
  warming. `X-Falcon-Verstat` and `X-Falcon-Signer` headers.
- Telecom IP intel table: CSV of CIDR blocks with provider and risk, from a
  file, a URL, or both. `X-Falcon-Provider` header.
- Allow and deny rules on numbers, IPs or CIDRs, and signer SPCs, with
  optional expiry.
- Operator API: filtered events with cursors, CSV export, stats with a dense
  timeseries, histogram, parties by signer, provider, or IP, rules, SSE
  stream, reload, redacted config, Prometheus metrics.
- Retention janitor with separate windows for decisions and raw SIP,
  editable at runtime.
- Value card on the Overview and `GET /v1/value`: what Falcon blocked,
  computed locally, no model. "Ask Falcon" assistant on a BYOK
  OpenAI-compatible model or the CallerAPI key.
- `AGENTS.md` runbook for coding agents, `NOTICE`, `ADOPTERS.md`.
- Outbound screening: customers and their numbers, `caller_id_not_owned`
  hard reject with an immediate webhook, per-customer reject alerts.
- Call outcomes (`POST /v1/outcome`) and behaviour rules: fan-out,
  sequential dialing, low answer rate, short calls, honeypot hits.
- Honeypot rules for unassigned numbers and prefixes.
- Voice sampling on triggers within a budget, repeat-recording and
  monologue detection on the host, transcription and classification
  through an OpenAI-compatible provider or the CallerAPI scan API,
  transcripts kept local, `voice_scam` and `repeat_recording` webhooks.
- Network reputation feed: scores per signer SPC and per SIP fingerprint
  from every sharing install, pulled hourly, corroboration by default,
  `FALCON_REPUTATION_ENFORCE` for hard rejects on strong signer scores.
- SIP fingerprints on every event: the sending tool's habits, never a
  party. Searchable, groupable, shared.
- Signed install identity (Ed25519) on telemetry and feed requests.
- STI-PA CA list JWS verification with same-origin signer, expiry, and
  sequence rollback checks; optional pin and root file.
- Webhook alerts with runtime thresholds, an audit log of every change,
  and a traceback pack export.
- Fuzz targets for the SIP parser, the redactor, and the fingerprinter.
- Telemetry to CallerAPI, on by default, opt out with `FALCON_SHARE=false`
  or the System view. The called party is replaced with `REDACTED`
  everywhere, forwarding numbers too, the PASSporT and SDP are removed, and
  a keyed per-install hash stands in for the called number. Replaces the
  consent box and `FALCON_CLOUD_INGEST`.
- SSRF-safe certificate fetching with public-only destinations, redirect
  re-validation, and an outbound fetch limiter. Strict CSP and security
  headers. Cross-site mutation guard. Startup refuses an open listen on a
  public interface. `SECURITY.md`.
- Dashboard rewrite: seven views, live tail, drawer with decoded PASSporT and
  verification checklist, quick allow and deny, tuning with what-if
  thresholds, system status.

Changed

- Module path `github.com/callerapi/falcon`. Binary `falcon`. Environment
  prefix `FALCON_`. Switch headers `X-Falcon-*`. Ingest path
  `/api/falcon/v1/ingest`.
- Events store verstat, signer, provider, the verification result, and a unix
  time column. Existing databases migrate on first start.
