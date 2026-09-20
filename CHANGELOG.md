# Changelog

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
