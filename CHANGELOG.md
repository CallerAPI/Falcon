# Changelog

## Unreleased

Added

- Every-call mode for the bridge. `FALCON_BRIDGE_CARRY=all`, or Settings,
  Call bridge, Carry: Every call, carries every call that is not a hard
  block, like a PBX. Falcon hears and records each one. A hard block in
  enforce mode still gets 603. Past the bridge capacity, a call gets 503
  and the switch routes it as before.
- `FALCON_SIP_DIRECTION=outbound` marks the calls the bridge screens as
  placed by your own customers. An `X-Falcon-Customer` header from the
  switch names the customer, so the caller ID check against that
  customer's numbers applies to bridged calls.

- Call bridge. `FALCON_SIP_MODE=bridge` makes the SIP listener a native
  back-to-back user agent. Add Falcon to the switch as a carrier and as a
  customer. A clean call gets 503 before any answer, so the switch routes
  it to the next vendor. A challenge, or a reject in monitor mode, is
  carried back to the switch with its audio. No Asterisk is needed.
- The bridge does not create FAS. It never answers the caller before the
  far end answers. A hangup on either side ends both legs. A cancel goes
  through. Silent calls end after `FALCON_RTP_TIMEOUT`. Shutdown hangs up
  every carried call.
- Vendor routes. A tech prefix names a vendor. Falcon strips it and sends
  the call back to the switch or to the vendor. Threats, Vendors shows the
  answers and the false answers per vendor.
- FAS guard. Falcon hears ringback, busy, intercept tones, and dead air
  after a vendor answers a bridged call. `monitor` (default) records and
  alerts. `enforce` holds the answer until a person speaks and fails a
  false answer back to the switch with 480.
- Recordings. Each bridged call is a stereo WAV, the caller on the left and
  the callee on the right. The call view plays it with the transcript.
- Transcripts split by speaker. Both voice providers transcribe each
  channel and put the turns on one timeline.
- A new dashboard with five pages: Overview, Calls, Threats, Rules, and
  Settings. The Overview shows the protection state, calls screened,
  blocked, flagged, the latency Falcon adds, and the items that need a
  decision, each with the one action that settles it.
- `GET /v1/overview`, `POST /v1/insights/dismiss`, `GET /v1/recordings/{id}.wav`,
  `GET /v1/vendors`, `/v1/routes`, `GET /v1/modules`, and `/v1/numbercheck/*`.
- Event filters `verdict`, `recorded`, `fas`, and `bridged`. Events carry
  `latency_us` and `held`.
- Protection mode and the FAS mode are runtime settings. No restart.
- The adapter e2e runs the bridge binary: 603 for a denied caller, 503 for
  a clean one.
- FCC autopilot. Rules, Upstream carriers lists the carriers that send you
  calls. Every 6 hours Falcon checks each one against the Robocall
  Mitigation Database and FCC orders. `monitor` (default) alerts and puts
  the upstream on the Overview. `enforce` adds deny rules for its addresses
  and signer codes, and removes them when the order is lifted. A block needs
  the RMD number or FRN. A name match only warns. The list comes from
  CallerAPI for installs that share or carry a key, or from
  `FALCON_FCC_FILE`. Matching runs on the host.
- `GET|POST /v1/upstreams`, `DELETE /v1/upstreams/{id}`, `GET /v1/compliance`,
  and the `fcc_mode` setting.
- Traceback requests. Threats, Tracebacks logs a request with the calling
  number, the called number, and the call time. Falcon finds the call,
  names the upstream, writes the answer, and shows the 24-hour clock on the
  Overview. `GET|POST /v1/tracebacks` and `/v1/tracebacks/{id}`.
- Threats, Upstreams: traffic, blocks, and traceback cases per upstream for
  one month, with the FCC standing. `GET /v1/upstreams/report` and
  `report.csv`.

Changed

- Telemetry follows `FALCON_SHARE` only. The dashboard shows the state and
  cannot change it. Demo mode never shares.
- Add-ons are built in. Number check, live reputation, the spam list, the
  IP fraud list, Business Caller ID, the bridge, the FAS guard, and AI voice
  are listed in Settings with the variable that turns each on.
- Suspects rank numbers with the most flagged calls first. A number Falcon
  already rejects on every call is no longer suggested for a block.
- The demo inserts its calls in time order and uses only the reason codes
  the engine emits.
- The demo uses fictional carriers, addresses from the RFC 5737
  documentation ranges, and fictional phone numbers. `examples/ipintel.csv`
  and the demo IP intel tables hold only fictional rows.
- Telemetry events carry `event_id`, the local event id. CallerAPI stores
  an event once per install and id, so a batch that is sent again after a
  timeout is not counted twice.
- Telemetry waits as long as CallerAPI asks with `Retry-After`. After a
  failure with no `Retry-After`, the wait doubles from 30 seconds up to 15
  minutes, with jitter. Before, an install retried every 30 seconds.
- An install with a CallerAPI key gets the network feed and the FCC list
  without sharing. Falcon sends the key with both requests. Before, a
  keyed install that did not share got neither.
- The Asterisk adapter reads `FALCON_URL` and `FALCON_TOKEN` from channel
  variables first, so one Asterisk can screen for several Falcon installs.
- Telemetry sends less. A call with a signal is still an event. A clean
  inbound call is counted once an hour per verified signer, sending tool,
  calling number with 3 or more calls, and install. One clean call in 20 is
  still sent in full as a sample (`FALCON_SHARE_CLEAN_EVERY`). A clean
  outbound call is never sent. On a carrier ingress most calls are clean,
  so most of the traffic is gone.

Removed

- The plugin catalog, the plugin SDK, and `FALCON_PLUGINS`,
  `FALCON_PLUGIN_REFRESH`, and `FALCON_PLUGIN_BUDGET`. Falcon does not load
  or run code from a catalog.
- The ConnexCS adapters, their harness, and their docs.
- The telemetry checkbox in the dashboard.

Fixed

- The image starts on a `/data` volume. `/data` now belongs to `nonroot`,
  and the image sets `FALCON_DB_PATH=/data/falcon.db`. Before, SQLite could
  not create the database on a new volume, and `docker compose up`
  restarted in a loop.
- The README Docker steps set `FALCON_VERSION`, which `docker-compose.yml`
  requires, and show how to run the published image.
- `AGENTS.md` says which adapters report the outcome at hangup. It no
  longer says that each adapter is under 100 lines.
- Every adapter forwards the SIP `Content-Type`. The FreeSWITCH adapter
  also sends the offer. Before, the adapters sent no `Content-Type`, so
  every call they screened got the `invite_no_sdp` reason.
- A request with no `Content-Type` and no body no longer gets
  `invite_no_sdp`. Falcon can not tell a missing offer from a missing
  field, so an older adapter stops adding 5 points to every call.
- The adapter e2e builds Falcon with the release version, from `VERSION`
  or the latest public tag. It also checks that every adapter sends
  `Content-Type`.
- An upstream name that ends with a period, such as `Example Inc.`, no
  longer shows two periods in the traceback views and on the Overview.

## 0.9.x patches

Added

- A bridge plugin is catalog data that names a core API. Falcon does not
  run plugin code. Secrets stay on the host. A new plugin that uses an
  existing core API does not need a Falcon release.

- ConnexCS route transcription posts to `POST /v1/voice/transcript`
  from `adapters/connexcs/falcon-transcript.js`. Falcon stores the text
  and scores it. The script does not score.

- A traffic event has a Transcript tab. It shows the voice score and
  whether the verdict is spam. A call that was not listened to says so.
  Search matches words in the transcript. A scam verdict adds a
  `voice_scam` reason marked evidence. It does not change the INVITE score.

- Numbers is its own page. It ranks calling numbers by score and shows
  the reasons that produced the score, heaviest first. Traffic stays the
  call list. Direction is its own column there. Decision, verification,
  direction, and search still stack.

- An enabled dashboard plugin shows on existing installs at the next
  catalog refresh. No Falcon upgrade is required. A feed or live plugin
  still runs only after a grant. The Plugins page also shows the spam
  database feed and the voice firewall.

- Number check can recheck a saved list on a schedule. The page sets the
  interval, the days, the hours, and the timezone. Each recheck costs 1
  credit per number.

- Number check accepts a file. Falcon sends the file to CallerAPI. CallerAPI
  reads numbers from CSV, spreadsheets, PDF, JSON, and plain text. The file
  does not need a fixed column. Each new number costs 1 credit. The page
  lists the inventory, with flagged numbers first.

- A plugin page is HTML Falcon fetches with the API key and shows on its
  own host. The browser does not load a CallerAPI frame, and the page
  does not use a ticket or a third-party cookie. A partner URL on a
  private or link-local address is refused.

- Plugin pages. A `view` plugin does not run on the INVITE path. `surface`
  `native` is a table or stats that Falcon draws. `surface` `iframe` is a
  page on the CallerAPI host. A frame on another host is refused. The
  operator search is the only number that page receives.

- Plugin catalog. Falcon loads granted plugins from CallerAPI on a timer.
  A plugin that stays inside `sdk` fields does not need a new Falcon binary.
  The called number, the raw SIP message, and the Identity header are not
  fields. Feed matches stay local. Live checks share `FALCON_PLUGIN_BUDGET`
  and fail open. `FALCON_PLUGINS=false` turns the catalog off.

- `FALCON_MODE=monitor` records the real decision and tells the switch to
  continue. `X-Falcon-Monitor` names the action that was not enforced.
- Release check against the public Falcon tag. One alert per new tag.
  `FALCON_UPDATE_CHECK=false` turns it off. Falcon does not install the release.
- Fleet hub: members push events and pull one deny list and the other
  switches' caller counts. The spare switch is another member. Nothing on
  this path runs during INVITE scoring except a memory read.
- Fleet Grafana dashboard and Prometheus scrape under `monitoring/`.
  `PROMETHEUS_RETENTION` sets how long the samples stay on disk (default
  30 days). `FALCON_METRICS_TOKEN` is the scrape credential. `GET /metrics`
  still accepts `FALCON_TOKEN` when the metrics token is empty.
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

- ConnexCS ScriptForge read keys the Raw Data does not have. The source
  address was the ConnexCS script server, the User-Agent was empty, and
  every call showed `missing_identity` and no signer. The script now reads
  `params.si`, `params.sp`, `params.userAgent`, `callid`, and
  `stir_shaken`.
- `signing` on `/v1/screen`: a switch that signs after the screen sends the
  attestation and the certificate URL. Falcon names the signer from the
  certificate and does not charge `missing_identity`. The event shows
  `switch signs`. The signing does not go into telemetry.
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
