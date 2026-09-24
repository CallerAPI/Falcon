#!/usr/bin/env node
// Drive adapters/telnyx/falcon.js the way a Call Control webhook handler
// does, against a live Falcon and a stand-in for the Telnyx API. Webhooks
// are signed with a fresh Ed25519 key exactly as Telnyx signs them. Checks:
//   signature                 good passes; tampered, wrong key, stale, unsigned fail
//   monitor                   never sends a command, even on a deny-listed caller
//   enforce, hard blocks only rejects the deny list, not a score
//   enforce, full             rejects on the score too
//   fail open                 no Falcon, or a failing Telnyx API, leaves the call alone
//   outbound                  hangs up a caller id the customer does not own
//   outcome                   answered and duration reach Falcon at hangup
// Usage: telnyx_harness.js <falcon_url> <deny_number> <clean_number>

const crypto = require('crypto');
const http = require('http');
const path = require('path');

const [url, deny, clean] = process.argv.slice(2);
const token = process.env.FALCON_TOKEN || '';
const base = url.replace(/\/v1\/screen$/, '');
const { create } = require(path.join(__dirname, '..', 'telnyx', 'falcon.js'));

const DEST = '+14155550100';
const PREMIUM = '+19005550100';
// Callers of their own, so velocity from the other harnesses never adds up.
const OWNED = '+13125550142';
const NOT_OWNED = '+13125550157';
const FRESH = ['+13125550163', '+13125550174', '+13125550186', '+13125550191'];

function keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const x = publicKey.export({ format: 'jwk' }).x;
  return { privateKey, publicB64: Buffer.from(x, 'base64url').toString('base64') };
}
const telnyxKey = keypair();
const otherKey = keypair();

function sign(body, key, ts) {
  ts = String(ts || Math.floor(Date.now() / 1000));
  const sig = crypto.sign(null, Buffer.from(ts + '|' + body), key.privateKey).toString('base64');
  return { 'telnyx-signature-ed25519': sig, 'telnyx-timestamp': ts };
}

// The Telnyx API: records every command and answers with `status`.
const commands = [];
let status = 200;
const api = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    commands.push({ path: req.url, auth: req.headers.authorization, body: body ? JSON.parse(body) : null });
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ data: { result: 'ok' } }));
  });
});

let n = 0;
function event(type, payload, occurredAt) {
  n += 1;
  const leg = payload.call_leg_id || 'tx-e2e-leg-' + process.pid + '-' + n;
  return {
    data: {
      record_type: 'event',
      event_type: type,
      id: crypto.randomUUID(),
      occurred_at: new Date(occurredAt || Date.now()).toISOString(),
      payload: Object.assign({ call_control_id: 'v3:e2e-' + leg, call_leg_id: leg, call_session_id: leg, connection_id: '7267' }, payload),
    },
  };
}
function initiated(from, to, extra) {
  return event('call.initiated', Object.assign({ from, to, direction: 'incoming', state: 'parked' }, extra));
}

async function falcon(pathAndQuery, method, body) {
  const res = await fetch(base + pathAndQuery, {
    method: method || 'GET',
    headers: { 'Content-Type': 'application/json', 'X-Falcon-Token': token },
    body: body ? JSON.stringify(body) : undefined,
  });
  return res.json();
}

(async () => {
  await new Promise((r) => api.listen(0, '127.0.0.1', r));
  const apiBase = 'http://127.0.0.1:' + api.address().port + '/v2';
  const opts = (o) => Object.assign({ falconUrl: url, falconToken: token, telnyxApiKey: 'KEY-e2e', telnyxApiBase: apiBase, telnyxPublicKey: telnyxKey.publicB64 }, o);
  const results = [];
  const check = (label, ok, detail) => results.push({ label, ok, detail });
  const run = async (adapter, ev) => {
    commands.length = 0;
    const out = await adapter.handle(ev);
    return { out, cmds: commands.slice() };
  };

  // signature
  let a = create(opts({}));
  const body = JSON.stringify(initiated(clean, DEST));
  const throws = (fn) => {
    try {
      fn();
      return false;
    } catch (e) {
      return true;
    }
  };
  let parsed = null;
  try {
    parsed = a.verify(body, sign(body, telnyxKey));
  } catch (e) {
    parsed = null;
  }
  check('signature: Telnyx-signed body verifies', parsed && parsed.data.event_type === 'call.initiated');
  check('signature: Buffer body and mixed-case headers verify', !throws(() => {
    const h = sign(body, telnyxKey);
    a.verify(Buffer.from(body), { 'Telnyx-Signature-Ed25519': h['telnyx-signature-ed25519'], 'Telnyx-Timestamp': h['telnyx-timestamp'] });
  }));
  check('signature: tampered body fails', throws(() => a.verify(body.replace(DEST, PREMIUM), sign(body, telnyxKey))));
  check('signature: another key fails', throws(() => a.verify(body, sign(body, otherKey))));
  check('signature: stale timestamp fails', throws(() => a.verify(body, sign(body, telnyxKey, Math.floor(Date.now() / 1000) - 600))));
  check('signature: unsigned fails', throws(() => a.verify(body, {})));

  // monitor: nothing is ever sent to Telnyx
  a = create(opts({ mode: 'monitor' }));
  let r = await run(a, initiated(deny, DEST));
  check('monitor: deny-listed caller is screened', r.out.screened && r.out.result.action === 'reject', JSON.stringify(r.out.result));
  check('monitor: no command sent', r.cmds.length === 0 && !r.out.rejected, JSON.stringify(r.cmds));

  // enforce, hard blocks only (the default in enforce)
  a = create(opts({ mode: 'enforce' }));
  r = await run(a, initiated(deny, DEST));
  const cmd = r.cmds[0] || {};
  check('enforce/hard: deny-listed caller is rejected', r.out.rejected && r.cmds.length === 1, JSON.stringify(r.cmds));
  check('enforce/hard: reject command shape',
    /\/v2\/calls\/v3%3Ae2e-[^/]+\/actions\/reject$/.test(cmd.path || '') && cmd.auth === 'Bearer KEY-e2e' && cmd.body && cmd.body.cause === 'CALL_REJECTED',
    JSON.stringify(cmd));
  r = await run(a, initiated(FRESH[0], PREMIUM));
  check('enforce/hard: score alone passes', r.out.screened && ['challenge', 'reject'].includes(r.out.result.action) && r.cmds.length === 0,
    JSON.stringify([r.out.result && r.out.result.action, r.cmds]));
  r = await run(a, initiated(FRESH[1], DEST, { caller_id_name: 'ACME "Corp"', shaken_stir_attestation: 'A', shaken_stir_validated: true }));
  check('enforce/hard: clean passes', r.out.screened && r.out.result.action === 'allow' && r.cmds.length === 0, JSON.stringify(r.out.result));
  check('enforce/hard: Telnyx attestation is returned', r.out.telnyx && r.out.telnyx.shaken_stir_attestation === 'A', JSON.stringify(r.out.telnyx));

  // enforce, full scoring
  a = create(opts({ mode: 'enforce', hardBlocksOnly: false }));
  r = await run(a, initiated(FRESH[2], PREMIUM));
  check('enforce/full: score rejects', r.out.rejected && r.cmds.length === 1, JSON.stringify(r.cmds));

  // fail open
  a = create(opts({ mode: 'enforce', falconUrl: 'http://127.0.0.1:1/v1/screen' }));
  r = await run(a, initiated(deny, DEST));
  check('fail open: no Falcon, call left alone', !r.out.screened && !r.out.rejected && r.cmds.length === 0, JSON.stringify(r));
  a = create(opts({ mode: 'enforce' }));
  status = 500;
  r = await run(a, initiated(deny, DEST));
  status = 200;
  check('fail open: failed reject is reported as not rejected', r.out.screened && !r.out.rejected && r.cmds.length === 1, JSON.stringify(r));

  // outbound: only legs with a customer are screened
  await falcon('/v1/customers', 'PUT', { id: 'telnyx-e2e', name: 'Telnyx e2e', dids: [OWNED] });
  a = create(opts({ mode: 'enforce', customerFor: (p) => ((p.tags || []).includes('customer:telnyx-e2e') ? 'telnyx-e2e' : '') }));
  r = await run(a, initiated(NOT_OWNED, DEST, { direction: 'outgoing', state: 'bridging' }));
  check('outbound: leg without a customer is not screened', !r.out.screened && r.cmds.length === 0, JSON.stringify(r));
  r = await run(a, initiated(NOT_OWNED, DEST, { direction: 'outgoing', state: 'bridging', tags: ['customer:telnyx-e2e'] }));
  check('outbound: caller id not owned is hung up',
    r.out.rejected && r.cmds.length === 1 && /\/actions\/hangup$/.test(r.cmds[0].path),
    JSON.stringify([r.out.result && r.out.result.headers_to_set, r.cmds]));
  r = await run(a, initiated(OWNED, DEST, { direction: 'outgoing', state: 'bridging', tags: ['customer:telnyx-e2e'] }));
  check('outbound: owned caller id passes', r.out.screened && r.cmds.length === 0, JSON.stringify(r));

  // outcome: answered for 7 seconds
  a = create(opts({ mode: 'monitor' }));
  const leg = 'tx-e2e-outcome-' + process.pid;
  const t0 = Date.now();
  await a.handle(initiated(FRESH[3], DEST, { call_leg_id: leg }));
  await a.handle(event('call.answered', { call_leg_id: leg, from: FRESH[3], to: DEST }, t0 + 2000));
  await a.handle(event('call.hangup', { call_leg_id: leg, from: FRESH[3], to: DEST, hangup_cause: 'normal_clearing', hangup_source: 'caller' }, t0 + 9000));
  const found = await falcon('/v1/events?range=1h&q=' + encodeURIComponent(leg));
  const ev = ((found && found.data) || []).find((e) => e.call_id === leg) || {};
  check('outcome: answered, duration, cause reach Falcon', ev.answered === true && ev.duration_s === 7 && ev.hangup_cause === 'normal_clearing', JSON.stringify(ev));

  api.close();
  let ok = true;
  for (const x of results) {
    console.log((x.ok ? 'ok   ' : 'FAIL ') + x.label + (x.ok ? '' : '  [' + x.detail + ']'));
    if (!x.ok) ok = false;
  }
  console.log('telnyx call control adapter:', ok ? 'PASS' : 'FAIL');
  process.exit(ok ? 0 : 1);
})();
