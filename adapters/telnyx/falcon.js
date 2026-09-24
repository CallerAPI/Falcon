// CallerAPI Falcon for Telnyx Call Control (Voice API v2 webhooks).
//
// Runs inside the webhook handler you already have for your Call Control
// application. It needs Node 18 or later and no packages.
//
//   const falcon = require('./falcon').create();
//
//   // In the POST handler, with the body read as raw text:
//   const event = falcon.verify(rawBody, req.headers); // throws on a bad signature
//   res.sendStatus(200);                               // ack first, as Telnyx asks
//   const out = await falcon.handle(event);
//   if (out.rejected) return;                          // Falcon already rejected it
//   // ... your own answer / transfer / TeXML logic ...
//
// Telnyx parks every call until your first command, so screening after the
// ack costs the caller nothing. A slow or missing Falcon, or a failed
// Telnyx command, leaves the call to your code: the adapter fails open.
//
// Settings come from the options object or the environment:
//   FALCON_URL            https://falcon.example.com/v1/screen (public HTTPS)
//   FALCON_TOKEN          the same token Falcon runs with
//   FALCON_MODE           monitor (default) or enforce
//   FALCON_HARD_BLOCKS_ONLY  false to reject on the score as well
//   TELNYX_API_KEY        to send reject and hangup
//   TELNYX_PUBLIC_KEY     Portal > Keys & Credentials > Public Key
//
// A webhook carries no source IP, User-Agent, Identity header, or SDP, so
// every screen starts at 30 points and Falcon cannot verify STIR/SHAKEN.
// Turn on "Enable SHAKEN/STIR" on the application and the attestation
// Telnyx saw is returned in out.telnyx for your logs.

'use strict';

const crypto = require('crypto');

// Telnyx allows five minutes of clock skew in its own SDKs.
const TOLERANCE_S = 300;

// Falcon answers in a few milliseconds on a hit.
const SCREEN_TIMEOUT_MS = 1500;
const COMMAND_TIMEOUT_MS = 3000;

function create(opts = {}) {
  const env = process.env;
  const cfg = {
    falconUrl: opts.falconUrl || env.FALCON_URL || 'http://127.0.0.1:8090/v1/screen',
    falconToken: opts.falconToken !== undefined ? opts.falconToken : env.FALCON_TOKEN || '',
    // monitor: never touch a call; the Traffic view shows what enforce
    // would have done. enforce: reject calls Falcon rejects.
    mode: opts.mode || env.FALCON_MODE || 'monitor',
    // In enforce mode, reject only on a hard block: a deny rule, the spam
    // feed, an IP intel block row, a caller id the customer does not own,
    // or a spoofed Business Caller ID. A score alone never drops a call.
    hardBlocksOnly: opts.hardBlocksOnly !== undefined ? opts.hardBlocksOnly : env.FALCON_HARD_BLOCKS_ONLY !== 'false',
    apiKey: opts.telnyxApiKey || env.TELNYX_API_KEY || '',
    apiBase: opts.telnyxApiBase || env.TELNYX_API_BASE || 'https://api.telnyx.com/v2',
    publicKey: opts.telnyxPublicKey || env.TELNYX_PUBLIC_KEY || '',
    // Outbound legs are screened only when this returns your account id for
    // the customer placing the call, from its tags or client_state. Falcon
    // then rejects a caller id the customer does not own. Transfer legs
    // return nothing and are left alone.
    customerFor: opts.customerFor || (() => ''),
  };
  // Screened legs, until hangup. Pass a shared store with async get, set,
  // and delete when more than one process takes the webhooks.
  const store = opts.store || memoryStore();
  const base = cfg.falconUrl.replace(/\/v1\/screen$/, '');
  let key = null;

  // verify checks the Ed25519 signature over "timestamp|body" and returns
  // the parsed event. It throws on anything Telnyx did not sign.
  function verify(rawBody, headers, now) {
    const body = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : String(rawBody);
    const sig = header(headers, 'telnyx-signature-ed25519');
    const ts = header(headers, 'telnyx-timestamp');
    if (!sig || !ts) {
      throw new Error('missing Telnyx signature headers');
    }
    if (!/^\d+$/.test(ts) || Math.abs((now || Date.now() / 1000) - Number(ts)) > TOLERANCE_S) {
      throw new Error('Telnyx timestamp outside tolerance');
    }
    if (!key) {
      const raw = Buffer.from(cfg.publicKey, 'base64');
      if (raw.length !== 32) {
        throw new Error('TELNYX_PUBLIC_KEY must be the base64 Ed25519 key from the Portal');
      }
      key = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') }, format: 'jwk' });
    }
    if (!crypto.verify(null, Buffer.from(ts + '|' + body), key, Buffer.from(sig, 'base64'))) {
      throw new Error('bad Telnyx signature');
    }
    return JSON.parse(body);
  }

  // handle acts on one verified event. On call.initiated it screens the
  // call and, when the mode says so, rejects it. It reports the outcome to
  // Falcon at hangup. It never throws.
  async function handle(event) {
    const data = (event && event.data) || {};
    const p = data.payload || {};
    const out = { event: data.event_type || '', screened: false, rejected: false, result: null, telnyx: null };
    try {
      if (data.event_type === 'call.initiated') {
        await initiated(p, out);
      } else if (data.event_type === 'call.answered') {
        const rec = await store.get(p.call_leg_id);
        if (rec) {
          rec.answeredAt = Date.parse(data.occurred_at) || Date.now();
          await store.set(p.call_leg_id, rec);
        }
      } else if (data.event_type === 'call.hangup') {
        await hangup(p, Date.parse(data.occurred_at) || Date.now());
      }
    } catch (e) {
      // Fail open.
    }
    return out;
  }

  async function initiated(p, out) {
    let direction = 'inbound';
    let customer = '';
    if (p.direction === 'outgoing') {
      customer = String(cfg.customerFor(p) || '');
      if (!customer) {
        return;
      }
      direction = 'outbound';
    }
    out.telnyx = {
      shaken_stir_attestation: p.shaken_stir_attestation,
      shaken_stir_validated: p.shaken_stir_validated,
      call_screening_result: p.call_screening_result,
    };
    const result = await post(cfg.falconUrl, payloadFor(p, direction, customer), SCREEN_TIMEOUT_MS);
    if (!result || !result.action) {
      return;
    }
    out.screened = true;
    await store.set(p.call_leg_id, { at: Date.now() });
    out.result = result;
    if (!shouldReject(result)) {
      return;
    }
    // An inbound call is still parked: reject it unanswered. An outbound
    // leg is already dialing: hang it up.
    const action = direction === 'inbound' ? 'reject' : 'hangup';
    const body = { command_id: 'falcon-' + action + '-' + p.call_leg_id };
    if (action === 'reject') {
      body.cause = 'CALL_REJECTED';
    }
    out.rejected = await command(p.call_control_id, action, body);
  }

  async function hangup(p, at) {
    const rec = await store.get(p.call_leg_id);
    if (!rec) {
      return;
    }
    await store.delete(p.call_leg_id);
    const answered = Boolean(rec.answeredAt);
    await post(base + '/v1/outcome', {
      call_id: p.call_leg_id,
      answered: answered,
      duration_s: answered ? Math.max(0, Math.round((at - rec.answeredAt) / 1000)) : 0,
      hangup_cause: String(p.hangup_cause || p.sip_hangup_cause || ''),
    }, 2000);
  }

  // shouldReject applies the mode and hard-blocks setting to one result.
  function shouldReject(result) {
    if (cfg.mode !== 'enforce') {
      return false;
    }
    if (result.action !== 'reject' && result.action !== 'challenge') {
      return false;
    }
    if (cfg.hardBlocksOnly) {
      const block = (result.headers_to_set || {})['X-Falcon-Block'];
      return typeof block === 'string' && block !== '';
    }
    return true;
  }

  async function post(url, body, timeout) {
    const headers = { 'Content-Type': 'application/json' };
    if (cfg.falconToken) {
      headers['X-Falcon-Token'] = cfg.falconToken;
    }
    const res = await request(url, headers, body, timeout);
    return res && res.ok ? res.json() : null;
  }

  async function command(callControlId, action, body) {
    if (!cfg.apiKey || !callControlId) {
      return false;
    }
    const url = cfg.apiBase + '/calls/' + encodeURIComponent(callControlId) + '/actions/' + action;
    const headers = { 'Content-Type': 'application/json', Authorization: 'Bearer ' + cfg.apiKey };
    const res = await request(url, headers, body, COMMAND_TIMEOUT_MS);
    return Boolean(res && res.ok);
  }

  return { verify, handle };
}

// payloadFor maps a call.initiated payload to a /v1/screen request. The
// leg id is the Call-ID, so the outcome at hangup finds the same event.
function payloadFor(p, direction, customer) {
  const from = uri(p.from);
  const to = uri(p.to);
  const name = String(p.caller_id_name || '').replace(/["\\\r\n]/g, '');
  const display = name && name !== String(p.from) ? '"' + name + '" ' : '';
  return {
    switch: 'telnyx',
    direction: direction,
    customer: customer,
    method: 'INVITE',
    request_uri: to,
    headers: {
      From: display + '<' + from + '>;tag=tx',
      To: '<' + to + '>',
      'Call-ID': String(p.call_leg_id || ''),
    },
  };
}

// uri keeps a SIP URI as it is and puts a bare number inside one. Falcon
// reads numbers only from sip:, sips:, or tel: URIs.
function uri(v) {
  v = String(v || '').trim().replace(/[<>\s]/g, '');
  if (/^(sips?|tel):/i.test(v)) {
    return v;
  }
  return 'sip:' + (v || 'unknown') + '@telnyx.invalid';
}

function header(headers, name) {
  if (!headers) {
    return '';
  }
  if (typeof headers.get === 'function') {
    return headers.get(name) || '';
  }
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === name) {
      const v = headers[k];
      return Array.isArray(v) ? v[0] : String(v || '');
    }
  }
  return '';
}

async function request(url, headers, body, timeout) {
  try {
    return await fetch(url, { method: 'POST', headers, body: JSON.stringify(body), signal: AbortSignal.timeout(timeout) });
  } catch (e) {
    return null;
  }
}

// memoryStore forgets legs after 12 hours, in case a hangup never arrives.
function memoryStore() {
  const m = new Map();
  const ttl = 12 * 3600 * 1000;
  return {
    async get(k) {
      const v = m.get(k);
      return v && Date.now() - v.at < ttl ? v : null;
    },
    async set(k, v) {
      if (m.size > 10000) {
        for (const [key, val] of m) {
          if (Date.now() - val.at >= ttl) m.delete(key);
        }
      }
      m.set(k, v);
    },
    async delete(k) {
      m.delete(k);
    },
  };
}

module.exports = { create, payloadFor };
