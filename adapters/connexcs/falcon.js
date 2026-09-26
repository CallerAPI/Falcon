// CallerAPI Falcon for ConnexCS. ScriptForge App for Class 4 Routing.
//
// Create it as type App (a Script cannot make HTTP calls). Assign it under
// Management > Customer > Routing > [Route] > ScriptForge for the calls your
// customers send you, or under Management > Customer > DID > [DID] >
// ScriptForge for calls to your DIDs. Set the ScriptForge Timeout to 3000
// and the Timeout Action to "200 OK", so a slow Falcon never drops a call.
//
// Falcon must be reachable from the ConnexCS cloud: a public HTTPS URL in
// front of the Falcon host, and FALCON_TOKEN set on both sides.
//
// Run Falcon with FALCON_PROFILE=carrier. On a wholesale ingress the default
// per-IP and per-CLI velocity rules fire on normal call center traffic.

const axios = require('axios');

const env = (typeof process !== 'undefined' && process.env) || {};
const FALCON_URL = env.FALCON_URL || 'https://falcon.example.com/v1/screen';
const FALCON_TOKEN = env.FALCON_TOKEN || '';

// MODE:
//   'monitor'  Never touch a call. Falcon records every screen and the
//              dashboard shows what enforce would have done. Start here.
//   'enforce'  Reject calls Falcon rejects.
const MODE = env.FALCON_MODE || 'monitor';

// In enforce mode, reject only on a hard block: an operator deny rule, a
// spam feed hit, an IP intel block row, a caller id the customer does
// not own, or a spoofed Business Caller ID. Heuristic scores alone never
// drop a call. Set false only after the Traffic view shows the score
// thresholds fit your traffic.
const ENFORCE_HARD_BLOCKS_ONLY = env.FALCON_HARD_BLOCKS_ONLY !== 'false';

// Add X-Falcon-* headers to the egress INVITEs on allow and flag. Off until
// you have confirmed the header shape on your build with Save and Run.
const ADD_HEADERS = env.FALCON_ADD_HEADERS === 'true';

// Falcon answers in a few milliseconds on a hit. Keep this below the
// ScriptForge Timeout so the script, not ConnexCS, decides on a slow answer.
const TIMEOUT_MS = 1500;

// 'outbound' on a Route: your customer is placing the call and Falcon checks
// the caller id against the numbers registered for that account.
// 'inbound' on a DID: the call is coming to one of your numbers.
const DIRECTION = env.FALCON_DIRECTION || 'outbound';

// ConnexCS signs the call on the INVITE it sends to the carrier, after this
// script returns, so the INVITE here has no Identity header.
// routing.stir_shaken is that signing decision, and the PASSporT x5u is
// CERT_BASE + cert_id + '.crt'.
const CERT_BASE = env.FALCON_CERT_BASE || 'https://cdn.cnxcdn.com/shaken/';

function sipURI(num, host) {
  num = String(num || '').trim();
  if (!num) {
    return '';
  }
  return '<sip:' + num + '@' + host + '>';
}

function signingFor(ss) {
  if (!ss || !ss.attest) {
    return null;
  }
  const certID = String(ss.cert_id || '');
  return {
    attest: String(ss.attest),
    origid: String(ss.origid || ''),
    x5u: /^[A-Za-z0-9_-]+$/.test(certID) ? CERT_BASE + certID + '.crt' : '',
  };
}

// data.routing is the Raw Data of the call log. params holds what the switch
// read from the INVITE: si and sp are the source address and port, and
// userAgent is the User-Agent header.
function payloadFor(routing) {
  const params = routing.params || {};
  const ip = String(params.si || routing.switch || '');
  const payload = {
    switch: 'connexcs',
    direction: DIRECTION,
    customer: routing.account_id !== undefined && routing.account_id !== null ? String(routing.account_id) : '',
    method: 'INVITE',
    request_uri: 'sip:' + (routing.dest_number || 'unknown') + '@connexcs.invalid',
    source_ip: ip,
    headers: {
      From: sipURI(routing.cli || params.fU, ip || 'connexcs.invalid') + ';tag=cx',
      To: sipURI(routing.dest_number, 'connexcs.invalid'),
      'Call-ID': String(routing.callid || params.callid || ''),
      'User-Agent': String(params.userAgent || ''),
    },
  };
  if (params.sp) {
    payload.source_port = Number(params.sp);
  }
  const signing = signingFor(routing.stir_shaken);
  if (signing) {
    payload.signing = signing;
  }
  return payload;
}

async function screen(payload) {
  const headers = { 'Content-Type': 'application/json' };
  if (FALCON_TOKEN) {
    headers['X-Falcon-Token'] = FALCON_TOKEN;
  }
  const res = await axios.post(FALCON_URL, payload, {
    headers,
    timeout: TIMEOUT_MS,
    validateStatus: () => true,
  });
  if (res.status !== 200 || !res.data || !res.data.action) {
    return null;
  }
  return res.data;
}

// shouldReject applies MODE and ENFORCE_HARD_BLOCKS_ONLY to one result.
function shouldReject(result) {
  if (MODE !== 'enforce') {
    return false;
  }
  if (result.action !== 'reject' && result.action !== 'challenge') {
    return false;
  }
  if (ENFORCE_HARD_BLOCKS_ONLY) {
    const block = (result.headers_to_set || {})['X-Falcon-Block'];
    return typeof block === 'string' && block !== '';
  }
  return true;
}

async function main(data = {}) {
  const routing = data.routing || {};
  let result = null;
  try {
    result = await screen(payloadFor(routing));
  } catch (e) {
    result = null;
  }
  // Fail open: no answer from Falcon means the call goes through.
  if (!result) {
    return data;
  }

  if (shouldReject(result)) {
    // ConnexCS reads "[code] [reason]" from the thrown Error.
    const code = result.action === 'reject' && result.sip_status >= 300 ? result.sip_status : 603;
    const reason = String(result.sip_reason || 'Decline').replace(/[^\w .-]/g, '') || 'Decline';
    throw new Error(code + ' ' + reason);
  }

  if (ADD_HEADERS) {
    const toSet = result.headers_to_set || {};
    const add = [];
    for (const key of Object.keys(toSet)) {
      if ((key.indexOf('X-Falcon-') === 0 || key === 'Remote-Party-ID' || key === 'Call-Info') && toSet[key]) {
        add.push({ key: key, value: String(toSet[key]) });
      }
    }
    if (add.length) {
      data.headers = (data.headers || []).concat(add);
    }
  }
  return data;
}
