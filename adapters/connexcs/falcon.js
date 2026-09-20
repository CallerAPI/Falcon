// CallerAPI Falcon for ConnexCS. ScriptForge App for Class 4 Routing.
//
// Create it as type App (a Script cannot make HTTP calls). Assign it under
// Management > Customer > Routing > [Route] > ScriptForge for the calls your
// customers send you, or under Management > Customer > DID > [DID] >
// ScriptForge for calls to your DIDs. Set the ScriptForge Timeout above
// TIMEOUT_MS so a slow Falcon never trips the Timeout Action.
//
// Falcon must be reachable from the ConnexCS cloud: a public HTTPS URL in
// front of the Falcon host, and FALCON_TOKEN set on both sides.

const axios = require('axios');

const env = (typeof process !== 'undefined' && process.env) || {};
const FALCON_URL = env.FALCON_URL || 'https://falcon.example.com/v1/screen';
const FALCON_TOKEN = env.FALCON_TOKEN || '';
// Falcon answers in a few milliseconds on a hit. Keep this below the
// ScriptForge Timeout so the script, not ConnexCS, decides on a slow answer.
const TIMEOUT_MS = 1500;
// 'outbound' on a Route: your customer is placing the call and Falcon checks
// the caller id against the numbers registered for that account.
// 'inbound' on a DID: the call is coming to one of your numbers.
const DIRECTION = env.FALCON_DIRECTION || 'outbound';

// data.routing carries the fields of the Raw Data tab of a call log.
// cli, dest_number, and account_id are documented by ConnexCS. The source
// IP and User-Agent keys differ by build, so the first key present wins.
// Run the script once with Save and Run on a real log to confirm them.
const IP_KEYS = ['ip', 'src_ip', 'source_ip', 'customer_ip', 'ingress_ip', 'remote_ip'];
const UA_KEYS = ['user_agent', 'ua', 'useragent'];
const CALLID_KEYS = ['call_id', 'callid', 'sip_call_id'];

function pick(obj, keys) {
  for (const k of keys) {
    if (obj && obj[k] !== undefined && obj[k] !== null && obj[k] !== '') {
      return String(obj[k]);
    }
  }
  return '';
}

function sipURI(num, host) {
  num = String(num || '').trim();
  if (!num) {
    return '';
  }
  return '<sip:' + num + '@' + host + '>';
}

function payloadFor(routing) {
  const ip = pick(routing, IP_KEYS);
  return {
    switch: 'connexcs',
    direction: DIRECTION,
    customer: routing.account_id !== undefined && routing.account_id !== null ? String(routing.account_id) : '',
    method: 'INVITE',
    request_uri: 'sip:' + (routing.dest_number || 'unknown') + '@connexcs.invalid',
    source_ip: ip,
    headers: {
      From: sipURI(routing.cli, ip || 'connexcs.invalid') + ';tag=cx',
      To: sipURI(routing.dest_number, 'connexcs.invalid'),
      'Call-ID': pick(routing, CALLID_KEYS),
      'User-Agent': pick(routing, UA_KEYS),
    },
  };
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

  if (result.action === 'reject' || result.action === 'challenge') {
    // ConnexCS reads "[code] [reason]" from the thrown Error.
    const code = result.action === 'reject' && result.sip_status >= 300 ? result.sip_status : 603;
    const reason = String(result.sip_reason || 'Decline').replace(/[^\w .-]/g, '') || 'Decline';
    throw new Error(code + ' ' + reason);
  }

  // allow and flag: continue, and carry the Falcon headers to every
  // destination so the far end can see the score.
  const toSet = result.headers_to_set || {};
  const add = [];
  for (const key of Object.keys(toSet)) {
    if (key.indexOf('X-Falcon-') === 0 && toSet[key]) {
      add.push({ key: key, value: String(toSet[key]) });
    }
  }
  if (add.length) {
    data.headers = (data.headers || []).concat(add);
  }
  return data;
}
