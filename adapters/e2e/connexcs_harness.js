#!/usr/bin/env node
// Drive adapters/connexcs/falcon.js the way ScriptForge does, against a
// live Falcon. Supplies require('axios') on top of Node's fetch, calls
// main(data) with a routing object, and checks each MODE:
//   monitor                   never throws, even on a deny-listed CLI
//   enforce, hard blocks only throws 603 on the deny list, not on a score
//   enforce, full             throws on both
// The routing object has the keys of a real ConnexCS Raw Data log, with
// documentation addresses and numbers.
// Usage: connexcs_harness.js <falcon_url> <deny_number> <clean_number>

const fs = require('fs');
const path = require('path');

const [url, deny, clean] = process.argv.slice(2);
const src = fs.readFileSync(path.join(__dirname, '..', 'connexcs', 'falcon.js'), 'utf8');
const token = process.env.FALCON_TOKEN || '';
const sent = [];

// The subset of axios the app uses.
const axios = {
  async post(target, body, opts) {
    sent.push(body);
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), opts.timeout);
    try {
      const res = await fetch(target, {
        method: 'POST',
        headers: opts.headers,
        body: JSON.stringify(body),
        signal: ctl.signal,
      });
      const text = await res.text();
      let data = text;
      try {
        data = JSON.parse(text);
      } catch (e) {
        // leave as text
      }
      return { status: res.status, data };
    } finally {
      clearTimeout(timer);
    }
  },
};

const sandboxRequire = (name) => {
  if (name === 'axios') {
    return axios;
  }
  throw new Error('ScriptForge would not provide module ' + name);
};

function load(envOverrides) {
  const fakeProcess = {
    env: Object.assign(
      { FALCON_URL: url, FALCON_TOKEN: token, FALCON_DIRECTION: 'inbound' },
      envOverrides
    ),
  };
  return new Function('require', 'process', src + '\nreturn main;')(sandboxRequire, fakeProcess);
}

let n = 0;
function routing(cli, ua) {
  n += 1;
  const callid = 'cx-e2e-' + cli + '-' + n;
  return {
    routing: {
      params: {
        switch: '203.0.113.9',
        oU: '4155550100',
        fU: cli,
        callid,
        userAgent: ua || 'connexcs-e2e/1.0',
        si: '203.0.113.9',
        sp: 5070,
        proto: 'udp',
        csIp: '198.51.100.1',
      },
      server: '198.51.100.1',
      switch: '203.0.113.9',
      cli,
      callid,
      account_id: 4242,
      direction: 'term',
      dest_number: '14155550100',
      stir_shaken: { attest: 'A', origid: '00000000-0000-4000-8000-000000000001', cert_id: 'e2e0000001' },
      egress_routing: [{ gw: {} }],
    },
  };
}

async function outcome(main, data) {
  try {
    const out = await main(data);
    return { threw: null, headers: out.headers || null };
  } catch (e) {
    return { threw: e.message, headers: null };
  }
}

async function storedEvent(callid) {
  const eventsURL = url.replace(/\/v1\/screen$/, '/v1/events');
  for (let i = 0; i < 30; i++) {
    const res = await fetch(eventsURL, { headers: { 'X-Falcon-Token': token } });
    const body = await res.json();
    const ev = (body.data || []).find((e) => e.call_id === callid);
    if (ev) {
      return ev;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  return null;
}

(async () => {
  const results = [];
  const check = (label, ok, detail) => {
    results.push({ label, ok, detail });
  };

  // monitor: nothing is ever thrown
  let main = load({ FALCON_MODE: 'monitor' });
  let r = await outcome(main, routing(deny));
  check('monitor: deny-listed CLI passes', r.threw === null, r.threw);
  const probe = routing(clean, 'Acme SBC/3.6');
  r = await outcome(main, probe);
  check('monitor: clean passes', r.threw === null, r.threw);
  const body = sent[sent.length - 1];
  check('payload: source is params.si', body.source_ip === '203.0.113.9' && body.source_port === 5070, JSON.stringify(body));
  check('payload: user agent is params.userAgent', body.headers['User-Agent'] === 'Acme SBC/3.6', JSON.stringify(body.headers));
  check('payload: call id is routing.callid', body.headers['Call-ID'] === probe.routing.callid, JSON.stringify(body.headers));
  check(
    'payload: signing from routing.stir_shaken',
    body.signing && body.signing.attest === 'A' && body.signing.x5u === 'https://cdn.cnxcdn.com/shaken/e2e0000001.crt',
    JSON.stringify(body.signing)
  );
  const ev = await storedEvent(probe.routing.callid);
  const codes = ev ? (ev.reasons || []).map((x) => x.code) : [];
  check(
    'event: switch signing stored',
    ev && ev.shaken_attest === 'A' && ev.shaken && ev.shaken.source === 'switch' && ev.source_ip === '203.0.113.9' && ev.user_agent === 'Acme SBC/3.6',
    JSON.stringify(ev)
  );
  check('event: no missing_identity when the switch signs', ev && codes.indexOf('missing_identity') < 0, codes.join(','));

  r = await outcome(main, routing(clean, 'friendly-scanner'));
  check('monitor: scanner UA passes', r.threw === null, r.threw);
  check('monitor: no headers added by default', r.headers === null, JSON.stringify(r.headers));

  // enforce, hard blocks only (the default in enforce)
  main = load({ FALCON_MODE: 'enforce' });
  r = await outcome(main, routing(deny));
  check('enforce/hard: deny-listed CLI is 603', /^603 /.test(r.threw || ''), r.threw);
  r = await outcome(main, routing(clean, 'friendly-scanner'));
  check('enforce/hard: scanner score alone passes', r.threw === null, r.threw);
  r = await outcome(main, routing(clean));
  check('enforce/hard: clean passes', r.threw === null, r.threw);

  // enforce, full scoring
  main = load({ FALCON_MODE: 'enforce', FALCON_HARD_BLOCKS_ONLY: 'false', FALCON_ADD_HEADERS: 'true' });
  r = await outcome(main, routing(clean, 'friendly-scanner'));
  check('enforce/full: scanner score is 603', /^603 /.test(r.threw || ''), r.threw);
  r = await outcome(main, routing(clean));
  const action = r.headers && r.headers.find((h) => h.key === 'X-Falcon-Action');
  check('enforce/full: clean passes with headers', r.threw === null && action && action.value === 'allow', r.threw || JSON.stringify(r.headers));

  let ok = true;
  for (const x of results) {
    console.log((x.ok ? 'ok   ' : 'FAIL ') + x.label + (x.ok ? '' : '  [' + x.detail + ']'));
    if (!x.ok) ok = false;
  }
  console.log('connexcs scriptforge adapter:', ok ? 'PASS' : 'FAIL');
  process.exit(ok ? 0 : 1);
})();
