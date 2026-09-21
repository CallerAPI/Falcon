#!/usr/bin/env node
// Drive adapters/connexcs/falcon.js the way ScriptForge does, against a
// live Falcon. Supplies require('axios') on top of Node's fetch, calls
// main(data) with a routing object, and checks each MODE:
//   monitor                   never throws, even on a deny-listed CLI
//   enforce, hard blocks only throws 603 on the deny list, not on a score
//   enforce, full             throws on both
// Usage: connexcs_harness.js <falcon_url> <deny_number> <clean_number>

const fs = require('fs');
const path = require('path');

const [url, deny, clean] = process.argv.slice(2);
const src = fs.readFileSync(path.join(__dirname, '..', 'connexcs', 'falcon.js'), 'utf8');

// The subset of axios the app uses.
const axios = {
  async post(target, body, opts) {
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
      { FALCON_URL: url, FALCON_TOKEN: process.env.FALCON_TOKEN || '', FALCON_DIRECTION: 'inbound' },
      envOverrides
    ),
  };
  return new Function('require', 'process', src + '\nreturn main;')(sandboxRequire, fakeProcess);
}

let n = 0;
function routing(cli, ua) {
  n += 1;
  return {
    routing: {
      cli,
      dest_number: '+14155550100',
      account_id: 4242,
      ip: '203.0.113.9',
      user_agent: ua || 'connexcs-e2e/1.0',
      call_id: 'cx-e2e-' + cli + '-' + n,
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

(async () => {
  const results = [];
  const check = (label, ok, detail) => {
    results.push({ label, ok, detail });
  };

  // monitor: nothing is ever thrown
  let main = load({ FALCON_MODE: 'monitor' });
  let r = await outcome(main, routing(deny));
  check('monitor: deny-listed CLI passes', r.threw === null, r.threw);
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
