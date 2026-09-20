#!/usr/bin/env node
// Drive adapters/connexcs/falcon.js the way ScriptForge does, against a
// live Falcon. Supplies require('axios') on top of Node's fetch, calls
// main(data) with a routing object, and checks the thrown SIP code and the
// headers. Usage: connexcs_harness.js <falcon_url> <deny_number> <clean_number>

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

const fakeProcess = { env: { FALCON_URL: url, FALCON_TOKEN: process.env.FALCON_TOKEN || '', FALCON_DIRECTION: 'inbound' } };
const main = new Function('require', 'process', src + '\nreturn main;')(sandboxRequire, fakeProcess);

function routing(cli) {
  return {
    routing: {
      cli,
      dest_number: '+14155550100',
      account_id: 4242,
      ip: '203.0.113.9',
      user_agent: 'connexcs-e2e/1.0',
      call_id: 'cx-e2e-' + cli,
      egress_routing: [{ gw: {} }],
    },
  };
}

(async () => {
  let ok = true;
  let denied = 'no throw';
  try {
    await main(routing(deny));
  } catch (e) {
    denied = e.message;
  }
  if (!/^603 /.test(denied)) {
    ok = false;
  }
  let allowed;
  try {
    allowed = await main(routing(clean));
  } catch (e) {
    allowed = 'threw ' + e.message;
    ok = false;
  }
  const action = allowed && allowed.headers && allowed.headers.find((h) => h.key === 'X-Falcon-Action');
  if (!action || action.value !== 'allow') {
    ok = false;
  }
  console.log('denied:', denied);
  console.log('allowed:', allowed && allowed.headers ? JSON.stringify(allowed.headers) : allowed);
  console.log('connexcs scriptforge adapter:', ok ? 'PASS' : 'FAIL');
  process.exit(ok ? 0 : 1);
})();
