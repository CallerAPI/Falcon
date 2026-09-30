// ConnexCS live transcription listener. Type App+.
//
// Do not assign this on the route. The route already has falcon.js.
// This script stays up only while a client is connected to
// wss://app.connexcs.com/api/cp/scriptforge/<this script id>.
// Falcon connects to it from Plugins > AI voice firewall.
//
// 1. On the route, turn Transcription on. Leave ScriptForge on falcon.js.
// 2. IDE > Script Forge > Add Script. App Type = App+. Paste this file. Save.
// 3. Copy the numeric script id from the URL.
// 4. Setup > Integrations > Opaque Tokens. Create an Access Token.

import { subscribe } from 'cxPubSub';
import * as socket from 'cxWebSocket';

export async function main() {
  subscribe('transcription', '*', (msg) => {
    const body = typeof msg === 'string' ? msg : JSON.stringify(msg == null ? {} : msg);
    socket.send(body);
  });
  await socket.waitForClose();
}
