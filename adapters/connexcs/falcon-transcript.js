// CallerAPI Falcon for ConnexCS route transcription.
//
// ScriptForge on the route screens the INVITE. It does not hear the call.
// This app does not score. It forwards ConnexCS transcription events to
// Falcon. Falcon stores the text and decides the verdict.
//
// 1. Management > Customer > Routing > [Route]. Turn on Transcription. Save.
//    Customers keep dialing the normal number. Do not add a prefix.
// 2. IDE > Script Forge > Add Script. App Type = App+.
//    Paste this file. Set FALCON_URL and FALCON_TOKEN.
// 3. Save. Leave the script running. It subscribes to the transcription
//    bus and posts each message to Falcon.
//
// The bus payload is not documented. This script sends the message unchanged.
// Falcon reads the text from the fields it knows. A message with no text is
// stored as JSON so the field names can be seen, and it is not scored.

import { subscribe } from 'cxPubSub';

const FALCON_URL = 'https://falcon.example.com/v1/voice/transcript';
const FALCON_TOKEN = '';

async function forward(msg) {
  const body = typeof msg === 'string' ? msg : JSON.stringify(msg == null ? {} : msg);
  await fetch(FALCON_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Falcon-Token': FALCON_TOKEN,
    },
    body,
  });
}

export async function main() {
  subscribe('transcription', '*', (msg) => {
    forward(msg).catch(() => {});
  });
  await new Promise(() => {});
}
