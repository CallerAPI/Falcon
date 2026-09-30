// Do not install this as a second ScriptForge app.
//
// A ConnexCS route has one ScriptForge slot. That slot is falcon.js
// (type App). It screens the INVITE and returns. The caller has not
// spoken yet, and ConnexCS does not pass the transcript into that call.
//
// ConnexCS documents live transcription as a different script (type App+)
// that stays open only while a websocket client is connected. Do not put
// that script on the route, and do not replace falcon.js with it.
