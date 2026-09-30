#!/usr/bin/env python3
"""Hold the ConnexCS transcription socket open and post each message to Falcon.

The route script does not see this text. ConnexCS delivers it only while
this process is connected. Requires the Debian package python3-websocket.
"""

import os
import sys
import time
import urllib.error
import urllib.request

import websocket

SCRIPT_ID = os.environ.get("CONNEXCS_SCRIPT_ID", "").strip()
TOKEN = os.environ.get("CONNEXCS_TOKEN", "").strip()
FALCON_URL = os.environ.get("FALCON_URL", "http://127.0.0.1:8090/v1/voice/transcript")
FALCON_TOKEN = os.environ.get("FALCON_TOKEN", "").strip()


def post(message):
    if isinstance(message, bytes):
        body = message
    else:
        body = str(message).encode()
    req = urllib.request.Request(FALCON_URL, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if FALCON_TOKEN:
        req.add_header("X-Falcon-Token", FALCON_TOKEN)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except urllib.error.URLError as exc:
        print("falcon post failed: %s" % exc, file=sys.stderr)


def main():
    if not SCRIPT_ID or not TOKEN:
        print("CONNEXCS_SCRIPT_ID and CONNEXCS_TOKEN are required", file=sys.stderr)
        return 1
    url = "wss://app.connexcs.com/api/cp/scriptforge/" + SCRIPT_ID
    while True:
        ws = websocket.WebSocketApp(
            url,
            header={"Authorization": "Bearer " + TOKEN},
            on_message=lambda _ws, message: post(message),
            on_error=lambda _ws, err: print("socket error: %s" % err, file=sys.stderr),
        )
        ws.run_forever(ping_interval=20, ping_timeout=10)
        time.sleep(2)


if __name__ == "__main__":
    sys.exit(main() or 0)
