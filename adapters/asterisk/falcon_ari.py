#!/usr/bin/env python3
"""Asterisk REST Interface app. Drop or continue a channel after Falcon scores it."""

import json
import os
import sys
import urllib.request

import ari

FALCON_URL = os.environ.get("FALCON_URL", "http://127.0.0.1:8090/v1/screen")
FALCON_TOKEN = os.environ.get("FALCON_TOKEN", "")
ARI_URL = os.environ.get("ARI_URL", "http://127.0.0.1:8088")
ARI_USER = os.environ.get("ARI_USER", "falcon")
ARI_PASSWORD = os.environ.get("ARI_PASSWORD", "falcon")
STASIS_APP = os.environ.get("ARI_APP", "falcon")
# Context for allowed calls. Required. The first Stasis argument overrides it.
CONTINUE_CONTEXT = os.environ.get("FALCON_ARI_CONTEXT", "").strip()
# Internal dialing contexts. A trunk call sent there can dial out.
UNSAFE_CONTEXTS = {"from-internal", "from-internal-xfer", "from-internal-noxfer"}


def screen(channel):
    headers = {}
    for name in ("From", "To", "Call-ID", "User-Agent", "P-Asserted-Identity", "Identity", "Contact"):
        try:
            value = channel.getChannelVar(variable="PJSIP_HEADER(read,%s)" % name).get("value")
        except Exception:
            value = ""
        if value:
            headers[name] = value
    payload = {
        "switch": "asterisk-ari",
        "method": "INVITE",
        "request_uri": "sip:%s@localhost" % (channel.json.get("dialplan", {}).get("exten") or "unknown"),
        "source_ip": "",
        "headers": headers,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(FALCON_URL, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if FALCON_TOKEN:
        req.add_header("X-Falcon-Token", FALCON_TOKEN)
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return {"action": "allow", "switch_hints": {}}


def on_start(channel, ev):
    result = screen(channel)
    action = result.get("action") or "allow"
    if action in ("reject", "challenge"):
        cause = int((result.get("switch_hints") or {}).get("asterisk_hangup_cause") or 21)
        channel.hangup(reason="normal", cause=cause)
        return
    args = ev.get("args") or []
    next_ctx = args[0] if len(args) > 0 and args[0] else CONTINUE_CONTEXT
    if next_ctx in UNSAFE_CONTEXTS:
        sys.stderr.write("falcon_ari: refusing to continue a trunk call to %s\n" % next_ctx)
        channel.hangup(reason="normal", cause=21)
        return
    next_ext = args[1] if len(args) > 1 else channel.json.get("dialplan", {}).get("exten")
    next_pri = args[2] if len(args) > 2 else "1"
    channel.continueInDialplan(context=next_ctx, extension=next_ext, priority=next_pri)


def main():
    if not CONTINUE_CONTEXT or CONTINUE_CONTEXT in UNSAFE_CONTEXTS:
        sys.exit(
            "falcon_ari: set FALCON_ARI_CONTEXT to your inbound context "
            "(from-pstn on FreePBX). It must not be from-internal or any context that can dial out."
        )
    client = ari.connect(ARI_URL, ARI_USER, ARI_PASSWORD)
    client.on_channel_event("StasisStart", on_start)
    client.run(apps=STASIS_APP)


if __name__ == "__main__":
    main()
