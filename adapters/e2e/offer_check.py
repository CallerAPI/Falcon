#!/usr/bin/env python3
"""Check that adapter INVITEs name an audio offer.

An event with invite_no_sdp fails the run.
An Asterisk, FreeSWITCH, Kamailio, or OpenSIPS event fails the run when
the stored message has no Content-Type application/sdp.
A switch this run started must leave at least one event.
SIP redirect events use a sip/ switch name. They stay out of that list.
The invite_no_sdp check still covers them.
"""

import json
import sys
import urllib.request

SWITCHES = ("asterisk", "freeswitch", "kamailio", "opensips")
OFFER = "content-type: application/sdp"


def failures(events, raw_of, expected):
    no_offer = []
    unnamed = []
    seen = set()
    for event in events:
        switch = event.get("switch")
        if switch in SWITCHES:
            seen.add(switch)
        reasons = event.get("reasons") or []
        if any(reason.get("code") == "invite_no_sdp" for reason in reasons):
            no_offer.append(event["id"])
        if switch in SWITCHES and OFFER not in (raw_of(event["id"]) or "").lower():
            unnamed.append(event["id"])
    missing = [name for name in expected if name not in seen]
    return no_offer, unnamed, missing


def self_test():
    def raw(mapping):
        return lambda event_id: mapping.get(event_id, "")

    sdp = "INVITE sip:x SIP/2.0\nContent-Type: application/sdp\n\n"
    bare = "INVITE sip:x SIP/2.0\n\n"
    asterisk_only = [
        {"id": 1, "switch": "sip/127.0.0.1", "reasons": []},
        {"id": 2, "switch": "asterisk", "reasons": []},
        {"id": 3, "switch": "asterisk", "reasons": []},
    ]
    bodies = {1: sdp, 2: sdp, 3: sdp}
    assert failures(asterisk_only, raw(bodies), ["asterisk"]) == ([], [], [])

    bodies[3] = bare
    no_offer, unnamed, missing = failures(asterisk_only, raw(bodies), ["asterisk"])
    assert unnamed == [3] and no_offer == [] and missing == [], (no_offer, unnamed, missing)

    no_offer, unnamed, missing = failures(asterisk_only, raw({1: sdp, 2: sdp, 3: sdp}), ["kamailio"])
    assert missing == ["kamailio"] and unnamed == [] and no_offer == [], (no_offer, unnamed, missing)

    mixed = [
        {"id": 4, "switch": "asterisk", "reasons": []},
        {"id": 5, "switch": "kamailio", "reasons": [{"code": "denylist"}]},
    ]
    no_offer, unnamed, missing = failures(mixed, raw({4: sdp, 5: bare}), ["asterisk", "kamailio"])
    assert unnamed == [5] and missing == [] and no_offer == [], (no_offer, unnamed, missing)

    poisoned = [
        {"id": 6, "switch": "sip/127.0.0.1", "reasons": [{"code": "invite_no_sdp"}]},
        {"id": 7, "switch": "freeswitch", "reasons": []},
        {"id": 8, "switch": "opensips", "reasons": []},
    ]
    no_offer, unnamed, missing = failures(
        poisoned, raw({6: "", 7: sdp, 8: sdp}), ["freeswitch", "opensips"]
    )
    assert no_offer == [6] and unnamed == [] and missing == [], (no_offer, unnamed, missing)

    only_redirect = [{"id": 9, "switch": "sip/10.0.0.1", "reasons": []}]
    no_offer, unnamed, missing = failures(only_redirect, raw({9: sdp}), ["kamailio", "opensips"])
    assert missing == ["kamailio", "opensips"] and no_offer == [] and unnamed == [], (
        no_offer,
        unnamed,
        missing,
    )
    print("offer self-test: PASS")


def live(port, token, expected):
    def get(path):
        req = urllib.request.Request(
            "http://127.0.0.1:%s%s" % (port, path),
            headers={"X-Falcon-Token": token},
        )
        return json.load(urllib.request.urlopen(req))

    events = get("/v1/events?limit=500")["data"]

    def raw_of(event_id):
        return get("/v1/events/%s" % event_id).get("raw_sip") or ""

    no_offer, unnamed, missing = failures(events, raw_of, expected)
    adapters = [event for event in events if event.get("switch") in SWITCHES]
    print(
        "events=%d adapter_events=%d invite_no_sdp=%s no_content_type=%s missing=%s"
        % (len(events), len(adapters), no_offer, unnamed, missing)
    )
    if no_offer or unnamed or missing:
        print("offer: FAIL")
        return 1
    print("offer: PASS")
    return 0


def parse_expected(text):
    expected = []
    for name in text.split(","):
        name = name.strip()
        if name and name not in expected:
            expected.append(name)
    return expected


def main(argv):
    if len(argv) == 2 and argv[1] == "--self-test":
        self_test()
        return 0
    if len(argv) != 4:
        print(
            "usage: offer_check.py --self-test | offer_check.py <port> <token> <switches>",
            file=sys.stderr,
        )
        return 2
    return live(argv[1], argv[2], parse_expected(argv[3]))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
