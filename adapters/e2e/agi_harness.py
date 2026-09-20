#!/usr/bin/env python3
"""Drive adapters/asterisk/falcon.agi the way Asterisk does, against a live
Falcon. Feeds the AGI environment, answers its GET VARIABLE requests, and
records the SET VARIABLE lines it emits. Exit status is non-zero on any
mismatch. Usage: agi_harness.py <falcon_url> <deny_number> <clean_number>
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
AGI = os.path.join(HERE, "..", "asterisk", "falcon.agi")


def run(falcon_url, caller, callee):
    variables = {
        "EXTEN": callee,
        "CHANNEL(pjsip,remote_addr)": "203.0.113.9:5060",
        "PJSIP_HEADER(read,From)": '<sip:%s@203.0.113.9>;tag=a1' % caller,
        "PJSIP_HEADER(read,To)": "<sip:%s@carrier.example>" % callee,
        "PJSIP_HEADER(read,Call-ID)": "agi-e2e-%s@203.0.113.9" % caller,
        "PJSIP_HEADER(read,User-Agent)": "e2e-harness/1.0",
        "PJSIP_HEADER(read,Contact)": "<sip:%s@203.0.113.9>" % caller,
        "PJSIP_HEADER(read,Max-Forwards)": "70",
    }
    env = dict(os.environ, FALCON_URL=falcon_url)
    p = subprocess.Popen([sys.executable, AGI], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env, bufsize=1)
    p.stdin.write("agi_request: falcon.agi\nagi_channel: PJSIP/trunk-0001\nagi_callerid: %s\nagi_extension: %s\n\n" % (caller, callee))
    p.stdin.flush()
    sets = {}
    while True:
        line = p.stdout.readline()
        if not line:
            break
        line = line.strip()
        if line.startswith("GET VARIABLE "):
            name = line[len("GET VARIABLE "):].strip().strip('"')
            value = variables.get(name, "")
            p.stdin.write("200 result=1 (%s)\n" % value if value else "200 result=0\n")
            p.stdin.flush()
        elif line.startswith("SET VARIABLE "):
            rest = line[len("SET VARIABLE "):]
            name, _, value = rest.partition(" ")
            sets[name] = value.strip().strip('"')
            p.stdin.write("200 result=1\n")
            p.stdin.flush()
        else:
            p.stdin.write("200 result=1\n")
            p.stdin.flush()
    p.wait(timeout=10)
    return sets


def main():
    url, deny, clean = sys.argv[1], sys.argv[2], sys.argv[3]
    denied = run(url, deny, "+14155550100")
    allowed = run(url, clean, "+14155550100")
    print("denied:", denied)
    print("allowed:", allowed)
    ok = denied.get("FALCON_ACTION") == "reject" and allowed.get("FALCON_ACTION") == "allow"
    ok = ok and "denylist" in denied.get("FALCON_REASONS", "")
    print("asterisk agi adapter:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
