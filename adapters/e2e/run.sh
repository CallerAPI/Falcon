#!/usr/bin/env bash
# Adapter end-to-end tests. Starts a Falcon with a token, one deny rule,
# and the SIP redirect listener, plus a second Falcon in bridge mode, then
# drives each adapter against them. Host parts need python3, curl, lua5.4,
# and Go. The Kamailio and OpenSIPS parts need Docker and run only when
# KAMAILIO_IMAGE or OPENSIPS_IMAGE is set.
set -euo pipefail
cd "$(dirname "$0")/../.."

PORT="${FALCON_E2E_PORT:-8090}"
SIP_PORT="${FALCON_E2E_SIP_PORT:-5062}"
BRIDGE_PORT="${FALCON_E2E_BRIDGE_PORT:-8091}"
BRIDGE_SIP_PORT="${FALCON_E2E_BRIDGE_SIP_PORT:-5064}"
TOKEN="e2e-token"
DENY="+13125550188"
CLEAN="+13125550199"
DB="$(mktemp -d)/e2e.db"
BRIDGE_DB="$(mktemp -d)/bridge.db"
export FALCON_TOKEN="$TOKEN"

# A Falcon build carries its release. VERSION defaults to the latest public tag.
VERSION="${VERSION:-$(git ls-remote --tags --refs --sort=-v:refname https://github.com/CallerAPI/Falcon.git 'v*' 2>/dev/null | head -1 | sed 's#.*refs/tags/v##')}"
if [ -z "$VERSION" ] || [ "$VERSION" = "dev" ]; then
  echo "set VERSION to the release, for example VERSION=0.9.32"
  exit 1
fi
go build -ldflags "-X main.version=$VERSION" -o /tmp/falcon-e2e ./cmd/falcon
go build -o /tmp/sipsend ./adapters/e2e/sipsend
FALCON_LISTEN="127.0.0.1:${PORT}" FALCON_SIP_LISTEN="127.0.0.1:${SIP_PORT}" FALCON_DB_PATH="$DB" \
  FALCON_SHAKEN=false FALCON_SHARE=false FALCON_REPUTATION=false FALCON_TOKEN="$TOKEN" \
  /tmp/falcon-e2e >/tmp/falcon-e2e.log 2>&1 &
FALCON_PID=$!
FALCON_LISTEN="127.0.0.1:${BRIDGE_PORT}" FALCON_SIP_LISTEN="127.0.0.1:${BRIDGE_SIP_PORT}" FALCON_SIP_MODE=bridge \
  FALCON_DB_PATH="$BRIDGE_DB" FALCON_SHAKEN=false FALCON_SHARE=false FALCON_REPUTATION=false FALCON_TOKEN="$TOKEN" \
  /tmp/falcon-e2e >/tmp/falcon-e2e-bridge.log 2>&1 &
BRIDGE_PID=$!
cleanup() {
  kill "$FALCON_PID" "$BRIDGE_PID" 2>/dev/null || true
  docker rm -f falcon-e2e-kamailio falcon-e2e-opensips falcon-e2e-asterisk falcon-e2e-freeswitch >/dev/null 2>&1 || true
}
trap cleanup EXIT
for port in "$PORT" "$BRIDGE_PORT"; do
  for _ in $(seq 1 30); do
    curl -sf "http://127.0.0.1:${port}/v1/health" >/dev/null && break
    sleep 0.5
  done
  curl -sf -X POST -H 'Content-Type: application/json' -H "X-Falcon-Token: $TOKEN" \
    -d "{\"kind\":\"deny\",\"subject\":\"number\",\"value\":\"${DENY}\",\"note\":\"e2e\"}" \
    "http://127.0.0.1:${port}/v1/rules" >/dev/null
done

fail=0
# The AGI harness always screens as Asterisk. Each later switch appends its
# name. The offer check requires one event for every name in this list.
offer_switches="asterisk"
add_offer_switch() {
  case ",${offer_switches}," in
    *",$1,"*) ;;
    *) offer_switches="${offer_switches},$1" ;;
  esac
}

echo "== sip redirect (udp ${SIP_PORT})"
set +e
denied=$(/tmp/sipsend -to "127.0.0.1:${SIP_PORT}" -from "$DENY")
allowed=$(/tmp/sipsend -to "127.0.0.1:${SIP_PORT}" -from "$CLEAN")
set -e
echo "denied=${denied} allowed=${allowed}"
if [ "$denied" = "603" ] && [ "$allowed" = "302" ]; then
  echo "sip redirect: PASS"
else
  echo "sip redirect: FAIL"; fail=1
fi

# The bridge rejects a denied caller with 603 and fails a clean call with
# 503 before any answer, so the switch routes it to the next vendor.
echo "== sip bridge (udp ${BRIDGE_SIP_PORT})"
set +e
denied=$(/tmp/sipsend -to "127.0.0.1:${BRIDGE_SIP_PORT}" -from "$DENY")
allowed=$(/tmp/sipsend -to "127.0.0.1:${BRIDGE_SIP_PORT}" -from "$CLEAN")
set -e
echo "denied=${denied} allowed=${allowed}"
if [ "$denied" = "603" ] && [ "$allowed" = "503" ]; then
  echo "sip bridge: PASS"
else
  echo "sip bridge: FAIL"; fail=1
  tail -n 40 /tmp/falcon-e2e-bridge.log
fi

echo "== asterisk agi"
python3 adapters/e2e/agi_harness.py "http://127.0.0.1:${PORT}/v1/screen" "$DENY" "$CLEAN" || fail=1

echo "== freeswitch lua"
if command -v lua5.4 >/dev/null; then
  lua5.4 adapters/e2e/fs_harness.lua "http://127.0.0.1:${PORT}/v1/screen" "$DENY" "$CLEAN" || fail=1
  add_offer_switch freeswitch
else
  echo "lua5.4 not installed, skipped"
fi

# Docker on Linux shares the host network, so the proxy reaches Falcon on
# 127.0.0.1 and sipsend reaches the proxy on 127.0.0.1:5060. Docker Desktop
# on macOS does not, so the proxy port is published and the proxy calls
# Falcon through host.docker.internal.
if [ "$(uname -s)" = "Linux" ]; then
  DOCKER_NET=(--network host)
  FALCON_IN_CONTAINER="http://127.0.0.1:${PORT}/v1/screen"
else
  DOCKER_NET=(-p 5060:5060/udp)
  FALCON_IN_CONTAINER="http://host.docker.internal:${PORT}/v1/screen"
fi
E2E_TMP="$(mktemp -d)"
for f in kamailio kamailio_async opensips opensips_async; do
  sed "s#http://127.0.0.1:8090/v1/screen#${FALCON_IN_CONTAINER}#" "adapters/e2e/$f.cfg" >"$E2E_TMP/$f.cfg"
done

# wait_udp <container> waits for the proxy to answer OPTIONS on 5060.
wait_udp() {
  for _ in $(seq 1 60); do
    if docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null | grep -q true; then
      if /tmp/sipsend -to 127.0.0.1:5060 -from "+10000000000" -method OPTIONS -wait 1s >/dev/null 2>&1; then
        return 0
      fi
    fi
    sleep 0.5
  done
  return 1
}

# proxy_check <label> <container> runs the deny and clean INVITEs.
proxy_check() {
  set +e
  denied=$(/tmp/sipsend -to 127.0.0.1:5060 -from "$DENY"); deny_rc=$?
  allowed=$(/tmp/sipsend -to 127.0.0.1:5060 -from "$CLEAN"); allow_rc=$?
  set -e
  echo "denied=${denied} allowed=${allowed}"
  if [ "$deny_rc" -ne 0 ] || [ "$allow_rc" -ne 0 ] || [ "$denied" != "603" ] || [ "$allowed" != "404" ]; then
    echo "$1 adapter: FAIL"; fail=1
    docker logs "$2" 2>&1 | tail -n 80
  else
    echo "$1 adapter: PASS"
  fi
  docker rm -f "$2" >/dev/null 2>&1 || true
}

# kamailio_case <label> <e2e cfg> <adapter cfg>
kamailio_case() {
  echo "== kamailio $1 ${KAMAILIO_IMAGE}"
  docker rm -f falcon-e2e-kamailio >/dev/null 2>&1 || true
  # kamailio-ci ENTRYPOINT is already "kamailio -DD -E".
  docker run -d --name falcon-e2e-kamailio "${DOCKER_NET[@]}" \
    -v "$E2E_TMP/$2.cfg:/etc/kamailio/kamailio.cfg:ro" \
    -v "$PWD/adapters/kamailio/$3.cfg:/etc/kamailio/$3.cfg:ro" \
    "$KAMAILIO_IMAGE" -f /etc/kamailio/kamailio.cfg >/dev/null
  wait_udp falcon-e2e-kamailio || true
  proxy_check "kamailio $1" falcon-e2e-kamailio
}

# opensips_case <label> <e2e cfg> <adapter cfg>
opensips_case() {
  echo "== opensips $1 ${OPENSIPS_IMAGE}"
  docker rm -f falcon-e2e-opensips >/dev/null 2>&1 || true
  # The published image carries the core only. rest_client and json are
  # separate Debian packages from the same repository.
  docker run -d --name falcon-e2e-opensips "${DOCKER_NET[@]}" --entrypoint sh \
    -v "$E2E_TMP/$2.cfg:/etc/opensips/opensips.cfg:ro" \
    -v "$PWD/adapters/opensips/$3.cfg:/etc/opensips/falcon.cfg:ro" \
    "$OPENSIPS_IMAGE" -c 'apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq opensips-restclient-module opensips-json-module >/dev/null && exec /usr/sbin/opensips -F -f /etc/opensips/opensips.cfg' >/dev/null
  wait_udp falcon-e2e-opensips || true
  proxy_check "opensips $1" falcon-e2e-opensips
}

# switch_check <label> <container> <port> <deny code> <allow code>
switch_check() {
  set +e
  denied=$(/tmp/sipsend -to "127.0.0.1:$3" -from "$DENY" -wait 8s); deny_rc=$?
  allowed=$(/tmp/sipsend -to "127.0.0.1:$3" -from "$CLEAN" -wait 8s); allow_rc=$?
  set -e
  echo "denied=${denied} allowed=${allowed}"
  if [ "$deny_rc" -ne 0 ] || [ "$allow_rc" -ne 0 ] || [ "$denied" != "$4" ] || [ "$allowed" != "$5" ]; then
    echo "$1 adapter: FAIL"; fail=1
    docker logs "$2" 2>&1 | tail -n 60
  else
    echo "$1 adapter: PASS"
  fi
  docker rm -f "$2" >/dev/null 2>&1 || true
}

# wait_port <container> <port> waits until an INVITE gets a real answer.
# A switch answers OPTIONS before its dialplan and script modules are up,
# and answers 503 in between, so OPTIONS alone is not enough.
wait_port() {
  for _ in $(seq 1 90); do
    if docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null | grep -q true; then
      code=$(/tmp/sipsend -to "127.0.0.1:$2" -from "+10000000001" -wait 2s 2>/dev/null || true)
      case "$code" in
        ""|503|480) ;;
        *) return 0 ;;
      esac
    fi
    sleep 1
  done
  return 1
}

if [ "$(uname -s)" = "Linux" ]; then
  FS_NET=(--network host); AST_NET=(--network host); FS_SIP_IP=127.0.0.1
else
  FS_NET=(-p 5080:5080/udp); AST_NET=(-p 5060:5060/udp); FS_SIP_IP=0.0.0.0
fi
mkdir -p "$E2E_TMP/freeswitch"
sed "s#FALCON_E2E_SIP_IP#${FS_SIP_IP}#" adapters/e2e/freeswitch/freeswitch.xml >"$E2E_TMP/freeswitch/freeswitch.xml"

# outcome_check <label> <cause>... passes when Falcon holds an outcome with
# each hangup cause. Only a hangup handler that ran falcon_hangup.agi
# posts one.
outcome_check() {
  label=$1; shift
  for _ in $(seq 1 20); do
    if curl -sf -H "X-Falcon-Token: $TOKEN" "http://127.0.0.1:${PORT}/v1/events?limit=200" \
      | python3 -c 'import json,sys; got={e.get("hangup_cause") for e in json.load(sys.stdin)["data"]}; sys.exit(0 if set(sys.argv[1:])<=got else 1)' "$@"; then
      echo "$label outcome: PASS"
      return 0
    fi
    sleep 0.5
  done
  echo "$label outcome: FAIL (no outcome with causes $*)"; fail=1
}

# Real Asterisk from adapters/e2e/asterisk/Dockerfile. A reject hangs up
# with cause 21, which is 403 on the wire. An allowed call lands in
# falcon-allowed-inbound and hangs up with cause 22, which is 410. The
# hangup handler reports both outcomes to Falcon.
if [ "${ASTERISK_E2E:-}" = "1" ]; then
  echo "== asterisk (real, Alpine package)"
  docker build -q -t falcon-e2e-asterisk adapters/e2e/asterisk >/dev/null
  docker rm -f falcon-e2e-asterisk >/dev/null 2>&1 || true
  docker run -d --name falcon-e2e-asterisk "${AST_NET[@]}" \
    -e FALCON_URL="${FALCON_IN_CONTAINER}" -e FALCON_TOKEN="$TOKEN" \
    -v "$PWD/adapters/asterisk/extensions.conf:/etc/asterisk/falcon-extensions.conf:ro" \
    -v "$PWD/adapters/asterisk/falcon.agi:/var/lib/asterisk/agi-bin/falcon.agi:ro" \
    -v "$PWD/adapters/asterisk/falcon_hangup.agi:/var/lib/asterisk/agi-bin/falcon_hangup.agi:ro" \
    falcon-e2e-asterisk >/dev/null
  wait_port falcon-e2e-asterisk 5060 || true
  switch_check "asterisk real" falcon-e2e-asterisk 5060 403 410
  outcome_check "asterisk real" 21 22
fi

# Real FreeSWITCH with mod_curl and mod_lua. A reject hangs up with
# CALL_REJECTED, which sofia sends as 603. An allowed call gets 404 from
# the test dialplan.
if [ -n "${FREESWITCH_IMAGE:-}" ]; then
  echo "== freeswitch (real) ${FREESWITCH_IMAGE}"
  docker rm -f falcon-e2e-freeswitch >/dev/null 2>&1 || true
  docker run -d --name falcon-e2e-freeswitch "${FS_NET[@]}" \
    -e FALCON_URL="${FALCON_IN_CONTAINER}" -e FALCON_TOKEN="$TOKEN" \
    -v "$E2E_TMP/freeswitch:/etc/freeswitch:ro" \
    -v "$PWD/adapters/freeswitch/falcon.lua:/usr/share/freeswitch/scripts/falcon.lua:ro" \
    -v "$PWD/adapters/freeswitch/falcon_hangup.lua:/usr/share/freeswitch/scripts/falcon_hangup.lua:ro" \
    --entrypoint freeswitch "$FREESWITCH_IMAGE" -nonat -nf -nc -conf /etc/freeswitch -log /tmp -db /tmp -run /tmp >/dev/null
  wait_port falcon-e2e-freeswitch 5080 || true
  switch_check "freeswitch real" falcon-e2e-freeswitch 5080 603 404
  add_offer_switch freeswitch
fi

if [ -n "${KAMAILIO_IMAGE:-}" ]; then
  kamailio_case sync kamailio falcon
  kamailio_case async kamailio_async falcon_async
  add_offer_switch kamailio
fi

if [ -n "${OPENSIPS_IMAGE:-}" ]; then
  opensips_case sync opensips falcon
  opensips_case async opensips_async falcon_async
  add_offer_switch opensips
fi

# Every INVITE in this run carries an offer. No event may say it has none.
# Every Asterisk, FreeSWITCH, Kamailio, and OpenSIPS event must name
# Content-Type. A switch this run started must leave at least one event.
echo "== offer"
python3 adapters/e2e/offer_check.py --self-test || fail=1
python3 adapters/e2e/offer_check.py "$PORT" "$TOKEN" "$offer_switches" || fail=1

if [ "$fail" -ne 0 ]; then
  echo "adapters: FAIL"
  tail -n 40 /tmp/falcon-e2e.log
  exit 1
fi
echo "adapters: PASS"
