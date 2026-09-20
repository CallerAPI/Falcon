#!/usr/bin/env bash
# Adapter end-to-end tests. Starts a Falcon with a token, one deny rule,
# and the SIP redirect listener, then drives each adapter against it.
# Host parts need python3, curl, lua5.4, node, and Go. The Kamailio and
# OpenSIPS parts need Docker and run only when KAMAILIO_IMAGE or
# OPENSIPS_IMAGE is set.
set -euo pipefail
cd "$(dirname "$0")/../.."

PORT="${FALCON_E2E_PORT:-8090}"
SIP_PORT="${FALCON_E2E_SIP_PORT:-5062}"
TOKEN="e2e-token"
DENY="+13125550188"
CLEAN="+13125550199"
DB="$(mktemp -d)/e2e.db"
export FALCON_TOKEN="$TOKEN"

go build -o /tmp/falcon-e2e ./cmd/falcon
go build -o /tmp/sipsend ./adapters/e2e/sipsend
FALCON_LISTEN="127.0.0.1:${PORT}" FALCON_SIP_LISTEN="127.0.0.1:${SIP_PORT}" FALCON_DB_PATH="$DB" \
  FALCON_SHAKEN=false FALCON_SHARE=false FALCON_REPUTATION=false FALCON_TOKEN="$TOKEN" \
  /tmp/falcon-e2e >/tmp/falcon-e2e.log 2>&1 &
FALCON_PID=$!
cleanup() {
  kill "$FALCON_PID" 2>/dev/null || true
  docker rm -f falcon-e2e-kamailio falcon-e2e-opensips >/dev/null 2>&1 || true
}
trap cleanup EXIT
for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:${PORT}/v1/health" >/dev/null && break
  sleep 0.5
done
curl -sf -X POST -H 'Content-Type: application/json' -H "X-Falcon-Token: $TOKEN" \
  -d "{\"kind\":\"deny\",\"subject\":\"number\",\"value\":\"${DENY}\",\"note\":\"e2e\"}" \
  "http://127.0.0.1:${PORT}/v1/rules" >/dev/null

fail=0

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

echo "== asterisk agi"
python3 adapters/e2e/agi_harness.py "http://127.0.0.1:${PORT}/v1/screen" "$DENY" "$CLEAN" || fail=1

echo "== freeswitch lua"
if command -v lua5.4 >/dev/null; then
  lua5.4 adapters/e2e/fs_harness.lua "http://127.0.0.1:${PORT}/v1/screen" "$DENY" "$CLEAN" || fail=1
else
  echo "lua5.4 not installed, skipped"
fi

echo "== connexcs scriptforge"
if command -v node >/dev/null; then
  node adapters/e2e/connexcs_harness.js "http://127.0.0.1:${PORT}/v1/screen" "$DENY" "$CLEAN" || fail=1
else
  echo "node not installed, skipped"
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
sed "s#http://127.0.0.1:8090/v1/screen#${FALCON_IN_CONTAINER}#" adapters/e2e/kamailio.cfg >"$E2E_TMP/kamailio.cfg"
sed "s#http://127.0.0.1:8090/v1/screen#${FALCON_IN_CONTAINER}#" adapters/e2e/opensips.cfg >"$E2E_TMP/opensips.cfg"

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

if [ -n "${KAMAILIO_IMAGE:-}" ]; then
  echo "== kamailio ${KAMAILIO_IMAGE}"
  docker rm -f falcon-e2e-kamailio >/dev/null 2>&1 || true
  # kamailio-ci ENTRYPOINT is already "kamailio -DD -E".
  docker run -d --name falcon-e2e-kamailio "${DOCKER_NET[@]}" \
    -v "$E2E_TMP/kamailio.cfg:/etc/kamailio/kamailio.cfg:ro" \
    -v "$PWD/adapters/kamailio/falcon.cfg:/etc/kamailio/falcon.cfg:ro" \
    "$KAMAILIO_IMAGE" -f /etc/kamailio/kamailio.cfg >/dev/null
  wait_udp falcon-e2e-kamailio || true
  proxy_check kamailio falcon-e2e-kamailio
fi

if [ -n "${OPENSIPS_IMAGE:-}" ]; then
  echo "== opensips ${OPENSIPS_IMAGE}"
  docker rm -f falcon-e2e-opensips >/dev/null 2>&1 || true
  # The published image carries the core only. rest_client and json are
  # separate Debian packages from the same repository.
  docker run -d --name falcon-e2e-opensips "${DOCKER_NET[@]}" --entrypoint sh \
    -v "$E2E_TMP/opensips.cfg:/etc/opensips/opensips.cfg:ro" \
    -v "$PWD/adapters/opensips/falcon.cfg:/etc/opensips/falcon.cfg:ro" \
    "$OPENSIPS_IMAGE" -c 'apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq opensips-restclient-module opensips-json-module >/dev/null && exec /usr/sbin/opensips -F -f /etc/opensips/opensips.cfg' >/dev/null
  wait_udp falcon-e2e-opensips || true
  proxy_check opensips falcon-e2e-opensips
fi

if [ "$fail" -ne 0 ]; then
  echo "adapters: FAIL"
  tail -n 40 /tmp/falcon-e2e.log
  exit 1
fi
echo "adapters: PASS"
