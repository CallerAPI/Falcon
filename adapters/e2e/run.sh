#!/usr/bin/env bash
# Adapter end-to-end tests. Starts a Falcon with one deny rule and drives
# each adapter against it. Host parts need python3, curl, lua5.4, and Go.
# The Kamailio part needs Docker and runs only when KAMAILIO_IMAGE is set.
set -euo pipefail
cd "$(dirname "$0")/../.."

PORT="${FALCON_E2E_PORT:-8090}"
DENY="+13125550188"
CLEAN="+13125550199"
DB="$(mktemp -d)/e2e.db"

go build -o /tmp/falcon-e2e ./cmd/falcon
FALCON_LISTEN="127.0.0.1:${PORT}" FALCON_DB_PATH="$DB" FALCON_SHAKEN=false FALCON_SHARE=false \
  FALCON_REPUTATION=false FALCON_TOKEN="" /tmp/falcon-e2e >/tmp/falcon-e2e.log 2>&1 &
FALCON_PID=$!
trap 'kill $FALCON_PID 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:${PORT}/v1/health" >/dev/null && break
  sleep 0.5
done
curl -sf -X POST -H 'Content-Type: application/json' \
  -d "{\"kind\":\"deny\",\"subject\":\"number\",\"value\":\"${DENY}\",\"note\":\"e2e\"}" \
  "http://127.0.0.1:${PORT}/v1/rules" >/dev/null

echo "== asterisk agi"
python3 adapters/e2e/agi_harness.py "http://127.0.0.1:${PORT}/v1/screen" "$DENY" "$CLEAN"

echo "== freeswitch lua"
if command -v lua5.4 >/dev/null; then
  lua5.4 adapters/e2e/fs_harness.lua "http://127.0.0.1:${PORT}/v1/screen" "$DENY" "$CLEAN"
else
  echo "lua5.4 not installed, skipped"
fi

if [ -n "${KAMAILIO_IMAGE:-}" ]; then
  echo "== kamailio ${KAMAILIO_IMAGE}"
  go build -o /tmp/sipsend ./adapters/e2e/sipsend
  docker rm -f falcon-e2e-kamailio >/dev/null 2>&1 || true
  # kamailio-ci ENTRYPOINT is already "kamailio -DD -E". Extra "kamailio"
  # here made the process exit before it bound UDP/5060.
  docker run -d --name falcon-e2e-kamailio --network host \
    -v "$PWD/adapters/e2e/kamailio.cfg:/etc/kamailio/kamailio.cfg:ro" \
    -v "$PWD/adapters/kamailio/falcon.cfg:/etc/kamailio/falcon.cfg:ro" \
    "$KAMAILIO_IMAGE" -f /etc/kamailio/kamailio.cfg >/dev/null
  trap 'kill $FALCON_PID 2>/dev/null || true; docker rm -f falcon-e2e-kamailio >/dev/null 2>&1 || true' EXIT
  for _ in $(seq 1 20); do
    if docker inspect -f '{{.State.Running}}' falcon-e2e-kamailio 2>/dev/null | grep -q true; then
      break
    fi
    sleep 0.25
  done
  sleep 1
  set +e
  denied=$(/tmp/sipsend -to 127.0.0.1:5060 -from "$DENY")
  deny_rc=$?
  allowed=$(/tmp/sipsend -to 127.0.0.1:5060 -from "$CLEAN")
  allow_rc=$?
  set -e
  echo "denied=${denied} allowed=${allowed}"
  if [ "$deny_rc" -ne 0 ] || [ "$allow_rc" -ne 0 ] || [ "$denied" != "603" ] || [ "$allowed" != "404" ]; then
    echo "kamailio adapter: FAIL"
    docker logs falcon-e2e-kamailio | tail -n 80
    exit 1
  fi
  echo "kamailio adapter: PASS"
fi
