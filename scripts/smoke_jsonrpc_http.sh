#!/usr/bin/env bash
#
# On-device smoke test for the local HTTP JSON-RPC transport added in
# feat/jsonrpc-non-webrtc-transport. Run it against a JetKVM reachable on the
# LAN after deploying the patched app. It never opens a WebRTC session, so you
# can keep a browser console open to the same device while it runs and confirm
# the session is NOT taken over.
#
# Usage:
#   scripts/smoke_jsonrpc_http.sh <device-ip> [password]
#
# With no password the device must be in noPassword local-auth mode. With a
# password, the script logs in at /auth/login-local and reuses the session
# cookie — exactly the flow nana's client uses.
set -euo pipefail

HOST="${1:?usage: smoke_jsonrpc_http.sh <device-ip> [password]}"
PASSWORD="${2:-}"
BASE="http://${HOST}"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

curl_json() { curl -sS --max-time 15 -b "$JAR" -c "$JAR" "$@"; }

# rpc <method> [params-json]  ->  prints the JSON-RPC response
rpc() {
  local method="$1" params="${2:-{}}"
  curl_json -X POST "${BASE}/jsonrpc" \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"${method}\",\"params\":${params}}"
}

echo "== device: ${HOST} =="

if [ -n "$PASSWORD" ]; then
  echo "-- login (/auth/login-local) --"
  code=$(curl_json -o /dev/null -w '%{http_code}' -X POST "${BASE}/auth/login-local" \
    -H 'Content-Type: application/json' -d "{\"password\":\"${PASSWORD}\"}")
  [ "$code" = "200" ] || { echo "login failed (HTTP $code)"; exit 1; }
  echo "ok"
fi

echo "-- unauthenticated call is rejected --"
code=$(curl -sS --max-time 15 -o /dev/null -w '%{http_code}' -X POST "${BASE}/jsonrpc" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}')
if [ -n "$PASSWORD" ]; then
  # 401 (rejected) is the pass condition; a fresh jar carries no cookie.
  [ "$code" = "401" ] && echo "ok (401)" || echo "WARN: expected 401, got $code"
else
  echo "n/a (noPassword mode)"
fi

echo "-- ping --"
rpc ping; echo
echo "-- getDeviceID --"
rpc getDeviceID; echo
echo "-- getActiveExtension (power extension probe) --"
rpc getActiveExtension; echo
echo "-- getUSBState / getVideoState (boot-macro readiness signals) --"
rpc getUSBState; echo
rpc getVideoState; echo
echo "-- method-not-found returns a JSON-RPC error (code -32601) --"
rpc thisMethodDoesNotExist; echo

echo
echo "Done. If the calls above returned results (not timeouts) and any open"
echo "browser console stayed connected, the non-WebRTC transport works."
