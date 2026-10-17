#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# MVP lab walkthrough (#22), end to end, on one Linux machine with Docker.
# Documented step by step in docs/mvp-walkthrough.md; CI runs this script.
#
# LAB ONLY. Uses the Docker lab runtime (never for a public IP), a local
# registry, the in-memory mock control plane and loopback-only ports.
# Needs: docker with buildx, sudo for one iptables rule, cargo, curl, python3.
set -euo pipefail

ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
cd "$ROOT"
WORK="${WORK:-$(mktemp -d)}"
API=127.0.0.1:8787
NET=foiled-lab
SUBNET=10.86.0.0/24
ENTRY=catalogue/entries/foiled/demo-app/1.0.0.yaml
PIDS=()

log() { printf '\n== %s\n' "$*"; }

diagnose() {
  echo "---- diagnostics" >&2
  docker ps -a --filter label=foiled.decoy >&2
  for c in $(docker ps -aq --filter label=foiled.decoy); do docker logs "$c" 2>&1 | tail -20 >&2; done
  tail -20 "$WORK/hostd.log" >&2 2>/dev/null
  tail -5 "$WORK/mock.log" >&2 2>/dev/null
}

cleanup() {
  local status=$?
  set +e
  [ "$status" -ne 0 ] && diagnose
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  docker ps -aq --filter label=foiled.decoy | xargs -r docker rm -f >/dev/null
  docker rm -f foiled-registry >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  sudo iptables -D DOCKER-USER -s "$SUBNET" -m conntrack --ctstate NEW -j REJECT 2>/dev/null
  git checkout -- "$ENTRY" 2>/dev/null
}
trap cleanup EXIT

api() { # method path [json]
  local args=(-sS -f -X "$1" "http://$API$2" -H "authorization: Bearer $TOKEN")
  if [ $# -ge 3 ]; then args+=(-H "content-type: application/json" -d "$3"); fi
  curl "${args[@]}"
}

wait_for() { # description seconds command...
  local what="$1" secs="$2"; shift 2
  for _ in $(seq 1 "$secs"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "timed out waiting for: $what" >&2
  return 1
}

log "1. Build the demo image and push it to a local registry"
docker run -d --rm --name foiled-registry -p 127.0.0.1:5000:5000 registry:2 >/dev/null
# Same Containerfile and offline build as build/recipes/foiled-demo-app/build.sh,
# loaded into the local image store so it can be pushed to the lab registry.
grep -vE '^[[:space:]]*(#|$)' build/recipes/foiled-demo-app/sources.lock \
  | (cd build/recipes/foiled-demo-app && sha256sum -c -)
docker buildx build --builder default --load --network=none \
  -f build/recipes/foiled-demo-app/Containerfile \
  -t localhost:5000/foiled-demo-app:1.0.0 build/recipes/foiled-demo-app
docker push -q localhost:5000/foiled-demo-app:1.0.0 >/dev/null
IMAGE="$(docker inspect --format '{{index .RepoDigests 0}}' localhost:5000/foiled-demo-app:1.0.0)"
DIGEST="${IMAGE#*@}"
echo "image: $IMAGE"

log "2. Pin the catalogue entry to that digest (working tree only)"
python3 - "$ENTRY" "$IMAGE" <<'PY'
import sys
path, image = sys.argv[1], sys.argv[2]
s = open(path).read()
s = s.replace("  recipe_id: foiled-demo-app\n", f"  recipe_id: foiled-demo-app\n  image: {image}\n", 1)
open(path, "w").write(s)
PY
cargo run -q -p foiled-lint -- .

log "3. Lab network with outbound connections from decoys rejected"
docker network create --subnet "$SUBNET" "$NET" >/dev/null
sudo iptables -I DOCKER-USER -s "$SUBNET" -m conntrack --ctstate NEW -j REJECT

log "4. Start the mock control plane in lab mode"
cargo build -q -p foiled-mock-api -p foiled-hostd
target/debug/foiled-mock-api "$API" --lab-host lab-host-1 >"$WORK/mock.log" 2>&1 &
PIDS+=($!)
wait_for "mock API" 60 grep -q '^token:' "$WORK/mock.log"
TOKEN="$(sed -n 's/^token: //p' "$WORK/mock.log")"
PUBLIC_KEY="$(sed -n 's/^public_key = "\(.*\)"/\1/p' "$WORK/mock.log")"

log "5. Start the host agent with the Docker lab runtime"
cat >"$WORK/hostd.toml" <<EOF
host_id = "lab-host-1"
api_base = "http://$API"
publicly_exposed = false
sandbox_runtime = "docker"
allowlist = ["$DIGEST"]
state_dir = "$WORK/state"
poll_secs = 1
heartbeat_secs = 5

[docker]
network = "$NET"
bind = "127.0.0.1"
writable = ["/tmp", "/srv/demo-app"]

[[trusted_keys]]
id = "lab"
public_key = "$PUBLIC_KEY"
EOF
target/debug/foiled-hostd "$WORK/hostd.toml" >"$WORK/hostd.log" 2>&1 &
PIDS+=($!)

log "6. Launch the demo decoy"
DECOY="$(api POST /v0/decoys '{"catalogue_id":"foiled/demo-app/1.0.0","label":"mvp lab"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["decoy"]["id"])')"
echo "decoy: $DECOY"
healthy() { api GET "/v0/decoys/$DECOY" | grep -q '"state":"healthy"'; }
wait_for "decoy healthy" 90 healthy
wait_for "demo app answering" 30 curl -sf http://127.0.0.1:8080/

log "7. Exploit FOILED-DEMO-0001 (harmless marker file)"
curl -sS -X POST "http://127.0.0.1:8080/api/upload?path=../../../tmp/foiled-lab-marker.txt" \
  -H 'user-agent: foiled-mvp-lab' --data 'lab marker, not a payload'
echo

log "8. Verify the decoy cannot reach the internet"
if docker exec "foiled-$DECOY" python3 -I -c \
  "import socket; socket.create_connection(('192.0.2.1', 80), timeout=5)" 2>/dev/null; then
  echo "FAIL: decoy opened an outbound connection" >&2
  exit 1
fi
echo "outbound connection refused, as required"

log "9. Capture reached the control plane"
has_hook() { api GET /v0/exports/iocs.csv | grep -q FOILED-DEMO-0001; }
wait_for "hook event in the IOC export" 60 has_hook

log "10. Rotate the decoy; capture already shipped stays"
api POST "/v0/decoys/$DECOY:rotate" '{"reason":{"code":"operator_manual","text":"mvp lab rotation"}}' >/dev/null
rotated() { api GET "/v0/decoys/$DECOY" | grep -q '"generation":2'; }
wait_for "rotation to generation 2" 90 rotated
wait_for "rotated decoy healthy" 60 healthy

log "11. Export iocs.csv with bearer auth"
api GET /v0/exports/iocs.csv | tee "$WORK/iocs.csv"
ROWS="$(tail -n +2 "$WORK/iocs.csv" | grep -c . || true)"
if [ "$ROWS" -lt 1 ]; then
  echo "FAIL: empty IOC export" >&2
  exit 1
fi
grep -q FOILED-DEMO-0001 "$WORK/iocs.csv"
echo
echo "MVP lab walkthrough passed: $ROWS source address(es) exported."
