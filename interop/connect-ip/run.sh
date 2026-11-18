#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 mp0rta
#
# CONNECT-IP cells against connect-ip-go (docs/interop.md, CONNECT-IP section).
#
#   interop/connect-ip/run.sh   (interop/run.sh calls it after its own cells)
#
# Needs the h3wire-interop-h3wire image (interop/run.sh builds it), Docker with NET_ADMIN
# and /dev/net/tun. Clones connect-ip-go at the pinned commit into
# target/interop/connect-ip-go, applies connect-ip-go.patch, builds its integration/
# programs in $GO_IMAGE and their images, and runs each cell with upstream's
# docker-compose.yml plus our overrides (common.yml for every cell, h3wire-proxy.yml and
# h3wire-client.yml to put our examples in place of upstream's proxy or client). A cell
# passes when the client exits 0; an address-request cell also needs the client's
# `address-request: ok` line. Logs: target/interop/out/connect-ip-<cell>.log. Appends a
# CONNECT-IP section to target/interop-report.md and exits non-zero on a failed cell.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
here=$root/interop/connect-ip
cd "$root"
# shellcheck source=interop/versions.env
. interop/versions.env

W=$root/target/interop
C=$W/connect-ip-go
I=$C/integration
P=h3wire-connect-ip
U="$(id -u):$(id -g)"
mkdir -p "$W/out"
rm -rf "$C"
git -c advice.detachedHead=false clone -q --depth 1 --branch "$CONNECT_IP_GO_TAG" https://github.com/quic-go/connect-ip-go "$C"
if [ "$(git -C "$C" rev-parse HEAD)" != "$CONNECT_IP_GO_COMMIT" ]; then
    echo "connect-ip-go $CONNECT_IP_GO_TAG is not $CONNECT_IP_GO_COMMIT" >&2
    exit 1
fi
git -C "$C" apply "$here/connect-ip-go.patch"

# No Go on the host: build in $GO_IMAGE, with the module and build caches kept between runs.
cache=$root/target/connect-ip-go-cache
mkdir -p "$cache"
docker run --rm --user "$U" -v "$C:/src" -v "$cache:/cache" -w /src/integration \
    -e HOME=/tmp -e GOCACHE=/cache/build -e GOMODCACHE=/cache/mod -e GOFLAGS=-modcacherw \
    -e GOTOOLCHAIN=local -e CGO_ENABLED=0 -e GOOS=linux "$GO_IMAGE" sh -ec '
        go build -o proxy/proxy ./proxy
        go build -o client/client ./client
        go build -o server/server ./server
        # rustls refuses the Makefile'\''s CN-only proxy certificate; this one is
        # interop/run.sh'\''s recipe. The server keeps the Makefile'\''s own.
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 7 \
            -subj /CN=proxy -addext subjectAltName=DNS:proxy \
            -addext basicConstraints=critical,CA:FALSE \
            -keyout proxy/key.pem -out proxy/cert.pem 2>/dev/null
        openssl req -new -x509 -newkey Ed25519 -keyout server/key.pem -out server/cert.pem \
            -days 365 -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=server" -nodes \
            2>/dev/null'

compose() { docker compose -p "$P" --project-directory "$I" -f "$I/docker-compose.yml" "$@"; }
down() { compose --env-file "$I/ipv4.env" down --timeout 1 >/dev/null 2>&1 || true; }
trap down EXIT
(cd "$I" && TESTCASE=build compose --env-file ipv4.env build)

rows=()
failed=0
# cell <direction> <ipv4|ipv6> <ping|http> [<REQUEST_ADDRS>]
cell() {
    local dir=$1 fam=$2 tc=$3 req=${4:-} files=(-f "$here/common.yml") cap peer=connect-ip-go
    local version="connect-ip-go $CONNECT_IP_GO_TAG"
    case $dir in
    h3wire-\>peer) files+=(-f "$here/h3wire-client.yml") ;;
    peer-\>h3wire) files+=(-f "$here/h3wire-proxy.yml") ;;
    h3wire-\>h3wire) files+=(-f "$here/h3wire-proxy.yml" -f "$here/h3wire-client.yml")
        peer=h3wire version=- ;;
    esac
    cap="CONNECT-IP $tc ($fam)"
    if [ -n "$req" ]; then cap="CONNECT-IP ADDRESS_REQUEST ($fam)"; fi
    local id
    id=connect-ip-$(printf '%s-%s' "$cap" "$dir" | tr -cs 'A-Za-z0-9' '-' | sed 's/-$//')
    local log=$W/out/$id.log t0=$SECONDS result=fail
    down
    if FILTER_IP_PROTOCOL=0 TESTCASE=$tc REQUEST_ADDRS=$req timeout 180 \
        docker compose -p "$P" --project-directory "$I" --env-file "$I/$fam.env" \
        -f "$I/docker-compose.yml" "${files[@]}" up --no-build --exit-code-from client \
        >"$log" 2>&1 \
        && { [ -z "$req" ] || grep -qE '^client +\| address-request: ok ids=' "$log"; }; then
        result=pass
    else
        failed=$((failed + 1))
    fi
    down
    echo "$result: $cap, $peer, $dir"
    rows+=("| $cap | $peer | $version | $dir | $result | $((SECONDS - t0)) |")
}

cell h3wire-\>h3wire ipv4 ping
for dir in h3wire-\>peer peer-\>h3wire; do
    for fam in ipv4 ipv6; do
        cell "$dir" "$fam" ping
        cell "$dir" "$fam" http
    done
done
for dir in h3wire-\>peer peer-\>h3wire; do
    cell "$dir" ipv4 ping 194.166.0.10/32,194.166.0.11/32
    cell "$dir" ipv6 ping 2001:db8:1::10/128,2001:db8:1::11/128
done
for dir in h3wire-\>peer peer-\>h3wire; do
    rows+=("| CONNECT-IP (capsule) | connect-ip-go | connect-ip-go $CONNECT_IP_GO_TAG | $dir | unsupported | - |")
done

{
    echo
    echo "## CONNECT-IP"
    echo
    echo "connect-ip-go $CONNECT_IP_GO_TAG ($CONNECT_IP_GO_COMMIT), integration/ harness with interop/connect-ip/connect-ip-go.patch."
    echo
    echo "| capability | peer | version | direction | result | seconds |"
    echo "|---|---|---|---|---|---|"
    printf '%s\n' "${rows[@]}"
    echo
    echo "Mandatory failures: $failed. Logs: \`target/interop/out/connect-ip-<cell>.log\`."
} >>"$root/target/interop-report.md"
[ "$failed" = 0 ]
