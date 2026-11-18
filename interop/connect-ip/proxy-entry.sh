#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 mp0rta
#
# Entry point of h3wire-ip-proxy in connect-ip-go's integration harness
# (interop/connect-ip/h3wire-proxy.yml). As upstream's proxy/run.sh, it drops direct
# forwarding between the two Docker interfaces in both families, so the only path from
# the client net to the server net is the tunnel, and a passing cell proves it.
set -e
for t in iptables ip6tables; do
    "$t" -A FORWARD -i eth0 -o eth1 -j DROP
    "$t" -A FORWARD -i eth1 -o eth0 -j DROP
done
exec h3wire-ip-proxy
