#!/usr/bin/env bash
# OpenWRT Declarative Image Builder
# https://github.com/gucci-on-fleek/openwrt-builder-template
# SPDX-License-Identifier: MPL-2.0+
# SPDX-FileCopyrightText: 2025 Max Chernoff
set -euo pipefail
cd "$(dirname "$0")"

podman system service --time=0 & disown

for f in *.conf.toml; do
    podman unshare ./build.py "$f" &
done

wait
