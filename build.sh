#!/bin/sh
# OpenWRT Declarative Image Builder
# https://github.com/gucci-on-fleek/openwrt-builder-template
# SPDX-License-Identifier: MPL-2.0+
# SPDX-FileCopyrightText: 2024 Max Chernoff

set -eu
cd "$(dirname "$0")"

podman system service --time=0 &

for f in *.conf.toml; do
    podman unshare ./build.py "$f"
done
