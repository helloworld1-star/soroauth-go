#!/usr/bin/env bash
# Runs once when the container is created: warms the module and package caches
# so `make` and `make vectors` do not start by downloading.
set -euo pipefail

cd "$(dirname "$0")/.."

# The checkout is mounted from the host, so git sees a different owner.
git config --global --add safe.directory "$PWD"

go mod download
npm ci --no-audit --no-fund
(cd testdata/gen && npm ci --no-audit --no-fund)
