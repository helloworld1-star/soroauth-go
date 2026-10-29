#!/usr/bin/env bash
# Reads the versions this repository pins, from the files that pin them.
#
# The dev container installs and then checks its tools against these functions,
# and nothing else states a version, so the container cannot drift from the
# repository: change a pin file and the next build installs the new version.
#
#   Go           go.mod: the toolchain line, else the go line
#   Node         testdata/gen/package.json: engines.node (">=X.Y.Z")
#   Rust         every rust-toolchain.toml: channel
#   stellar-cli  e2e/contracts/stellar-cli.version
#
# Each function takes the directory that holds the pin files, laid out like the
# repository, and prints what it found (nothing when the pin is missing).

pin_go() {
  local v
  v="$(awk '$1 == "toolchain" { sub(/^go/, "", $2); print $2; exit }' "$1/go.mod")"
  if [ -z "$v" ]; then
    v="$(awk '$1 == "go" { print $2; exit }' "$1/go.mod")"
  fi
  printf '%s\n' "$v"
}

# The lowest Node release the repository's tooling accepts.
pin_node_min() {
  jq -r '.engines.node // empty' "$1/testdata/gen/package.json" | sed -n 's/^>=\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)$/\1/p'
}

pin_stellar() {
  tr -d '[:space:]' <"$1/e2e/contracts/stellar-cli.version"
  echo
}

# One channel per line, deduplicated.
pin_rust_channels() {
  find "$1" -name rust-toolchain.toml -not -path '*/node_modules/*' | sort |
    while IFS= read -r f; do
      sed -n 's/^channel *= *"\(.*\)".*/\1/p' "$f"
    done | sort -u
}
