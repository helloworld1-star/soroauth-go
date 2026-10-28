#!/usr/bin/env bash
# Proves the dev container works: every tool is the version the repository
# pins, and the tasks CONTRIBUTING.md names run from a clean start.
#
# CI runs this inside the container on every change to a pin file or to
# .devcontainer, and weekly (.github/workflows/ci-devcontainer.yml), so the
# container cannot rot silently. A contributor can run it too:
#
#   bash .devcontainer/verify.sh
#
# The e2e step compiles the fixture contract and the e2e tests but does not run
# the scenarios: those submit live transactions to testnet, which is
# .github/workflows/e2e.yml's job.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
# shellcheck source=pins.sh
. "$root/.devcontainer/pins.sh"

failed=0
check() {
  local what="$1" want="$2" got="$3"
  if [ "$got" = "$want" ]; then
    printf 'ok    %-12s %s\n' "$what" "$got"
  else
    printf 'FAIL  %-12s pinned %s, installed %s\n' "$what" "$want" "$got" >&2
    failed=1
  fi
}

go_want="$(pin_go "$root")"
check go "$go_want" "$(go env GOVERSION | sed 's/^go//')"

node_min="$(pin_node_min "$root")"
node_have="$(node --version | sed 's/^v//')"
if [ "$(printf '%s\n%s\n' "$node_min" "$node_have" | sort -V | head -n 1)" = "$node_min" ] &&
  [ "${node_have%%.*}" = "${node_min%%.*}" ]; then
  printf 'ok    %-12s %s (pinned >= %s, same major)\n' node "$node_have" "$node_min"
else
  printf 'FAIL  %-12s pinned >= %s, installed %s\n' node "$node_min" "$node_have" >&2
  failed=1
fi

# Rust is checked where it is used: rustup resolves the channel from the
# rust-toolchain.toml of the directory a build runs in.
while IFS= read -r file; do
  dir="$(dirname "$file")"
  want="$(sed -n 's/^channel *= *"\(.*\)".*/\1/p' "$file")"
  got="$(cd "$dir" && rustc --version | awk '{ print $2 }')"
  check "rustc ${dir#"$root"/}" "$want" "$got"
done < <(find "$root" -name rust-toolchain.toml -not -path '*/node_modules/*' | sort)

check stellar-cli "$(pin_stellar "$root")" "$(stellar --version | awk 'NR == 1 { print $2 }')"

[ "$failed" -eq 0 ] || exit 1

# `make` is fmt, vet and test.
make

# Regenerates the golden vectors from the pinned reference SDK and fails if the
# committed ones changed.
make vectors-check

# What `make e2e` does before it talks to testnet: build the fixture contract
# with stellar-cli, then compile the e2e suite.
(cd e2e/contracts && stellar contract build)
go test -tags e2e -run '^$' ./e2e/...

echo "dev container verified"
