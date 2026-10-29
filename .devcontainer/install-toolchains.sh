#!/usr/bin/env bash
# Installs the toolchains the repository pins into the dev container image.
#
# Nothing is typed here: every version comes from the file that pins it (see
# pins.sh), and every download is checked against a checksum published by the
# project that ships it, or committed next to the pin. A download whose
# checksum cannot be found or does not match fails the build; there is no
# unchecked fallback.
#
# Usage: install-toolchains.sh <directory holding the pin files>
set -euo pipefail

pins="${1:?usage: install-toolchains.sh <directory holding the pin files>}"
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=pins.sh
. "$here/pins.sh"

fail() {
  echo "install-toolchains: $*" >&2
  exit 1
}

case "$(uname -m)" in
x86_64)
  go_arch=amd64
  node_arch=x64
  triple=x86_64-unknown-linux-gnu
  ;;
aarch64)
  go_arch=arm64
  node_arch=arm64
  triple=aarch64-unknown-linux-gnu
  ;;
*) fail "unsupported architecture $(uname -m)" ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fetch() { curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$2" "$1"; }

install_go() {
  local v sum
  v="$(pin_go "$pins")"
  [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "go.mod pins no full Go version (got '$v')"

  # go.dev publishes the checksum of every archive it serves.
  fetch 'https://go.dev/dl/?mode=json&include=all' "$work/go.json"
  sum="$(jq -r --arg v "go$v" --arg a "$go_arch" \
    '.[] | select(.version == $v) | .files[] | select(.os == "linux" and .arch == $a and .kind == "archive") | .sha256' \
    "$work/go.json")"
  [ -n "$sum" ] || fail "go.dev lists no linux/$go_arch archive for go$v"

  fetch "https://go.dev/dl/go$v.linux-$go_arch.tar.gz" "$work/go.tgz"
  echo "$sum  $work/go.tgz" | sha256sum -c -
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$work/go.tgz"
}

install_node() {
  local min major base file ver lowest sum
  min="$(pin_node_min "$pins")"
  [ -n "$min" ] || fail "testdata/gen/package.json must state engines.node as '>=X.Y.Z'"
  major="${min%%.*}"

  # The newest release of the pinned major, which must still satisfy the
  # minimum the generator declares. nodejs.org publishes the archives' checksums.
  base="https://nodejs.org/dist/latest-v${major}.x"
  fetch "$base/SHASUMS256.txt" "$work/node.sums"
  file="$(awk -v suffix="-linux-$node_arch.tar.xz" 'index($2, suffix) { print $2; exit }' "$work/node.sums")"
  [ -n "$file" ] || fail "nodejs.org lists no linux-$node_arch archive for Node $major"
  ver="${file#node-v}"
  ver="${ver%%-linux*}"
  lowest="$(printf '%s\n%s\n' "$min" "$ver" | sort -V | head -n 1)"
  [ "$lowest" = "$min" ] || fail "latest Node $major is $ver, below the pinned minimum $min"
  sum="$(awk -v f="$file" '$2 == f { print $1 }' "$work/node.sums")"

  fetch "$base/$file" "$work/node.txz"
  echo "$sum  $work/node.txz" | sha256sum -c -
  tar -C /usr/local --strip-components=1 --no-same-owner -xJf "$work/node.txz"
}

install_rust() {
  local expected file dir
  # rustup-init is published with its checksum beside it.
  fetch "https://static.rust-lang.org/rustup/dist/$triple/rustup-init" "$work/rustup-init"
  fetch "https://static.rust-lang.org/rustup/dist/$triple/rustup-init.sha256" "$work/rustup-init.sha256"
  expected="$(awk '{ print $1; exit }' "$work/rustup-init.sha256")"
  [ -n "$expected" ] || fail "rustup-init.sha256 is empty"
  echo "$expected  $work/rustup-init" | sha256sum -c -
  chmod +x "$work/rustup-init"
  "$work/rustup-init" -y --no-modify-path --profile minimal --default-toolchain none

  export PATH="$CARGO_HOME/bin:$PATH"
  # With no argument, `rustup toolchain install` installs what the
  # rust-toolchain.toml in the current directory pins: its channel, components
  # and targets. Every file the repository pins is installed, so a contributor
  # can build the e2e contracts, the Rust binding and the parity harness.
  while IFS= read -r file; do
    dir="$(dirname "$file")"
    (cd "$dir" && rustup toolchain install --profile minimal)
  done < <(find "$pins" -name rust-toolchain.toml | sort)
  rustup default "$(cd "$pins/e2e/contracts" && rustup show active-toolchain | awk '{ print $1; exit }')"
}

install_stellar() {
  local v asset
  v="$(pin_stellar "$pins")"
  [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "e2e/contracts/stellar-cli.version is not a full version (got '$v')"
  asset="stellar-cli-$v-$triple.tar.gz"

  # The release publishes no checksum file, so the sums are committed beside
  # the version; bumping the version without them fails here.
  grep -F "  $asset" "$pins/e2e/contracts/stellar-cli.sha256" >"$work/stellar.sum" ||
    fail "e2e/contracts/stellar-cli.sha256 has no checksum for $asset: add one when you change the version"
  fetch "https://github.com/stellar/stellar-cli/releases/download/v$v/$asset" "$work/$asset"
  (cd "$work" && sha256sum -c stellar.sum)
  tar -C /usr/local/bin --no-same-owner -xzf "$work/$asset" stellar
}

install_go
install_node
install_rust
install_stellar
