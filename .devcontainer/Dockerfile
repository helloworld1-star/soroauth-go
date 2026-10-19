FROM mcr.microsoft.com/devcontainers/base:debian12

# Install build essentials
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends curl build-essential git pkg-config libssl-dev jq

COPY go.mod go.sum package.json e2e/contracts/rust-toolchain.toml /tmp/pins/

# Install Go, Node, Rust, and stellar-cli reading pinned versions directly from pin files
RUN set -ex; \
    GO_VERSION=$(grep '^go ' /tmp/pins/go.mod | awk '{print $2}'); \
    curl -fsSL https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz | tar -C /usr/local -xz;

ENV PATH=/usr/local/go/bin:${PATH}

RUN set -ex; \
    NODE_MAJOR=$(grep -oE '"node":\s*"[^"]+"' /tmp/pins/package.json | grep -oE '[0-9]+' | head -n1); \
    [ -z "$NODE_MAJOR" ] && NODE_MAJOR=22; \
    curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get install -y nodejs

ENV RUSTUP_HOME=/opt/rustup
ENV CARGO_HOME=/opt/cargo
RUN set -ex; \
    RUST_VERSION=$(grep '^channel' /tmp/pins/rust-toolchain.toml | cut -d'"' -f2); \
    [ -z "$RUST_VERSION" ] && RUST_VERSION=1.93.0; \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain ${RUST_VERSION}

ENV PATH=/opt/cargo/bin:${PATH}

RUN cargo install --locked --version 28.0.0 stellar-cli

WORKDIR /workspace
