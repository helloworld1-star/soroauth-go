FROM mcr.microsoft.com/devcontainers/base:debian12

# Install build essentials
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends curl build-essential git pkg-config libssl-dev

# Install Go (pinned to 1.25.4 matching toolchain in go.mod)
ARG GO_VERSION=1.25.4
RUN curl -fsSL https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH=/usr/local/go/bin:${PATH}

# Install Node.js (v22 matching package.json)
ARG NODE_MAJOR=22
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get install -y nodejs

# Install Rust (pinned to 1.93.0 matching e2e/contracts/rust-toolchain.toml)
ENV RUSTUP_HOME=/opt/rustup
ENV CARGO_HOME=/opt/cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.93.0 --target wasm32v1-none
ENV PATH=/opt/cargo/bin:${PATH}

# Install stellar-cli (pinned to v28.0.0)
RUN cargo install --locked --version 28.0.0 stellar-cli

WORKDIR /workspace
