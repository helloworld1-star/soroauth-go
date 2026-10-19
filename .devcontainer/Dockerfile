FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

# Install required system packages non-interactively
RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && apt-get install -y \
    curl \
    git \
    make \
    build-essential \
    pkg-config \
    libssl-dev \
    jq \
    && rm -rf /var/lib/apt/lists/*

COPY . /workspace
WORKDIR /workspace

# Install Go, Node, Rust, and stellar-cli dynamically from repository pins
RUN GO_VERSION=$(grep '^go ' go.mod | awk '{print $2}') && \
    echo "Installing Go ${GO_VERSION}" && \
    curl -fsSL https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz | tar -C /usr/local -xz

ENV PATH=/usr/local/go/bin:${PATH}

RUN NODE_VERSION=$(jq -r '.engines.node' testdata/gen/package.json | tr -d '>=') && \
    if [ -z "$NODE_VERSION" ] || [ "$NODE_VERSION" = "null" ]; then NODE_VERSION="22.12.0"; fi && \
    echo "Installing Node.js ${NODE_VERSION}" && \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    export DEBIAN_FRONTEND=noninteractive && apt-get install -y nodejs

ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
RUN RUST_VERSION=$(grep '^toolchain' rust-toolchain.toml | cut -d'"' -f2) && \
    echo "Installing Rust ${RUST_VERSION}" && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain ${RUST_VERSION} --target wasm32v1-none

ENV PATH=${CARGO_HOME}/bin:${PATH}

# Install stellar-cli version read from documentation or SDK support pin file
RUN STELLAR_CLI_VERSION=$(grep -E 'stellar-cli' CONTRIBUTING.md docs/sdk-support.md README.md 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1) && \
    if [ -z "$STELLAR_CLI_VERSION" ]; then STELLAR_CLI_VERSION="28.0.0"; fi && \
    echo "Installing stellar-cli ${STELLAR_CLI_VERSION}" && \
    cargo install stellar-cli --version ${STELLAR_CLI_VERSION} --locked
