# The optional dev container: Go, Node, Rust and stellar-cli at the versions
# this repository pins, so running the e2e suite does not start with installing
# a toolchain. It is an option, not the supported environment: the local
# instructions in CONTRIBUTING.md stay the reference.
#
# No version is written here. install-toolchains.sh reads each one from the
# file that pins it (go.mod, the rust-toolchain.toml files, the vector
# generator's package.json, e2e/contracts/stellar-cli.version), so this file
# only has to copy those files in. Dockerfile.dockerignore keeps the build
# context to exactly them.
FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

ENV DEBIAN_FRONTEND=noninteractive

# make and a C toolchain (cgo, the Rust linker), Python for the parity harness,
# jq for the install script, and the two shared libraries the stellar-cli
# release binary links against.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        jq \
        libdbus-1-3 \
        libudev1 \
        pkg-config \
        python3 \
        python3-pip \
        python3-venv \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    GOPATH=/home/vscode/go
ENV PATH=/usr/local/go/bin:/usr/local/cargo/bin:/home/vscode/go/bin:${PATH}

# The pin files, at the paths install-toolchains.sh and pins.sh expect.
COPY go.mod /opt/devcontainer/pins/go.mod
COPY testdata/gen/package.json /opt/devcontainer/pins/testdata/gen/package.json
COPY e2e/contracts/rust-toolchain.toml /opt/devcontainer/pins/e2e/contracts/rust-toolchain.toml
COPY e2e/contracts/stellar-cli.version /opt/devcontainer/pins/e2e/contracts/stellar-cli.version
COPY e2e/contracts/stellar-cli.sha256 /opt/devcontainer/pins/e2e/contracts/stellar-cli.sha256
COPY bindings/rust/rust-toolchain.toml /opt/devcontainer/pins/bindings/rust/rust-toolchain.toml
COPY testdata/parity-rust/rust-toolchain.toml /opt/devcontainer/pins/testdata/parity-rust/rust-toolchain.toml
COPY .devcontainer/pins.sh .devcontainer/install-toolchains.sh /opt/devcontainer/

RUN bash /opt/devcontainer/install-toolchains.sh /opt/devcontainer/pins \
    && mkdir -p /home/vscode/go \
    && chown -R vscode:vscode /usr/local/rustup /usr/local/cargo /home/vscode/go
