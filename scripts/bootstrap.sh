#!/usr/bin/env bash
set -euo pipefail

ARGUS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ARGUS_DIR"

echo "=== ARGUS Bootstrap Script ==="
echo "Detecting OS..."

# OS Detection
OS=""
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
fi

case "$OS" in
    debian|ubuntu|vyos)
        echo "Detected: $OS ($VERSION_ID)"
        ;;
    *)
        echo "Unsupported OS: $OS"
        echo "ARGUS requires Debian, Ubuntu, or VyOS."
        exit 1
        ;;
esac

# Install system dependencies
echo "=== Installing system dependencies ==="
sudo apt-get update -qq
sudo apt-get install -y -qq \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    bpftool \
    pkg-config \
    libssl-dev \
    linux-headers-$(uname -r) \
    docker.io \
    docker-compose-plugin \
    ansible-core \
    postgresql-client \
    redis-tools \
    cmake \
    curl \
    git

# Install rustup if missing
if ! command -v rustup &>/dev/null; then
    echo "=== Installing rustup ==="
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
    . "$HOME/.cargo/env"
fi

. "$HOME/.cargo/env"

# Install pinned toolchain
echo "=== Installing Rust toolchain ==="
rustup show active-toolchain 2>/dev/null || rustup toolchain install stable
rustup component add rustfmt clippy llvm-tools-preview

# Install cargo tools
echo "=== Installing cargo tools ==="
cargo install cargo-audit --locked
cargo install cargo-deny --locked
cargo install cargo-fuzz --locked
cargo install cargo-criterion --locked
cargo install cargo-tarpaulin --locked || echo "tarpaulin may require additional libs"
cargo install cargo-llvm-cov --locked
cargo install cargo-geiger --locked

# Verify bpftool
echo "=== Verifying eBPF tooling ==="
bpftool version || echo "WARNING: bpftool not found, eBPF programs cannot be loaded"

# Verify Rust toolchain
echo "=== Verifying Rust toolchain ==="
rustc --version
cargo --version

echo "=== Bootstrap complete! ==="
echo "Run 'cargo build' to compile the workspace."
