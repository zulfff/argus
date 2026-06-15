# ARGUS Development Guide

## Prerequisites

```bash
# Debian/Ubuntu
sudo apt-get update && sudo apt-get install -y \
    build-essential pkg-config libssl-dev \
    clang llvm libbpf-dev bpftool \
    curl git cmake

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Add rustfmt, clippy, llvm-tools
rustup component add rustfmt clippy llvm-tools-preview
```

## Project Setup

```bash
git clone <argus-repo>
cd argus
cargo build --workspace --exclude argus-ebpf
```

## Development Workflow

### 1. Checkout a feature branch

```bash
git checkout -b feature/my-feature
```

### 2. Make changes

Edit code in relevant crates. See [Architecture](architecture.md) for module layout.

### 3. Build and lint

```bash
# Check compilation (fast, no codegen)
cargo check --workspace --exclude argus-ebpf

# Lint with strict warnings
cargo clippy --workspace --exclude argus-ebpf -- -D warnings

# Format
cargo fmt
```

### 4. Test

```bash
# Unit tests
cargo test --workspace --exclude argus-ebpf

# Specific crate
cargo test -p argus-core

# Run with logging
RUST_LOG=debug cargo test -p argus-core -- --nocapture
```

### 5. Security audit

```bash
# Cargo audit (vulnerability check)
cargo audit

# Check for secrets in code
git diff --cached | grep -iE '(password|secret|token|key).*='
```

### 6. Commit

```bash
git add .
git commit -m "module: brief description of change"
```

## Code Style & Conventions

### Error Handling
```rust
// ✓ GOOD: Typed errors
pub fn validate(&self) -> Result<()> { ... }

// ✗ BAD: No unwrap() in non-test code
let x = some_option.unwrap();
```

### Unsafe Blocks
```rust
// ✓ GOOD: SAFETY comment required
// SAFETY: pointer is within [data, data_end) bounds verified above.
let hdr = &*(data as *const Ipv4Hdr);
```

### Async Code
```rust
// ✓ GOOD: Don't hold MutexGuard across .await
let data = {
    let lock = self.data.lock().unwrap();
    lock.values().cloned().collect::<Vec<_>>()
}; // lock dropped here
async_call(data).await;
```

### Arithmetic
```rust
// ✓ GOOD: Checked/overflow-safe on untrusted input
let result = value.checked_add(offset).ok_or(Error::Overflow)?;
```

## Testing

### Unit Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_happy_path() { ... }

    #[test]
    fn test_edge_case() { ... }

    #[test]
    fn test_error_path() { ... }
}
```

### Running Specific Tests

```bash
# Run tests in a module
cargo test -p argus-core -- rule_engine

# Run a single test
cargo test -p argus-core -- test_ip_in_cidr_v4

# Run with backtrace on failure
RUST_BACKTRACE=1 cargo test -p argus-core
```

## Crate Dependency Graph

```
argus-common  ◄── (type definitions, no deps on other argus crates)
    │
    ├── argus-core  ◄── (engines: rule, connection, rate, scan, etc.)
    │       │
    │       ├── argus-api  ◄── (Axum server + JWT auth + WebSocket)
    │       │       │
    │       │       └── argus-observability  ◄── (Prometheus + Loki + tracing)
    │       │
    │       ├── argus-orchestrator  ◄── (NetBox + VyOS + Ansible + drift)
    │       │
    │       └── argus-cli  ◄── (clap CLI + ratatui TUI)
    │
    └── argus-ebpf  ◄── (#![no_std], aya-ebpf, independent build target)
```

## Adding a New Crate

```bash
cargo init --lib crates/argus-newmod
```

Add to `Cargo.toml` workspace members and `[workspace.dependencies]`.

## Adding a New Module to argus-core

1. Create file: `crates/argus-core/src/my_module.rs`
2. Add to `lib.rs`: `pub mod my_module;`
3. Add tests at bottom of file: `#[cfg(test)] mod tests { ... }`
4. Wire into `AppState` in `argus-api/src/main.rs` if needed

## eBPF Development

The `argus-ebpf` crate requires nightly Rust + `bpfel-unknown-none` target.

```bash
# One-time setup
rustup toolchain install nightly
rustup target add --toolchain nightly bpfel-unknown-none

# Build eBPF programs
cargo +nightly build --release -p argus-ebpf

# Load and verify (requires root)
sudo bpftool prog load target/bpfel-unknown-none/release/argus-ebpf \
    /sys/fs/bpf/argus_firewall type xdp
```

### eBPF Development Tips
- XDP programs run with preemption disabled — keep them short
- All loops must be bounded (known at compile time)
- BPF maps have per-CPU counters for stats
- Use `aya-log` for print debugging in BPF programs
- Test with `bpftool prog load` to verify verifier acceptance

## Environment Variables for Development

```bash
# Enable debug logging
export RUST_LOG=argus=debug,tower_governor=warn

# Custom JWT secret (use a fixed value for dev)
export ARGUS_JWT_SECRET="dev-secret-32-bytes-long-key!!"

# API URL for CLI testing
export ARGUS_API_URL="http://127.0.0.1:8443"
```

## Troubleshooting

### `cargo build` fails with linker errors
```bash
sudo apt-get install -y build-essential pkg-config libssl-dev
```

### `rustc --version` segfaults
```bash
# Reinstall the toolchain
rustup toolchain uninstall stable
rustup toolchain install stable
```

### BPF compilation fails with "target not found"
```bash
rustup target add --toolchain nightly bpfel-unknown-none
```

### Tests fail with "connection refused"
Make sure the API server is running:
```bash
cargo run -p argus-api &
cargo test -p argus-cli
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes following the conventions above
4. Ensure `cargo clippy -- -D warnings` and `cargo test` pass
5. Submit a pull request with a clear description
