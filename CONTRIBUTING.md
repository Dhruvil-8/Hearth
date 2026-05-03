# Contributing to Hearth

Thank you for considering contributing to Hearth.

> **Note**: This codebase was originally written by Claude Opus 4.6 (Anthropic) using Antigravity IDE by Google. It is a prototype. Community contributions to improve, test, and extend it are welcome.

## How to Contribute

### Reporting Bugs

- Open a GitHub issue with the `bug` label.
- Include: OS, Rust version, steps to reproduce, expected vs actual behavior.
- Paste relevant log output (run with `RUST_LOG=debug` for verbose logs).

### Suggesting Features

- Open an issue with the `enhancement` label.
- Describe the use case and why it matters for a home network monitoring tool.

### Code Contributions

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes.
4. Run tests: `cargo test --workspace`
5. Run clippy: `cargo clippy --workspace`
6. Submit a pull request.

### Code Style

- Follow standard Rust formatting: `cargo fmt`
- No warnings from `cargo clippy`
- Add doc comments for public APIs
- Write tests for new functionality

## Development Setup

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/hearth.git
cd hearth

# Build
cargo build --workspace

# Run tests
cargo test --workspace

# Run the daemon in demo mode (no root needed)
RUST_LOG=info cargo run -p hearth-daemon

# Run clippy
cargo clippy --workspace
```

## Areas That Need Help

- **Testing** — Integration tests, edge cases, CI/CD pipeline
- **Linux Testing** — Validate on actual Raspberry Pi hardware
- **ONNX VAD** — Integrate real Silero VAD model via `tract-onnx`
- **Security Audit** — Review for any security concerns
- **Documentation** — More examples, tutorials, screenshots
- **Packaging** — Debian packages, Docker images, cross-compilation
- **Dashboard** — Additional visualizations, mobile responsiveness
- **DNS Monitoring** — DNS query logging for domain-level visibility

## Project Structure

| Crate | Purpose |
|-------|---------|
| `hearth-core` | Core library: capture, stats, store, types |
| `hearth-daemon` | Main binary — orchestrator |
| `hearth-dashboard` | Web server + embedded UI |
| `hearth-vad` | Voice Activity Detection (standalone) |
| `hearth-rules` | nftables enforcement engine |
| `hearth-cli` | Terminal CLI |
