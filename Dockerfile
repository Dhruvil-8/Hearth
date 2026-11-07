# Multi-stage build for Hearth Daemon
FROM rust:bookworm AS builder

WORKDIR /usr/src/hearth

# Install build dependencies for SQLite and packet capture
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    libpcap-dev \
    pkg-config \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace source files
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build release binaries
RUN cargo build --release --bin hearth --bin hearth-cli

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    nftables \
    iproute2 \
    net-tools \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create working directory and copy binaries
WORKDIR /var/lib/hearth
COPY --from=builder /usr/src/hearth/target/release/hearth /usr/local/bin/hearth
COPY --from=builder /usr/src/hearth/target/release/hearth-cli /usr/local/bin/hearth-cli

# Create config directory
RUN mkdir -p /etc/hearth /var/lib/hearth

EXPOSE 7777 53/udp 53/tcp

ENTRYPOINT ["hearth"]
CMD ["--config", "/etc/hearth/hearth.toml"]
