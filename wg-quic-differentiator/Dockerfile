FROM rust:1.91.1-slim AS builder

WORKDIR /build

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY Cargo.toml .
COPY src/ src/

# Build the application
RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

# Copy the built binary
COPY --from=builder /build/target/release/wg-quic-differentiator /app/wg-quic-differentiator

# Expose the UDP port
EXPOSE 8080/udp

# Set environment for logging
ENV RUST_LOG=info

CMD ["/app/wg-quic-differentiator"]
