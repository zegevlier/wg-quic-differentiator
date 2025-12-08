FROM rust:1.91.1-slim AS builder

WORKDIR /build

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the HTTP3 server code
COPY server.rs .
COPY Cargo.toml .

# Build the server
RUN cargo build --release

FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the built binary
COPY --from=builder /build/target/release/http3-server /app/http3-server

# Expose HTTP/3 port
EXPOSE 8443/udp

CMD ["/app/http3-server"]
