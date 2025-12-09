# WG-QUIC Differentiator

A UDP proxy that differentiates between WireGuard and QUIC/HTTP3 traffic and forwards to the appropriate backend server.

## Building

```bash
docker compose build
```

## Running

```bash
docker compose up -d
```

## Services

- **wg-quic-differentiator** (port 8080/udp) - Main proxy service that differentiates traffic
- **wireguard** (port 51820/udp) - WireGuard VPN server
- **http3-server** (port 8443/udp) - Very basic HTTP/3 server

## Testing

### Test HTTP/3

First, install [h3i](https://crates.io/crates/h3i) (`cargo install h3i`).

```bash
h3i 127.0.0.1:8080 --no-verify --qlog-input example_qlog.sqlog
```

### Test WireGuard

Add the `client-through-proxy.conf` configuration file to your Wireguard client, and activate it. Then, either `ping 10.9.9.9` or `nc 10.9.9.9 8888` (which will return `pong`) to test connectivity.

## How it works

The differentiator examines incoming UDP packets:

- If the packet starts with bytes `0x00-0x04` followed by three `0x00` bytes, it's identified as WireGuard
- Otherwise, it's treated as QUIC/HTTP3

See [`src/main.rs`](wg-quic-differentiator/src/main.rs#L161) for the (limited) implementation details on the differentiator.

Connections are maintained per client address with automatic cleanup after 30 seconds of inactivity. This is needed for QUIC, as it requires a persistent connection.
