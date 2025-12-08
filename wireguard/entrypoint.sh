#!/bin/bash

# Create config directory if it doesn't exist
mkdir -p /config/wg_confs

# Create WireGuard config with environment variables
cat > /config/wg_confs/wg0.conf <<EOF
[Interface]
# Server private key
PrivateKey = ${SERVER_PRIVATE_KEY}
# Server IP address in the VPN subnet
Address = 10.13.13.1/24, 10.9.9.9/32
# Listen port
ListenPort = 51820
# Post-up and post-down rules for NAT
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
# Client public key
PublicKey = ${CLIENT_PUBLIC_KEY}
# Allowed IPs for this peer
AllowedIPs = 10.13.13.2/32
EOF

chmod 600 /config/wg_confs/wg0.conf

# Start the pong server in background
(
  sleep 10
  echo "Starting ping-pong server on 10.9.9.9:8888..."
  while true; do
    echo "pong" | nc -l -p 8888 -s 10.9.9.9
  done
) &

# Execute the original entrypoint
exec /init
