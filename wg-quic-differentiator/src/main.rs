use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PacketType {
    Wireguard,
    Quic,
}

const SERVER_ADDR: &str = "0.0.0.0:8080";
// const WIREGUARD_SERVER_ADDR: &str = "wireguard:51820";
// const QUIC_SERVER_ADDR: &str = "http3-server:8443";
const WIREGUARD_SERVER_ADDR: &str = "localhost:51820";
const QUIC_SERVER_ADDR: &str = "localhost:8443";
const CONNECTION_TIMEOUT_SECS: u64 = 30;

const BUFFER_SIZE: usize = 65536;

type ConnectionMap = Arc<Mutex<HashMap<(SocketAddr, PacketType), mpsc::Sender<Vec<u8>>>>>;

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();
    let client_sock = Arc::new(UdpSocket::bind(SERVER_ADDR).await?);
    log::info!("Listening on {SERVER_ADDR}...");

    // Map to maintain persistent forwarding sockets per client
    let connections: ConnectionMap = Arc::new(Mutex::new(HashMap::new()));
    let mut buf = [0; BUFFER_SIZE];

    loop {
        let (len, addr) = client_sock.recv_from(&mut buf).await?;
        log::info!("{:?} bytes received from {:?}", len, addr);
        if log::log_enabled!(log::Level::Debug) {
            log::debug!("Data: {:02x?}", &buf[..len.min(32)]);
        }

        let packet_data = &buf[..len];

        let packet_type = determine_packet_type(&packet_data, &addr);

        let forward_address = match packet_type {
            PacketType::Wireguard => WIREGUARD_SERVER_ADDR,
            PacketType::Quic => QUIC_SERVER_ADDR,
        };

        let sender = {
            let lock = connections.lock().await;
            lock.get(&(addr, packet_type)).cloned()
        };

        if let Some(sender) = sender {
            // If we already have a forwarding socket for this client and destination, send the packet through it
            if let Err(e) = sender.send(packet_data.to_vec()).await {
                log::error!("Error sending packet to forwarding task: {:?}", e);
                let mut lock = connections.lock().await;
                lock.remove(&(addr, packet_type));
            }
        } else {
            // Otherwise, create a new forwarding socket and task
            let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
            let mut lock = connections.lock().await;
            lock.insert((addr, packet_type), tx);

            let connections_clone = connections.clone();

            let forward_sock = UdpSocket::bind("0.0.0.0:0").await?;
            forward_sock.connect(&forward_address).await?;

            // Send the first packet immediately
            forward_sock.send(packet_data).await?;
            log::debug!(
                "--> Sent {} bytes to {}",
                packet_data.len(),
                forward_address
            );

            let client_sock_clone = client_sock.clone();

            tokio::spawn(async move {
                let mut proxy_buf = [0u8; BUFFER_SIZE];

                loop {
                    tokio::select! {
                        // Forward responses from the server back to the client
                        result = forward_sock.recv(&mut proxy_buf) => {
                            match result {
                                Ok(response_len) => {
                                    log::info!(
                                        "<-- Received {} bytes from {}",
                                        response_len,
                                        forward_address
                                    );

                                    if let Err(e) = client_sock_clone
                                        .send_to(&proxy_buf[..response_len], addr)
                                        .await
                                    {
                                        log::error!("Error sending response back to client: {:?}", e);
                                        break;
                                    }
                                    log::debug!("<-- Forwarded {} bytes back to {:?}", response_len, addr);
                                }
                                Err(e) => {
                                    log::error!("Error receiving from server: {:?}", e);
                                    break;
                                }
                            }
                        }

                        // Forward packets from the client to the server
                        Some(packet) = rx.recv() => {
                            if let Err(e) = forward_sock.send(&packet).await {
                                log::error!("Error forwarding packet to server: {:?}", e);
                                break;
                            }
                            log::debug!("--> Forwarded {} bytes to {}", packet.len(), forward_address);
                        }

                        // Handle connection timeout
                        _ = tokio::time::sleep(tokio::time::Duration::from_secs(CONNECTION_TIMEOUT_SECS)) => {
                            log::info!("Connection with {:?} timed out due to inactivity", (addr, packet_type));
                            break;
                        }
                    }
                }
                // Clean up connection on exit
                connections_clone.lock().await.remove(&(addr, packet_type));
            });
        }
    }
}

fn determine_packet_type(buf: &[u8], _source_addr: &SocketAddr) -> PacketType {
    // Simple heuristic: Wireguard packets start with 0x00 to 0x04 followed by 3 bytes of 0x00
    if buf.len() >= 4
        && buf[0] <= 0x04
        && buf[0] > 0
        && buf[1] == 0x00
        && buf[2] == 0x00
        && buf[3] == 0x00
    {
        match buf[0] {
            0x01 if buf.len() == 148 => log::info!("Identified as Wireguard: Handshake Initiation"),
            0x02 if buf.len() == 92 => log::info!("Identified as Wireguard: Handshake Response"),
            0x03 if buf.len() == 64 => log::info!("Identified as Wireguard: Cookie Reply"),
            0x04 if buf.len() >= 32 => log::info!("Identified as Wireguard: Data"),
            _ => log::info!("Identified as Wireguard: Unknown type {}", buf[0]),
        }
        PacketType::Wireguard
    } else {
        PacketType::Quic
    }
}
