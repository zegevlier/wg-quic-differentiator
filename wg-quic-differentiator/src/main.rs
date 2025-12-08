use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashMap;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};

enum PacketType {
    Wireguard,
    Quic,
}

const SERVER_ADDR: &str = "0.0.0.0:8080";
const WIREGUARD_SERVER_ADDR: &str = "wireguard:51820";
const QUIC_SERVER_ADDR: &str = "http3-server:8443";
const CONNECTION_TIMEOUT_SECS: u64 = 30;

struct Connection {
    socket: Arc<UdpSocket>,
    last_activity: Instant,
}

type ConnectionMap = Arc<Mutex<HashMap<SocketAddr, Connection>>>;

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();
    let sock = Arc::new(UdpSocket::bind(SERVER_ADDR).await?);
    log::info!("Listening on {SERVER_ADDR}...");
    
    // Map to maintain persistent forwarding sockets per client
    let connections: ConnectionMap = Arc::new(Mutex::new(HashMap::new()));
    
    // Spawn cleanup task
    let connections_cleanup = connections.clone();
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            let mut conn_map = connections_cleanup.lock().await;
            let now = Instant::now();
            let before_count = conn_map.len();
            
            conn_map.retain(|addr, conn| {
                let elapsed = now.duration_since(conn.last_activity);
                if elapsed.as_secs() > CONNECTION_TIMEOUT_SECS {
                    log::info!("Cleaning up idle connection for {:?} (idle for {}s)", addr, elapsed.as_secs());
                    false
                } else {
                    true
                }
            });
            
            let after_count = conn_map.len();
            if before_count != after_count {
                log::info!("Cleaned up {} idle connections ({} remaining)", before_count - after_count, after_count);
            }
        }
    });
    
    let mut buf = [0; 65536];

    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        log::info!("{:?} bytes received from {:?}", len, addr);
        if log::log_enabled!(log::Level::Debug) {
            log::debug!("Data: {:02x?}", &buf[..len.min(32)]);
        }

        let packet_type = determine_packet_type(&buf[..len], &addr);

        let forward_address = match packet_type {
            PacketType::Wireguard => Some(WIREGUARD_SERVER_ADDR),
            PacketType::Quic => Some(QUIC_SERVER_ADDR),
        };
        
        if let Some(forward_addr) = forward_address {
            let buf = buf[..len].to_vec();
            let sock = sock.clone();
            let connections = connections.clone();
            
            tokio::spawn(async move {
                if let Err(e) = forward_udp(&buf, forward_addr, addr, sock, connections).await {
                    log::error!("Error forwarding packet: {:?}", e);
                }
            });
        }
    }
}

async fn forward_udp(
    buf: &[u8],
    server_address: &str,
    addr: SocketAddr,
    sock: Arc<UdpSocket>,
    connections: ConnectionMap,
) -> io::Result<()> {
    log::info!("--> Forwarding {} bytes to {}", buf.len(), server_address);

    // Get or create a forwarding socket for this client
    let mut conn_map = connections.lock().await;
    let forward_sock = if let Some(existing) = conn_map.get_mut(&addr) {
        // Update last activity time
        existing.last_activity = Instant::now();
        existing.socket.clone()
    } else {
        let new_sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        new_sock.connect(server_address).await?;
        
        // Spawn a task to continuously forward responses back
        let new_sock_clone = new_sock.clone();
        let sock_clone = sock.clone();
        let server_address_str = server_address.to_string();
        let connections_clone = connections.clone();
        tokio::spawn(async move {
            let mut response_buf = [0; 65536];
            loop {
                match new_sock_clone.recv(&mut response_buf).await {
                    Ok(response_len) => {
                        log::info!("<-- Received {} bytes from {}", response_len, server_address_str);
                        
                        // Update last activity time
                        {
                            let mut conn_map = connections_clone.lock().await;
                            if let Some(conn) = conn_map.get_mut(&addr) {
                                conn.last_activity = Instant::now();
                            }
                        }
                        
                        if let Err(e) = sock_clone.send_to(&response_buf[..response_len], addr).await {
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
        });
        
        conn_map.insert(addr, Connection {
            socket: new_sock.clone(),
            last_activity: Instant::now(),
        });
        new_sock
    };
    drop(conn_map);

    // Send the packet to the server
    forward_sock.send(buf).await?;
    log::debug!("--> Sent {} bytes to {}", buf.len(), server_address);

    Ok(())
}

fn determine_packet_type(buf: &[u8], _source_addr: &SocketAddr) -> PacketType {
    // Simple heuristic: Wireguard packets start with 0x00 to 0x04 followed by 3 bytes of 0x00
    if buf.len() >= 4 && buf[0] <= 0x04 && buf[0] > 0 && buf[1] == 0x00 && buf[2] == 0x00 && buf[3] == 0x00 {
        PacketType::Wireguard
    } else {
        PacketType::Quic
    }
}
