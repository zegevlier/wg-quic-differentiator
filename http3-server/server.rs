// This thing is entirely AI-generated, and should serve only as a demo HTTP/3 server.

use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use bytes::Bytes;
use h3::quic::BidiStream;
use h3::server::RequestStream;
use h3_quinn::quinn;
use http::{Request, StatusCode};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = "0.0.0.0:8443".parse()?;

    // Load or generate certificate
    let (cert, key) = load_or_generate_cert()?;

    // Configure QUIC server
    let mut tls_config = rustls::ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;

    tls_config.max_early_data_size = u32::MAX;
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_config));
    let endpoint = quinn::Endpoint::server(server_config, addr)?;

    println!("HTTP/3 server listening on {}", addr);

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming).await {
                eprintln!("Connection error: {}", e);
            }
        });
    }

    Ok(())
}

async fn handle_connection(incoming: quinn::Connecting) -> Result<(), Box<dyn std::error::Error>> {
    let connection = incoming.await?;
    println!("New connection from {}", connection.remote_address());

    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(connection))
        .await?;

    loop {
        match h3_conn.accept().await {
            Ok(Some((req, stream))) => {
                tokio::spawn(async move {
                    if let Err(e) = handle_request(req, stream).await {
                        eprintln!("Request error: {}", e);
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("Accept error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

async fn handle_request<T>(
    req: Request<()>,
    mut stream: RequestStream<T, Bytes>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: BidiStream<Bytes>,
{
    println!("Received request: {} {}", req.method(), req.uri());

    // Read request body if present
    while let Some(_data) = stream.recv_data().await? {}

    // Prepare response
    let content = b"Hello World from HTTP/3!\n";
    let response = http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .header("content-length", content.len())
        .body(())?;

    stream.send_response(response).await?;
    stream.send_data(Bytes::from_static(content)).await?;
    stream.finish().await?;

    Ok(())
}

fn load_or_generate_cert() -> Result<(rustls::Certificate, rustls::PrivateKey), Box<dyn std::error::Error>> {
    // Try to load existing certificate
    let cert_path = PathBuf::from("/certs/cert.der");
    let key_path = PathBuf::from("/certs/key.der");

    if cert_path.exists() && key_path.exists() {
        let cert_data = std::fs::read(&cert_path)?;
        let key_data = std::fs::read(&key_path)?;
        return Ok((
            rustls::Certificate(cert_data),
            rustls::PrivateKey(key_data),
        ));
    }

    // Generate self-signed certificate
    println!("Generating self-signed certificate...");
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = cert.serialize_der()?;
    let key_der = cert.serialize_private_key_der();

    // Save certificate for reuse
    std::fs::create_dir_all("/certs").ok();
    std::fs::write(&cert_path, &cert_der).ok();
    std::fs::write(&key_path, &key_der).ok();

    Ok((
        rustls::Certificate(cert_der),
        rustls::PrivateKey(key_der),
    ))
}
