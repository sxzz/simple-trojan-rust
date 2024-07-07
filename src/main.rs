use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::{fs::File, io::BufReader};
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() {
    let (certs, priv_key) = load_cert("pem/cert.pem", "pem/key.pem");
    let server_cfg = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, priv_key)
            .unwrap(),
    );

    let tls_acceptor = TlsAcceptor::from(server_cfg);
    let tcp_listener = TcpListener::bind("0.0.0.0:443")
        .await
        .expect("failed to bind");

    loop {
        let (stream, _) = tcp_listener.accept().await.unwrap();
        let tls_stream = tls_acceptor.accept(stream).await.unwrap();

        tokio::spawn(async move {
            handle(tls_stream).await;
        });
    }
}

fn load_cert(
    certs: &str,
    priv_key: &str,
) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let mut certs = BufReader::new(File::open(certs).unwrap());
    let mut priv_key = BufReader::new(File::open(priv_key).unwrap());

    let certs = rustls_pemfile::certs(&mut certs)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let priv_key = rustls_pemfile::private_key(&mut priv_key).unwrap().unwrap();

    (certs, priv_key)
}

async fn handle<IO: AsyncRead + AsyncWrite + Unpin>(mut tls_stream: TlsStream<IO>) {
    let mut passwd: [u8; 56] = [0_u8; 56];
    tls_stream.read_exact(&mut passwd).await.unwrap();

    read_crlf(&mut tls_stream).await;
    let cmd = tls_stream.read_u8().await.unwrap();
    if cmd != 0x1 {
        return;
    }
    let address_type = tls_stream.read_u8().await.unwrap();
    let address = match address_type {
        0x1 => {
            // ipv4
            let buf = tls_stream.read_u32().await.unwrap();
            IpAddr::V4(Ipv4Addr::from(buf)).to_string()
        }
        0x3 => {
            let length = tls_stream.read_u8().await.unwrap();
            let mut buf = vec![0_u8; length as usize];
            tls_stream.read_exact(&mut buf).await.unwrap();
            String::from_utf8(buf).unwrap()
        }
        0x4 => {
            // ipv6
            let buf = tls_stream.read_u128().await.unwrap();
            IpAddr::V6(Ipv6Addr::from(buf)).to_string()
        }
        _ => {
            unimplemented!("unsupported address type")
        }
    };

    let port = tls_stream.read_u16().await.unwrap();
    read_crlf(&mut tls_stream).await;

    let mut target_tcp_stream = TcpStream::connect(format!("{}:{}", address, port))
        .await
        .unwrap();

    copy_bidirectional(&mut target_tcp_stream, &mut tls_stream)
        .await
        .unwrap();
}

async fn read_crlf<IO: AsyncRead + AsyncWrite + Unpin>(mut tls_stream: IO) {
    tls_stream.read_u16().await.unwrap();
}
