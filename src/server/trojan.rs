use rustls::ServerConfig;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, span, Level};

pub struct TrojanServer {
    address: String,
    server_config: Arc<ServerConfig>,
}

impl TrojanServer {
    pub fn new(address: &str, server_config: ServerConfig) -> Self {
        Self {
            address: address.to_string(),
            server_config: Arc::new(server_config),
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let tls_acceptor = TlsAcceptor::from(self.server_config);

        let span = span!(Level::INFO, "TCP", "{}", self.address).entered();
        info!("Starting TCP server...",);
        let tcp_listener = TcpListener::bind(self.address)
            .await
            .expect("failed to bind");
        info!("Started TCP server.");
        span.exit();

        loop {
            match tcp_listener.accept().await {
                Ok((stream, addr)) => {
                    let addr = Arc::new(addr);
                    if let Ok(tls_stream) = tls_acceptor
                        .accept(stream)
                        .await
                        .inspect_err(|error| error!("{error}"))
                    {
                        tokio::spawn(async {
                            if let Err(err) = Self::handle(tls_stream, addr).await {
                                error!("{err}")
                            };
                        });
                    }
                }
                Err(err) => {
                    error!("{err}");
                }
            }
        }
    }

    async fn handle<IO: AsyncRead + AsyncWrite + Unpin>(
        mut tls_stream: IO,
        addr: Arc<SocketAddr>,
    ) -> anyhow::Result<()> {
        let mut passwd: [u8; 56] = [0_u8; 56];
        tls_stream.read_exact(&mut passwd).await?;

        Self::read_crlf(&mut tls_stream).await;
        let cmd = tls_stream.read_u8().await?;
        if cmd != 0x1 {
            return Ok(());
        }
        let address_type = tls_stream.read_u8().await?;
        let address = match address_type {
            0x1 => {
                // ipv4
                let buf = tls_stream.read_u32().await?;
                IpAddr::V4(Ipv4Addr::from(buf)).to_string()
            }
            0x3 => {
                // domain
                let length = tls_stream.read_u8().await?;
                let mut buf = vec![0_u8; length as usize];
                tls_stream.read_exact(&mut buf).await?;
                String::from_utf8(buf).unwrap()
            }
            0x4 => {
                // ipv6
                let buf = tls_stream.read_u128().await?;
                IpAddr::V6(Ipv6Addr::from(buf)).to_string()
            }
            _ => {
                unimplemented!("unsupported address type")
            }
        };

        let port = tls_stream.read_u16().await?;
        Self::read_crlf(&mut tls_stream).await;

        let mut target_tcp_stream = TcpStream::connect(format!("{}:{}", address, port)).await?;

        info!("{} connected to {}:{}", addr, address, port);

        copy_bidirectional(&mut target_tcp_stream, &mut tls_stream).await?;

        Ok(())
    }

    async fn read_crlf<IO: AsyncRead + Unpin>(mut tls_stream: IO) {
        tls_stream.read_u16().await.unwrap();
    }
}
