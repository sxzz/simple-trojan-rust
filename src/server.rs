use anyhow::bail;
use rustls::ServerConfig;
use std::{
    fs::File,
    io::{self, BufReader},
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use thiserror::Error;
use tokio::{
    io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, span, warn, Level};

#[derive(Error, Debug)]
enum TrojanError {
    #[error("Transport error")]
    TransportError(#[from] io::Error),

    #[error("Protocol error")]
    ProtocolError(#[from] anyhow::Error),
}

pub struct TrojanServer {
    address: String,
    tls_acceptor: Arc<TlsAcceptor>,
    password: Arc<[u8; 56]>,
}

impl TrojanServer {
    pub fn new(address: &str, cert: &str, cert_key: &str) -> anyhow::Result<Arc<Self>> {
        let (certs, priv_key) = Self::load_certs(cert, cert_key)?;

        let server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, priv_key)?,
        );
        let tls_acceptor = Arc::new(TlsAcceptor::from(server_config));

        Ok(Arc::new(Self {
            address: address.to_string(),
            tls_acceptor,
            password: Arc::new([0_u8; 56]), // TODO
        }))
    }

    fn load_certs(
        certs: &str,
        priv_key: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), io::Error> {
        let mut certs = BufReader::new(File::open(certs)?);
        let mut priv_key = BufReader::new(File::open(priv_key)?);

        let certs = rustls_pemfile::certs(&mut certs).collect::<Result<Vec<_>, _>>()?;
        let priv_key = rustls_pemfile::private_key(&mut priv_key)?.ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            "no private key found",
        ))?;

        Ok((certs, priv_key))
    }

    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        let span = span!(Level::INFO, "TCP", "{}", self.address).entered();
        info!("Starting TCP server...",);
        let tcp_listener = TcpListener::bind(&self.address)
            .await
            .expect("failed to bind");
        info!("Started TCP server.");
        span.exit();

        loop {
            match tcp_listener
                .accept()
                .await
                .map_err(|error| TrojanError::TransportError(error))
            {
                Ok(tcp_result) => {
                    self.clone().accept_tls(tcp_result).await;
                }
                Err(error) => {
                    error!("{error}");
                }
            };
        }
    }

    async fn accept_tls(self: Arc<Self>, (stream, addr): (TcpStream, SocketAddr)) {
        let tls_acceptor = self.tls_acceptor.clone();

        tokio::spawn(async move {
            let tls_stream = match tls_acceptor.accept(stream).await {
                Ok(tls_stream) => tls_stream,
                Err(err) => {
                    error!("{:?}", TrojanError::TransportError(err));
                    return;
                }
            };

            if let Err(err) = self.handle_tls(tls_stream, addr).await {
                error!("{:?}", TrojanError::ProtocolError(err));
            };
        });
    }

    async fn handle_tls<IO: AsyncRead + AsyncWrite + Unpin>(
        self: Arc<Self>,
        mut tls_stream: IO,
        addr: SocketAddr,
    ) -> anyhow::Result<()> {
        let mut passwd: [u8; 56] = [0_u8; 56];
        tls_stream.read_exact(&mut passwd).await?;

        let password = self.password.clone();

        Self::read_crlf(&mut tls_stream).await;
        let cmd = tls_stream.read_u8().await?;
        if cmd == 0x3 {
            warn!("unsupported UDP");
            return Result::Ok(());
        } else if cmd != 0x1 {
            bail!("unsupported command")
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
