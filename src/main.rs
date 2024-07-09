use std::{
    fs::File,
    io::{self, BufReader},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use tokio::{
    io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer},
        ServerConfig,
    },
    TlsAcceptor,
};
use tracing::{error, info, level_filters::LevelFilter, span, Level};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::DEBUG)
        .init();

    let (certs, priv_key) = load_certs("pem/cert.pem", "pem/key.pem")?;

    let server_cfg = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, priv_key)?,
    );

    let tls_acceptor = TlsAcceptor::from(server_cfg);

    let address = "0.0.0.0:443";
    let span = span!(Level::INFO, "TCP", "{}", address).entered();
    info!("Starting TCP server...",);
    let tcp_listener = TcpListener::bind(address).await.expect("failed to bind");
    info!("Started TCP server.");
    span.exit();

    loop {
        match tcp_listener.accept().await {
            Ok((stream, ..)) => {
                if let Ok(tls_stream) = tls_acceptor
                    .accept(stream)
                    .await
                    .inspect_err(|error| error!("{error}"))
                {
                    tokio::spawn(async {
                        if let Err(err) = handle(tls_stream).await {
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

async fn handle<IO: AsyncRead + AsyncWrite + Unpin>(mut tls_stream: IO) -> anyhow::Result<()> {
    let mut passwd: [u8; 56] = [0_u8; 56];
    tls_stream.read_exact(&mut passwd).await?;

    read_crlf(&mut tls_stream).await;
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
    read_crlf(&mut tls_stream).await;

    let mut target_tcp_stream = TcpStream::connect(format!("{}:{}", address, port)).await?;

    println!("{}:{} connected", address, port);

    copy_bidirectional(&mut target_tcp_stream, &mut tls_stream).await?;

    Ok(())
}

async fn read_crlf<IO: AsyncRead + Unpin>(mut tls_stream: IO) {
    tls_stream.read_u16().await.unwrap();
}
