use cli::init_cmd;
use server::TrojanServer;
use std::{
    fs::File,
    io::{self, BufReader},
};
use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig,
};

mod cli;
mod server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        // .with_max_level(LevelFilter::DEBUG)
        .init();

    let args = init_cmd();
    let (certs, priv_key) = load_certs(args.cert.as_str(), args.cert_key.as_str())?;

    let server_cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, priv_key)?;
    let trojan_server = TrojanServer::new(args.server_address.as_str(), server_cfg);
    trojan_server.run().await?;

    Ok(())
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
