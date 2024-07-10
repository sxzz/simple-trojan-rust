use cli::init_cmd;
use server::TrojanServer;

mod cli;
mod server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        // .with_max_level(LevelFilter::DEBUG)
        .init();

    let args = init_cmd();
    let trojan_server = TrojanServer::new(
        args.server_address.as_str(),
        args.cert.as_str(),
        args.cert_key.as_str(),
    )?;
    trojan_server.run().await?;

    Ok(())
}
