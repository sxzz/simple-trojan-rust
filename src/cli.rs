use clap::Parser;

#[derive(Parser)]
pub struct Args {
    #[arg(
        short = 'a',
        long = "address",
        default_value_t = String::from("0.0.0.0:443")
    )]
    pub server_address: String,

    #[arg(
        short, long,
        default_value_t = String::from("pem/cert.pem")
    )]
    pub cert: String,

    #[arg(
        short = 'k', long,
        default_value_t = String::from("pem/key.pem")
    )]
    pub cert_key: String,
}

pub fn init_cmd() -> Args {
    Args::parse()
}
