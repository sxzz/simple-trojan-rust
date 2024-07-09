use clap::Parser;

#[derive(Parser)]
pub struct Args {
    #[arg(default_value_t = String::from("0.0.0.0:443"))]
    pub server_address: String,
}

pub fn init_cmd() -> Args {
    Args::parse()
}
