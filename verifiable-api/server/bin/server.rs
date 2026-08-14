use clap::Parser;

use helios_verifiable_api_server::server::{Network, VerifiableApiServer};
use helios_verifiable_api_server::telemetry;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // Pre setup. Installs OTLP export + the W3C propagator when OTLP_ENDPOINT
    // is set, otherwise plain stdout logging exactly as before.
    telemetry::init("verifiable-api");

    // parse CLI arguments
    let cli = Cli::parse();

    // construct and start the server
    let mut server = VerifiableApiServer::new(cli.network);

    server.start().await.unwrap();
}


#[derive(Parser)]
#[command(version, about)]
/// Helios' Verifiable API server
struct Cli {
    #[command(subcommand)]
    network: Network,
}
