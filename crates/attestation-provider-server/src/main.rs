use std::{net::SocketAddr, path::PathBuf};

use attestation::{
    AttestationGenerator,
    AttestationType,
    AttestationVerifier,
    measurements::MeasurementPolicy,
};
use attestation_provider_server::{attestation_provider_client, attestation_provider_server};
use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tracing::level_filters::LevelFilter;

const GIT_REV: &str = match option_env!("GIT_REV") {
    Some(rev) => rev,
    None => "unknown",
};

#[derive(Parser, Debug, Clone)]
#[command(version = GIT_REV, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: CliCommand,
    /// Log debug messages
    #[arg(long, global = true)]
    log_debug: bool,
    /// Log in JSON format
    #[arg(long, global = true)]
    log_json: bool,
    /// Log DCAP quotes to folder `quotes/`
    #[arg(long, global = true)]
    log_dcap_quote: bool,
}
#[derive(Subcommand, Debug, Clone)]
enum CliCommand {
    Server {
        /// Socket address to listen on
        #[arg(short, long, default_value = "0.0.0.0:0", env = "LISTEN_ADDR")]
        listen_addr: SocketAddr,
        /// Type of attestation to present (will attempt to detect if not
        /// given)
        #[arg(long)]
        server_attestation_type: Option<String>,
        /// PCCS URL used to fetch collateral bundled with generated
        /// attestations. Defaults to Intel PCS.
        #[arg(long, env = "PCCS_URL")]
        pccs_url: Option<String>,
    },
    Client {
        /// Socket address of a attestation provider server
        server_addr: SocketAddr,
        /// Optional path to file containing JSON measurements to be
        /// enforced on the remote party
        #[arg(long, global = true, env = "MEASUREMENTS_FILE")]
        measurements_file: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let level_filter = if cli.log_debug { LevelFilter::DEBUG } else { LevelFilter::WARN };

    let env_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(level_filter.into())
        .from_env_lossy();

    let subscriber = tracing_subscriber::fmt::Subscriber::builder().with_env_filter(env_filter);

    if cli.log_json {
        subscriber.json().init();
    } else {
        subscriber.pretty().init();
    }

    if cli.log_dcap_quote {
        tokio::fs::create_dir_all("quotes").await?;
    }

    match cli.command {
        CliCommand::Server { listen_addr, server_attestation_type, pccs_url } => {
            let none_requested = server_attestation_type.as_deref() == Some("none");
            let attestation_generator = AttestationGenerator::new_with_detection_and_pccs_url(
                server_attestation_type,
                None,
                pccs_url,
            )?;

            if attestation_generator.attestation_type == AttestationType::None && !none_requested {
                anyhow::bail!(
                    "Failed to detect attestation type. To run without attestation, pass --server-attestation-type none"
                );
            }

            let listener = TcpListener::bind(listen_addr).await?;

            println!("Listening on {}", listener.local_addr()?);
            attestation_provider_server(listener, attestation_generator).await?;
        }
        CliCommand::Client { server_addr, measurements_file } => {
            let measurement_policy = match measurements_file {
                Some(measurements_file) => MeasurementPolicy::from_file(measurements_file).await?,
                None => MeasurementPolicy::accept_anything(),
            };

            let attestation_verifier =
                AttestationVerifier::new(measurement_policy, None, cli.log_dcap_quote, false);

            let attestation_message =
                attestation_provider_client(server_addr, attestation_verifier).await?;

            println!("{attestation_message:?}")
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_accepts_pccs_url() {
        let cli = Cli::try_parse_from([
            "attestation-provider-server",
            "server",
            "--server-attestation-type",
            "dcap-tdx",
            "--pccs-url",
            "http://127.0.0.1:8081",
        ])
        .unwrap();

        let CliCommand::Server { pccs_url, .. } = cli.command else {
            panic!("expected server command");
        };
        assert_eq!(pccs_url.as_deref(), Some("http://127.0.0.1:8081"));
    }
}
