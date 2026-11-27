use std::path::PathBuf;

use attestation::{AttestationType, AttestationVerifier, measurements::MeasurementPolicy};
use attestation_provider_server::{
    AttestationGenerator,
    ProviderSocket,
    attestation_provider_client,
    attestation_provider_server,
};
use clap::{Parser, Subcommand, ValueEnum};
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
    /// Filesystem socket used by both server and client
    #[arg(
        long,
        global = true,
        env = "ATTESTATION_PROVIDER_SOCKET",
        default_value = "/run/attestation-provider/attestation.sock"
    )]
    socket_path: PathBuf,
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
        /// Type of attestation to generate
        #[arg(long, value_enum)]
        server_attestation_type: QuoteType,
    },
    Client {
        /// Optional path to file containing JSON measurements to be
        /// enforced on the remote party
        #[arg(long, global = true, env = "MEASUREMENTS_FILE")]
        measurements_file: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum QuoteType {
    #[value(alias = "qemu-tdx")]
    DcapTdx,
    GcpTdx,
}

impl From<QuoteType> for AttestationType {
    fn from(quote_type: QuoteType) -> Self {
        match quote_type {
            QuoteType::DcapTdx => Self::DcapTdx,
            QuoteType::GcpTdx => Self::GcpTdx,
        }
    }
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
        CliCommand::Server { server_attestation_type } => {
            let attestation_generator = AttestationGenerator::new(server_attestation_type.into())?;
            let socket = ProviderSocket::bind(&cli.socket_path)?;
            println!("Listening on {}", cli.socket_path.display());
            tokio::select! {
                result = attestation_provider_server(&socket.listener, attestation_generator) => result?,
                _ = shutdown_signal() => {},
            }
            drop(socket);
        }
        CliCommand::Client { measurements_file } => {
            let measurement_policy = match measurements_file {
                Some(measurements_file) => MeasurementPolicy::from_file(measurements_file).await?,
                None => MeasurementPolicy::accept_anything(),
            };

            let attestation_verifier = AttestationVerifier::builder(measurement_policy)
                .with_dump_dcap_quotes(cli.log_dcap_quote)
                .build();

            let attestation_message =
                attestation_provider_client(cli.socket_path, attestation_verifier).await?;

            println!("{attestation_message:?}")
        }
    }

    Ok(())
}

async fn shutdown_signal() {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("Install SIGTERM handler");
    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_requires_a_quote_type() {
        assert!(Cli::try_parse_from(["provider", "server"]).is_err());
        for value in ["none", "auto"] {
            assert!(
                Cli::try_parse_from(["provider", "server", "--server-attestation-type", value])
                    .is_err()
            );
        }
        for (value, expected) in [
            ("dcap-tdx", QuoteType::DcapTdx),
            ("qemu-tdx", QuoteType::DcapTdx),
            ("gcp-tdx", QuoteType::GcpTdx),
        ] {
            let cli =
                Cli::try_parse_from(["provider", "server", "--server-attestation-type", value])
                    .unwrap();
            assert!(matches!(
                cli.command,
                CliCommand::Server { server_attestation_type } if server_attestation_type == expected
            ));
        }
    }
}
