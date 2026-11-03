use std::{os::fd::AsFd, path::PathBuf};

use attestation::{
    AttestationGenerator,
    AttestationType,
    AttestationVerifier,
    measurements::MeasurementPolicy,
};
use attestation_provider_server::{
    ProviderSocket,
    attestation_provider_client,
    attestation_provider_server,
};
use clap::{Parser, Subcommand};
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
        /// Type of attestation to present (will attempt to detect if
        /// not given)
        #[arg(long)]
        server_attestation_type: Option<String>,
    },
    Client {
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
        CliCommand::Server { server_attestation_type } => {
            let none_requested = server_attestation_type.as_deref() == Some("none");
            let attestation_generator =
                AttestationGenerator::new_with_detection(server_attestation_type, None)?;

            if attestation_generator.attestation_type == AttestationType::None && !none_requested {
                anyhow::bail!(
                    "Failed to detect attestation type. To run without attestation, pass --server-attestation-type none"
                );
            }

            let socket = ProviderSocket::bind(&cli.socket_path)?;
            println!("Listening on {}", cli.socket_path.display());
            let listener = std::os::unix::net::UnixListener::from(
                socket.listener.as_fd().try_clone_to_owned()?,
            );
            let listener = tokio::net::UnixListener::from_std(listener)?;
            tokio::select! {
                result = attestation_provider_server(listener, attestation_generator) => result?,
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
