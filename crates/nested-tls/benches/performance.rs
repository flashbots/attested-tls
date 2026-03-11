use std::{
    sync::{Arc, OnceLock},
    thread,
    time::{Duration, Instant},
};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use nested_tls::{client::NestingTlsConnector, server::NestingTlsAcceptor};
use rustls::{
    ClientConfig,
    RootCertStore,
    ServerConfig,
    SupportedCipherSuite,
    crypto::aws_lc_rs::cipher_suite::{
        TLS13_AES_128_GCM_SHA256,
        TLS13_AES_256_GCM_SHA384,
        TLS13_CHACHA20_POLY1305_SHA256,
    },
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, duplex},
    runtime::Runtime,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

// ---------------------------------------------------------------------

const PAYLOAD_BYTES: usize = 512 * 1024;
const DUPLEX_BUFFER_BYTES: usize = 64 * 1024;
const LATENCY_RANDOM_MIN_BYTES: usize = 64;
const LATENCY_RANDOM_MAX_BYTES: usize = 65535;
const LATENCY_RANDOM_SEED: u64 = 0xA11C_E5EE_D15C_A11C;

const CIPHER_PROFILES: [CipherProfile; 3] = [
    CipherProfile { name: "tls13_aes_128_gcm_sha256", suite: TLS13_AES_128_GCM_SHA256 },
    CipherProfile { name: "tls13_aes_256_gcm_sha384", suite: TLS13_AES_256_GCM_SHA384 },
    CipherProfile { name: "tls13_chacha20_poly1305_sha256", suite: TLS13_CHACHA20_POLY1305_SHA256 },
];

const NETWORK_LATENCY_PROFILES: [NetworkLatencyProfile; 3] = [
    NetworkLatencyProfile { name: "0ms", delay: None },
    NetworkLatencyProfile { name: "1ms", delay: Some(Duration::from_millis(1)) },
    NetworkLatencyProfile { name: "5ms", delay: Some(Duration::from_millis(5)) },
];

// NetworkLatencyProfile -----------------------------------------------
#[derive(Clone, Copy)]
struct NetworkLatencyProfile {
    name: &'static str,
    delay: Option<Duration>,
}

// CipherProfile -------------------------------------------------------

#[derive(Clone, Copy)]
struct CipherProfile {
    name: &'static str,
    suite: SupportedCipherSuite,
}

// helpers -------------------------------------------------------------

fn install_crypto_provider() {
    static PROVIDER: OnceLock<()> = OnceLock::new();
    PROVIDER.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn config_pair(cipher_suite: SupportedCipherSuite) -> (ServerConfig, ClientConfig) {
    install_crypto_provider();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der: CertificateDer<'static> = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites = vec![cipher_suite];
    let provider = Arc::new(provider);

    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(cert_der).unwrap();

    let client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (server, client)
}

fn nested_endpoints(
    cipher_suite: SupportedCipherSuite,
) -> (NestingTlsAcceptor, NestingTlsConnector) {
    let (outer_server, outer_client) = config_pair(cipher_suite);
    let (inner_server, inner_client) = config_pair(cipher_suite);
    let acceptor = NestingTlsAcceptor::new(Arc::new(outer_server), Arc::new(inner_server));
    let connector = NestingTlsConnector::new(Arc::new(outer_client), Arc::new(inner_client));
    (acceptor, connector)
}

fn next_random_u64(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

async fn relay_with_latency<R, W>(
    mut reader: R,
    mut writer: W,
    delay: Duration,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0_u8; 16 * 1024];
    loop {
        let bytes_read = reader.read(&mut buf).await?;
        if bytes_read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }

        thread::sleep(delay);
        writer.write_all(&buf[..bytes_read]).await?;
        writer.flush().await?;
    }
}

fn network_duplex(delay: Option<Duration>) -> (DuplexStream, DuplexStream) {
    match delay {
        None => duplex(DUPLEX_BUFFER_BYTES),
        Some(delay) => {
            let (client_io, network_client) = duplex(DUPLEX_BUFFER_BYTES);
            let (network_server, server_io) = duplex(DUPLEX_BUFFER_BYTES);

            tokio::spawn(async move {
                let (nc_read, nc_write) = tokio::io::split(network_client);
                let (ns_read, ns_write) = tokio::io::split(network_server);

                let client_to_server = tokio::spawn(relay_with_latency(nc_read, ns_write, delay));
                let server_to_client = tokio::spawn(relay_with_latency(ns_read, nc_write, delay));

                let _ = tokio::try_join!(client_to_server, server_to_client);
            });

            (client_io, server_io)
        }
    }
}

// benchmark -----------------------------------------------------------

criterion_main!(benches);

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(1000))
        .measurement_time(Duration::from_millis(30000))
        .sample_size(20);
    targets = benchmark
}

fn benchmark(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();

    for profile in CIPHER_PROFILES {
        let payload = vec![0xAB; PAYLOAD_BYTES];
        let latency_payload = vec![0xCD; LATENCY_RANDOM_MAX_BYTES];
        let (single_server, single_client) = config_pair(profile.suite);
        let (nested_acceptor, nested_connector) = nested_endpoints(profile.suite);

        let single_server = Arc::new(single_server);
        let single_client = Arc::new(single_client);

        for network_latency in NETWORK_LATENCY_PROFILES {
            // handshake latency
            {
                let mut group = c.benchmark_group(format!(
                    "tls_handshake_latency/{}/{}",
                    profile.name, network_latency.name
                ));

                group.bench_function("1_tls", |b| {
                    b.iter(|| {
                        runtime.block_on(async {
                            let (client_io, server_io) = network_duplex(network_latency.delay);

                            let acceptor = TlsAcceptor::from(single_server.clone());
                            let connector = TlsConnector::from(single_client.clone());

                            let server = tokio::spawn(async move {
                                let _server_stream = acceptor.accept(server_io).await.unwrap();
                            });

                            let domain = ServerName::try_from("localhost").unwrap();
                            let _client_stream =
                                connector.connect(domain, client_io).await.unwrap();

                            server.await.unwrap();
                        });
                    });
                });

                group.bench_function("2_tls", |b| {
                    b.iter(|| {
                        runtime.block_on(async {
                            let (client_io, server_io) = network_duplex(network_latency.delay);
                            let nested_acceptor = nested_acceptor.clone();
                            let nested_connector = nested_connector.clone();

                            let server = tokio::spawn(async move {
                                let _server_stream =
                                    nested_acceptor.accept(server_io).await.unwrap();
                            });

                            let domain = ServerName::try_from("localhost").unwrap();
                            let _client_stream =
                                nested_connector.connect(domain, client_io).await.unwrap();

                            server.await.unwrap();
                        });
                    });
                });

                group.finish();
            }

            // latency per byte
            {
                let mut group = c.benchmark_group(format!(
                    "tls_latency_per_byte/{}/{}",
                    profile.name, network_latency.name
                ));
                let mut rand_state_0_tls = LATENCY_RANDOM_SEED;
                let mut rand_state_1_tls = LATENCY_RANDOM_SEED ^ 0x1111_1111_1111_1111;
                let mut rand_state_2_tls = LATENCY_RANDOM_SEED ^ 0x2222_2222_2222_2222;

                group.bench_function("0_tls", |b| {
                    b.iter_custom(|iters| {
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            let rand = next_random_u64(&mut rand_state_0_tls) as usize;
                            let size = LATENCY_RANDOM_MIN_BYTES +
                                (rand %
                                    (LATENCY_RANDOM_MAX_BYTES - LATENCY_RANDOM_MIN_BYTES + 1));

                            let per_byte_latency = runtime.block_on(async {
                                let (mut client_io, mut server_io) =
                                    network_duplex(network_latency.delay);

                                let server = tokio::spawn(async move {
                                    let mut size_buf = [0_u8; 4];
                                    server_io.read_exact(&mut size_buf).await.unwrap();
                                    let incoming_size = u32::from_le_bytes(size_buf) as usize;
                                    let mut received = vec![0_u8; incoming_size];
                                    server_io.read_exact(&mut received).await.unwrap();
                                });

                                let start = Instant::now();
                                client_io.write_all(&(size as u32).to_le_bytes()).await.unwrap();
                                client_io.write_all(&latency_payload[..size]).await.unwrap();
                                client_io.flush().await.unwrap();
                                server.await.unwrap();

                                start.elapsed() / ((size + 4) as u32)
                            });

                            total += per_byte_latency;
                        }
                        total
                    });
                });

                group.bench_function("1_tls", |b| {
                    b.iter_custom(|iters| {
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            let rand = next_random_u64(&mut rand_state_1_tls) as usize;
                            let size = LATENCY_RANDOM_MIN_BYTES +
                                (rand %
                                    (LATENCY_RANDOM_MAX_BYTES - LATENCY_RANDOM_MIN_BYTES + 1));

                            let per_byte_latency = runtime.block_on(async {
                                let (client_io, server_io) = network_duplex(network_latency.delay);

                                let acceptor = TlsAcceptor::from(single_server.clone());
                                let connector = TlsConnector::from(single_client.clone());

                                let server = tokio::spawn(async move {
                                    let mut server_stream =
                                        acceptor.accept(server_io).await.unwrap();
                                    let mut size_buf = [0_u8; 4];
                                    server_stream.read_exact(&mut size_buf).await.unwrap();
                                    let incoming_size = u32::from_le_bytes(size_buf) as usize;
                                    let mut received = vec![0_u8; incoming_size];
                                    server_stream.read_exact(&mut received).await.unwrap();
                                });

                                let domain = ServerName::try_from("localhost").unwrap();
                                let mut client_stream =
                                    connector.connect(domain, client_io).await.unwrap();

                                let start = Instant::now();
                                client_stream
                                    .write_all(&(size as u32).to_le_bytes())
                                    .await
                                    .unwrap();
                                client_stream.write_all(&latency_payload[..size]).await.unwrap();
                                client_stream.flush().await.unwrap();
                                server.await.unwrap();

                                start.elapsed() / ((size + 4) as u32)
                            });

                            total += per_byte_latency;
                        }
                        total
                    });
                });

                group.bench_function("2_tls", |b| {
                    b.iter_custom(|iters| {
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            let rand = next_random_u64(&mut rand_state_2_tls) as usize;
                            let size = LATENCY_RANDOM_MIN_BYTES +
                                (rand %
                                    (LATENCY_RANDOM_MAX_BYTES - LATENCY_RANDOM_MIN_BYTES + 1));

                            let per_byte_latency = runtime.block_on(async {
                                let (client_io, server_io) = network_duplex(network_latency.delay);
                                let nested_acceptor = nested_acceptor.clone();
                                let nested_connector = nested_connector.clone();

                                let server = tokio::spawn(async move {
                                    let mut server_stream =
                                        nested_acceptor.accept(server_io).await.unwrap();
                                    let mut size_buf = [0_u8; 4];
                                    server_stream.read_exact(&mut size_buf).await.unwrap();
                                    let incoming_size = u32::from_le_bytes(size_buf) as usize;
                                    let mut received = vec![0_u8; incoming_size];
                                    server_stream.read_exact(&mut received).await.unwrap();
                                });

                                let domain = ServerName::try_from("localhost").unwrap();
                                let mut client_stream =
                                    nested_connector.connect(domain, client_io).await.unwrap();

                                let start = Instant::now();
                                client_stream
                                    .write_all(&(size as u32).to_le_bytes())
                                    .await
                                    .unwrap();
                                client_stream.write_all(&latency_payload[..size]).await.unwrap();
                                client_stream.flush().await.unwrap();
                                server.await.unwrap();

                                start.elapsed() / ((size + 4) as u32)
                            });

                            total += per_byte_latency;
                        }
                        total
                    });
                });

                group.finish();
            }

            // throughput
            {
                let mut group = c.benchmark_group(format!(
                    "tls_throughput/{}/{}",
                    profile.name, network_latency.name
                ));
                group.throughput(Throughput::Bytes(PAYLOAD_BYTES as u64));

                group.bench_function("0_tls", |b| {
                    b.iter(|| {
                        runtime.block_on(async {
                            let (mut client_io, mut server_io) =
                                network_duplex(network_latency.delay);

                            let server = tokio::spawn(async move {
                                let mut received = vec![0_u8; PAYLOAD_BYTES];
                                server_io.read_exact(&mut received).await.unwrap();
                            });

                            client_io.write_all(&payload).await.unwrap();
                            client_io.flush().await.unwrap();

                            server.await.unwrap();
                        });
                    });
                });

                group.bench_function("1_tls", |b| {
                    b.iter(|| {
                        runtime.block_on(async {
                            let (client_io, server_io) = network_duplex(network_latency.delay);

                            let acceptor = TlsAcceptor::from(single_server.clone());
                            let connector = TlsConnector::from(single_client.clone());

                            let server = tokio::spawn(async move {
                                let mut server_stream = acceptor.accept(server_io).await.unwrap();
                                let mut received = vec![0_u8; PAYLOAD_BYTES];
                                server_stream.read_exact(&mut received).await.unwrap();
                            });

                            let domain = ServerName::try_from("localhost").unwrap();
                            let mut client_stream =
                                connector.connect(domain, client_io).await.unwrap();
                            client_stream.write_all(&payload).await.unwrap();
                            client_stream.flush().await.unwrap();

                            server.await.unwrap();
                        });
                    });
                });

                group.bench_function("2_tls", |b| {
                    b.iter(|| {
                        runtime.block_on(async {
                            let (client_io, server_io) = network_duplex(network_latency.delay);
                            let nested_acceptor = nested_acceptor.clone();
                            let nested_connector = nested_connector.clone();

                            let server = tokio::spawn(async move {
                                let mut server_stream =
                                    nested_acceptor.accept(server_io).await.unwrap();
                                let mut received = vec![0_u8; PAYLOAD_BYTES];
                                server_stream.read_exact(&mut received).await.unwrap();
                            });

                            let domain = ServerName::try_from("localhost").unwrap();
                            let mut client_stream =
                                nested_connector.connect(domain, client_io).await.unwrap();
                            client_stream.write_all(&payload).await.unwrap();
                            client_stream.flush().await.unwrap();

                            server.await.unwrap();
                        });
                    });
                });

                group.finish();
            }
        }
    }
}
