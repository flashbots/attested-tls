use std::{
    sync::{Arc, OnceLock},
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
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    runtime::Runtime,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const PAYLOAD_BYTES: usize = 512 * 1024;
const DUPLEX_BUFFER_BYTES: usize = 64 * 1024;
const LATENCY_RANDOM_MIN_BYTES: usize = 64;
const LATENCY_RANDOM_MAX_BYTES: usize = 65535;
const LATENCY_RANDOM_SEED: u64 = 0xA11C_E5EE_D15C_A11C;

#[derive(Clone, Copy)]
struct CipherProfile {
    name: &'static str,
    suite: SupportedCipherSuite,
}

const CIPHER_PROFILES: [CipherProfile; 3] = [
    CipherProfile { name: "tls13_aes_128_gcm_sha256", suite: TLS13_AES_128_GCM_SHA256 },
    CipherProfile { name: "tls13_aes_256_gcm_sha384", suite: TLS13_AES_256_GCM_SHA384 },
    CipherProfile { name: "tls13_chacha20_poly1305_sha256", suite: TLS13_CHACHA20_POLY1305_SHA256 },
];

fn ensure_crypto_provider_installed() {
    static PROVIDER: OnceLock<()> = OnceLock::new();
    PROVIDER.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn test_tls_config_pair(cipher_suite: SupportedCipherSuite) -> (ServerConfig, ClientConfig) {
    ensure_crypto_provider_installed();

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

fn make_nested_endpoints(
    cipher_suite: SupportedCipherSuite,
) -> (NestingTlsAcceptor, NestingTlsConnector) {
    let (outer_server, outer_client) = test_tls_config_pair(cipher_suite);
    let (inner_server, inner_client) = test_tls_config_pair(cipher_suite);
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

fn benchmark(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();

    for profile in CIPHER_PROFILES {
        let payload = vec![0xAB; PAYLOAD_BYTES];
        let latency_payload = vec![0xCD; LATENCY_RANDOM_MAX_BYTES];
        let (single_server, single_client) = test_tls_config_pair(profile.suite);
        let (nested_acceptor, nested_connector) = make_nested_endpoints(profile.suite);

        let single_server = Arc::new(single_server);
        let single_client = Arc::new(single_client);

        // handshake latency
        {
            let mut group = c.benchmark_group(format!("tls_handshake_latency/{}", profile.name));

            group.bench_function("1_tls", |b| {
                b.iter(|| {
                    runtime.block_on(async {
                        let (client_io, server_io) = duplex(DUPLEX_BUFFER_BYTES);

                        let acceptor = TlsAcceptor::from(single_server.clone());
                        let connector = TlsConnector::from(single_client.clone());

                        let server = tokio::spawn(async move {
                            let _server_stream = acceptor.accept(server_io).await.unwrap();
                        });

                        let domain = ServerName::try_from("localhost").unwrap();
                        let _client_stream = connector.connect(domain, client_io).await.unwrap();

                        server.await.unwrap();
                    });
                });
            });

            group.bench_function("2_tls", |b| {
                b.iter(|| {
                    runtime.block_on(async {
                        let (client_io, server_io) = duplex(DUPLEX_BUFFER_BYTES);
                        let nested_acceptor = nested_acceptor.clone();
                        let nested_connector = nested_connector.clone();

                        let server = tokio::spawn(async move {
                            let _server_stream = nested_acceptor.accept(server_io).await.unwrap();
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
            let mut group = c.benchmark_group(format!("tls_latency_per_byte/{}", profile.name));
            let mut rand_state_0_tls = LATENCY_RANDOM_SEED;
            let mut rand_state_1_tls = LATENCY_RANDOM_SEED ^ 0x1111_1111_1111_1111;
            let mut rand_state_2_tls = LATENCY_RANDOM_SEED ^ 0x2222_2222_2222_2222;

            group.bench_function("0_tls", |b| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let rand = next_random_u64(&mut rand_state_0_tls) as usize;
                        let size = LATENCY_RANDOM_MIN_BYTES +
                            (rand % (LATENCY_RANDOM_MAX_BYTES - LATENCY_RANDOM_MIN_BYTES + 1));

                        let per_byte_latency = runtime.block_on(async {
                            let (mut client_io, mut server_io) = duplex(DUPLEX_BUFFER_BYTES);

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
                            (rand % (LATENCY_RANDOM_MAX_BYTES - LATENCY_RANDOM_MIN_BYTES + 1));

                        let per_byte_latency = runtime.block_on(async {
                            let (client_io, server_io) = duplex(DUPLEX_BUFFER_BYTES);

                            let acceptor = TlsAcceptor::from(single_server.clone());
                            let connector = TlsConnector::from(single_client.clone());

                            let server = tokio::spawn(async move {
                                let mut server_stream = acceptor.accept(server_io).await.unwrap();
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
                            client_stream.write_all(&(size as u32).to_le_bytes()).await.unwrap();
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
                            (rand % (LATENCY_RANDOM_MAX_BYTES - LATENCY_RANDOM_MIN_BYTES + 1));

                        let per_byte_latency = runtime.block_on(async {
                            let (client_io, server_io) = duplex(DUPLEX_BUFFER_BYTES);
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
                            client_stream.write_all(&(size as u32).to_le_bytes()).await.unwrap();
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
            let mut group = c.benchmark_group(format!("tls_throughput/{}", profile.name));
            group.throughput(Throughput::Bytes(PAYLOAD_BYTES as u64));

            group.bench_function("0_tls", |b| {
                b.iter(|| {
                    runtime.block_on(async {
                        let (mut client_io, mut server_io) = duplex(DUPLEX_BUFFER_BYTES);

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
                        let (client_io, server_io) = duplex(DUPLEX_BUFFER_BYTES);

                        let acceptor = TlsAcceptor::from(single_server.clone());
                        let connector = TlsConnector::from(single_client.clone());

                        let server = tokio::spawn(async move {
                            let mut server_stream = acceptor.accept(server_io).await.unwrap();
                            let mut received = vec![0_u8; PAYLOAD_BYTES];
                            server_stream.read_exact(&mut received).await.unwrap();
                        });

                        let domain = ServerName::try_from("localhost").unwrap();
                        let mut client_stream = connector.connect(domain, client_io).await.unwrap();
                        client_stream.write_all(&payload).await.unwrap();
                        client_stream.flush().await.unwrap();

                        server.await.unwrap();
                    });
                });
            });

            group.bench_function("2_tls", |b| {
                b.iter(|| {
                    runtime.block_on(async {
                        let (client_io, server_io) = duplex(DUPLEX_BUFFER_BYTES);
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

criterion_group!(benches, benchmark);
criterion_main!(benches);
