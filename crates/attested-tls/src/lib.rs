use std::{
    fmt,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

pub use attestation::{
    AttestationExchangeMessage,
    AttestationGenerator,
    AttestationType,
    AttestationVerifier,
};
use ra_tls::{
    attestation::{Attestation, AttestationQuote, VersionedAttestation},
    cert::{CaCert, CertRequest},
    rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256},
};
use rustls::{
    DigitallySignedStruct,
    DistinguishedName,
    RootCertStore,
    SignatureScheme,
    client::{
        ResolvesClientCert,
        VerifierBuilderError,
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::CryptoProvider,
    pki_types::{
        CertificateDer,
        PrivateKeyDer,
        PrivatePkcs8KeyDer,
        ServerName,
        UnixTime,
        pem::PemObject,
    },
    server::{
        ResolvesServerCert,
        WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::{CertifiedKey, SigningKey},
};
use sha2::{Digest as _, Sha512};
use thiserror::Error;
use x509_parser::oid_registry::Oid;

/// The length of time a certificate is valid for
#[cfg(not(test))]
const CERTIFICATE_VALIDITY: Duration = Duration::from_secs(30 * 60);
#[cfg(test)]
const CERTIFICATE_VALIDITY: Duration = Duration::from_secs(4);

/// How long before expiry to renew certificate
#[cfg(not(test))]
const CERTIFICATE_RENEWAL_LEAD_TIME: Duration = Duration::from_secs(5 * 60);
#[cfg(test)]
const CERTIFICATE_RENEWAL_LEAD_TIME: Duration = Duration::from_secs(2);

/// How long to wait before re-trying certificate renewal on failure
#[cfg(not(test))]
const CERTIFICATE_RENEWAL_RETRY_DELAY: Duration = Duration::from_secs(30);
#[cfg(test)]
const CERTIFICATE_RENEWAL_RETRY_DELAY: Duration = Duration::from_millis(200);

/// A TLS certificate resolver which includes an attestation as a
/// certificate extension
#[derive(Clone)]
pub struct AttestedCertificateResolver {
    /// Cloneable inner state
    state: Arc<ResolverState>,
}

impl fmt::Debug for AttestedCertificateResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttestedCertificateResolver").finish_non_exhaustive()
    }
}

/// Internal state used by the resolver and its renewal loop
struct ResolverState {
    /// The private TLS key in a format ready to be
    /// used in handshake
    key: Arc<dyn SigningKey>,
    /// Optional CA used to sign leaf certificates - default is self-signed
    ca: Option<Arc<CaCert>>,
    /// The private TLS key in a format ready to be used by to sign
    /// certificates if no CA is used
    key_pair_der: Vec<u8>,
    /// The current certificate with attestation
    certificate: RwLock<Vec<CertificateDer<'static>>>,
    /// Attestation generator used when renewing ceritifcate
    attestation_generator: AttestationGenerator,
    /// Primary DNS name used as certificate subject / common name.
    primary_name: String,
    /// DNS subject alternative names, including the primary name.
    subject_alt_names: Vec<String>,
}

impl AttestedCertificateResolver {
    /// Create a certificate resolver with a given attestation generator
    /// A private cerificate authority can also be given - otherwise
    /// certificates will be self signed
    pub async fn new(
        attestation_generator: AttestationGenerator,
        ca: Option<CaCert>,
        primary_name: String,
        subject_alt_names: Vec<String>,
    ) -> Result<Self, AttestedTlsError> {
        Self::new_with_provider(
            attestation_generator,
            ca,
            primary_name,
            subject_alt_names,
            default_crypto_provider()?,
        )
        .await
    }

    /// Also provide a crypto provider
    pub async fn new_with_provider(
        attestation_generator: AttestationGenerator,
        ca: Option<CaCert>,
        primary_name: String,
        subject_alt_names: Vec<String>,
        provider: Arc<CryptoProvider>,
    ) -> Result<Self, AttestedTlsError> {
        debug_assert!(CERTIFICATE_RENEWAL_LEAD_TIME < CERTIFICATE_VALIDITY);
        let subject_alt_names =
            normalized_subject_alt_names(primary_name.as_str(), subject_alt_names);

        // Generate keypair
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let key_pair_der = key_pair.serialize_der();
        let key = Self::load_signing_key(&key_pair, provider)?;

        // Generate initial attested certificate
        let certificate = Self::issue_ra_cert_chain(
            &key_pair,
            ca.as_ref(),
            primary_name.as_str(),
            &subject_alt_names,
            &attestation_generator,
        )
        .await?;

        let state = Arc::new(ResolverState {
            key,
            certificate: RwLock::new(certificate),
            ca: ca.map(Arc::new),
            key_pair_der,
            attestation_generator,
            primary_name,
            subject_alt_names,
        });

        // Start a loop which will periodically renew the certificate
        Self::spawn_renewal_task(Arc::downgrade(&state));

        Ok(Self { state })
    }

    /// Create an attested certificate chain - either self-signed or with
    /// the provided CA
    async fn issue_ra_cert_chain(
        key: &KeyPair,
        ca: Option<&CaCert>,
        primary_name: &str,
        subject_alt_names: &[String],
        attestation_generator: &AttestationGenerator,
    ) -> Result<Vec<CertificateDer<'static>>, AttestedTlsError> {
        let pubkey = key.public_key_der();
        let now = SystemTime::now();
        let not_after = now + CERTIFICATE_VALIDITY;

        let attestation =
            Self::create_attestation_payload(pubkey, now, not_after, attestation_generator).await?;

        let cert_request = CertRequest::builder()
            .key(key)
            .subject(primary_name)
            .alt_names(subject_alt_names)
            .not_before(now)
            .not_after(not_after)
            .usage_server_auth(true)
            .usage_client_auth(true)
            .attestation(&attestation)
            .build();

        let leaf = match ca {
            Some(ca) => ca.sign(cert_request).map_err(AttestedTlsError::RaTls)?,
            None => cert_request.self_signed().map_err(AttestedTlsError::RaTls)?,
        };

        let mut chain = vec![leaf.der().to_vec().into()];
        if let Some(ca) = ca {
            chain.push(CertificateDer::from_pem_slice(ca.pem_cert.as_bytes())?);
        }

        Ok(chain)
    }

    /// Get keypair into a format ready to be used in handshakes
    fn load_signing_key(
        key_pair: &KeyPair,
        provider: Arc<CryptoProvider>,
    ) -> Result<Arc<dyn SigningKey>, AttestedTlsError> {
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        provider.key_provider.load_private_key(private_key).map_err(AttestedTlsError::SigningKey)
    }

    /// Create an attestation, and format it to be used in certificate
    /// extension
    async fn create_attestation_payload(
        pubkey: Vec<u8>,
        not_before: SystemTime,
        not_after: SystemTime,
        attestation_generator: &AttestationGenerator,
    ) -> Result<VersionedAttestation, AttestedTlsError> {
        let report_data = create_report_data(pubkey, not_before, not_after)?;
        let attestation = attestation_generator.generate_attestation(report_data).await.unwrap();
        Ok(VersionedAttestation::V0 {
            attestation: Attestation {
                quote: ra_tls::attestation::AttestationQuote::DstackTdx(
                    ra_tls::attestation::TdxQuote {
                        quote: serde_json::to_vec(&attestation).unwrap(),
                        event_log: Vec::new(),
                    },
                ),
                runtime_events: Vec::new(),
                report_data,
                config: String::new(),
                report: (),
            },
        })
    }

    /// Start a loop which periodically renews the certificate
    fn spawn_renewal_task(state: std::sync::Weak<ResolverState>) {
        tokio::spawn(async move {
            let renewal_delay = CERTIFICATE_VALIDITY - CERTIFICATE_RENEWAL_LEAD_TIME;

            loop {
                tokio::time::sleep(renewal_delay).await;
                let Some(current) = state.upgrade() else {
                    tracing::warn!("Resolver has been dropped - stopping renewal loop");
                    break;
                };

                let key_pair = match KeyPair::try_from(current.key_pair_der.clone()) {
                    Ok(key_pair) => key_pair,
                    Err(e) => {
                        tracing::error!("Failed to load keypair: {e}");
                        tokio::time::sleep(CERTIFICATE_RENEWAL_RETRY_DELAY).await;
                        continue;
                    }
                };

                match Self::issue_ra_cert_chain(
                    &key_pair,
                    current.ca.as_deref(),
                    current.primary_name.as_str(),
                    &current.subject_alt_names,
                    &current.attestation_generator,
                )
                .await
                {
                    Ok(certificate) => {
                        *current.certificate.write().expect("Certificate lock poisoned") =
                            certificate;
                    }
                    Err(e) => {
                        tracing::error!("Failed to renew attested certificate: {e}");
                        tokio::time::sleep(CERTIFICATE_RENEWAL_RETRY_DELAY).await;
                    }
                }
            }
        });
    }
}

impl ResolvesServerCert for AttestedCertificateResolver {
    fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current_certified_key()
    }
}

impl ResolvesClientCert for AttestedCertificateResolver {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        self.current_certified_key()
    }

    fn has_certs(&self) -> bool {
        !self.state.certificate.read().expect("certificate lock poisoned").is_empty()
    }
}

impl AttestedCertificateResolver {
    fn current_certified_key(&self) -> Option<Arc<CertifiedKey>> {
        let certificate = self.state.certificate.read().expect("certificate lock poisoned").clone();
        Some(Arc::new(CertifiedKey::new(certificate, self.state.key.clone())))
    }
}

fn default_crypto_provider() -> Result<Arc<CryptoProvider>, AttestedTlsError> {
    CryptoProvider::get_default().cloned().ok_or(AttestedTlsError::CryptoProviderUnavailable)
}

fn normalized_subject_alt_names(primary_name: &str, subject_alt_names: Vec<String>) -> Vec<String> {
    let mut normalized = Vec::with_capacity(subject_alt_names.len() + 1);
    normalized.push(primary_name.to_string());

    for name in subject_alt_names {
        if !normalized.iter().any(|existing| existing == &name) {
            normalized.push(name);
        }
    }

    normalized
}

/// Make input data for the attestation by hashing together public key and
/// validity period
fn create_report_data(
    public_key: Vec<u8>,
    not_before: SystemTime,
    not_after: SystemTime,
) -> Result<[u8; 64], AttestedTlsError> {
    let not_before = not_before
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(AttestedTlsError::SystemTime)?
        .as_secs()
        .to_be_bytes();
    let not_after = not_after
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(AttestedTlsError::SystemTime)?
        .as_secs()
        .to_be_bytes();

    let mut hasher = Sha512::new();
    hasher.update(public_key);
    hasher.update(not_before);
    hasher.update(not_after);

    Ok(hasher.finalize().into())
}

#[derive(Debug)]
pub struct AttestedCertificateVerifier {
    server_inner: Arc<WebPkiServerVerifier>,
    client_inner: Arc<dyn ClientCertVerifier>,
    attestation_verifier: AttestationVerifier,
}

impl AttestedCertificateVerifier {
    pub fn new(
        root_store: RootCertStore,
        attestation_verifier: AttestationVerifier,
    ) -> Result<Self, AttestedTlsError> {
        Self::new_with_provider(root_store, attestation_verifier, default_crypto_provider()?)
    }

    pub fn new_with_provider(
        root_store: RootCertStore,
        attestation_verifier: AttestationVerifier,
        provider: Arc<CryptoProvider>,
    ) -> Result<Self, AttestedTlsError> {
        let root_store = Arc::new(root_store);
        let server_inner =
            WebPkiServerVerifier::builder_with_provider(root_store.clone(), provider.clone())
                .build()
                .map_err(AttestedTlsError::VerifierBuilder)?;
        let client_inner = WebPkiClientVerifier::builder_with_provider(root_store, provider)
            .build()
            .map_err(AttestedTlsError::VerifierBuilder)?;

        Ok(Self { server_inner, client_inner, attestation_verifier })
    }

    fn extract_custom_attestation_from_cert(
        cert: &CertificateDer<'_>,
    ) -> Result<AttestationExchangeMessage, rustls::Error> {
        // First try to parse using ra_tls which assumes DCAP
        if let Ok(Some(attestation)) = ra_tls::attestation::from_der(cert.as_ref()) &&
            let AttestationQuote::DstackTdx(tdx_quote) = attestation.quote
        {
            return Ok(AttestationExchangeMessage {
                attestation_type: AttestationType::DcapTdx,
                attestation: tdx_quote.quote,
            });
        }

        // If that fails, extract and parse the extension
        let (_, cert) = x509_parser::parse_x509_certificate(cert.as_ref()).unwrap();
        let oid = Oid::from(ra_tls::oids::PHALA_RATLS_TDX_QUOTE).unwrap();
        let ext = cert.get_extension_unique(&oid).unwrap().unwrap();
        let payload = yasna::parse_der(ext.value, |reader| reader.read_bytes()).unwrap();
        Ok(serde_json::from_slice(&payload).unwrap())
    }

    /// Given a certifcate, get the public key and validity period to check
    /// against attestation input
    fn expected_input_data_from_cert(cert: &CertificateDer<'_>) -> Result<[u8; 64], rustls::Error> {
        let (_, cert) = x509_parser::parse_x509_certificate(cert.as_ref()).unwrap();
        let not_before: u64 = cert
            .validity()
            .not_before
            .timestamp()
            .try_into()
            .map_err(|_| rustls::Error::General("invalid certificate not_before".into()))?;
        let not_after: u64 = cert
            .validity()
            .not_after
            .timestamp()
            .try_into()
            .map_err(|_| rustls::Error::General("invalid certificate not_after".into()))?;
        create_report_data(
            cert.public_key().raw.to_vec(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(not_before),
            SystemTime::UNIX_EPOCH + Duration::from_secs(not_after),
        )
        .map_err(|err| rustls::Error::General(err.to_string()))
    }

    /// Given a cerificate and the current time, check if it is currently
    /// valid
    fn verify_cert_time_validity(
        cert: &CertificateDer<'_>,
        now: UnixTime,
    ) -> Result<(), rustls::Error> {
        let (_, cert) = x509_parser::parse_x509_certificate(cert.as_ref()).unwrap();
        let now = now.as_secs();
        let not_before: u64 = cert
            .validity()
            .not_before
            .timestamp()
            .try_into()
            .map_err(|_| rustls::Error::General("invalid certificate not_before".into()))?;
        let not_after: u64 = cert
            .validity()
            .not_after
            .timestamp()
            .try_into()
            .map_err(|_| rustls::Error::General("invalid certificate not_after".into()))?;

        if now < not_before {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidYetContext {
                    time: UnixTime::since_unix_epoch(Duration::from_secs(now)),
                    not_before: UnixTime::since_unix_epoch(Duration::from_secs(not_before)),
                },
            ));
        }

        if now > not_after {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ExpiredContext {
                    time: UnixTime::since_unix_epoch(Duration::from_secs(now)),
                    not_after: UnixTime::since_unix_epoch(Duration::from_secs(not_after)),
                },
            ));
        }

        Ok(())
    }

    fn verify_attestation_binding(
        &self,
        end_entity: &CertificateDer<'_>,
    ) -> Result<(), rustls::Error> {
        let expected_input_data = Self::expected_input_data_from_cert(end_entity)?;
        let attestation = Self::extract_custom_attestation_from_cert(end_entity)?;

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.attestation_verifier
                    .verify_attestation(attestation, expected_input_data)
                    .await
                    .unwrap();
            })
        });

        Ok(())
    }
}

impl ServerCertVerifier for AttestedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.server_inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)) => {
                // handle self-signed certs differently
                Self::verify_cert_time_validity(end_entity, now)?;
            }
            Err(err) => return Err(err),
            Ok(_) => {}
        };
        self.verify_attestation_binding(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.server_inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.server_inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.server_inner.supported_verify_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.server_inner.root_hint_subjects()
    }
}

impl ClientCertVerifier for AttestedCertificateVerifier {
    fn offer_client_auth(&self) -> bool {
        self.client_inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.client_inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.client_inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        match self.client_inner.verify_client_cert(end_entity, intermediates, now) {
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)) => {
                Self::verify_cert_time_validity(end_entity, now)?;
            }
            Err(err) => return Err(err),
            Ok(_) => {}
        };
        self.verify_attestation_binding(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.client_inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.client_inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.client_inner.supported_verify_schemes()
    }
}

#[derive(Debug, Error)]
pub enum AttestedTlsError {
    #[error("Failed to generate certificate key pair: {0}")]
    CertificateKeyGeneration(#[source] rcgen::Error),
    #[error("Failed to build certificate parameters: {0}")]
    CertificateParams(#[source] rcgen::Error),
    #[error("Failed to self-sign certificate: {0}")]
    CertificateSigning(#[source] rcgen::Error),
    #[error("Failed to load signing key into rustls: {0}")]
    SigningKey(#[source] rustls::Error),
    #[error("Failed to build certificate verifier: {0}")]
    VerifierBuilder(#[source] VerifierBuilderError),
    #[error("Cetificate generation: {0}")]
    RcGen(#[from] ra_tls::rcgen::Error),
    #[error("RA-TLS: {0}")]
    RaTls(#[source] anyhow::Error),
    #[error("Rustls: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("Failed to parse PEM certificate: {0}")]
    Pem(#[from] rustls::pki_types::pem::Error),
    #[error("System time: {0}")]
    SystemTime(#[source] std::time::SystemTimeError),
    #[error("No rustls CryptoProvider is installed")]
    CryptoProviderUnavailable,
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, sync::Arc};

    use ra_tls::rcgen::{BasicConstraints, CertificateParams, IsCa};
    use rustls::{
        ClientConfig,
        ClientConnection,
        RootCertStore,
        ServerConfig,
        ServerConnection,
        crypto::aws_lc_rs,
    };

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn certificate_resolver_creates_initial_certificate() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let resolver = AttestedCertificateResolver::new_with_provider(
            AttestationGenerator::new(AttestationType::DcapTdx, None)
                .expect("mock generator construction should succeed"),
            None,
            "foo".to_string(),
            vec![],
            provider,
        )
        .await
        .expect("resolver construction should succeed");
        let certificate = resolver.state.certificate.read().expect("certificate lock poisoned");

        assert_eq!(certificate.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn server_and_client_configs_complete_a_handshake() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let server_name = "foo";
        let resolver = AttestedCertificateResolver::new_with_provider(
            AttestationGenerator::new(AttestationType::DcapTdx, None)
                .expect("mock generator construction should succeed"),
            None,
            server_name.to_string(),
            vec![],
            provider.clone(),
        )
        .await
        .expect("resolver construction should succeed");
        let server_certificate = resolver
            .state
            .certificate
            .read()
            .expect("certificate lock poisoned")
            .first()
            .expect("resolver should hold a certificate")
            .clone();

        let mut roots = RootCertStore::empty();
        roots.add(server_certificate).expect("resolver certificate should be trusted");

        let verifier = AttestedCertificateVerifier::new_with_provider(
            roots,
            AttestationVerifier::mock(),
            provider.clone(),
        )
        .expect("verifier construction should succeed");

        let server_config = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("server config should support default protocol versions")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        let client_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("client config should support default protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        let mut client = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from(server_name).expect("server name should be valid"),
        )
        .expect("client connection should be created");
        let mut server =
            ServerConnection::new(Arc::new(server_config)).expect("server connection should exist");

        while client.is_handshaking() || server.is_handshaking() {
            transfer_tls_client_to_server(&mut client, &mut server);
            transfer_tls_server_to_client(&mut server, &mut client);
        }

        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ca_signed_server_and_client_configs_complete_a_handshake() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let server_name = "foo";
        let ca = test_ca();
        let ca_cert = CertificateDer::from_pem_slice(ca.pem_cert.as_bytes())
            .expect("test CA PEM should parse");
        let resolver = AttestedCertificateResolver::new_with_provider(
            AttestationGenerator::new(AttestationType::DcapTdx, None)
                .expect("mock generator construction should succeed"),
            Some(ca),
            server_name.to_string(),
            vec![],
            provider.clone(),
        )
        .await
        .expect("resolver construction should succeed");
        let certificate_chain =
            resolver.state.certificate.read().expect("certificate lock poisoned").clone();

        assert_eq!(certificate_chain.len(), 2);

        let mut roots = RootCertStore::empty();
        roots.add(ca_cert).expect("CA certificate should be trusted");

        let verifier = AttestedCertificateVerifier::new_with_provider(
            roots,
            AttestationVerifier::mock(),
            provider.clone(),
        )
        .expect("verifier construction should succeed");

        let server_config = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("server config should support default protocol versions")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        let client_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("client config should support default protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        let mut client = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from(server_name).expect("server name should be valid"),
        )
        .expect("client connection should be created");
        let mut server =
            ServerConnection::new(Arc::new(server_config)).expect("server connection should exist");

        while client.is_handshaking() || server.is_handshaking() {
            transfer_tls_client_to_server(&mut client, &mut server);
            transfer_tls_server_to_client(&mut server, &mut client);
        }

        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn certificate_is_renewed_before_expiry() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let resolver = AttestedCertificateResolver::new_with_provider(
            AttestationGenerator::new(AttestationType::DcapTdx, None)
                .expect("mock generator construction should succeed"),
            None,
            "foo".to_string(),
            vec![],
            provider,
        )
        .await
        .expect("resolver construction should succeed");
        let initial_certificate = resolver
            .state
            .certificate
            .read()
            .expect("certificate lock poisoned")
            .first()
            .expect("resolver should hold a certificate")
            .clone();

        tokio::time::sleep(
            CERTIFICATE_VALIDITY - CERTIFICATE_RENEWAL_LEAD_TIME + Duration::from_secs(1),
        )
        .await;

        let renewed_certificate = resolver
            .state
            .certificate
            .read()
            .expect("certificate lock poisoned")
            .first()
            .expect("resolver should hold a renewed certificate")
            .clone();

        assert_ne!(initial_certificate.as_ref(), renewed_certificate.as_ref());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn server_and_client_configs_complete_a_mutual_auth_handshake() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let server_name = "foo";

        let server_resolver = AttestedCertificateResolver::new_with_provider(
            AttestationGenerator::new(AttestationType::DcapTdx, None)
                .expect("mock generator construction should succeed"),
            None,
            server_name.to_string(),
            vec![],
            provider.clone(),
        )
        .await
        .expect("server resolver construction should succeed");

        let client_resolver = AttestedCertificateResolver::new_with_provider(
            AttestationGenerator::new(AttestationType::DcapTdx, None)
                .expect("mock generator construction should succeed"),
            None,
            "client".to_string(),
            vec![],
            provider.clone(),
        )
        .await
        .expect("client resolver construction should succeed");

        let server_certificate = server_resolver
            .state
            .certificate
            .read()
            .expect("certificate lock poisoned")
            .first()
            .expect("resolver should hold a certificate")
            .clone();
        let client_certificate = client_resolver
            .state
            .certificate
            .read()
            .expect("certificate lock poisoned")
            .first()
            .expect("resolver should hold a certificate")
            .clone();

        let mut client_roots = RootCertStore::empty();
        client_roots.add(server_certificate).expect("server certificate should be trusted");
        let mut server_roots = RootCertStore::empty();
        server_roots.add(client_certificate).expect("client certificate should be trusted");

        let server_verifier = AttestedCertificateVerifier::new_with_provider(
            server_roots,
            AttestationVerifier::mock(),
            provider.clone(),
        )
        .expect("server verifier construction should succeed");
        let client_verifier = AttestedCertificateVerifier::new_with_provider(
            client_roots,
            AttestationVerifier::mock(),
            provider.clone(),
        )
        .expect("client verifier construction should succeed");

        let server_config = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("server config should support default protocol versions")
            .with_client_cert_verifier(Arc::new(server_verifier))
            .with_cert_resolver(Arc::new(server_resolver));
        let client_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("client config should support default protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(client_verifier))
            .with_client_cert_resolver(Arc::new(client_resolver));

        let mut client = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from(server_name).expect("server name should be valid"),
        )
        .expect("client connection should be created");
        let mut server =
            ServerConnection::new(Arc::new(server_config)).expect("server connection should exist");

        while client.is_handshaking() || server.is_handshaking() {
            transfer_tls_client_to_server(&mut client, &mut server);
            transfer_tls_server_to_client(&mut server, &mut client);
        }

        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
        assert!(client.peer_certificates().is_some());
        assert!(server.peer_certificates().is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn alternate_san_completes_a_handshake() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let primary_name = "foo";
        let alternate_name = "bar";
        let resolver = AttestedCertificateResolver::new_with_provider(
            AttestationGenerator::new(AttestationType::DcapTdx, None)
                .expect("mock generator construction should succeed"),
            None,
            primary_name.to_string(),
            vec![alternate_name.to_string(), primary_name.to_string()],
            provider.clone(),
        )
        .await
        .expect("resolver construction should succeed");
        let server_certificate = resolver
            .state
            .certificate
            .read()
            .expect("certificate lock poisoned")
            .first()
            .expect("resolver should hold a certificate")
            .clone();

        let mut roots = RootCertStore::empty();
        roots.add(server_certificate).expect("resolver certificate should be trusted");

        let verifier = AttestedCertificateVerifier::new_with_provider(
            roots,
            AttestationVerifier::mock(),
            provider.clone(),
        )
        .expect("verifier construction should succeed");

        let server_config = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("server config should support default protocol versions")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        let client_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("client config should support default protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        let mut client = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from(alternate_name).expect("alternate server name should be valid"),
        )
        .expect("client connection should be created");
        let mut server =
            ServerConnection::new(Arc::new(server_config)).expect("server connection should exist");

        while client.is_handshaking() || server.is_handshaking() {
            transfer_tls_client_to_server(&mut client, &mut server);
            transfer_tls_server_to_client(&mut server, &mut client);
        }

        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
    }

    fn test_ca() -> CaCert {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .expect("test CA key generation should succeed");
        let mut params = CertificateParams::new(vec!["test-ca".to_string()])
            .expect("test CA params should be created");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("test CA certificate should be self-signed");

        CaCert::from_parts(key, cert)
    }

    fn transfer_tls_client_to_server(client: &mut ClientConnection, server: &mut ServerConnection) {
        let mut tls = Vec::new();

        while client.wants_write() {
            client.write_tls(&mut tls).expect("writing tls should succeed");
        }

        if tls.is_empty() {
            return;
        }

        server.read_tls(&mut Cursor::new(tls)).expect("reading tls should succeed");
        server.process_new_packets().expect("processing tls packets should succeed");
    }

    fn transfer_tls_server_to_client(server: &mut ServerConnection, client: &mut ClientConnection) {
        let mut tls = Vec::new();

        while server.wants_write() {
            server.write_tls(&mut tls).expect("writing tls should succeed");
        }

        if tls.is_empty() {
            return;
        }

        client.read_tls(&mut Cursor::new(tls)).expect("reading tls should succeed");
        client.process_new_packets().expect("processing tls packets should succeed");
    }
}
