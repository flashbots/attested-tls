//! An attested TLS certificate resolver and verifier
use std::{
    collections::HashMap,
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
pub use ra_tls::cert::CaCert;
use ra_tls::{
    attestation::{Attestation, AttestationQuote, VersionedAttestation},
    cert::CertRequest,
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
        verify_server_name,
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
        ParsedCertificate,
        ResolvesServerCert,
        WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::{CertifiedKey, SigningKey},
};
use sha2::{Digest as _, Sha512};
use thiserror::Error;
use x509_parser::{certificate::X509Certificate, oid_registry::Oid};

/// How long to wait before re-trying certificate renewal on failure
#[cfg(not(test))]
const CERTIFICATE_RENEWAL_RETRY_DELAY: Duration = Duration::from_secs(30);
#[cfg(test)]
const CERTIFICATE_RENEWAL_RETRY_DELAY: Duration = Duration::from_millis(200);

/// Certificate validity must be strictly greater than 3x the retry delay so
/// that, after renewing at 2/3 of the validity period, there is still
/// enough time left for one retry before the certificate expires.
#[cfg(not(test))]
const MIN_CERTIFICATE_VALIDITY_DURATION: Duration = Duration::from_secs(91);
#[cfg(test)]
const MIN_CERTIFICATE_VALIDITY_DURATION: Duration = Duration::from_millis(601);

/// A TLS certificate resolver which includes an attestation as a
/// certificate extension
#[derive(Clone, Debug)]
pub struct AttestedCertificateResolver {
    /// Cloneable inner state
    state: Arc<ResolverState>,
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
    /// Attestation generator used when renewing certificate
    attestation_generator: AttestationGenerator,
    /// Primary DNS name used as certificate subject / common name.
    primary_name: String,
    /// DNS subject alternative names, including the primary name.
    subject_alt_names: Vec<String>,
}

impl fmt::Debug for ResolverState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let certificate_chain_len = self.certificate.read().ok().map(|certs| certs.len());

        f.debug_struct("ResolverState")
            .field("key", &"<signing key>")
            .field("ca_present", &self.ca.is_some())
            .field("key_pair_der_len", &self.key_pair_der.len())
            .field("certificate_chain_len", &certificate_chain_len)
            .field("attestation_generator", &self.attestation_generator)
            .field("primary_name", &self.primary_name)
            .field("subject_alt_names", &self.subject_alt_names)
            .finish()
    }
}

impl AttestedCertificateResolver {
    /// Create a certificate resolver with a given attestation generator
    /// A private certificate authority can also be given - otherwise
    /// certificates will be self signed
    pub async fn new(
        attestation_generator: AttestationGenerator,
        ca: Option<CaCert>,
        primary_name: String,
        subject_alt_names: Vec<String>,
        certificate_validity_duration: Duration,
    ) -> Result<Self, AttestedTlsError> {
        Self::new_with_provider(
            attestation_generator,
            ca,
            primary_name,
            subject_alt_names,
            default_crypto_provider()?,
            certificate_validity_duration,
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
        certificate_validity_duration: Duration,
    ) -> Result<Self, AttestedTlsError> {
        if certificate_validity_duration < MIN_CERTIFICATE_VALIDITY_DURATION {
            return Err(AttestedTlsError::InvalidCertificateValidityDuration {
                minimum: MIN_CERTIFICATE_VALIDITY_DURATION,
            });
        }
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
            certificate_validity_duration,
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
        Self::spawn_renewal_task(Arc::downgrade(&state), certificate_validity_duration);

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
        certificate_validity_duration: Duration,
    ) -> Result<Vec<CertificateDer<'static>>, AttestedTlsError> {
        tracing::debug!("Generating new remote-attested certificate for {primary_name}");
        let pubkey = key.public_key_der();
        let now = SystemTime::now();
        let not_after = now + certificate_validity_duration;

        let attestation = Self::create_attestation_payload(
            pubkey,
            now,
            not_after,
            primary_name,
            attestation_generator,
        )
        .await?;

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

        Ok(provider.key_provider.load_private_key(private_key)?)
    }

    /// Create an attestation, and format it to be used in certificate
    /// extension
    async fn create_attestation_payload(
        pubkey: Vec<u8>,
        not_before: SystemTime,
        not_after: SystemTime,
        primary_name: &str,
        attestation_generator: &AttestationGenerator,
    ) -> Result<VersionedAttestation, AttestedTlsError> {
        let report_data =
            create_report_data(pubkey, not_before, not_after, primary_name.as_bytes())?;
        let attestation = attestation_generator.generate_attestation(report_data).await?;
        Ok(VersionedAttestation::V0 {
            attestation: Attestation {
                quote: ra_tls::attestation::AttestationQuote::DstackTdx(
                    ra_tls::attestation::TdxQuote {
                        quote: serde_json::to_vec(&attestation)?,
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
    fn spawn_renewal_task(
        state: std::sync::Weak<ResolverState>,
        certificate_validity_duration: Duration,
    ) {
        tokio::spawn(async move {
            let renewal_delay = renewal_delay(certificate_validity_duration);
            let mut next_delay = renewal_delay;

            loop {
                tokio::time::sleep(next_delay).await;
                let Some(current) = state.upgrade() else {
                    tracing::warn!("Resolver has been dropped - stopping renewal loop");
                    break;
                };

                let key_pair = match KeyPair::try_from(current.key_pair_der.clone()) {
                    Ok(key_pair) => key_pair,
                    Err(e) => {
                        tracing::error!("Failed to load keypair: {e}");
                        next_delay = CERTIFICATE_RENEWAL_RETRY_DELAY;
                        continue;
                    }
                };

                next_delay = match Self::issue_ra_cert_chain(
                    &key_pair,
                    current.ca.as_deref(),
                    current.primary_name.as_str(),
                    &current.subject_alt_names,
                    &current.attestation_generator,
                    certificate_validity_duration,
                )
                .await
                {
                    Ok(certificate) => {
                        *current.certificate.write().expect("Certificate lock poisoned") =
                            certificate;
                        renewal_delay
                    }
                    Err(e) => {
                        tracing::error!("Failed to renew attested certificate: {e}");
                        CERTIFICATE_RENEWAL_RETRY_DELAY
                    }
                };
            }
        });
    }
}

/// Renew certificates after 2/3 of their configured validity period
fn renewal_delay(certificate_validity_duration: Duration) -> Duration {
    certificate_validity_duration
        .checked_mul(2)
        .and_then(|duration| duration.checked_div(3))
        .unwrap_or(certificate_validity_duration)
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
        !self.state.certificate.read().expect("Certificate lock poisoned").is_empty()
    }
}

impl AttestedCertificateResolver {
    fn current_certified_key(&self) -> Option<Arc<CertifiedKey>> {
        let certificate = self.state.certificate.read().expect("Certificate lock poisoned").clone();
        Some(Arc::new(CertifiedKey::new(certificate, self.state.key.clone())))
    }
}

fn default_crypto_provider() -> Result<Arc<CryptoProvider>, AttestedTlsError> {
    CryptoProvider::get_default().cloned().ok_or(AttestedTlsError::CryptoProviderUnavailable)
}

/// Ensures that SAN contains the primary hostname
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

/// Make input data for the attestation by hashing together public key,
/// validity period and hostname
fn create_report_data(
    public_key: Vec<u8>,
    not_before: SystemTime,
    not_after: SystemTime,
    hostname: &[u8],
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
    hasher.update(hostname);

    Ok(hasher.finalize().into())
}

/// Verifies attested TLS server or client certificates during TLS handshake
#[derive(Debug)]
pub struct AttestedCertificateVerifier {
    /// Underlying verifier when used with a private CA rather than
    /// self-signed
    server_inner: Option<Arc<WebPkiServerVerifier>>,
    /// Underlying client verifier when used with a private CA rather than
    /// self-signed
    client_inner: Option<Arc<dyn ClientCertVerifier>>,
    /// Underlying cryptography provider
    provider: Arc<CryptoProvider>,
    /// Configured for verifying attestations
    attestation_verifier: AttestationVerifier,
    /// Report data of pre-trusted certificates with cache expiry time
    trusted_certificates: Arc<RwLock<HashMap<[u8; 64], UnixTime>>>,
}

impl AttestedCertificateVerifier {
    /// Create a certificate verifier with given attestation verification
    /// and optionally a private CA root of trust
    pub fn new(
        root_store: Option<RootCertStore>,
        attestation_verifier: AttestationVerifier,
    ) -> Result<Self, AttestedTlsError> {
        Self::new_with_provider(root_store, attestation_verifier, default_crypto_provider()?)
    }

    /// Also provide a crypto provider
    pub fn new_with_provider(
        root_store: Option<RootCertStore>,
        attestation_verifier: AttestationVerifier,
        provider: Arc<CryptoProvider>,
    ) -> Result<Self, AttestedTlsError> {
        let (server_inner, client_inner) = match root_store {
            Some(root_store) => {
                let root_store = Arc::new(root_store);
                let server_inner = WebPkiServerVerifier::builder_with_provider(
                    root_store.clone(),
                    provider.clone(),
                )
                .build()
                .map_err(AttestedTlsError::VerifierBuilder)?;
                let client_inner =
                    WebPkiClientVerifier::builder_with_provider(root_store, provider.clone())
                        .build()
                        .map_err(AttestedTlsError::VerifierBuilder)?;

                (Some(server_inner), Some(client_inner))
            }
            None => (None, None),
        };

        Ok(Self {
            server_inner,
            client_inner,
            provider,
            attestation_verifier,
            trusted_certificates: Default::default(),
        })
    }

    /// Given a TLS certificate, return the embedded attestation
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
        let cert = Self::parse_x509_certificate(cert)?;
        let oid = Oid::from(ra_tls::oids::PHALA_RATLS_TDX_QUOTE)
            .map_err(|err| rustls::Error::General(format!("invalid attestation OID: {err}")))?;
        let ext = cert
            .get_extension_unique(&oid)
            .map_err(|err| Self::bad_encoding(format!("invalid attestation extension: {err}")))?
            .ok_or_else(|| Self::bad_encoding("missing attestation extension"))?;
        let payload = yasna::parse_der(ext.value, |reader| reader.read_bytes())
            .map_err(|err| Self::bad_encoding(format!("invalid attestation DER payload: {err}")))?;
        serde_json::from_slice(&payload)
            .map_err(|err| Self::bad_encoding(format!("invalid attestation JSON payload: {err}")))
    }

    /// Given a certificate, return the attestation report input data based
    /// on public key and expiry, as well as the expiry time
    fn cert_binding_data(cert: &CertificateDer<'_>) -> Result<([u8; 64], UnixTime), rustls::Error> {
        let cert = Self::parse_x509_certificate(cert)?;
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
        let hostname = Self::hostname_from_cert(&cert)?;
        let expected_input_data = create_report_data(
            cert.public_key().raw.to_vec(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(not_before),
            SystemTime::UNIX_EPOCH + Duration::from_secs(not_after),
            &hostname,
        )
        .map_err(|err| rustls::Error::General(err.to_string()))?;
        let not_after = UnixTime::since_unix_epoch(Duration::from_secs(not_after));

        Ok((expected_input_data, not_after))
    }

    /// Given a certificate and the current time, check if it is currently
    /// valid
    fn verify_cert_time_validity(
        cert: &CertificateDer<'_>,
        now: UnixTime,
    ) -> Result<(), rustls::Error> {
        let cert = Self::parse_x509_certificate(cert)?;
        Self::verify_cert_time_validity_parsed(&cert, now)
    }

    /// Given a parsed certificate and the current time, check if it is
    /// currently valid
    fn verify_cert_time_validity_parsed(
        cert: &X509Certificate<'_>,
        now: UnixTime,
    ) -> Result<(), rustls::Error> {
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

    /// Verify server name and time validity for self-signed certs
    fn verify_server_cert_constraints(
        cert: &CertificateDer<'_>,
        server_name: &ServerName<'_>,
        now: UnixTime,
    ) -> Result<(), rustls::Error> {
        let parsed = ParsedCertificate::try_from(cert)?;
        let cert = Self::parse_x509_certificate(cert)?;
        Self::verify_cert_time_validity_parsed(&cert, now)?;
        verify_server_name(&parsed, server_name)
    }

    /// Given a certificate with embedded attestation, verify the
    /// attestation if it has not already been verified
    fn verify_attestation_binding(
        &self,
        end_entity: &CertificateDer<'_>,
        now: UnixTime,
    ) -> Result<(), rustls::Error> {
        let (expected_input_data, expiry) = Self::cert_binding_data(end_entity)?;

        // First check if we have already successfully verified the attestation
        // associated with this certificate
        {
            let trusted_certificates = self.trusted_certificates.read().map_err(|_| {
                rustls::Error::General("Trusted certificate cache lock poisoned".into())
            })?;
            if trusted_certificates.get(&expected_input_data).is_some_and(|expiry| *expiry >= now) {
                tracing::debug!("Skipping attestation verification for trusted certificate");
                return Ok(());
            }
        }

        let attestation = Self::extract_custom_attestation_from_cert(end_entity)?;

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.attestation_verifier
                    .verify_attestation(attestation, expected_input_data)
                    .await
                    .map_err(|err| {
                        tracing::warn!(
                            "Rejecting certificate after attestation verification failure: {err}"
                        );
                        rustls::Error::InvalidCertificate(
                            rustls::CertificateError::ApplicationVerificationFailure,
                        )
                    })
            })
        })?;

        let mut trusted_certificates = self.trusted_certificates.write().map_err(|_| {
            rustls::Error::General("Trusted certificate cache lock poisoned".into())
        })?;

        // Remove any expired entries
        trusted_certificates.retain(|_, cached_expiry| *cached_expiry >= now);
        // Write trusted certificate details to cache
        trusted_certificates.insert(expected_input_data, expiry);

        Ok(())
    }

    /// Helper for creating encoding related verification errors
    fn bad_encoding(message: impl Into<String>) -> rustls::Error {
        let message = message.into();
        tracing::debug!("Rejecting malformed certificate or attestation payload: {message}");
        rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
    }

    /// Helper to parse a certificate and map the error for rustls
    fn parse_x509_certificate<'a>(
        cert: &'a CertificateDer<'_>,
    ) -> Result<X509Certificate<'a>, rustls::Error> {
        x509_parser::parse_x509_certificate(cert.as_ref())
            .map(|(_, parsed)| parsed)
            .map_err(|err| Self::bad_encoding(format!("Invalid X.509 DER: {err}")))
    }

    /// Given a certificate get the hostname for report input data
    fn hostname_from_cert(cert: &X509Certificate<'_>) -> Result<Vec<u8>, rustls::Error> {
        cert.subject()
            .iter_common_name()
            .next()
            .ok_or_else(|| Self::bad_encoding("Missing common name"))?
            .as_str()
            .map(|hostname| hostname.as_bytes().to_vec())
            .map_err(|err| Self::bad_encoding(format!("Invalid common name: {err}")))
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
        if let Some(server_inner) = &self.server_inner {
            match server_inner.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            ) {
                Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)) => {
                    // handle self-signed certs differently
                    Self::verify_server_cert_constraints(end_entity, server_name, now)?;
                }
                Err(err) => return Err(err),
                Ok(_) => {}
            }
        } else {
            Self::verify_server_cert_constraints(end_entity, server_name, now)?;
        }
        self.verify_attestation_binding(end_entity, now)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.server_inner.as_ref().and_then(|server_inner| server_inner.root_hint_subjects())
    }
}

impl ClientCertVerifier for AttestedCertificateVerifier {
    fn offer_client_auth(&self) -> bool {
        self.client_inner.as_ref().is_none_or(|client_inner| client_inner.offer_client_auth())
    }

    fn client_auth_mandatory(&self) -> bool {
        self.client_inner.as_ref().is_none_or(|client_inner| client_inner.client_auth_mandatory())
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.client_inner.as_ref().map_or(&[], |client_inner| client_inner.root_hint_subjects())
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if let Some(client_inner) = &self.client_inner {
            match client_inner.verify_client_cert(end_entity, intermediates, now) {
                Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)) => {
                    Self::verify_cert_time_validity(end_entity, now)?;
                }
                Err(err) => return Err(err),
                Ok(_) => {}
            }
        } else {
            Self::verify_cert_time_validity(end_entity, now)?;
        }
        self.verify_attestation_binding(end_entity, now)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Debug, Error)]
pub enum AttestedTlsError {
    #[error("Certificate validity duration must be at least {minimum:?}")]
    InvalidCertificateValidityDuration { minimum: Duration },
    #[error("Failed to generate certificate key pair: {0}")]
    CertificateKeyGeneration(#[source] rcgen::Error),
    #[error("Failed to build certificate parameters: {0}")]
    CertificateParams(#[source] rcgen::Error),
    #[error("Failed to self-sign certificate: {0}")]
    CertificateSigning(#[source] rcgen::Error),
    #[error("Failed to build certificate verifier: {0}")]
    VerifierBuilder(#[source] VerifierBuilderError),
    #[error("Certificate generation: {0}")]
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
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Attestation: {0}")]
    Attestation(#[from] attestation::AttestationError),
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, sync::Arc};

    use ra_tls::rcgen::{BasicConstraints, CertificateParams, IsCa};
    use rustls::{
        CertificateError,
        ClientConfig,
        ClientConnection,
        Error,
        RootCertStore,
        ServerConfig,
        ServerConnection,
        crypto::aws_lc_rs,
    };

    use super::*;

    /// Test helper to verify a certificate
    fn verify_server_cert_direct(
        verifier: &AttestedCertificateVerifier,
        end_entity: &CertificateDer<'_>,
        server_name: &ServerName<'_>,
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        rustls::client::danger::ServerCertVerifier::verify_server_cert(
            verifier,
            end_entity,
            &[],
            server_name,
            &[],
            now,
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn certificate_resolver_creates_initial_certificate() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let resolver = AttestedCertificateResolver::new_with_provider(
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            None,
            "foo".to_string(),
            vec![],
            provider,
            Duration::from_secs(4),
        )
        .await
        .unwrap();

        let certificate = resolver.state.certificate.read().unwrap();

        assert_eq!(certificate.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn certificate_resolver_rejects_too_short_validity_duration() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let error = AttestedCertificateResolver::new_with_provider(
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            None,
            "foo".to_string(),
            vec![],
            provider,
            CERTIFICATE_RENEWAL_RETRY_DELAY * 3,
        )
        .await
        .unwrap_err();

        assert!(matches!(error, AttestedTlsError::InvalidCertificateValidityDuration { .. }));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn server_and_client_configs_complete_a_handshake() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let server_name = "foo";
        let resolver = AttestedCertificateResolver::new_with_provider(
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            None,
            server_name.to_string(),
            vec![],
            provider.clone(),
            Duration::from_secs(4),
        )
        .await
        .unwrap();

        let verifier = AttestedCertificateVerifier::new_with_provider(
            None,
            AttestationVerifier::mock(),
            provider.clone(),
        )
        .unwrap();

        let server_config = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        let client_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        let mut client = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from(server_name).unwrap(),
        )
        .unwrap();

        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

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
        let ca_cert = CertificateDer::from_pem_slice(ca.pem_cert.as_bytes()).unwrap();

        let resolver = AttestedCertificateResolver::new_with_provider(
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            Some(ca),
            server_name.to_string(),
            vec![],
            provider.clone(),
            Duration::from_secs(4),
        )
        .await
        .unwrap();

        let certificate_chain = resolver.state.certificate.read().unwrap().clone();

        assert_eq!(certificate_chain.len(), 2);

        let mut roots = RootCertStore::empty();
        roots.add(ca_cert).unwrap();

        let verifier = AttestedCertificateVerifier::new_with_provider(
            Some(roots),
            AttestationVerifier::mock(),
            provider.clone(),
        )
        .unwrap();

        let server_config = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));

        let client_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        let mut client = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from(server_name).unwrap(),
        )
        .unwrap();

        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

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
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            None,
            "foo".to_string(),
            vec![],
            provider,
            Duration::from_secs(4),
        )
        .await
        .unwrap();
        let initial_certificate =
            resolver.state.certificate.read().unwrap().first().unwrap().clone();

        tokio::time::sleep(renewal_delay(Duration::from_secs(4)) + Duration::from_secs(1)).await;

        let renewed_certificate =
            resolver.state.certificate.read().unwrap().first().unwrap().clone();

        assert_ne!(initial_certificate.as_ref(), renewed_certificate.as_ref());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn server_and_client_configs_complete_a_mutual_auth_handshake() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let server_name = "foo";

        let server_resolver = AttestedCertificateResolver::new_with_provider(
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            None,
            server_name.to_string(),
            vec![],
            provider.clone(),
            Duration::from_secs(4),
        )
        .await
        .unwrap();

        let client_resolver = AttestedCertificateResolver::new_with_provider(
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            None,
            "client".to_string(),
            vec![],
            provider.clone(),
            Duration::from_secs(4),
        )
        .await
        .unwrap();

        let server_verifier = AttestedCertificateVerifier::new_with_provider(
            None,
            AttestationVerifier::mock(),
            provider.clone(),
        )
        .unwrap();
        let client_verifier = AttestedCertificateVerifier::new_with_provider(
            None,
            AttestationVerifier::mock(),
            provider.clone(),
        )
        .unwrap();

        let server_config = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(Arc::new(server_verifier))
            .with_cert_resolver(Arc::new(server_resolver));
        let client_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(client_verifier))
            .with_client_cert_resolver(Arc::new(client_resolver));

        let mut client = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from(server_name).unwrap(),
        )
        .unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

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
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            None,
            primary_name.to_string(),
            vec![alternate_name.to_string(), primary_name.to_string()],
            provider.clone(),
            Duration::from_secs(4),
        )
        .await
        .unwrap();
        let verifier = AttestedCertificateVerifier::new_with_provider(
            None,
            AttestationVerifier::mock(),
            provider.clone(),
        )
        .unwrap();

        let server_config = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        let client_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        let mut client = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from(alternate_name).unwrap(),
        )
        .unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        while client.is_handshaking() || server.is_handshaking() {
            transfer_tls_client_to_server(&mut client, &mut server);
            transfer_tls_server_to_client(&mut server, &mut client);
        }

        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_certificate_returns_bad_encoding() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let verifier = AttestedCertificateVerifier::new_with_provider(
            None,
            AttestationVerifier::mock(),
            provider,
        )
        .unwrap();
        let cert = CertificateDer::from(vec![1_u8, 2, 3, 4]);

        let result = verify_server_cert_direct(
            &verifier,
            &cert,
            &ServerName::try_from("foo").unwrap(),
            UnixTime::now(),
        );

        assert_eq!(result.unwrap_err(), Error::InvalidCertificate(CertificateError::BadEncoding));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn certificate_without_attestation_extension_returns_bad_encoding() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let cert = plain_self_signed_certificate("foo");
        let mut roots = RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        let verifier = AttestedCertificateVerifier::new_with_provider(
            Some(roots),
            AttestationVerifier::mock(),
            provider,
        )
        .unwrap();

        let result = verify_server_cert_direct(
            &verifier,
            &cert,
            &ServerName::try_from("foo").unwrap(),
            UnixTime::now(),
        );

        assert_eq!(result.unwrap_err(), Error::InvalidCertificate(CertificateError::BadEncoding));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn self_signed_attested_certificate_with_wrong_name_is_rejected() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let resolver = AttestedCertificateResolver::new_with_provider(
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            None,
            "foo".to_string(),
            vec![],
            provider.clone(),
            Duration::from_secs(4),
        )
        .await
        .unwrap();
        let verifier = AttestedCertificateVerifier::new_with_provider(
            None,
            AttestationVerifier::mock(),
            provider,
        )
        .unwrap();
        let cert = resolver.state.certificate.read().unwrap().first().unwrap().clone();

        let result = verify_server_cert_direct(
            &verifier,
            &cert,
            &ServerName::try_from("bar").unwrap(),
            UnixTime::now(),
        );

        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidCertificate(CertificateError::NotValidForNameContext { .. })
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn certificate_binding_changes_when_identity_changes() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let resolver = AttestedCertificateResolver::new_with_provider(
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            None,
            "foo".to_string(),
            vec![],
            provider.clone(),
            Duration::from_secs(4),
        )
        .await
        .unwrap();
        let original_cert = resolver.state.certificate.read().unwrap().first().unwrap().clone();
        let (original_report_data, original_not_after) =
            AttestedCertificateVerifier::cert_binding_data(&original_cert).unwrap();
        let parsed_cert =
            AttestedCertificateVerifier::parse_x509_certificate(&original_cert).unwrap();
        let not_before = parsed_cert.validity().not_before.timestamp() as u64;
        let not_after = parsed_cert.validity().not_after.timestamp() as u64;
        let key_pair = KeyPair::try_from(resolver.state.key_pair_der.clone()).unwrap();
        let replay_name = "bar".to_string();
        let replay_alt_names = vec![replay_name.clone()];
        let replayed_cert_request = CertRequest::builder()
            .key(&key_pair)
            .subject(&replay_name)
            .alt_names(&replay_alt_names)
            .not_before(SystemTime::UNIX_EPOCH + Duration::from_secs(not_before))
            .not_after(SystemTime::UNIX_EPOCH + Duration::from_secs(not_after))
            .usage_server_auth(true)
            .usage_client_auth(true)
            .build();
        let replayed_cert: CertificateDer<'static> =
            replayed_cert_request.self_signed().unwrap().der().to_vec().into();
        let (replayed_report_data, replayed_not_after) =
            AttestedCertificateVerifier::cert_binding_data(&replayed_cert).unwrap();

        assert_eq!(original_not_after, replayed_not_after);
        assert_ne!(original_report_data, replayed_report_data);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn attestation_rejection_returns_application_verification_failure() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let resolver = AttestedCertificateResolver::new_with_provider(
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            None,
            "foo".to_string(),
            vec![],
            provider.clone(),
            Duration::from_secs(4),
        )
        .await
        .unwrap();
        let verifier = AttestedCertificateVerifier::new_with_provider(
            None,
            AttestationVerifier::expect_none(),
            provider,
        )
        .unwrap();
        let cert = resolver.state.certificate.read().unwrap().first().unwrap().clone();

        let result = verify_server_cert_direct(
            &verifier,
            &cert,
            &ServerName::try_from("foo").unwrap(),
            UnixTime::now(),
        );

        assert_eq!(
            result.unwrap_err(),
            Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verifier_reuses_trusted_certificate_cache() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let resolver = AttestedCertificateResolver::new_with_provider(
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            None,
            "foo".to_string(),
            vec![],
            provider.clone(),
            Duration::from_secs(4),
        )
        .await
        .unwrap();
        let mut verifier = AttestedCertificateVerifier::new_with_provider(
            None,
            AttestationVerifier::mock(),
            provider,
        )
        .unwrap();
        let cert = resolver.state.certificate.read().unwrap().first().unwrap().clone();
        let (expected_input_data, not_after) =
            AttestedCertificateVerifier::cert_binding_data(&cert).unwrap();

        verify_server_cert_direct(
            &verifier,
            &cert,
            &ServerName::try_from("foo").unwrap(),
            UnixTime::now(),
        )
        .unwrap();
        assert_eq!(
            verifier.trusted_certificates.read().unwrap().get(&expected_input_data),
            Some(&not_after)
        );

        verifier.attestation_verifier = AttestationVerifier::expect_none();

        verify_server_cert_direct(
            &verifier,
            &cert,
            &ServerName::try_from("foo").unwrap(),
            UnixTime::now(),
        )
        .unwrap();
    }

    /// Helper to create a private certificate authority
    fn test_ca() -> CaCert {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec!["test-ca".to_string()]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).unwrap();

        CaCert::from_parts(key, cert)
    }

    /// Helper to create a self signed cert with no attestation
    fn plain_self_signed_certificate(subject_name: &str) -> CertificateDer<'static> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let params = CertificateParams::new(vec![subject_name.to_string()]).unwrap();
        params.self_signed(&key).unwrap().der().to_vec().into()
    }

    fn transfer_tls_client_to_server(client: &mut ClientConnection, server: &mut ServerConnection) {
        let mut tls = Vec::new();

        while client.wants_write() {
            client.write_tls(&mut tls).unwrap();
        }

        if tls.is_empty() {
            return;
        }

        server.read_tls(&mut Cursor::new(tls)).unwrap();
        server.process_new_packets().unwrap();
    }

    fn transfer_tls_server_to_client(server: &mut ServerConnection, client: &mut ClientConnection) {
        let mut tls = Vec::new();

        while server.wants_write() {
            server.write_tls(&mut tls).unwrap();
        }

        if tls.is_empty() {
            return;
        }

        client.read_tls(&mut Cursor::new(tls)).unwrap();
        client.process_new_packets().unwrap();
    }
}
