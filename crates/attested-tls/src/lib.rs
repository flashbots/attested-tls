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
use ra_tls::{
    attestation::{Attestation, AttestationQuote, VersionedAttestation},
    cert::CertRequest,
    rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256},
};
pub use ra_tls::{cert::CaCert, rcgen};
use rustls::{
    CertificateError,
    DigitallySignedStruct,
    DistinguishedName,
    Error::InvalidCertificate,
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
    subject: String,
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
            .field("subject", &self.subject)
            .field("subject_alt_names", &self.subject_alt_names)
            .finish()
    }
}

impl AttestedCertificateResolver {
    /// Create a default TLS certificate resolver wrapping given attestation
    /// generator
    pub fn try_default(
        subject: &str,
        attestation_generator: AttestationGenerator,
    ) -> Result<Self, AttestedTlsError> {
        Self::build(subject, attestation_generator).finish()
    }

    /// Build attested certificate resolver
    pub fn build<'a, 'b>(
        subject: &'b str,
        attestation_generator: AttestationGenerator,
    ) -> AttestedCertificateResolverBuilder<'a, 'b> {
        AttestedCertificateResolverBuilder {
            attestation_generator,
            ca_cert: None,
            certificate_validity: Duration::from_millis(300000),
            key_pair: None,
            crypto_provider: None,
            subject,
            subject_alt_names: None,
        }
    }

    /// Create an attested certificate chain - either self-signed or with
    /// the provided CA
    fn issue_ra_cert_chain(
        key_pair: &KeyPair,
        ca: Option<&CaCert>,
        subject: &str,
        subject_alt_names: &[String],
        attestation_generator: &AttestationGenerator,
        certificate_validity_duration: Duration,
    ) -> Result<Vec<CertificateDer<'static>>, AttestedTlsError> {
        tracing::debug!("Generating new remote-attested certificate for {subject}");
        let pubkey = key_pair.public_key_der();
        let now = SystemTime::now();
        let not_after = now + certificate_validity_duration;

        let attestation = Self::create_attestation_payload(
            pubkey,
            now,
            not_after,
            subject,
            attestation_generator,
        )?;

        let cert_request = CertRequest::builder()
            .key(key_pair)
            .subject(subject)
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
    fn create_attestation_payload(
        pubkey: Vec<u8>,
        not_before: SystemTime,
        not_after: SystemTime,
        subject: &str,
        attestation_generator: &AttestationGenerator,
    ) -> Result<VersionedAttestation, AttestedTlsError> {
        let report_data = create_report_data(pubkey, not_before, not_after, subject.as_bytes())?;
        let attestation = attestation_generator.generate_attestation(report_data)?;
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
                    current.subject.as_str(),
                    &current.subject_alt_names,
                    &current.attestation_generator,
                    certificate_validity_duration,
                ) {
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

pub struct AttestedCertificateResolverBuilder<'a, 'b> {
    /// Configured to generate attestations
    attestation_generator: AttestationGenerator,
    /// CA to sign leaf certificates
    ca_cert: Option<CaCert>,
    /// Duration of certificate validity
    certificate_validity: Duration,
    /// Key-pair to use
    key_pair: Option<&'a KeyPair>,
    /// Underlying cryptography provider
    crypto_provider: Option<Arc<CryptoProvider>>,
    /// Certificate subject
    subject: &'b str,
    // Subject alternative names
    subject_alt_names: Option<Vec<String>>,
}

impl<'a, 'b> AttestedCertificateResolverBuilder<'a, 'b> {
    /// Use specified CA to sign leaf certificates
    pub fn with_ca_cert(mut self, ca: CaCert) -> Self {
        self.ca_cert = Some(ca);
        self
    }

    /// Set duration of certificates validity (default is 30 minutes)
    pub fn with_certificate_validity(mut self, certificate_validity: Duration) -> Self {
        self.certificate_validity = certificate_validity;
        self
    }

    /// Use specified key-pair (default is to use randomly generated one)
    pub fn with_key_pair(mut self, key_pair: &'a KeyPair) -> Self {
        self.key_pair = Some(key_pair);
        self
    }

    /// Use specified crypto provider
    pub fn with_crypto_provider(mut self, provider: Arc<CryptoProvider>) -> Self {
        self.crypto_provider = Some(provider.clone());
        self
    }

    /// Use specified subject alternative names on generated certificates
    pub fn with_subject_alt_names(mut self, subject_alt_names: Vec<String>) -> Self {
        self.subject_alt_names = Some(subject_alt_names);
        self
    }

    /// Finish the build of AttestedCertificateResolver
    pub fn finish(self) -> Result<AttestedCertificateResolver, AttestedTlsError> {
        let provider = match self.crypto_provider {
            None => default_crypto_provider()?,
            Some(provider) => provider,
        };

        if self.certificate_validity < MIN_CERTIFICATE_VALIDITY_DURATION {
            return Err(AttestedTlsError::InvalidCertificateValidityDuration {
                minimum: MIN_CERTIFICATE_VALIDITY_DURATION,
            });
        }

        let key_pair = match self.key_pair {
            None => {
                &KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(AttestedTlsError::from)?
            }
            Some(key_pair) => key_pair,
        };

        let key_pair_der = key_pair.serialize_der();
        let key = AttestedCertificateResolver::load_signing_key(key_pair, provider)?;

        let subject_alt_names = match self.subject_alt_names {
            None => vec![self.subject.to_owned()],
            Some(subject_alt_names) => {
                normalized_subject_alt_names(self.subject, subject_alt_names)
            }
        };

        // Generate initial attested certificate
        let certificate = AttestedCertificateResolver::issue_ra_cert_chain(
            key_pair,
            self.ca_cert.as_ref(),
            self.subject,
            &subject_alt_names,
            &self.attestation_generator,
            self.certificate_validity,
        )?;

        let state = Arc::new(ResolverState {
            key,
            certificate: RwLock::new(certificate),
            ca: self.ca_cert.map(Arc::new),
            key_pair_der,
            attestation_generator: self.attestation_generator,
            subject: self.subject.to_owned(),
            subject_alt_names,
        });

        // Start a loop which will periodically renew the certificate
        AttestedCertificateResolver::spawn_renewal_task(
            Arc::downgrade(&state),
            self.certificate_validity,
        );

        Ok(AttestedCertificateResolver { state })
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
fn normalized_subject_alt_names(subject: &str, subject_alt_names: Vec<String>) -> Vec<String> {
    let mut normalized = Vec::with_capacity(subject_alt_names.len() + 1);
    normalized.push(subject.to_string());

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
    /// Underlying server certificates verifier
    server_verifier: Arc<WebPkiServerVerifier>,
    /// Underlying client certificates verifier (when used with a private CA
    /// rather than self-signed)
    client_verifier: Arc<dyn ClientCertVerifier>,
    /// Underlying cryptography provider
    crypto_provider: Arc<CryptoProvider>,
    /// Configured for verifying attestations
    attestation_verifier: AttestationVerifier,
    /// Report data of pre-trusted certificates with cache expiry time
    trusted_certs: Arc<RwLock<HashMap<[u8; 64], UnixTime>>>,
    /// Whether self-signed certificates should be accepted
    accept_self_signed_certs: bool,
    /// SHA512 hashes of ASN.1 DER representations of public keys allowed
    /// for leaf certificates
    ///
    /// Note: `None` means default behaviour, that is any public key for
    ///       leaf certificates is acceptable as long as the certificate
    ///       and its embedded attestation are valid
    allowed_leaf_cert_pubkeys: Option<Arc<Vec<[u8; 64]>>>,
}

impl AttestedCertificateVerifier {
    /// Create default TLS certificate verifier wrapping given attestation
    /// verifier
    pub fn try_default(
        attestation_verifier: AttestationVerifier,
    ) -> Result<Self, AttestedTlsError> {
        let crypto_provider = default_crypto_provider()?;

        let server_verifier = WebPkiServerVerifier::builder(Arc::new({
            let mut root_cert_store = rustls::RootCertStore::empty();
            root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.to_owned());
            root_cert_store
        }))
        .build()
        .map_err(AttestedTlsError::VerifierBuilder)?;

        let client_verifier = WebPkiClientVerifier::builder(Arc::new({
            let mut root_cert_store = rustls::RootCertStore::empty();
            root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.to_owned());
            root_cert_store
        }))
        .build()
        .map_err(AttestedTlsError::VerifierBuilder)?;

        Ok(Self {
            server_verifier,
            client_verifier,
            crypto_provider,
            attestation_verifier,
            trusted_certs: Default::default(),
            accept_self_signed_certs: true,
            allowed_leaf_cert_pubkeys: None,
        })
    }

    /// Create a TLS certificate verifier wrapping given attestation
    /// verifier
    pub fn build(attestation_verifier: AttestationVerifier) -> AttestedCertificateVerifierBuilder {
        AttestedCertificateVerifierBuilder {
            root_cert_store: None,
            crypto_provider: None,
            attestation_verifier,
            accept_self_signed_certs: false,
            allowed_leaf_cert_pubkeys: None,
        }
    }

    /// Given a TLS certificate, return the embedded attestation
    pub fn extract_custom_attestation_from_cert(
        cert: &X509Certificate<'_>,
    ) -> Result<AttestationExchangeMessage, rustls::Error> {
        if let Ok(Some(attestation)) = ra_tls::attestation::from_cert(cert) &&
            let AttestationQuote::DstackTdx(tdx_quote) = attestation.quote
        {
            if let Ok(message) =
                serde_json::from_slice::<AttestationExchangeMessage>(&tdx_quote.quote)
            {
                return Ok(message);
            }

            return Ok(AttestationExchangeMessage {
                attestation_type: AttestationType::DcapTdx,
                attestation: tdx_quote.quote,
            });
        }

        // If that fails, extract and parse the extension
        let oid = Oid::from(ra_tls::oids::PHALA_RATLS_TDX_QUOTE)
            .map_err(|err| rustls::Error::General(format!("invalid attestation OID: {err:?}")))?;
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
    fn cert_binding_data(
        cert: &X509Certificate<'_>,
    ) -> Result<([u8; 64], UnixTime), rustls::Error> {
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
        let hostname = Self::hostname_from_cert(cert)?;
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

    /// Given a parsed certificate and the current time, check if it is
    /// currently valid
    fn verify_cert_time_validity(
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
            return Err(InvalidCertificate(CertificateError::NotValidYetContext {
                time: UnixTime::since_unix_epoch(Duration::from_secs(now)),
                not_before: UnixTime::since_unix_epoch(Duration::from_secs(not_before)),
            }));
        }

        if now > not_after {
            return Err(InvalidCertificate(CertificateError::ExpiredContext {
                time: UnixTime::since_unix_epoch(Duration::from_secs(now)),
                not_after: UnixTime::since_unix_epoch(Duration::from_secs(not_after)),
            }));
        }

        Ok(())
    }

    /// Check if the certificate is self-signed and verify it if it is
    fn try_verifying_self_signed_cert(
        &self,
        cert: &X509Certificate<'_>,
        now: UnixTime,
    ) -> Result<(), rustls::Error> {
        if cert.subject() != cert.issuer() {
            // issuer != subject means it's not a self-signed cert, so we just return
            // the error as-is
            return Err(InvalidCertificate(CertificateError::UnknownIssuer));
        }

        // verify the signature
        cert.verify_signature(None)
            .inspect_err(|err| tracing::warn!("invalid self-signed certificate signature: {err:?}"))
            .map_err(|_| CertificateError::BadSignature)?;

        // verify cert-time
        Self::verify_cert_time_validity(cert, now)?;

        Ok(())
    }

    /// Given a certificate with embedded attestation, verify the
    /// attestation if it has not already been verified
    fn verify_attestation_binding(
        &self,
        cert: &X509Certificate<'_>,
        now: UnixTime,
    ) -> Result<(), rustls::Error> {
        let (expected_input_data, expiry) = Self::cert_binding_data(cert)?;

        // First check if we have already successfully verified the attestation
        // associated with this certificate
        {
            let trusted_certs = self.trusted_certs.read().map_err(|_| {
                rustls::Error::General("Trusted certificate cache lock poisoned".into())
            })?;
            if trusted_certs.get(&expected_input_data).is_some_and(|expiry| *expiry >= now) {
                tracing::debug!("Skipping attestation verification for trusted certificate");
                return Ok(());
            }
        }

        let attestation = Self::extract_custom_attestation_from_cert(cert)?;

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.attestation_verifier
                    .verify_attestation(attestation, expected_input_data)
                    .await
                    .map_err(|err| {
                        tracing::warn!(
                            "Rejecting certificate after attestation verification failure: {err}"
                        );
                        InvalidCertificate(CertificateError::ApplicationVerificationFailure)
                    })
            })
        })?;

        let mut trusted_certs = self.trusted_certs.write().map_err(|_| {
            rustls::Error::General("Trusted certificate cache lock poisoned".into())
        })?;

        // Remove any expired entries
        trusted_certs.retain(|_, cached_expiry| *cached_expiry >= now);
        // Write trusted certificate details to cache
        trusted_certs.insert(expected_input_data, expiry);

        Ok(())
    }

    /// Helper for creating encoding related verification errors
    fn bad_encoding(message: impl Into<String>) -> rustls::Error {
        let message = message.into();
        tracing::debug!("Rejecting malformed certificate or attestation payload: {message}");
        InvalidCertificate(CertificateError::BadEncoding)
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
        let cert = Self::parse_x509_certificate(end_entity)?;

        match self.server_verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Err(InvalidCertificate(CertificateError::UnknownIssuer)) => {
                if !self.accept_self_signed_certs || !intermediates.is_empty() {
                    return Err(InvalidCertificate(CertificateError::UnknownIssuer));
                }
                verify_server_name(&ParsedCertificate::try_from(end_entity)?, server_name)?;
                self.try_verifying_self_signed_cert(&cert, now)?;
            }
            Err(err) => return Err(err),
            Ok(_) => {}
        };

        if let Some(ref allowed_leaf_cert_pubkeys) = self.allowed_leaf_cert_pubkeys &&
            !allowed_leaf_cert_pubkeys.contains(&Sha512::digest(cert.public_key().raw).into())
        {
            tracing::warn!("Rejecting leaf certificate with un-allowed public key");
            return Err(InvalidCertificate(CertificateError::UnknownIssuer));
        }

        self.verify_attestation_binding(&cert, now)?;
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
            &self.crypto_provider.signature_verification_algorithms,
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
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto_provider.signature_verification_algorithms.supported_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.server_verifier.root_hint_subjects()
    }
}

impl ClientCertVerifier for AttestedCertificateVerifier {
    fn offer_client_auth(&self) -> bool {
        // client must send its cert so that server could verify the attestation
        // from the extension
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        // client must send its cert so that server could verify the attestation
        // from the extension
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        if self.accept_self_signed_certs {
            // allow client to elect self-signed cert for auth
            return &[];
        }
        self.client_verifier.as_ref().root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let cert = Self::parse_x509_certificate(end_entity)?;

        match self.client_verifier.verify_client_cert(end_entity, intermediates, now) {
            Err(InvalidCertificate(CertificateError::UnknownIssuer)) => {
                if !self.accept_self_signed_certs || !intermediates.is_empty() {
                    return Err(InvalidCertificate(CertificateError::UnknownIssuer));
                }
                self.try_verifying_self_signed_cert(&cert, now)?;
            }
            Err(err) => return Err(err),
            Ok(_) => {}
        }

        if let Some(ref allowed_leaf_cert_pubkeys) = self.allowed_leaf_cert_pubkeys &&
            !allowed_leaf_cert_pubkeys.contains(&Sha512::digest(cert.public_key().raw).into())
        {
            tracing::warn!("Rejecting leaf certificate with un-allowed public key");
            return Err(InvalidCertificate(CertificateError::UnknownIssuer));
        }

        self.verify_attestation_binding(&cert, now)?;
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
            &self.crypto_provider.signature_verification_algorithms,
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
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto_provider.signature_verification_algorithms.supported_schemes()
    }
}

pub struct AttestedCertificateVerifierBuilder {
    /// Configured for verifying attestations
    attestation_verifier: AttestationVerifier,
    /// Underlying cryptography provider
    crypto_provider: Option<Arc<CryptoProvider>>,
    /// Whether self-signed certificates should be accepted
    accept_self_signed_certs: bool,
    /// SHA512 hashes of ASN.1 DER representations of public keys allowed
    /// for leaf certificates
    ///
    /// Note: `None` means default behaviour, that is any public key for
    ///       leaf certificates is acceptable as long as the certificate
    ///       and its embedded attestation are valid
    allowed_leaf_cert_pubkeys: Option<Vec<[u8; 64]>>,
    // Custom root-of-trust
    root_cert_store: Option<Arc<RootCertStore>>,
}

impl AttestedCertificateVerifierBuilder {
    /// Use specified crypto provider
    pub fn with_crypto_provider(mut self, crypto_provider: Arc<CryptoProvider>) -> Self {
        self.crypto_provider = Some(crypto_provider.clone());
        self
    }

    /// Use specified root-of-trust
    ///
    /// Note: must not be used together with
    ///       [`Self::with_accepting_self_signed_certs`]
    pub fn with_root_cert_store(mut self, root_cert_store: RootCertStore) -> Self {
        if self.accept_self_signed_certs {
            panic!(
                "with_root_cert_store() can not be used together with with_accepting_self_signed_certs()"
            )
        }
        self.root_cert_store = Some(Arc::new(root_cert_store));
        self
    }

    /// Accept self-signed certificates
    ///
    /// Note: must not be used together with
    ///       [`Self::with_root_cert_store`]
    pub fn with_accepting_self_signed_certs(mut self) -> Self {
        if self.root_cert_store.is_some() {
            panic!(
                "with_accepting_self_signed_certs() can not be used together with with_root_cert_store()"
            )
        }
        self.accept_self_signed_certs = true;
        self
    }

    /// Allow specific public key for leaf certificates
    ///
    /// The input must be the DER-encoded public key bytes, such as
    /// [`rcgen::KeyPair::public_key_der`]
    ///
    /// Note: if at least 1 public key is added to this allow-list of leaf
    ///       certificate public keys, then only certificates with matching
    ///       public keys will be accepted
    pub fn with_allowed_leaf_cert_pubkey(mut self, pubkey_der: &[u8]) -> Self {
        let mut allowed_leaf_cert_pubkeys = self.allowed_leaf_cert_pubkeys.unwrap_or_default();
        allowed_leaf_cert_pubkeys.push(Sha512::digest(pubkey_der).into());
        self.allowed_leaf_cert_pubkeys = Some(allowed_leaf_cert_pubkeys);
        self
    }

    /// Allow multiple leaf certificate public keys
    ///
    /// The input should be a list of DER-encoded public key bytes, such as
    /// `rcgen::KeyPair::public_key_der()`
    ///
    /// Note: if at least 1 public key is added to this allow-list of leaf
    ///       certificate public keys, then only certificates with matching
    ///       public keys will be accepted
    pub fn with_allowed_leaf_cert_pubkeys<I, B>(mut self, pubkey_ders: I) -> Self
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut allowed_self_signed_cert_pubkeys =
            self.allowed_leaf_cert_pubkeys.unwrap_or_default();
        allowed_self_signed_cert_pubkeys.extend(
            pubkey_ders
                .into_iter()
                .map(|pubkey_der| -> [u8; 64] { Sha512::digest(pubkey_der.as_ref()).into() }),
        );
        self.allowed_leaf_cert_pubkeys = Some(allowed_self_signed_cert_pubkeys);
        self
    }

    /// Finish the build of AttestedCertificateVerifier
    pub fn finish(self) -> Result<AttestedCertificateVerifier, AttestedTlsError> {
        let crypto_provider = match self.crypto_provider {
            None => default_crypto_provider()?,
            Some(provider) => provider,
        };

        let server_verifier = WebPkiServerVerifier::builder_with_provider(
            self.root_cert_store.clone().unwrap_or_else(|| {
                Arc::new({
                    let mut root_cert_store = rustls::RootCertStore::empty();
                    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.to_owned());
                    root_cert_store
                })
            }),
            crypto_provider.clone(),
        )
        .build()
        .map_err(AttestedTlsError::VerifierBuilder)?;

        let client_verifier = WebPkiClientVerifier::builder_with_provider(
            self.root_cert_store.clone().unwrap_or_else(|| {
                Arc::new({
                    let mut root_cert_store = rustls::RootCertStore::empty();
                    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.to_owned());
                    root_cert_store
                })
            }),
            crypto_provider.clone(),
        )
        .build()
        .map_err(AttestedTlsError::VerifierBuilder)?;

        Ok(AttestedCertificateVerifier {
            server_verifier,
            client_verifier,
            crypto_provider,
            attestation_verifier: self.attestation_verifier,
            trusted_certs: Default::default(),
            accept_self_signed_certs: self.accept_self_signed_certs,
            allowed_leaf_cert_pubkeys: self.allowed_leaf_cert_pubkeys.map(Arc::new),
        })
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

    use ra_tls::rcgen::{
        BasicConstraints,
        CertificateParams,
        IsCa,
        KeyPair,
        PKCS_ECDSA_P256_SHA256,
    };
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

    /// Test helper to verify a client certificate
    fn verify_client_cert_direct(
        verifier: &AttestedCertificateVerifier,
        end_entity: &CertificateDer<'_>,
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        rustls::server::danger::ClientCertVerifier::verify_client_cert(
            verifier,
            end_entity,
            &[],
            now,
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn certificate_resolver_creates_initial_certificate() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let resolver = AttestedCertificateResolver::build(
            "foo",
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
        )
        .with_key_pair(&key_pair)
        .with_crypto_provider(provider)
        .with_certificate_validity(Duration::from_secs(4))
        .finish()
        .unwrap();

        let certificate = resolver.state.certificate.read().unwrap();

        assert_eq!(certificate.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn certificate_resolver_rejects_too_short_validity_duration() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let error = AttestedCertificateResolver::build(
            "foo",
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
        )
        .with_crypto_provider(provider)
        .with_key_pair(&key_pair)
        .with_certificate_validity(CERTIFICATE_RENEWAL_RETRY_DELAY * 3)
        .finish()
        .unwrap_err();

        assert!(matches!(error, AttestedTlsError::InvalidCertificateValidityDuration { .. }));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn server_and_client_configs_complete_a_handshake() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let server_name = "foo";
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let resolver = AttestedCertificateResolver::build(
            server_name,
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
        )
        .with_crypto_provider(provider.clone())
        .with_key_pair(&key_pair)
        .with_certificate_validity(Duration::from_secs(4))
        .finish()
        .unwrap();

        let verifier = AttestedCertificateVerifier::build(AttestationVerifier::mock())
            .with_crypto_provider(provider.clone())
            .with_accepting_self_signed_certs()
            .finish()
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

        complete_handshake_with_timeout(&mut client, &mut server).await;

        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ca_signed_server_and_client_configs_complete_a_handshake() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let server_name = "foo";
        let ca = test_ca();
        let ca_cert = CertificateDer::from_pem_slice(ca.pem_cert.as_bytes()).unwrap();

        let resolver = AttestedCertificateResolver::build(
            server_name,
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
        )
        .with_crypto_provider(provider.clone())
        .with_key_pair(&key_pair)
        .with_ca_cert(ca)
        .with_certificate_validity(Duration::from_secs(4))
        .finish()
        .unwrap();

        let certificate_chain = resolver.state.certificate.read().unwrap().clone();

        assert_eq!(certificate_chain.len(), 2);

        let mut roots = RootCertStore::empty();
        roots.add(ca_cert).unwrap();

        let verifier = AttestedCertificateVerifier::build(AttestationVerifier::mock())
            .with_crypto_provider(provider.clone())
            .with_root_cert_store(roots)
            .finish()
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

        complete_handshake_with_timeout(&mut client, &mut server).await;

        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn certificate_is_renewed_before_expiry() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let resolver = AttestedCertificateResolver::build(
            "foo",
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
        )
        .with_crypto_provider(provider.clone())
        .with_key_pair(&key_pair)
        .with_certificate_validity(Duration::from_secs(4))
        .finish()
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
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let server_name = "foo";

        let server_resolver = AttestedCertificateResolver::build(
            server_name,
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
        )
        .with_crypto_provider(provider.clone())
        .with_key_pair(&key_pair)
        .with_certificate_validity(Duration::from_secs(4))
        .finish()
        .unwrap();

        let client_resolver = AttestedCertificateResolver::build(
            "client",
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
        )
        .with_crypto_provider(provider.clone())
        .with_key_pair(&key_pair)
        .with_certificate_validity(Duration::from_secs(4))
        .finish()
        .unwrap();

        let server_verifier = AttestedCertificateVerifier::build(AttestationVerifier::mock())
            .with_crypto_provider(provider.clone())
            .with_accepting_self_signed_certs()
            .finish()
            .unwrap();
        let client_verifier = AttestedCertificateVerifier::build(AttestationVerifier::mock())
            .with_crypto_provider(provider.clone())
            .with_accepting_self_signed_certs()
            .finish()
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

        complete_handshake_with_timeout(&mut client, &mut server).await;

        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
        assert!(client.peer_certificates().is_some());
        assert!(server.peer_certificates().is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn alternate_san_completes_a_handshake() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let subject = "foo";
        let alternate_name = "bar";
        let resolver = AttestedCertificateResolver::build(
            subject,
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
        )
        .with_subject_alt_names(vec![alternate_name.to_string(), subject.to_string()])
        .with_crypto_provider(provider.clone())
        .with_key_pair(&key_pair)
        .with_certificate_validity(Duration::from_secs(4))
        .finish()
        .unwrap();
        let verifier = AttestedCertificateVerifier::build(AttestationVerifier::mock())
            .with_crypto_provider(provider.clone())
            .with_accepting_self_signed_certs()
            .finish()
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

        complete_handshake_with_timeout(&mut client, &mut server).await;

        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_certificate_returns_bad_encoding() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let verifier = AttestedCertificateVerifier::build(AttestationVerifier::mock())
            .with_crypto_provider(provider)
            .finish()
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
        let verifier = AttestedCertificateVerifier::build(AttestationVerifier::mock())
            .with_crypto_provider(provider)
            .with_root_cert_store(roots)
            .finish()
            .unwrap();

        let result = verify_server_cert_direct(
            &verifier,
            &cert,
            &ServerName::try_from("foo").unwrap(),
            UnixTime::now(),
        );

        assert_eq!(result.unwrap_err(), Error::InvalidCertificate(CertificateError::BadEncoding),);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn private_ca_verifier_rejects_untrusted_self_signed_attested_server_cert() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let ca = test_ca();
        let ca_cert = CertificateDer::from_pem_slice(ca.pem_cert.as_bytes()).unwrap();
        let resolver = AttestedCertificateResolver::build(
            "foo",
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
        )
        .with_crypto_provider(provider.clone())
        .with_certificate_validity(Duration::from_secs(4))
        .finish()
        .unwrap();
        let cert = resolver.state.certificate.read().unwrap().first().unwrap().clone();

        let mut roots = RootCertStore::empty();
        roots.add(ca_cert).unwrap();
        let verifier = AttestedCertificateVerifier::build(AttestationVerifier::mock())
            .with_crypto_provider(provider)
            .with_root_cert_store(roots)
            .with_allowed_leaf_cert_pubkey(&[0u8; 32])
            .finish()
            .unwrap();

        let result = verify_server_cert_direct(
            &verifier,
            &cert,
            &ServerName::try_from("foo").unwrap(),
            UnixTime::now(),
        );

        assert_eq!(result.unwrap_err(), Error::InvalidCertificate(CertificateError::UnknownIssuer));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn private_ca_verifier_rejects_untrusted_self_signed_attested_client_cert() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let ca = test_ca();
        let ca_cert = CertificateDer::from_pem_slice(ca.pem_cert.as_bytes()).unwrap();
        let resolver = AttestedCertificateResolver::build(
            "client",
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
        )
        .with_crypto_provider(provider.clone())
        .with_certificate_validity(Duration::from_secs(4))
        .finish()
        .unwrap();
        let cert = resolver.state.certificate.read().unwrap().first().unwrap().clone();

        let mut roots = RootCertStore::empty();
        roots.add(ca_cert).unwrap();
        let verifier = AttestedCertificateVerifier::build(AttestationVerifier::mock())
            .with_crypto_provider(provider)
            .with_root_cert_store(roots)
            .with_allowed_leaf_cert_pubkey(&[0u8; 32])
            .finish()
            .unwrap();

        let result = verify_client_cert_direct(&verifier, &cert, UnixTime::now());

        assert_eq!(result.unwrap_err(), Error::InvalidCertificate(CertificateError::UnknownIssuer));
    }

    #[tokio::test]
    async fn non_self_signed_attested_certificate_with_unknown_issuer_is_rejected() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let resolver = AttestedCertificateResolver::build(
            "foo",
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
        )
        .with_crypto_provider(provider.clone())
        .with_key_pair(&key_pair)
        .with_ca_cert(test_ca())
        .with_certificate_validity(Duration::from_secs(4))
        .finish()
        .unwrap();
        let verifier = AttestedCertificateVerifier::build(AttestationVerifier::mock())
            .with_crypto_provider(provider)
            .finish()
            .unwrap();
        let cert = resolver.state.certificate.read().unwrap().first().unwrap().clone();
        let parsed_cert = AttestedCertificateVerifier::parse_x509_certificate(&cert).unwrap();

        assert_ne!(parsed_cert.subject(), parsed_cert.issuer());

        let result = verify_server_cert_direct(
            &verifier,
            &cert,
            &ServerName::try_from("foo").unwrap(),
            UnixTime::now(),
        );

        assert_eq!(result.unwrap_err(), Error::InvalidCertificate(CertificateError::UnknownIssuer));
    }

    #[tokio::test]
    async fn self_signed_attested_certificate_with_wrong_name_is_rejected() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let resolver = AttestedCertificateResolver::build(
            "foo",
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
        )
        .with_crypto_provider(provider.clone())
        .with_key_pair(&key_pair)
        .with_certificate_validity(Duration::from_secs(4))
        .finish()
        .unwrap();
        let verifier = AttestedCertificateVerifier::build(AttestationVerifier::mock())
            .with_crypto_provider(provider)
            .with_accepting_self_signed_certs()
            .finish()
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
        ),);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn self_signed_attested_certificate_with_allowed_pubkey_is_accepted() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let resolver = AttestedCertificateResolver::build(
            "foo",
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
        )
        .with_crypto_provider(provider.clone())
        .with_key_pair(&key_pair)
        .with_certificate_validity(Duration::from_secs(4))
        .finish()
        .unwrap();
        let verifier = AttestedCertificateVerifier::build(AttestationVerifier::mock())
            .with_crypto_provider(provider)
            .with_accepting_self_signed_certs()
            .with_allowed_leaf_cert_pubkey(&key_pair.public_key_der())
            .finish()
            .unwrap();
        let cert = resolver.state.certificate.read().unwrap().first().unwrap().clone();

        verify_server_cert_direct(
            &verifier,
            &cert,
            &ServerName::try_from("foo").unwrap(),
            UnixTime::now(),
        )
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn self_signed_attested_certificate_with_not_allowed_pubkey_is_rejected() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let trusted_key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let presented_key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let resolver = AttestedCertificateResolver::build(
            "foo",
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
        )
        .with_crypto_provider(provider.clone())
        .with_key_pair(&presented_key_pair)
        .with_certificate_validity(Duration::from_secs(4))
        .finish()
        .unwrap();
        let verifier = AttestedCertificateVerifier::build(AttestationVerifier::mock())
            .with_crypto_provider(provider)
            .with_allowed_leaf_cert_pubkey(&trusted_key_pair.public_key_der())
            .finish()
            .unwrap();
        let cert = resolver.state.certificate.read().unwrap().first().unwrap().clone();

        let result = verify_server_cert_direct(
            &verifier,
            &cert,
            &ServerName::try_from("foo").unwrap(),
            UnixTime::now(),
        );

        assert_eq!(result.unwrap_err(), Error::InvalidCertificate(CertificateError::UnknownIssuer));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn certificate_binding_changes_when_identity_changes() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let resolver = AttestedCertificateResolver::build(
            "foo",
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
        )
        .with_crypto_provider(provider.clone())
        .with_key_pair(&key_pair)
        .with_certificate_validity(Duration::from_secs(4))
        .finish()
        .unwrap();

        let cert = resolver.state.certificate.read().unwrap();
        let cert =
            AttestedCertificateVerifier::parse_x509_certificate(cert.first().unwrap()).unwrap();
        let (original_report_data, original_not_after) =
            AttestedCertificateVerifier::cert_binding_data(&cert).unwrap();
        let not_before = cert.validity().not_before.timestamp() as u64;
        let not_after = cert.validity().not_after.timestamp() as u64;
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
        let replayed_cert = replayed_cert_request.self_signed().unwrap();
        let replayed_cert =
            AttestedCertificateVerifier::parse_x509_certificate(replayed_cert.der()).unwrap();
        let (replayed_report_data, replayed_not_after) =
            AttestedCertificateVerifier::cert_binding_data(&replayed_cert).unwrap();

        assert_eq!(original_not_after, replayed_not_after);
        assert_ne!(original_report_data, replayed_report_data);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn attestation_rejection_returns_application_verification_failure() {
        let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let resolver = AttestedCertificateResolver::build(
            "foo",
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
        )
        .with_crypto_provider(provider.clone())
        .with_key_pair(&key_pair)
        .with_certificate_validity(Duration::from_secs(4))
        .finish()
        .unwrap();
        let verifier = AttestedCertificateVerifier::build(AttestationVerifier::expect_none())
            .with_crypto_provider(provider)
            .with_accepting_self_signed_certs()
            .finish()
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
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let resolver = AttestedCertificateResolver::build(
            "foo",
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
        )
        .with_crypto_provider(provider.clone())
        .with_key_pair(&key_pair)
        .with_certificate_validity(Duration::from_secs(4))
        .finish()
        .unwrap();
        let mut verifier = AttestedCertificateVerifier::build(AttestationVerifier::mock())
            .with_crypto_provider(provider)
            .with_accepting_self_signed_certs()
            .finish()
            .unwrap();
        let cert = resolver.state.certificate.read().unwrap().first().unwrap().clone();

        let (expected_input_data, not_after) = AttestedCertificateVerifier::cert_binding_data(
            &AttestedCertificateVerifier::parse_x509_certificate(&cert).unwrap(),
        )
        .unwrap();

        verify_server_cert_direct(
            &verifier,
            &cert,
            &ServerName::try_from("foo").unwrap(),
            UnixTime::now(),
        )
        .unwrap();
        assert_eq!(
            verifier.trusted_certs.read().unwrap().get(&expected_input_data),
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

    async fn complete_handshake_with_timeout(
        client: &mut ClientConnection,
        server: &mut ServerConnection,
    ) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while client.is_handshaking() || server.is_handshaking() {
                transfer_tls_client_to_server(client, server);
                transfer_tls_server_to_client(server, client);

                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("TLS handshake timed out");
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
