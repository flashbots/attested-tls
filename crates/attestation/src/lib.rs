//! CVM attestation generation and verification

// `azure-verifier` is the base Azure feature: it gates the whole module,
// and `azure-attester` (which implies it) additionally enables the
// generation code inside, on the x86_64 linux targets where the vTPM it
// reads exists.
#[cfg(feature = "azure-verifier")]
pub mod azure;
pub mod dcap;
mod gcp;
pub mod measurements;
mod trusted_firmware;
#[cfg(test)]
use std::sync::OnceLock;
use std::{
    fmt::{self, Display, Formatter},
    io::Read,
    net::IpAddr,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use attest_measure::platform::PlatformError;
pub use attest_types::{AttestationEvidence, PlatformMetadata};
/// Re-exported so callers can archive [EndorsementSnapshot::dcap] without
/// depending on `dcap-qvl` directly
pub use dcap_qvl::QuoteCollateralV3;
use measurements::{ExpectedMeasurements, MultiMeasurements};
use parity_scale_codec::{Decode, Encode};
use pccs::{Pccs, PccsError};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time::sleep;

use crate::{
    dcap::DcapVerificationError,
    gcp::{GcpFirmwareCache, GcpProvenanceChecker, GcpProvenanceError},
    measurements::{MeasurementFormatError, MeasurementPolicy},
};

#[cfg(test)]
static TEST_CRYPTO_PROVIDER: OnceLock<()> = OnceLock::new();

#[cfg(test)]
pub(crate) fn install_test_crypto_provider() {
    TEST_CRYPTO_PROVIDER.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Used in attestation type detection to check if we are on GCP
const GCP_METADATA_API: &str = "http://metadata.google.internal";

/// How often a dynamic measurement policy is refreshed in the background.
const DYNAMIC_MEASUREMENT_POLICY_REFRESH_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);

/// An attestation payload together with its type
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode)]
pub struct AttestationExchangeMessage {
    /// Attestation payload with platform metadata, if present.
    /// `None` means no evidence presented.
    pub attestation_evidence: Option<AttestationEvidence>,
}

impl AttestationExchangeMessage {
    /// Create an empty attestation payload for the case that we are running
    /// in a non-confidential environment
    pub fn without_attestation() -> Self {
        Self { attestation_evidence: None }
    }

    /// Extract the measurements from the attestation, if present, but do
    /// not verify
    pub fn get_measurements(&self) -> Result<Option<MultiMeasurements>, AttestationError> {
        let Some(attestation_evidence) = &self.attestation_evidence else {
            return Ok(None);
        };

        match self.attestation_type() {
            AttestationType::None => Ok(None),
            AttestationType::AzureTdx => {
                #[cfg(feature = "azure-verifier")]
                {
                    Ok(Some(azure::get_measurements(&attestation_evidence.quote)?))
                }
                #[cfg(not(feature = "azure-verifier"))]
                {
                    Err(AttestationError::AttestationTypeNotSupported)
                }
            }
            AttestationType::DcapTdx | AttestationType::GcpTdx => {
                let quote = dcap_qvl::verify::Quote::parse(&attestation_evidence.quote)
                    .map_err(DcapVerificationError::from)?;
                Ok(Some(MultiMeasurements::from_dcap_qvl_quote(&quote)?))
            }
        }
    }

    pub fn attestation_type(&self) -> AttestationType {
        self.attestation_evidence
            .as_ref()
            .map(|evidence| evidence.platform.attestation_type.into())
            .unwrap_or(AttestationType::None)
    }
}

impl From<AttestationEvidence> for AttestationExchangeMessage {
    fn from(attestation_evidence: AttestationEvidence) -> Self {
        Self { attestation_evidence: Some(attestation_evidence) }
    }
}

impl From<attest_types::AttestationType> for AttestationType {
    fn from(attestation_type: attest_types::AttestationType) -> Self {
        match attestation_type {
            attest_types::AttestationType::GcpTdx => AttestationType::GcpTdx,
            attest_types::AttestationType::AzureTdx => AttestationType::AzureTdx,
            attest_types::AttestationType::SelfHostedTdx => AttestationType::DcapTdx,
        }
    }
}

impl TryFrom<AttestationType> for attest_types::AttestationType {
    type Error = AttestationError;

    fn try_from(attestation_type: AttestationType) -> Result<Self, Self::Error> {
        match attestation_type {
            AttestationType::None => Err(AttestationError::AttestationTypeNotAccepted),
            AttestationType::AzureTdx => Ok(attest_types::AttestationType::AzureTdx),
            AttestationType::GcpTdx => Ok(attest_types::AttestationType::GcpTdx),
            AttestationType::DcapTdx => Ok(attest_types::AttestationType::SelfHostedTdx),
        }
    }
}

/// Type of attestation used
/// Only supported (or soon-to-be supported) types are given
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationType {
    /// No attestation
    None,
    /// TDX on Google Cloud Platform
    GcpTdx,
    /// TDX on Azure, with MAA
    AzureTdx,
    /// DCAP TDX (no cloud platform specified)
    #[serde(alias = "qemu-tdx")] // To support legacy measurements file format
    DcapTdx,
}

impl AttestationType {
    /// Matches the names used by Constellation aTLS
    pub fn as_str(&self) -> &'static str {
        match self {
            AttestationType::None => "none",
            AttestationType::AzureTdx => "azure-tdx",
            AttestationType::GcpTdx => "gcp-tdx",
            AttestationType::DcapTdx => "dcap-tdx",
        }
    }

    /// Whether a measurement policy record with this attestation type may
    /// be used to check a peer reporting the given attestation type.
    ///
    /// `dcap-tdx` policy also accepts a `gcp-tdx` attestation - as dcap-tdx
    /// effectively means DCAP on any platform.
    pub fn accepts(&self, peer: AttestationType) -> bool {
        matches!((self, peer), (AttestationType::DcapTdx, AttestationType::GcpTdx)) || *self == peer
    }

    /// Detect what platform we are on by attempting an attestation
    pub fn detect() -> Result<Self, AttestationError> {
        // First attempt azure, if the feature is present
        #[cfg(azure_attester_x86_64_linux)]
        {
            if azure::detect_azure_cvm()? {
                return Ok(AttestationType::AzureTdx);
            }
        }
        // Otherwise try DCAP quote - this internally checks that the quote
        // provider is `tdx_guest`
        if tdx_attest::get_quote(&[0; 64]).is_ok() {
            if running_on_gcp()? {
                return Ok(AttestationType::GcpTdx);
            } else {
                return Ok(AttestationType::DcapTdx);
            }
        }
        Ok(AttestationType::None)
    }
}

/// SCALE encode (used over the wire)
impl Encode for AttestationType {
    fn encode(&self) -> Vec<u8> {
        self.as_str().encode()
    }
}

/// SCALE decode
impl Decode for AttestationType {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        let s: String = String::decode(input)?;
        serde_json::from_str(&format!("\"{s}\"")).map_err(|_| "Failed to decode enum".into())
    }
}

impl Display for AttestationType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Can generate a local attestation based on attestation type
#[derive(Debug, Clone)]
pub struct AttestationGenerator {
    pub attestation_type: AttestationType,
    attestation_provider_url: Option<String>,
}

impl AttestationGenerator {
    /// Create an attestation generator with given attestation type
    pub fn new(
        attestation_type: AttestationType,
        attestation_provider_url: Option<String>,
    ) -> Result<Self, AttestationError> {
        // If an attestation provider is given, normalize the URL and check
        // that it looks like a local IP
        let attestation_provider_url =
            attestation_provider_url.map(map_attestation_provider_url).transpose()?;

        Ok(Self { attestation_type, attestation_provider_url })
    }

    /// Detect what confidential compute platform is present and create the
    /// appropriate attestation generator
    pub fn detect() -> Result<Self, AttestationError> {
        Self::new_with_detection(None, None)
    }

    /// Do not generate attestations
    pub fn with_no_attestation() -> Self {
        Self { attestation_type: AttestationType::None, attestation_provider_url: None }
    }

    /// Create an [AttestationGenerator] detecting the attestation type if
    /// it is not given
    pub fn new_with_detection(
        attestation_type_string: Option<String>,
        attestation_provider_url: Option<String>,
    ) -> Result<Self, AttestationError> {
        if attestation_provider_url.is_some() {
            // If a remote provider is used, dont do detection
            let attestation_type = serde_json::from_value(serde_json::Value::String(
                attestation_type_string.ok_or(AttestationError::AttestationTypeNotGiven)?,
            ))?;
            return Self::new(attestation_type, attestation_provider_url);
        };

        let attestation_type_string = attestation_type_string.unwrap_or_else(|| "auto".to_string());
        let attestation_type = if attestation_type_string == "auto" {
            tracing::info!("Doing attestation type detection...");
            AttestationType::detect()?
        } else {
            serde_json::from_value(serde_json::Value::String(attestation_type_string))?
        };
        tracing::info!("Local platform: {attestation_type}");

        Self::new(attestation_type, None)
    }

    /// Generate an attestation exchange message with given input data
    pub fn generate_attestation(
        &self,
        input_data: [u8; 64],
    ) -> Result<AttestationExchangeMessage, AttestationError> {
        if let Some(url) = &self.attestation_provider_url {
            Self::use_attestation_provider(url, self.attestation_type, input_data)
        } else {
            match self.attestation_type {
                AttestationType::None => Ok(AttestationExchangeMessage::without_attestation()),
                AttestationType::AzureTdx => {
                    #[cfg(azure_attester_x86_64_linux)]
                    {
                        let platform = attest_measure::platform::metadata_for(
                            self.attestation_type.try_into()?,
                        )?;
                        Ok(AttestationExchangeMessage {
                            attestation_evidence: Some(AttestationEvidence {
                                quote: azure::create_azure_attestation(input_data)?,
                                platform,
                            }),
                        })
                    }
                    #[cfg(not(azure_attester_x86_64_linux))]
                    {
                        tracing::error!(
                            "Azure attestation generation requires the `azure-attester` feature on an x86_64 linux host"
                        );
                        Err(AttestationError::AttestationTypeNotSupported)
                    }
                }
                AttestationType::DcapTdx | AttestationType::GcpTdx => {
                    #[cfg(any(test, feature = "mock"))]
                    let platform = mock_platform_metadata(self.attestation_type)?;
                    #[cfg(not(any(test, feature = "mock")))]
                    let platform =
                        attest_measure::platform::metadata_for(self.attestation_type.try_into()?)?;
                    Ok(AttestationExchangeMessage {
                        attestation_evidence: Some(AttestationEvidence {
                            quote: dcap::create_dcap_attestation(input_data)?,
                            platform,
                        }),
                    })
                }
            }
        }
    }

    /// Generate an attestation by using an external service for the
    /// attestation generation
    fn use_attestation_provider(
        url: &str,
        attestation_type: AttestationType,
        input_data: [u8; 64],
    ) -> Result<AttestationExchangeMessage, AttestationError> {
        if attestation_type == AttestationType::None {
            return Ok(AttestationExchangeMessage::without_attestation());
        }

        let url = format!("{}/attest/{}", url, hex::encode(input_data));

        let mut response = ureq::get(&url)
            .timeout(Duration::from_millis(1000))
            .call()
            .map_err(|err| AttestationError::AttestationProvider(err.to_string()))?
            .into_reader();
        let mut body = Vec::new();
        response
            .read_to_end(&mut body)
            .map_err(|err| AttestationError::AttestationProvider(err.to_string()))?;

        AttestationExchangeMessage::decode(&mut &body[..])
            .map_err(|err| AttestationError::AttestationProvider(err.to_string()))
    }
}

/// How the verifier obtains DCAP collateral
#[derive(Clone, Debug)]
pub enum PccsMode {
    /// No internal collateral cache. Collateral is always fetched from
    /// remote source.
    None,
    /// Internal cache pre-filled with all available collateral at build
    /// time.
    Prewarmed,
    /// Internal cache that starts empty and fetches on demand.
    Lazy,
}

/// Fetched endorsement material, bound to the instant it was evaluated at
///
/// Everything fetched expires — `nextUpdate` on TCB Info, QE Identity and
/// both CRLs, `notAfter` on the issuer chains — so a bundle answers
/// freshness only with respect to an instant. Pairing the two is what makes
/// a verdict reproducible: same evidence, same snapshot, same verdict.
///
/// What a verifier fetches is a transport choice of the protocol, not a
/// property of the platform: evidence can carry its own endorsements
/// instead. Hence a struct that grows fields rather than an enum keyed by
/// platform, and `#[non_exhaustive]` to keep that growth additive.
///
/// Two caveats. Trust anchors are compiled in rather than captured here, so
/// a replay needs a build carrying the same ones — under `mock`, the mock
/// root. And "endorsements" is loose: in [RFC 9334] terms a DCAP bundle
/// spans both Endorsements (issuer chains, CRLs) and Reference Values (TCB
/// Info, QE Identity).
///
/// [RFC 9334]: https://www.rfc-editor.org/rfc/rfc9334.html
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct EndorsementSnapshot {
    /// Seconds since the Unix epoch — the unit `dcap-qvl` and webpki take
    pub at: u64,
    /// `Some` when the verification fetched a DCAP bundle, `None` when the
    /// evidence carried its own or the platform has no DCAP leg. The bundle
    /// consumed, not a second copy: a cache can refresh between two fetches
    pub dcap: Option<QuoteCollateralV3>,
}

impl EndorsementSnapshot {
    /// A verification that fetched one DCAP collateral bundle
    pub fn dcap(collateral: QuoteCollateralV3, at: u64) -> Self {
        Self { at, dcap: Some(collateral) }
    }
}

/// Evidence whose authenticity a Verifier established, with what it was
/// established against
///
/// Not an Attestation Result in [RFC 9334] terms: the appraisal policy runs
/// after this value is built, and a caller may configure it to check
/// nothing, so no Reference Value comparison is implied. Archived beside
/// the evidence, it reproduces the verdict.
///
/// [RFC 9334]: https://www.rfc-editor.org/rfc/rfc9334.html
#[derive(Clone, Debug)]
pub struct VerifiedAttestation {
    /// MRTD and RTMR0–3 from the quote on DCAP and GCP. On Azure the vTPM
    /// PCRs, which measure the guest boot rather than the launched TD and
    /// chain to the TD quote: its report data commits to the HCL var data
    /// carrying the AK public key that signs the vTPM quote
    pub measurements: MultiMeasurements,
    /// The reference measurements from the policy record that matched this
    /// attestation. This is populated by [`AttestationVerifier`], after the
    /// platform-specific verification has completed.
    pub expected_measurements: Option<ExpectedMeasurements>,
    /// The half of a reproducible verdict that does not ride in the
    /// evidence
    pub endorsements: EndorsementSnapshot,
}

/// Allows remote attestations to be verified
#[derive(Clone, Debug)]
pub struct AttestationVerifier {
    /// The measurement policy with accepted values and attestation types,
    /// shared between clones
    measurement_policy: Arc<RwLock<MeasurementPolicyState>>,
    /// Whether to write quotes to files on disk
    dump_dcap_quotes: bool,
    /// Whether to override outdated TCB when on Azure
    ///
    /// This provides a workaround for a known outdated FMSPC used by Azure
    #[cfg_attr(not(feature = "azure-verifier"), allow(dead_code))]
    override_azure_outdated_tcb: bool,
    /// Internal cache for collateral
    internal_pccs: Option<Pccs>,
    /// Cached GCP firmware blobs indexed by MRTD
    known_gcp_firmware: GcpFirmwareCache,
    /// Cached PPIDs that have a valid GCP host-registry document
    gcp_provenance_checker: GcpProvenanceChecker,
    /// Dynamic measurement policy to re-fetch from file or URL
    dynamic_measurement_policy: Option<String>,
}

/// Measurement policy together with a generation number used to track
/// changes
#[derive(Clone, Debug)]
struct MeasurementPolicyState {
    policy: MeasurementPolicy,
    generation: u64,
}

impl MeasurementPolicyState {
    fn new(policy: MeasurementPolicy) -> Self {
        Self { policy, generation: 0 }
    }
}

/// Options used to construct an [AttestationVerifier]
pub struct AttestationVerifierBuilder {
    /// The measurement policy with accepted values and attestation types
    measurement_policy: MeasurementPolicy,
    /// Internal PCCS setting
    pccs_mode: PccsMode,
    /// A dynamic measurement policy file or URL
    dynamic_measurement_policy: Option<String>,
    /// A PCCS service to use - defaults to Intel PCS
    pccs_url: Option<String>,
    dump_dcap_quotes: bool,
    /// Whether to override outdated TCB when on Azure
    override_azure_outdated_tcb: bool,
}

impl AttestationVerifierBuilder {
    pub fn build(self) -> AttestationVerifier {
        let internal_pccs = match self.pccs_mode {
            PccsMode::None => None,
            PccsMode::Prewarmed => Some(Pccs::new(self.pccs_url)),
            PccsMode::Lazy => Some(Pccs::new_without_prewarm(self.pccs_url)),
        };

        let verifier = AttestationVerifier {
            measurement_policy: Arc::new(RwLock::new(MeasurementPolicyState::new(
                self.measurement_policy,
            ))),
            dump_dcap_quotes: self.dump_dcap_quotes,
            override_azure_outdated_tcb: self.override_azure_outdated_tcb,
            internal_pccs,
            known_gcp_firmware: GcpFirmwareCache::new(),
            gcp_provenance_checker: GcpProvenanceChecker::new(),
            dynamic_measurement_policy: self.dynamic_measurement_policy,
        };

        verifier.spawn_dynamic_measurement_policy_refresh();
        verifier
    }

    /// Whether to write quotes to files on disk
    pub fn with_dump_dcap_quotes(mut self, dump_dcap_quotes: bool) -> Self {
        self.dump_dcap_quotes = dump_dcap_quotes;
        self
    }

    /// Whether to override outdated TCB when on Azure
    ///
    /// This provides a workaround for a known outdated FMSPC used by Azure
    /// When `azure-verifier` is disabled, this option has no effect because
    /// Azure attestations are not supported.
    pub fn with_override_azure_outdated_tcb(mut self, override_azure_outdated_tcb: bool) -> Self {
        self.override_azure_outdated_tcb = override_azure_outdated_tcb;
        self
    }

    pub fn with_pccs_mode(mut self, pccs_mode: PccsMode) -> Self {
        self.pccs_mode = pccs_mode;
        self
    }

    /// Set the URL used by internal PCCS
    pub fn with_pccs_url(mut self, pccs_url: String) -> Self {
        self.pccs_url = Some(pccs_url);
        self
    }

    /// Re-fetch the measurement policy from this file or URL periodically
    /// and after a measurement mismatch.
    ///
    /// Both asynchronous and synchronous verification perform one retry
    /// with the refreshed policy. Synchronous URL refreshes block for
    /// up to ten seconds.
    pub fn with_dynamic_measurements_file_or_url(mut self, file_or_url: String) -> Self {
        self.dynamic_measurement_policy = Some(file_or_url);
        self
    }
}

impl AttestationVerifier {
    pub fn builder(measurement_policy: MeasurementPolicy) -> AttestationVerifierBuilder {
        AttestationVerifierBuilder {
            measurement_policy,
            pccs_mode: PccsMode::None,
            pccs_url: None,
            dump_dcap_quotes: false,
            override_azure_outdated_tcb: false,
            dynamic_measurement_policy: None,
        }
    }

    /// Create an [AttestationVerifier] which will only allow no attestation
    /// and will reject if one is given
    pub fn expect_none() -> Self {
        Self {
            measurement_policy: Arc::new(RwLock::new(MeasurementPolicyState::new(
                MeasurementPolicy::expect_none(),
            ))),
            dump_dcap_quotes: false,
            override_azure_outdated_tcb: false,
            internal_pccs: None,
            known_gcp_firmware: GcpFirmwareCache::new(),
            gcp_provenance_checker: GcpProvenanceChecker::new(),
            dynamic_measurement_policy: None,
        }
    }

    /// Expect mock measurements used in tests
    #[cfg(any(test, feature = "mock"))]
    pub fn mock() -> Self {
        Self {
            measurement_policy: Arc::new(RwLock::new(MeasurementPolicyState::new(
                MeasurementPolicy::mock(),
            ))),
            dump_dcap_quotes: false,
            override_azure_outdated_tcb: false,
            internal_pccs: None,
            known_gcp_firmware: GcpFirmwareCache::new(),
            gcp_provenance_checker: GcpProvenanceChecker::new(),
            dynamic_measurement_policy: None,
        }
    }

    /// Expect mock measurements used in tests, and use a PCCS
    #[cfg(any(test, feature = "mock"))]
    pub fn mock_with_pccs(pccs_url: String) -> Self {
        Self {
            measurement_policy: Arc::new(RwLock::new(MeasurementPolicyState::new(
                MeasurementPolicy::mock(),
            ))),
            dump_dcap_quotes: false,
            override_azure_outdated_tcb: false,
            internal_pccs: Some(Pccs::new(Some(pccs_url))),
            known_gcp_firmware: GcpFirmwareCache::new(),
            gcp_provenance_checker: GcpProvenanceChecker::new(),
            dynamic_measurement_policy: None,
        }
    }

    /// Resolves once the internal PCCS cache is ready to verify
    /// attestations
    ///
    /// Calling this is optional - it is only really needed when you want to
    /// guarantee that collateral will not be fetched during
    /// verification
    pub async fn ready(&self) -> Result<(), AttestationError> {
        // If we have no PCCS then we are ready
        let Some(pccs) = &self.internal_pccs else {
            return Ok(());
        };

        // If we have pccs, and pre-warm is disabled we are also ready
        match pccs.ready().await {
            Ok(_) | Err(PccsError::PrewarmDisabled) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    /// Verify an attestation, and return the expected measurements from the
    /// matching policy record.
    pub async fn verify_attestation(
        &self,
        attestation_exchange_message: AttestationExchangeMessage,
        expected_input_data: [u8; 64],
    ) -> Result<Option<VerifiedAttestation>, AttestationError> {
        let attestation_type = attestation_exchange_message.attestation_type();
        tracing::debug!("Verifying {attestation_type} attestation");

        if self.dump_dcap_quotes {
            log_attestation(&attestation_exchange_message);
        }

        let mut verified = match attestation_type {
            AttestationType::None => {
                if self.has_remote_attestation() {
                    return Err(AttestationError::AttestationTypeNotAccepted);
                }
                if attestation_exchange_message.attestation_evidence.is_none() {
                    return Ok(None);
                } else {
                    return Err(AttestationError::AttestationGivenWhenNoneExpected);
                }
            }
            AttestationType::AzureTdx => {
                #[cfg(feature = "azure-verifier")]
                {
                    let attestation_evidence = attestation_exchange_message
                        .attestation_evidence
                        .as_ref()
                        .ok_or(AttestationError::AttestationTypeNotAccepted)?;
                    azure::verify_azure_attestation(
                        attestation_evidence.quote.clone(),
                        expected_input_data,
                        self.internal_pccs.clone(),
                        self.override_azure_outdated_tcb,
                    )
                    .await?
                }
                #[cfg(not(feature = "azure-verifier"))]
                {
                    return Err(AttestationError::AttestationTypeNotSupported);
                }
            }
            AttestationType::DcapTdx | AttestationType::GcpTdx => {
                let attestation_evidence = attestation_exchange_message
                    .attestation_evidence
                    .as_ref()
                    .ok_or(AttestationError::AttestationTypeNotAccepted)?;
                let (verified, quote) = dcap::verify_dcap_attestation(
                    attestation_evidence.quote.clone(),
                    expected_input_data,
                    self.internal_pccs.clone(),
                )
                .await?;
                if attestation_type == AttestationType::GcpTdx {
                    self.gcp_provenance_checker.verify_provenance(quote).await?;
                }
                verified
            }
        };

        // Do a measurement / attestation type policy check
        let platform_metadata = attestation_exchange_message
            .attestation_evidence
            .as_ref()
            .map(|evidence| evidence.platform.clone());
        let policy_state = self.measurement_policy_read().clone();
        let policy_check = policy_state.policy.check_measurement_with_gcp_cache(
            &verified.measurements,
            platform_metadata.as_ref(),
            Some(&self.known_gcp_firmware),
        );

        let matched_measurements = match policy_check {
            Ok(matched_measurements) => matched_measurements,
            Err(err) => {
                // If this fails, and we have dynamic measurement policy,
                // re-retrieve our measurement policy, then
                // check the policy a second time
                if let Some(file_or_url) = &self.dynamic_measurement_policy {
                    let new_measurement_policy =
                        MeasurementPolicy::from_file_or_url(file_or_url.to_string()).await?;
                    let measurement_policy = self
                        .set_measurement_policy(new_measurement_policy, policy_state.generation);
                    measurement_policy.check_measurement_with_gcp_cache(
                        &verified.measurements,
                        platform_metadata.as_ref(),
                        Some(&self.known_gcp_firmware),
                    )?
                } else {
                    return Err(err);
                }
            }
        };

        tracing::debug!("Verification successful");
        verified.expected_measurements = Some(matched_measurements);
        Ok(Some(verified))
    }

    /// Verify an attestation synchronously, and return the expected
    /// measurements from the matching policy record.
    pub fn verify_attestation_sync(
        &self,
        attestation_exchange_message: AttestationExchangeMessage,
        expected_input_data: [u8; 64],
    ) -> Result<Option<VerifiedAttestation>, AttestationError> {
        let attestation_type = attestation_exchange_message.attestation_type();
        tracing::debug!("Verifying {attestation_type} attestation");

        if self.dump_dcap_quotes {
            log_attestation(&attestation_exchange_message);
        }

        let mut verified = match attestation_type {
            AttestationType::None => {
                if self.has_remote_attestation() {
                    return Err(AttestationError::AttestationTypeNotAccepted);
                }
                if attestation_exchange_message.attestation_evidence.is_none() {
                    return Ok(None);
                } else {
                    return Err(AttestationError::AttestationGivenWhenNoneExpected);
                }
            }
            AttestationType::AzureTdx => {
                #[cfg(feature = "azure-verifier")]
                {
                    let attestation_evidence = attestation_exchange_message
                        .attestation_evidence
                        .as_ref()
                        .ok_or(AttestationError::AttestationTypeNotAccepted)?;
                    let pccs = self.internal_pccs.clone().ok_or(AttestationError::NoPccs)?;
                    azure::verify_azure_attestation_sync(
                        attestation_evidence.quote.clone(),
                        expected_input_data,
                        pccs,
                        self.override_azure_outdated_tcb,
                    )?
                }
                #[cfg(not(feature = "azure-verifier"))]
                {
                    return Err(AttestationError::AttestationTypeNotSupported);
                }
            }
            AttestationType::DcapTdx | AttestationType::GcpTdx => {
                let attestation_evidence = attestation_exchange_message
                    .attestation_evidence
                    .as_ref()
                    .ok_or(AttestationError::AttestationTypeNotAccepted)?;
                #[cfg(any(test, feature = "mock"))]
                let pccs =
                    self.internal_pccs.clone().unwrap_or_else(|| Pccs::new_without_prewarm(None));
                #[cfg(not(any(test, feature = "mock")))]
                let pccs = self.internal_pccs.clone().ok_or(AttestationError::NoPccs)?;

                let (verified, quote) = dcap::verify_dcap_attestation_sync(
                    attestation_evidence.quote.clone(),
                    expected_input_data,
                    pccs,
                )?;
                if attestation_type == AttestationType::GcpTdx {
                    self.gcp_provenance_checker.verify_provenance_sync(&quote)?;
                }
                verified
            }
        };

        // Do a measurement / attestation type policy check
        let platform_metadata = attestation_exchange_message
            .attestation_evidence
            .as_ref()
            .map(|evidence| evidence.platform.clone());
        let policy_state = self.measurement_policy_read().clone();
        let policy_check = policy_state.policy.check_measurement_with_gcp_cache(
            &verified.measurements,
            platform_metadata.as_ref(),
            Some(&self.known_gcp_firmware),
        );

        let matched_measurements = match policy_check {
            Ok(matched_measurements) => matched_measurements,
            Err(err) => {
                if let Some(file_or_url) = &self.dynamic_measurement_policy {
                    let new_measurement_policy =
                        MeasurementPolicy::from_file_or_url_sync(file_or_url.to_string())?;
                    let measurement_policy = self
                        .set_measurement_policy(new_measurement_policy, policy_state.generation);
                    measurement_policy.check_measurement_with_gcp_cache(
                        &verified.measurements,
                        platform_metadata.as_ref(),
                        Some(&self.known_gcp_firmware),
                    )?
                } else {
                    return Err(err);
                }
            }
        };

        tracing::debug!("Verification successful");
        verified.expected_measurements = Some(matched_measurements);
        Ok(Some(verified))
    }

    /// Whether we allow no remote attestation
    pub fn has_remote_attestation(&self) -> bool {
        self.measurement_policy_read().policy.has_remote_attestation()
    }

    /// Returns a snapshot of the measurement policy currently in use.
    pub fn measurement_policy(&self) -> MeasurementPolicy {
        self.measurement_policy_read().policy.clone()
    }

    /// Whether this verifier automatically refreshes its measurement policy
    /// periodically and after a mismatch.
    pub fn has_dynamic_measurement_policy(&self) -> bool {
        self.dynamic_measurement_policy.is_some()
    }

    /// Periodically refreshes a dynamic policy so removals are observed
    /// even while incoming attestations continue to match the cached
    /// policy.
    fn spawn_dynamic_measurement_policy_refresh(&self) {
        let Some(file_or_url) = self.dynamic_measurement_policy.clone() else {
            return;
        };

        Self::spawn_dynamic_measurement_policy_refresh_with_interval(
            Arc::downgrade(&self.measurement_policy),
            file_or_url,
            DYNAMIC_MEASUREMENT_POLICY_REFRESH_INTERVAL,
        );
    }

    fn spawn_dynamic_measurement_policy_refresh_with_interval(
        measurement_policy: std::sync::Weak<RwLock<MeasurementPolicyState>>,
        file_or_url: String,
        refresh_interval: Duration,
    ) {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(Self::refresh_dynamic_measurement_policy(
                measurement_policy,
                file_or_url,
                refresh_interval,
            ));
        } else {
            std::thread::spawn(move || {
                Self::refresh_dynamic_measurement_policy_sync(
                    measurement_policy,
                    file_or_url,
                    refresh_interval,
                );
            });
        }
    }

    async fn refresh_dynamic_measurement_policy(
        measurement_policy: std::sync::Weak<RwLock<MeasurementPolicyState>>,
        file_or_url: String,
        refresh_interval: Duration,
    ) {
        loop {
            sleep(refresh_interval).await;

            let Some(generation) = Self::measurement_policy_generation(&measurement_policy) else {
                return;
            };

            let new_policy = match MeasurementPolicy::from_file_or_url(file_or_url.clone()).await {
                Ok(policy) => policy,
                Err(err) => {
                    tracing::warn!(error = %err, "Failed to periodically refresh measurement policy");
                    continue;
                }
            };

            if !Self::install_measurement_policy(&measurement_policy, new_policy, generation) {
                return;
            }
        }
    }

    fn refresh_dynamic_measurement_policy_sync(
        measurement_policy: std::sync::Weak<RwLock<MeasurementPolicyState>>,
        file_or_url: String,
        refresh_interval: Duration,
    ) {
        loop {
            std::thread::sleep(refresh_interval);

            let Some(generation) = Self::measurement_policy_generation(&measurement_policy) else {
                return;
            };

            let new_policy = match MeasurementPolicy::from_file_or_url_sync(file_or_url.clone()) {
                Ok(policy) => policy,
                Err(err) => {
                    tracing::warn!(error = %err, "Failed to periodically refresh measurement policy");
                    continue;
                }
            };

            if !Self::install_measurement_policy(&measurement_policy, new_policy, generation) {
                return;
            }
        }
    }

    fn measurement_policy_generation(
        measurement_policy: &std::sync::Weak<RwLock<MeasurementPolicyState>>,
    ) -> Option<u64> {
        let policy_state = measurement_policy.upgrade()?;
        Some(policy_state.read().unwrap_or_else(|poisoned| poisoned.into_inner()).generation)
    }

    /// Installs a refreshed policy if no newer refresh won the race.
    /// Returns false when the verifier has been dropped and the refresh
    /// loop should exit.
    fn install_measurement_policy(
        measurement_policy: &std::sync::Weak<RwLock<MeasurementPolicyState>>,
        new_policy: MeasurementPolicy,
        expected_generation: u64,
    ) -> bool {
        let Some(policy_state) = measurement_policy.upgrade() else {
            return false;
        };
        let mut state = policy_state.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.generation == expected_generation {
            state.policy = new_policy;
            state.generation = state.generation.wrapping_add(1);
        }
        true
    }

    /// Replaces the measurement policy used by this verifier and all of its
    /// clones if it has not changed since `expected_generation` was
    /// observed.
    pub(crate) fn set_measurement_policy(
        &self,
        measurement_policy: MeasurementPolicy,
        expected_generation: u64,
    ) -> MeasurementPolicy {
        let mut state = self.measurement_policy_write();
        if state.generation == expected_generation {
            state.policy = measurement_policy;
            state.generation = state.generation.wrapping_add(1);
        }
        state.policy.clone()
    }

    fn measurement_policy_read(&self) -> RwLockReadGuard<'_, MeasurementPolicyState> {
        self.measurement_policy.read().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn measurement_policy_write(&self) -> RwLockWriteGuard<'_, MeasurementPolicyState> {
        self.measurement_policy.write().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Write attestation data to a log file
fn log_attestation(attestation: &AttestationExchangeMessage) {
    if let Some(attestation_evidence) = &attestation.attestation_evidence {
        let timestamp =
            SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_nanos();

        let attestation_type = attestation.attestation_type();
        let filename = format!("quotes/{attestation_type}-{timestamp}");
        let attestation_bytes = attestation_evidence.quote.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Err(err) = tokio::fs::write(&filename, attestation_bytes).await {
                    tracing::warn!("Failed to write {filename}: {err}");
                }
            });
        } else {
            std::thread::spawn(move || {
                if let Err(err) = std::fs::write(&filename, attestation_bytes) {
                    tracing::warn!("Failed to write {filename}: {err}");
                }
            });
        }
    }
}

/// Test whether it looks like we are running on GCP by hitting the metadata
/// API
fn running_on_gcp() -> Result<bool, AttestationError> {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_millis(200)).build();
    let resp = agent.get(GCP_METADATA_API).call();

    if let Ok(r) = resp {
        return Ok(r.status() == 200 &&
            r.header("Metadata-Flavor").map(|v| v == "Google").unwrap_or(false));
    }

    Ok(false)
}

/// If an attestation provider service is used, we ensure that it looks like
/// a local IP
///
/// This is to avoid dangerous configuration where the attestation is
/// provided by a remote machine
///
/// This by no means guarantees a safe configuration
fn map_attestation_provider_url(url: String) -> Result<String, AttestationError> {
    // Fist put it in the format that reqwest expects
    let url = if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("http://{}", url.trim_start_matches("http://"))
    };

    let url = url.strip_suffix('/').unwrap_or(&url).to_string();
    let url = url.strip_suffix("/attest").unwrap_or(&url).to_string();

    // If compiled in test mode, skip this check
    if !cfg!(test) {
        let parsed = url
            .parse::<std::net::SocketAddr>()
            .or_else(|_| {
                // Try parsing as a URL to extract host
                let parsed = url.parse::<http::Uri>().map_err(|_| "Invalid URL")?;

                let host = parsed.host().ok_or("URL missing host")?;

                host.parse::<std::net::IpAddr>()
                    .map_err(|_| "Only local IP addresses may be used as attestation provider URL")
                    .map(|ip| std::net::SocketAddr::new(ip, 0))
            })
            .map_err(|e| AttestationError::AttestationProviderUrl(e.to_string()))?;

        if !is_local_ip(parsed.ip()) {
            return Err(AttestationError::AttestationProviderUrl(
                "Given URL does not appear to contain a local IP address".to_string(),
            ));
        }
    }
    Ok(url)
}

/// Check if an IP address looks like it is local
fn is_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

#[cfg(any(test, feature = "mock"))]
/// Create mock platform metadata for tests
pub fn mock_platform_metadata(
    attestation_type: AttestationType,
) -> Result<PlatformMetadata, AttestationError> {
    Ok(PlatformMetadata {
        attestation_type: attestation_type.try_into()?,
        ram_bytes: 0,
        num_disks: 0,
        acpi: None,
        dm_verity_boot: false,
        smbios_handoff: None,
    })
}

/// An error when generating or verifying an attestation
#[derive(Error, Debug)]
pub enum AttestationError {
    #[error("Certificate chain is empty")]
    NoCertificate,
    #[error("X509 parse: {0}")]
    X509Parse(#[from] x509_parser::asn1_rs::Err<x509_parser::error::X509Error>),
    #[error("X509: {0}")]
    X509(#[from] x509_parser::error::X509Error),
    #[error("Configuration mismatch - expected no remote attestation")]
    AttestationGivenWhenNoneExpected,
    #[error("TDX quote generation: {0}")]
    QuoteGeneration(#[from] tdx_attest::TdxAttestError),
    #[error("DCAP verification: {0}")]
    DcapVerification(#[from] DcapVerificationError),
    #[error("GCP provenance: {0}")]
    GcpProvenance(#[from] GcpProvenanceError),
    #[error("Attestation type not supported")]
    AttestationTypeNotSupported,
    #[error("Attestation type not accepted")]
    AttestationTypeNotAccepted,
    #[error("Measurements not accepted")]
    MeasurementsNotAccepted,
    #[error("Failed to refresh measurement policy: {0}")]
    MeasurementPolicyRefresh(#[from] MeasurementFormatError),
    #[cfg(feature = "azure-verifier")]
    #[error("Microsoft Azure Attestation (MAA): {0}")]
    Maa(#[from] azure::MaaError),
    #[error("If using a an attestation provider an attestation type must be given")]
    AttestationTypeNotGiven,
    #[error("Attestation provider server: {0}")]
    AttestationProvider(String),
    #[error("Attestation provider URL: {0}")]
    AttestationProviderUrl(String),
    #[error("JSON: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("HTTP client: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("PCCS: {0}")]
    Pccs(#[from] PccsError),
    #[error("Sync verification requested but no PCCS configured")]
    NoPccs,
    #[cfg(any(test, feature = "mock"))]
    #[error("Cannot create mock attestation: {0}")]
    Mock(String),
    #[error("Cannot retrieve platform metadata: {0}")]
    PlatformMetadata(#[from] PlatformError),
}

#[cfg(test)]
mod tests {
    use mock_tdx::mock_pcs::{MockPcsConfig, spawn_mock_pcs_server};

    use super::*;

    #[test]
    fn attestation_detection_does_not_panic() {
        // We dont enforce what platform the test is run on, only that the
        // function does not panic
        let _ = AttestationGenerator::new_with_detection(None, None);
    }

    #[test]
    fn running_on_gcp_check_does_not_panic() {
        let _ = running_on_gcp();
    }

    #[tokio::test]
    async fn verifier_returns_no_verified_attestation_when_none_is_expected() {
        let verifier = AttestationVerifier::expect_none();
        let attestation = AttestationExchangeMessage::without_attestation();
        let input_data = [0u8; 64];

        assert!(
            verifier.verify_attestation(attestation.clone(), input_data).await.unwrap().is_none()
        );
        assert!(verifier.verify_attestation_sync(attestation, input_data).unwrap().is_none());
    }

    #[tokio::test]
    async fn mock_verifier_supports_sync_verification() {
        let input_data = [7u8; 64];
        let quote = dcap::create_dcap_attestation(input_data).unwrap();
        let attestation_evidence = AttestationEvidence {
            quote,
            platform: mock_platform_metadata(AttestationType::DcapTdx).unwrap(),
        };

        let mock_pcs_server = spawn_mock_pcs_server(MockPcsConfig::default()).await.unwrap();

        let verifier = AttestationVerifier::mock_with_pccs(mock_pcs_server.base_url.clone());
        if let Some(ref pccs) = verifier.internal_pccs {
            pccs.ready().await.unwrap();
        }

        let result = verifier.verify_attestation_sync(attestation_evidence.into(), input_data);

        assert!(
            matches!(
                result,
                Ok(Some(VerifiedAttestation {
                    expected_measurements: Some(ExpectedMeasurements::Dcap(_)),
                    ..
                }))
            ),
            "expected sync mock verification to return matched DCAP measurements: {result:?}"
        );
    }

    /// On the fetching path, the reported bundle is the one the fetch
    /// produced — the property that makes archiving it provenance rather
    /// than a second, possibly different, copy.
    #[tokio::test]
    async fn verify_reports_the_collateral_the_fetch_produced() {
        let input_data = [7u8; 64];
        let quote_bytes = dcap::create_dcap_attestation(input_data).unwrap();
        let quote = dcap_qvl::quote::Quote::parse(&quote_bytes).unwrap();
        let fmspc = hex::encode_upper(dcap_qvl::intel::quote_fmspc(&quote).unwrap());
        let ca = dcap_qvl::intel::quote_ca(&quote).unwrap().as_id_str();
        let attestation_evidence = AttestationEvidence {
            quote: quote_bytes,
            platform: mock_platform_metadata(AttestationType::DcapTdx).unwrap(),
        };

        let mock_pcs_server = spawn_mock_pcs_server(MockPcsConfig::default()).await.unwrap();
        let verifier = AttestationVerifier::mock_with_pccs(mock_pcs_server.base_url.clone());

        let verified = verifier
            .verify_attestation(attestation_evidence.into(), input_data)
            .await
            .unwrap()
            .expect("mock evidence carries an attestation");

        // The second read is served from the PCCS cache, not a second
        // fetch, so it yields the same bundle the verification
        // consumed. That is what makes it a valid comparison here —
        // and the reason a caller must not rely on the pattern in
        // general, where a refresh in between would hand back a
        // different bundle
        let (served, _is_fresh) = verifier
            .internal_pccs
            .as_ref()
            .unwrap()
            .get_collateral(
                fmspc,
                ca,
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            )
            .await
            .unwrap();
        assert_eq!(verified.endorsements.dcap, Some(served));
    }

    #[test]
    fn measurement_policy_can_be_updated_between_verification_attempts() {
        let verifier = AttestationVerifier::builder(MeasurementPolicy::tdx())
            .with_pccs_mode(PccsMode::None)
            .build();
        let verifier_clone = verifier.clone();
        let message = AttestationExchangeMessage::without_attestation();
        let input_data = [0; 64];

        assert!(matches!(
            verifier.verify_attestation_sync(message.clone(), input_data),
            Err(AttestationError::AttestationTypeNotAccepted)
        ));

        let generation = verifier_clone.measurement_policy_read().generation;
        verifier_clone.set_measurement_policy(MeasurementPolicy::expect_none(), generation);

        assert!(matches!(verifier.verify_attestation_sync(message, input_data), Ok(None)));
    }

    #[test]
    fn stale_measurement_policy_refresh_does_not_overwrite_newer_policy() {
        let verifier = AttestationVerifier::expect_none();
        let stale_generation = verifier.measurement_policy_read().generation;

        verifier.set_measurement_policy(MeasurementPolicy::tdx(), stale_generation);
        let installed_policy =
            verifier.set_measurement_policy(MeasurementPolicy::expect_none(), stale_generation);

        assert!(installed_policy.has_remote_attestation());
        assert!(verifier.has_remote_attestation());
    }

    #[tokio::test]
    async fn dynamic_measurement_policy_refetches_on_mismatch() {
        let temp_dir = tempfile::tempdir().unwrap();
        let policy_path = temp_dir.path().join("measurements.json");
        tokio::fs::write(&policy_path, br#"[{"attestation_type":"none"}]"#).await.unwrap();

        let initial_policy = MeasurementPolicy::from_file(policy_path.clone()).await.unwrap();
        let verifier = AttestationVerifier::builder(initial_policy)
            .with_pccs_mode(PccsMode::None)
            .with_dynamic_measurements_file_or_url(policy_path.to_string_lossy().into_owned())
            .build();

        let input_data = [7u8; 64];
        let quote = dcap::create_dcap_attestation(input_data).unwrap();
        let attestation = AttestationEvidence {
            quote,
            platform: mock_platform_metadata(AttestationType::DcapTdx).unwrap(),
        };
        let measurements = measurements::mock_dcap_measurements();

        assert!(verifier.measurement_policy().check_measurement(&measurements, None).is_err());

        tokio::fs::write(&policy_path, br#"[{"attestation_type":"dcap-tdx"}]"#).await.unwrap();

        let verified = verifier
            .verify_attestation(attestation.into(), input_data)
            .await
            .unwrap()
            .expect("mock evidence carries an attestation");

        assert!(matches!(verified.expected_measurements, Some(ExpectedMeasurements::Dcap(_))));

        assert!(verifier.measurement_policy().check_measurement(&measurements, None).is_ok());
    }

    #[tokio::test]
    async fn dynamic_measurement_policy_refreshes_periodically() {
        let temp_dir = tempfile::tempdir().unwrap();
        let policy_path = temp_dir.path().join("measurements.json");
        tokio::fs::write(&policy_path, br#"[{"attestation_type":"dcap-tdx"}]"#).await.unwrap();

        let policy_source = policy_path.to_string_lossy().into_owned();
        let initial_policy = MeasurementPolicy::from_file(policy_path.clone()).await.unwrap();
        let verifier = AttestationVerifier::builder(initial_policy)
            .with_pccs_mode(PccsMode::None)
            .with_dynamic_measurements_file_or_url(policy_source.clone())
            .build();
        let measurements = measurements::mock_dcap_measurements();

        assert!(verifier.measurement_policy().check_measurement(&measurements, None).is_ok());

        AttestationVerifier::spawn_dynamic_measurement_policy_refresh_with_interval(
            Arc::downgrade(&verifier.measurement_policy),
            policy_source,
            Duration::from_millis(10),
        );
        tokio::fs::write(&policy_path, br#"[{"attestation_type":"none"}]"#).await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if verifier.measurement_policy().check_measurement(&measurements, None).is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("periodic policy refresh did not remove the revoked measurement");
    }

    #[test]
    fn dynamic_measurement_policy_refreshes_periodically_without_tokio() {
        let temp_dir = tempfile::tempdir().unwrap();
        let policy_path = temp_dir.path().join("measurements.json");
        std::fs::write(&policy_path, br#"[{"attestation_type":"dcap-tdx"}]"#).unwrap();

        let policy_source = policy_path.to_string_lossy().into_owned();
        let initial_policy =
            MeasurementPolicy::from_file_or_url_sync(policy_source.clone()).unwrap();
        let verifier = AttestationVerifier::builder(initial_policy)
            .with_pccs_mode(PccsMode::None)
            .with_dynamic_measurements_file_or_url(policy_source.clone())
            .build();
        let measurements = measurements::mock_dcap_measurements();

        assert!(verifier.measurement_policy().check_measurement(&measurements, None).is_ok());

        AttestationVerifier::spawn_dynamic_measurement_policy_refresh_with_interval(
            Arc::downgrade(&verifier.measurement_policy),
            policy_source,
            Duration::from_millis(10),
        );
        std::fs::write(&policy_path, br#"[{"attestation_type":"none"}]"#).unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while verifier.measurement_policy().check_measurement(&measurements, None).is_ok() {
            assert!(
                std::time::Instant::now() < deadline,
                "standard-thread policy refresh did not remove the revoked measurement"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[tokio::test]
    async fn sync_verification_refetches_dynamic_measurement_policy_on_mismatch() {
        let temp_dir = tempfile::tempdir().unwrap();
        let policy_path = temp_dir.path().join("measurements.json");
        std::fs::write(&policy_path, br#"[{"attestation_type":"none"}]"#).unwrap();

        let policy_source = policy_path.to_string_lossy().into_owned();
        let initial_policy =
            MeasurementPolicy::from_file_or_url_sync(policy_source.clone()).unwrap();
        let mock_pcs_server = spawn_mock_pcs_server(MockPcsConfig::default()).await.unwrap();
        let verifier = AttestationVerifier::builder(initial_policy)
            .with_pccs_mode(PccsMode::Prewarmed)
            .with_pccs_url(mock_pcs_server.base_url.clone())
            .with_dynamic_measurements_file_or_url(policy_source)
            .build();
        verifier.ready().await.unwrap();

        let input_data = [7u8; 64];
        let quote = dcap::create_dcap_attestation(input_data).unwrap();
        let attestation = AttestationEvidence {
            quote,
            platform: mock_platform_metadata(AttestationType::DcapTdx).unwrap(),
        };

        std::fs::write(&policy_path, br#"[{"attestation_type":"dcap-tdx"}]"#).unwrap();

        let verified = verifier
            .verify_attestation_sync(attestation.into(), input_data)
            .unwrap()
            .expect("mock evidence carries an attestation");

        assert!(matches!(verified.expected_measurements, Some(ExpectedMeasurements::Dcap(_))));
    }
}
