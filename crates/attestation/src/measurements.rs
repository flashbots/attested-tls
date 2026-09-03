//! Measurements and policy for enforcing them when validating a remote
//! attestation
use std::{
    collections::HashMap,
    fmt,
    fmt::Formatter,
    io::Read,
    net::IpAddr,
    path::PathBuf,
    time::Duration,
};

use attest_measure::dcap::expected_dcap_registers;
use attest_types::{
    AttestationType as ImageAttestationType,
    DcapImageHashes,
    MeasurementOutput,
    PlatformMetadata,
};
use dcap_qvl::quote::Report;
use http::{HeaderValue, header::InvalidHeaderValue, uri::InvalidUri};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

use crate::{
    AttestationError,
    AttestationType,
    dcap::DcapVerificationError,
    gcp::{GcpFirmwareCache, fetch_firmware},
    trusted_firmware::firmware_for_mrtd,
};

/// Represents the measurement register types in a TDX quote
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DcapMeasurementRegister {
    MRTD,
    RTMR0,
    RTMR1,
    RTMR2,
    RTMR3,
}

/// For converting from the format used in headers
impl TryFrom<u8> for DcapMeasurementRegister {
    type Error = MeasurementFormatError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::MRTD),
            1 => Ok(Self::RTMR0),
            2 => Ok(Self::RTMR1),
            3 => Ok(Self::RTMR2),
            4 => Ok(Self::RTMR3),
            _ => Err(MeasurementFormatError::BadRegisterIndex),
        }
    }
}

impl DcapMeasurementRegister {
    fn from_policy_key(value: &str) -> Result<Self, MeasurementFormatError> {
        // For backwards compatiblity support numeric field names where
        // "0" is MRTD, "1" is RTMR0, etc.
        if let Ok(index) = value.parse::<u8>() {
            return Self::try_from(index);
        }

        match value.to_ascii_lowercase().as_str() {
            "mrtd" => Ok(Self::MRTD),
            "rtmr0" => Ok(Self::RTMR0),
            "rtmr1" => Ok(Self::RTMR1),
            "rtmr2" => Ok(Self::RTMR2),
            "rtmr3" => Ok(Self::RTMR3),
            _ => Err(MeasurementFormatError::BadRegisterIndex),
        }
    }
}

fn parse_azure_pcr_index(value: &str) -> Result<u32, MeasurementFormatError> {
    // For backwards compatibility support bare numeric field names. Also
    // accept a clearer case-insensitive "pcr" prefix, e.g. "pcr4".
    let index = if let Ok(index) = value.parse::<u32>() {
        index
    } else if let Some(suffix) = value.strip_prefix("pcr").or_else(|| value.strip_prefix("PCR")) {
        suffix.parse::<u32>()?
    } else if value.get(..3).is_some_and(|prefix| prefix.eq_ignore_ascii_case("pcr")) {
        value[3..].parse::<u32>()?
    } else {
        return Err(MeasurementFormatError::ParseInt(value.parse::<u32>().unwrap_err()));
    };

    if index > 23 {
        return Err(MeasurementFormatError::BadRegisterIndex);
    }

    Ok(index)
}

#[derive(Clone, PartialEq)]
pub struct DcapMeasurements {
    pub mrtd: [u8; 48],
    pub rtmr0: [u8; 48],
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
    pub rtmr3: [u8; 48],
}

impl DcapMeasurements {
    pub fn new(
        mrtd: [u8; 48],
        rtmr0: [u8; 48],
        rtmr1: [u8; 48],
        rtmr2: [u8; 48],
        rtmr3: [u8; 48],
    ) -> Self {
        Self { mrtd, rtmr0, rtmr1, rtmr2, rtmr3 }
    }

    fn iter(&self) -> impl Iterator<Item = (DcapMeasurementRegister, &[u8; 48])> {
        [
            (DcapMeasurementRegister::MRTD, &self.mrtd),
            (DcapMeasurementRegister::RTMR0, &self.rtmr0),
            (DcapMeasurementRegister::RTMR1, &self.rtmr1),
            (DcapMeasurementRegister::RTMR2, &self.rtmr2),
            (DcapMeasurementRegister::RTMR3, &self.rtmr3),
        ]
        .into_iter()
    }

    fn get(&self, register: &DcapMeasurementRegister) -> &[u8; 48] {
        match register {
            DcapMeasurementRegister::MRTD => &self.mrtd,
            DcapMeasurementRegister::RTMR0 => &self.rtmr0,
            DcapMeasurementRegister::RTMR1 => &self.rtmr1,
            DcapMeasurementRegister::RTMR2 => &self.rtmr2,
            DcapMeasurementRegister::RTMR3 => &self.rtmr3,
        }
    }
}

impl fmt::Debug for DcapMeasurements {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        DcapHexDebug(self).fmt(f)
    }
}

/// Represents a set of measurements values for one of the supported CVM
/// platforms
#[derive(Clone, PartialEq)]
pub enum MultiMeasurements {
    Dcap(DcapMeasurements),
    /// Azure vTPM PCR values, keyed by the register each one measures.
    ///
    /// The keys are the registers the quote attested, named by its
    /// `pcrSelect` bitmap. That is any subset the sending party chose, so a
    /// register absent from the map was not attested. Azure's own attester
    /// selects all 24 of a vTPM's registers, but nothing here requires it.
    ///
    /// Values are SHA-256 digests, the only PCR bank a quote may select
    /// here.
    Azure(HashMap<u32, [u8; 32]>),
    NoAttestation,
}

impl fmt::Debug for MultiMeasurements {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dcap(measurements) => f.debug_tuple("DCAP").field(measurements).finish(),
            Self::Azure(measurements) => {
                f.debug_tuple("Azure").field(&AzureHexDebug(measurements)).finish()
            }
            Self::NoAttestation => f.write_str("NoAttestation"),
        }
    }
}

/// Used to display DCAP measurements as hex
struct DcapHexDebug<'a>(&'a DcapMeasurements);

impl fmt::Debug for DcapHexDebug<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (register, value) in self.0.iter() {
            let hex_value = hex::encode(value);
            map.entry(&register, &hex_value);
        }
        map.finish()
    }
}

/// Used to display Azure measurements as hex
struct AzureHexDebug<'a>(&'a HashMap<u32, [u8; 32]>);

impl fmt::Debug for AzureHexDebug<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut entries: Vec<_> = self.0.iter().collect();
        entries.sort_by_key(|(index, _)| **index);

        let mut map = f.debug_map();
        for (index, value) in entries {
            let hex_value = hex::encode(value);
            map.entry(index, &hex_value);
        }
        map.finish()
    }
}

/// Expected measurement values for policy enforcement
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum ExpectedMeasurements {
    Image(DcapImageHashes),
    Dcap(HashMap<DcapMeasurementRegister, Vec<[u8; 48]>>),
    /// Accepted Azure vTPM PCR values, keyed by PCR register.
    ///
    /// These are the registers the policy constrains, not the registers a
    /// quote carries. Keys come from the policy's field names, spelled
    /// either `"4"` or `"pcr4"`, which [`parse_azure_pcr_index`] rejects
    /// above 23. Each register maps to every value that satisfies it, so
    /// one policy can accept several images.
    ///
    /// A register absent from the map is unconstrained. A register present
    /// here but absent from the evidence rejects that evidence.
    Azure(HashMap<u32, Vec<[u8; 32]>>),
    NoAttestation,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", content = "measurements", rename_all = "snake_case")]
enum ExpectedMeasurementsHeader {
    Image(Box<DcapImageHashes>),
    Dcap(HashMap<String, Vec<String>>),
    Azure(HashMap<String, Vec<String>>),
    NoAttestation,
}

impl ExpectedMeasurements {
    /// Convert to the JSON format used in HTTP headers
    pub fn to_header_format(&self) -> Result<HeaderValue, MeasurementFormatError> {
        let header_measurements = match self {
            Self::Image(image_hashes) => {
                ExpectedMeasurementsHeader::Image(Box::new(image_hashes.clone()))
            }
            Self::Dcap(dcap_measurements) => ExpectedMeasurementsHeader::Dcap(
                dcap_measurements
                    .iter()
                    .map(|(register, values)| {
                        (
                            (register.clone() as u8).to_string(),
                            values.iter().map(hex::encode).collect(),
                        )
                    })
                    .collect(),
            ),
            Self::Azure(azure_measurements) => ExpectedMeasurementsHeader::Azure(
                azure_measurements
                    .iter()
                    .map(|(index, values)| {
                        (index.to_string(), values.iter().map(hex::encode).collect())
                    })
                    .collect(),
            ),
            Self::NoAttestation => ExpectedMeasurementsHeader::NoAttestation,
        };

        Ok(HeaderValue::from_str(&serde_json::to_string(&header_measurements)?)?)
    }

    /// Parse the JSON used in HTTP headers
    pub fn from_header_format(input: &str) -> Result<Self, MeasurementFormatError> {
        fn decode_values<const N: usize>(
            values: Vec<String>,
        ) -> Result<Vec<[u8; N]>, MeasurementFormatError> {
            values
                .into_iter()
                .map(|value| {
                    hex::decode(value)?.try_into().map_err(|_| MeasurementFormatError::BadLength)
                })
                .collect()
        }

        Ok(match serde_json::from_str(input)? {
            ExpectedMeasurementsHeader::Image(image_hashes) => Self::Image(*image_hashes),
            ExpectedMeasurementsHeader::Dcap(dcap_measurements) => Self::Dcap(
                dcap_measurements
                    .into_iter()
                    .map(|(register, values)| {
                        Ok((register.parse::<u8>()?.try_into()?, decode_values::<48>(values)?))
                    })
                    .collect::<Result<_, MeasurementFormatError>>()?,
            ),
            ExpectedMeasurementsHeader::Azure(azure_measurements) => Self::Azure(
                azure_measurements
                    .into_iter()
                    .map(|(index, values)| Ok((index.parse()?, decode_values::<32>(values)?)))
                    .collect::<Result<_, MeasurementFormatError>>()?,
            ),
            ExpectedMeasurementsHeader::NoAttestation => Self::NoAttestation,
        })
    }
}

impl MultiMeasurements {
    /// Given a quote from the dcap_qvl library, extract the measurements
    pub fn from_dcap_qvl_quote(
        quote: &dcap_qvl::quote::Quote,
    ) -> Result<Self, DcapVerificationError> {
        let report = match quote.report {
            Report::TD10(report) => report,
            Report::TD15(report) => report.base,
            Report::SgxEnclave(_) => {
                return Err(DcapVerificationError::SgxNotSupported);
            }
        };
        Ok(Self::Dcap(DcapMeasurements::new(
            report.mr_td,
            report.rt_mr0,
            report.rt_mr1,
            report.rt_mr2,
            report.rt_mr3,
        )))
    }

    /// Azure measurements from PCR values already paired with the registers
    /// they measure.
    ///
    /// The pairing belongs to the quote — its `pcrSelect` bitmap says which
    /// registers it attests — so it arrives here rather than being inferred
    /// from list position. `pcrN` in a measurement policy names register N,
    /// and nothing else may decide that.
    pub fn from_indexed_pcrs(pcrs: impl IntoIterator<Item = (u32, [u8; 32])>) -> Self {
        Self::Azure(pcrs.into_iter().collect())
    }
}

/// Mock TDX measurement values used in tests
#[cfg(any(test, feature = "mock"))]
pub fn mock_dcap_measurements() -> MultiMeasurements {
    MultiMeasurements::Dcap(DcapMeasurements::new(
        mock_tdx::MOCK_MRTD,
        mock_tdx::MOCK_RTMR0,
        mock_tdx::MOCK_RTMR1,
        mock_tdx::MOCK_RTMR2,
        mock_tdx::MOCK_RTMR3,
    ))
}

/// An accepted measurement value given in the measurements file
#[derive(Clone, Debug, PartialEq)]
pub struct MeasurementRecord {
    /// An identifier, for example the name and version of the corresponding
    /// OS image
    pub measurement_id: String,
    /// The attestation type this record accepts
    pub attestation_type: AttestationType,
    /// The expected measurement register values
    pub measurements: ExpectedMeasurements,
}

impl MeasurementRecord {
    pub fn allow_no_attestation() -> Self {
        Self {
            measurement_id: "Allow no attestation".to_string(),
            attestation_type: AttestationType::None,
            measurements: ExpectedMeasurements::NoAttestation,
        }
    }

    pub fn allow_any_measurement(attestation_type: AttestationType) -> Self {
        Self {
            measurement_id: format!("Any measurement for {attestation_type}"),
            attestation_type,
            measurements: match attestation_type {
                AttestationType::None => ExpectedMeasurements::NoAttestation,
                AttestationType::AzureTdx => ExpectedMeasurements::Azure(HashMap::new()),
                AttestationType::DcapTdx | AttestationType::GcpTdx => {
                    ExpectedMeasurements::Dcap(HashMap::new())
                }
            },
        }
    }
}

/// Represents the measurement policy
///
/// This is a set of acceptable attestation types (CVM platforms) which may
/// or may not enforce acceptable measurement values for each attestation
/// type
#[derive(Clone, Debug)]
pub struct MeasurementPolicy {
    /// A map of accepted attestation types to accepted measurement values
    /// A value of None means accept any measurement value for this
    /// measurement type
    pub(crate) accepted_measurements: Vec<MeasurementRecord>,
}

impl MeasurementPolicy {
    /// This will only allow no attestation - and will reject it if one is
    /// given
    pub fn expect_none() -> Self {
        Self { accepted_measurements: vec![MeasurementRecord::allow_no_attestation()] }
    }

    /// Allow any measurements with the given attestation type
    pub fn single_attestation_type(attestation_type: AttestationType) -> Self {
        Self {
            accepted_measurements: vec![MeasurementRecord::allow_any_measurement(attestation_type)],
        }
    }

    /// Accept any attestation type with any measurements
    pub fn accept_anything() -> Self {
        Self {
            accepted_measurements: vec![
                MeasurementRecord::allow_no_attestation(),
                MeasurementRecord::allow_any_measurement(AttestationType::DcapTdx),
                MeasurementRecord::allow_any_measurement(AttestationType::GcpTdx),
                MeasurementRecord::allow_any_measurement(AttestationType::AzureTdx),
            ],
        }
    }

    /// Accept any TDX attestation regardless of platform
    pub fn tdx() -> Self {
        Self {
            accepted_measurements: vec![
                MeasurementRecord::allow_any_measurement(AttestationType::DcapTdx),
                MeasurementRecord::allow_any_measurement(AttestationType::GcpTdx),
                MeasurementRecord::allow_any_measurement(AttestationType::AzureTdx),
            ],
        }
    }

    /// Expect mock measurements used in tests
    #[cfg(any(test, feature = "mock"))]
    pub fn mock() -> Self {
        Self {
            accepted_measurements: vec![MeasurementRecord {
                measurement_id: "test".to_string(),
                attestation_type: AttestationType::DcapTdx,
                measurements: ExpectedMeasurements::Dcap(HashMap::from([
                    (DcapMeasurementRegister::MRTD, vec![mock_tdx::MOCK_MRTD]),
                    (DcapMeasurementRegister::RTMR0, vec![mock_tdx::MOCK_RTMR0]),
                    (DcapMeasurementRegister::RTMR1, vec![mock_tdx::MOCK_RTMR1]),
                    (DcapMeasurementRegister::RTMR2, vec![mock_tdx::MOCK_RTMR2]),
                    (DcapMeasurementRegister::RTMR3, vec![mock_tdx::MOCK_RTMR3]),
                ])),
            }],
        }
    }

    /// Given an attestation type and set of measurements, check whether
    /// they are acceptable.
    ///
    /// On success, returns the matched measurements.
    pub fn check_measurement(
        &self,
        measurements: &MultiMeasurements,
        platform_metadata: Option<&PlatformMetadata>,
    ) -> Result<ExpectedMeasurements, AttestationError> {
        self.check_measurement_with_gcp_cache(measurements, platform_metadata, None)
    }

    /// Given an attestation type and set of measurements, check whether
    /// they are acceptable, passing an optional cache for known GCP
    /// firmware. Returns the expected measurements from the matching policy
    /// record.
    pub(crate) fn check_measurement_with_gcp_cache(
        &self,
        measurements: &MultiMeasurements,
        platform_metadata: Option<&PlatformMetadata>,
        known_gcp_firmware: Option<&GcpFirmwareCache>,
    ) -> Result<ExpectedMeasurements, AttestationError> {
        let actual_attestation_type = platform_metadata
            .map(|metadata| metadata.attestation_type.into())
            .unwrap_or_else(|| match measurements {
                MultiMeasurements::Dcap(_) => AttestationType::DcapTdx,
                MultiMeasurements::Azure(_) => AttestationType::AzureTdx,
                MultiMeasurements::NoAttestation => AttestationType::None,
            });

        self.accepted_measurements
            .iter()
            .find(|measurement_record| match measurements {
                _ if !measurement_record.attestation_type.accepts(actual_attestation_type) => false,
                MultiMeasurements::Dcap(dcap_measurements) => {
                    match &measurement_record.measurements {
                        ExpectedMeasurements::Dcap(expected) => {
                            // All measurements in our policy must be given
                            // and must match
                            for (k, v) in expected.iter() {
                                let actual_value = dcap_measurements.get(k);
                                if !v.iter().any(|v| actual_value == v) {
                                    return false;
                                }
                            }
                            true
                        }
                        ExpectedMeasurements::Image(image_hashes) => {
                            compare_portable_dcap_measurement(
                                image_hashes,
                                dcap_measurements,
                                platform_metadata,
                                known_gcp_firmware,
                            )
                        }
                        ExpectedMeasurements::Azure(_) | ExpectedMeasurements::NoAttestation => {
                            false
                        }
                    }
                }
                MultiMeasurements::Azure(azure_measurements) => {
                    if let ExpectedMeasurements::Azure(expected) = &measurement_record.measurements
                    {
                        for (k, v) in expected.iter() {
                            match azure_measurements.get(k) {
                                Some(actual_value) if v.iter().any(|v| actual_value == v) => {}
                                _ => return false,
                            }
                        }
                        return true;
                    }
                    false
                }
                MultiMeasurements::NoAttestation => {
                    matches!(measurement_record.measurements, ExpectedMeasurements::NoAttestation)
                }
            })
            .map(|measurement_record| measurement_record.measurements.clone())
            .ok_or(AttestationError::MeasurementsNotAccepted)
    }

    /// Whether or not we require attestation
    pub fn has_remote_attestation(&self) -> bool {
        !self
            .accepted_measurements
            .iter()
            .any(|a| a.measurements == ExpectedMeasurements::NoAttestation)
    }

    /// Given either a URL or the path to a file, parse the measurement
    /// policy from JSON
    pub async fn from_file_or_url(file_or_url: String) -> Result<Self, MeasurementFormatError> {
        #[cfg(test)]
        crate::install_test_crypto_provider();

        if file_or_url.to_lowercase().trim_ascii().starts_with("https://") {
            let measurements_json = reqwest::get(file_or_url).await?.bytes().await?;
            Self::from_json_bytes(measurements_json.to_vec())
        } else if file_or_url.to_lowercase().trim_ascii().starts_with("http://") {
            if !Self::is_loopback_http_url(&file_or_url)? {
                return Err(MeasurementFormatError::InsecureHttpNotLoopback(file_or_url));
            }

            let measurements_json = reqwest::get(file_or_url).await?.bytes().await?;
            Self::from_json_bytes(measurements_json.to_vec())
        } else {
            Self::from_file(file_or_url.into()).await
        }
    }

    /// Synchronously parse a measurement policy from either a URL or a file
    /// path.
    pub fn from_file_or_url_sync(file_or_url: String) -> Result<Self, MeasurementFormatError> {
        #[cfg(test)]
        crate::install_test_crypto_provider();

        let normalized_source = file_or_url.to_lowercase();
        let normalized_source = normalized_source.trim_ascii();
        let is_https = normalized_source.starts_with("https://");
        let is_http = normalized_source.starts_with("http://");
        if is_https || is_http {
            if is_http && !Self::is_loopback_http_url(&file_or_url)? {
                return Err(MeasurementFormatError::InsecureHttpNotLoopback(file_or_url));
            }

            let response = ureq::get(&file_or_url)
                .timeout(Duration::from_secs(10))
                .call()
                .map_err(|error| MeasurementFormatError::Ureq(Box::new(error)))?;
            let mut measurements_json = Vec::new();
            response.into_reader().read_to_end(&mut measurements_json)?;
            Self::from_json_bytes(measurements_json)
        } else {
            Self::from_json_bytes(std::fs::read(file_or_url)?)
        }
    }

    /// Given the path to a JSON file containing measurements, return a
    /// [MeasurementPolicy]
    pub async fn from_file(measurement_file: PathBuf) -> Result<Self, MeasurementFormatError> {
        let measurements_json = tokio::fs::read(measurement_file).await?;
        Self::from_json_bytes(measurements_json)
    }

    /// Parse from JSON
    pub fn from_json_bytes(json_bytes: Vec<u8>) -> Result<Self, MeasurementFormatError> {
        #[derive(Debug, Deserialize)]
        struct MeasurementRecordSimple {
            measurement_id: Option<String>,
            attestation_type: String,
            measurements: Option<HashMap<String, MeasurementEntry>>,
            /// Image-component hashes for "portable" verification.
            /// Mutually exclusive with `measurements`.
            dcap_image_hashes: Option<DcapImageHashes>,
        }

        /// Measurement entry for a single register in the measurements JSON
        /// file. Use `expected_any` for new configurations;
        /// `expected` is deprecated.
        #[derive(Debug, Deserialize)]
        struct MeasurementEntry {
            /// Deprecated: use `expected_any` instead. Single hex-encoded
            /// expected value.
            #[serde(default)]
            expected: Option<String>,
            /// List of acceptable hex-encoded values (OR semantics - any
            /// value matches).
            #[serde(default)]
            expected_any: Option<Vec<String>>,
        }

        fn parse_measurement_entry<const N: usize>(
            entry: &MeasurementEntry,
            register_name: &str,
        ) -> Result<Vec<[u8; N]>, MeasurementFormatError> {
            match (&entry.expected, &entry.expected_any) {
                (Some(single), None) => {
                    let bytes: [u8; N] = hex::decode(single)?
                        .try_into()
                        .map_err(|_| MeasurementFormatError::BadLength)?;
                    Ok(vec![bytes])
                }
                (None, Some(any_list)) => {
                    if any_list.is_empty() {
                        return Err(MeasurementFormatError::EmptyExpectedAny(
                            register_name.to_string(),
                        ));
                    }
                    let values = any_list
                        .iter()
                        .map(|hex_str| {
                            hex::decode(hex_str)?
                                .try_into()
                                .map_err(|_| MeasurementFormatError::BadLength)
                        })
                        .collect::<Result<Vec<[u8; N]>, _>>()?;
                    Ok(values)
                }
                (Some(_), Some(_)) => Err(MeasurementFormatError::BothExpectedAndExpectedAny(
                    register_name.to_string(),
                )),
                (None, None) => {
                    Err(MeasurementFormatError::NoExpectedValue(register_name.to_string()))
                }
            }
        }

        let json: serde_json::Value = serde_json::from_slice(&json_bytes)?;

        // If a single object is given, we treat it as an array with a
        // single element
        let records = match json {
            serde_json::Value::Array(records) => records,
            record => vec![record],
        };

        let mut measurement_policy = Vec::new();

        for record_json in records {
            // Support the format output by the attest-measure crate
            if record_json.get("attestation_type").is_none() && record_json.get("kind").is_some() {
                match serde_json::from_value(record_json)? {
                    MeasurementOutput::Portable(portable) => {
                        if let Some(azure) = portable.azure {
                            measurement_policy.push(MeasurementRecord {
                                measurement_id: String::new(),
                                attestation_type: AttestationType::AzureTdx,
                                measurements: ExpectedMeasurements::Azure(HashMap::from([
                                    (4, vec![azure.pcr4]),
                                    (9, vec![azure.pcr9]),
                                    (11, vec![azure.pcr11]),
                                ])),
                            });
                        }

                        measurement_policy.push(MeasurementRecord {
                            measurement_id: String::new(),
                            attestation_type: AttestationType::DcapTdx,
                            measurements: ExpectedMeasurements::Image(portable.dcap),
                        });
                    }
                    MeasurementOutput::Azure(azure) => {
                        measurement_policy.push(MeasurementRecord {
                            measurement_id: String::new(),
                            attestation_type: AttestationType::AzureTdx,
                            measurements: ExpectedMeasurements::Azure(HashMap::from([
                                (4, vec![azure.pcr4]),
                                (9, vec![azure.pcr9]),
                                (11, vec![azure.pcr11]),
                            ])),
                        });
                    }
                    MeasurementOutput::Dcap(_) => {
                        // Not supported because only RTMR 1 and 2 are
                        // specified
                        return Err(MeasurementFormatError::UnsafeAttestMeasureDcapOutput);
                    }
                }
                continue;
            }

            let record: MeasurementRecordSimple = serde_json::from_value(record_json)?;
            let attestation_type: AttestationType =
                serde_json::from_value(serde_json::Value::String(record.attestation_type.clone()))?;

            let expected_measurements = match (record.measurements, record.dcap_image_hashes) {
                (Some(_), Some(_)) => {
                    return Err(MeasurementFormatError::BothMeasurementsAndDcapImageHashes);
                }
                (Some(measurements), None) => match attestation_type {
                    AttestationType::None => ExpectedMeasurements::NoAttestation,
                    AttestationType::AzureTdx => {
                        let azure_measurements = measurements
                            .iter()
                            .map(|(index_str, entry)| {
                                let index = parse_azure_pcr_index(index_str)?;
                                Ok((index, parse_measurement_entry::<32>(entry, index_str)?))
                            })
                            .collect::<Result<HashMap<u32, Vec<[u8; 32]>>, MeasurementFormatError>>(
                            )?;
                        ExpectedMeasurements::Azure(azure_measurements)
                    }
                    AttestationType::DcapTdx | AttestationType::GcpTdx => {
                        ExpectedMeasurements::Dcap(
                            measurements
                                .iter()
                                .map(|(index_str, entry)| {
                                    Ok((
                                        DcapMeasurementRegister::from_policy_key(index_str)?,
                                        parse_measurement_entry::<48>(entry, index_str)?,
                                    ))
                                })
                                .collect::<Result<
                                    HashMap<DcapMeasurementRegister, Vec<[u8; 48]>>,
                                    MeasurementFormatError,
                                >>()?,
                        )
                    }
                },
                (None, Some(image_hashes)) => match attestation_type {
                    AttestationType::DcapTdx | AttestationType::GcpTdx => {
                        ExpectedMeasurements::Image(image_hashes)
                    }
                    AttestationType::None | AttestationType::AzureTdx => {
                        return Err(
                            MeasurementFormatError::DcapImageHashesUnsupportedAttestationType(
                                record.attestation_type,
                            ),
                        );
                    }
                },
                (None, None) => {
                    measurement_policy
                        .push(MeasurementRecord::allow_any_measurement(attestation_type));
                    continue;
                }
            };

            measurement_policy.push(MeasurementRecord {
                measurement_id: record.measurement_id.unwrap_or_default(),
                attestation_type,
                measurements: expected_measurements,
            });
        }

        Ok(MeasurementPolicy { accepted_measurements: measurement_policy })
    }

    /// Determine whether a url is local / loopback device
    ///
    /// This is used to decide whether to allow fetching in plaintext http
    fn is_loopback_http_url(url: &str) -> Result<bool, MeasurementFormatError> {
        let uri: http::Uri = url.parse()?;
        let Some(host) = uri.host() else {
            return Ok(false);
        };
        let normalized_host = host.trim_start_matches('[').trim_end_matches(']');

        Ok(normalized_host.eq_ignore_ascii_case("localhost") ||
            normalized_host.parse::<IpAddr>().is_ok_and(|address| address.is_loopback()))
    }
}

/// Checks a set of DCAP measurement values against a set of OS image hashes
/// and platform metadata.
///
/// Returns true if the given measurements match the expected ones,
/// otherwise logs a warning and returns false.
pub(crate) fn compare_portable_dcap_measurement(
    image_hashes: &DcapImageHashes,
    dcap_measurements: &DcapMeasurements,
    platform_metadata: Option<&PlatformMetadata>,
    known_gcp_firmware: Option<&GcpFirmwareCache>,
) -> bool {
    let Some(platform_metadata) = &platform_metadata else {
        return false;
    };

    // Trusted firmware is needed to reconstruct MRTD and RTMR0. GCP
    // firmware is fetched with a signed endorsement; self-hosted
    // firmware is bundled.
    let firmware = match platform_metadata.attestation_type {
        ImageAttestationType::GcpTdx => {
            let mrtd = dcap_measurements.get(&DcapMeasurementRegister::MRTD);

            let result = if let Some(cache) = known_gcp_firmware {
                cache.get_or_fetch(*mrtd)
            } else {
                fetch_firmware(*mrtd)
            };
            match result {
                Ok(firmware) => Some(firmware),
                Err(err) => {
                    warn!(
                        "Could not match image hash measurement - failed to fetch or verify Google firmware: {err:?}"
                    );
                    return false;
                }
            }
        }
        ImageAttestationType::SelfHostedTdx => {
            let mrtd = *dcap_measurements.get(&DcapMeasurementRegister::MRTD);
            match firmware_for_mrtd(mrtd) {
                Some(firmware) => Some(firmware),
                None => {
                    warn!(
                        "Could not match image hash measurement - self-hosted MRTD {} is not trusted",
                        hex::encode(mrtd)
                    );
                    return false;
                }
            }
        }
        ImageAttestationType::AzureTdx => {
            warn!(
                "Attempting to match portable measurement policy with Azure TDX - not yet supported"
            );
            return false;
        }
    };

    // Compute expect measurements
    let expected_measurements =
        match expected_dcap_registers(image_hashes, platform_metadata, firmware.as_ref()) {
            Ok(expected) => expected,
            Err(err) => {
                warn!("Failed to compute expected DCAP registers: {err:?}");
                return false;
            }
        };

    if expected_measurements.mrtd.is_some_and(|expected_mrtd| {
        dcap_measurements.get(&DcapMeasurementRegister::MRTD) != &expected_mrtd
    }) {
        return false;
    }

    if expected_measurements.rtmr0.is_some_and(|expected_rtmr0| {
        dcap_measurements.get(&DcapMeasurementRegister::RTMR0) != &expected_rtmr0
    }) {
        return false;
    }

    if dcap_measurements.get(&DcapMeasurementRegister::RTMR1) != &expected_measurements.rtmr1 {
        return false;
    }

    if dcap_measurements.get(&DcapMeasurementRegister::RTMR2) != &expected_measurements.rtmr2 {
        return false;
    }

    true
}

/// An error when converting measurements / to or from HTTP header format
#[derive(Error, Debug)]
pub enum MeasurementFormatError {
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Invalid header value: {0}")]
    BadHeaderValue(#[from] InvalidHeaderValue),
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("Attestation type not valid")]
    AttestationTypeNotValid,
    #[error("Hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Expected 48 byte value")]
    BadLength,
    #[error("TDX quote register index must be in the ranger 0-3")]
    BadRegisterIndex,
    #[error("ParseInt: {0}")]
    ParseInt(#[from] std::num::ParseIntError),
    #[error("Failed to read measurements from URL: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Failed to synchronously read measurements from URL: {0}")]
    Ureq(#[source] Box<ureq::Error>),
    #[error("Invalid URL: {0}")]
    InvalidUri(#[from] InvalidUri),
    #[error("Refusing to load measurement policy over plain HTTP from non-loopback host: {0}")]
    InsecureHttpNotLoopback(String),
    #[error("Measurement entry for register '{0}' has both 'expected' and 'expected_any'")]
    BothExpectedAndExpectedAny(String),
    #[error("Measurement entry for register '{0}' has neither 'expected' nor 'expected_any'")]
    NoExpectedValue(String),
    #[error("Measurement entry for register '{0}' has empty 'expected_any' list")]
    EmptyExpectedAny(String),
    #[error("Measurement record has both 'measurements' and 'dcap_image_hashes' — set only one")]
    BothMeasurementsAndDcapImageHashes,
    #[error("Attestation type '{0}' does not support 'dcap_image_hashes'")]
    DcapImageHashesUnsupportedAttestationType(String),
    #[error(
        "DCAP attest-measure output only pins RTMR1 and RTMR2; use a portable output or an explicit measurement policy"
    )]
    UnsafeAttestMeasureDcapOutput,
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use attest_measure::dcap::{DcapFirmware, expected_dcap_registers};
    use attest_types::AcpiHashes;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};

    use super::*;
    use crate::trusted_firmware::any_trusted_firmware;

    fn test_dcap_measurements(mrtd: [u8; 48], rtmr0: [u8; 48]) -> MultiMeasurements {
        MultiMeasurements::Dcap(DcapMeasurements::new(mrtd, rtmr0, [0u8; 48], [0u8; 48], [0u8; 48]))
    }

    fn self_hosted_platform_metadata() -> PlatformMetadata {
        PlatformMetadata {
            attestation_type: ImageAttestationType::SelfHostedTdx,
            ram_bytes: 0,
            num_disks: 0,
            acpi: None,
            dm_verity_boot: false,
            smbios_handoff: None,
        }
    }

    /// MRTD from the pinned GCP firmware snapshot test asset
    const GCP_FIRMWARE_MRTD: &str = "feb7486608382c1ff0e15b4648ddc0acea6ca974eb53e3529f4c4bd5ffbaa20bf335cb75965cea65fe473aed9647c162";

    fn attest_measure_portable_json(include_azure: bool) -> serde_json::Value {
        let hash32 = "00".repeat(32);
        let hash48 = "00".repeat(48);

        serde_json::json!({
            "kind": "portable",
            "azure": include_azure.then(|| serde_json::json!({
                "pcr4": hash32,
                "pcr9": hash32,
                "pcr11": hash32,
            })),
            "dcap": {
                "uki_authenticode": hash48,
                "kernel_authenticode": hash48,
                "cmdline_hash": hash48,
                "initrd_hash": hash48,
                "gpt_disk_guid_hash": hash48,
            },
        })
    }

    /// CFV from the same pinned GCP firmware snapshot test asset
    const GCP_FIRMWARE_CFV: &str = "9cb6bf09aea7b4acb8549e328d0edd6f15defc0b00d744bb9fb5bab0962bc5c70f69d233e96dbc7c1105ba085781dc88";
    /// Base64-encoded HOB template from the historical GCP firmware asset
    /// in the attest repo.
    const GCP_HOB_TEMPLATE_B64: &str = "AQA4AAAAAAAJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASJKAAAAAAAADADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAA4v8AAAAAAAAeAAAAAAADADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAA4P8AAAAAAAACAAAAAAADADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAgQAAAAAAAAABAAAAAAADADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAACwgAAAAAAAACAAAAAAAAADADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAACQgAAAAAAAACAAAAAAAAADADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAgAAAAAAAAGAAAAAAAAADADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAAAABwAAEAAAAAAAAAAAAACAAAAAAAADADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAAAABwAAEABggAAAAAAAADAAAAAAAAADADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAAAABwAAEADQgAAAAAAAADAAAAAAAAADADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAAAABwAAEAAAggAAAAAAAAB+vwAAAAADADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAAAABwAAEAAAAAABAAAAAAAAQAMAAAA=";
    /// Offset used by the historical HOB template to patch the RAM length
    /// field.
    const GCP_HOB_LENGTH_OFFSET: usize = 0x240;
    /// RAM threshold embedded in the historical GCP HOB template snapshot.
    const GCP_RAM_THRESHOLD: u64 = 3 << 30;

    fn gcp_firmware_fixture() -> DcapFirmware {
        DcapFirmware {
            mrtd: hex::decode(GCP_FIRMWARE_MRTD).unwrap().try_into().unwrap(),
            cfv: hex::decode(GCP_FIRMWARE_CFV).unwrap().try_into().unwrap(),
            hob: attest_measure::dcap::HobTemplate {
                bytes: BASE64_STANDARD.decode(GCP_HOB_TEMPLATE_B64).unwrap(),
                length_offset: GCP_HOB_LENGTH_OFFSET,
                ram_threshold: GCP_RAM_THRESHOLD,
            },
        }
    }

    #[tokio::test]
    async fn test_read_measurements_file() {
        let specific_measurements =
            MeasurementPolicy::from_file("test-assets/measurements.json".into()).await.unwrap();

        assert_eq!(specific_measurements.accepted_measurements.len(), 3);

        let m = &specific_measurements.accepted_measurements[0];
        if let ExpectedMeasurements::Azure(a) = &m.measurements {
            assert_eq!(a.keys().collect::<HashSet<_>>(), HashSet::from([&9, &4, &11]));
        } else {
            panic!("Unexpected measurement type");
        }

        let m = &specific_measurements.accepted_measurements[1];
        if let ExpectedMeasurements::Azure(a) = &m.measurements {
            assert_eq!(a.keys().collect::<HashSet<_>>(), HashSet::from([&9, &4]));
        } else {
            panic!("Unexpected measurement type");
        }

        let m = &specific_measurements.accepted_measurements[2];
        if let ExpectedMeasurements::Dcap(d) = &m.measurements {
            assert!(d.contains_key(&DcapMeasurementRegister::MRTD));
            assert!(d.contains_key(&DcapMeasurementRegister::RTMR0));
            assert!(d.contains_key(&DcapMeasurementRegister::RTMR1));
            assert!(d.contains_key(&DcapMeasurementRegister::RTMR2));
            assert!(d.contains_key(&DcapMeasurementRegister::RTMR3));
        } else {
            panic!("Unexpected measurement type");
        }

        // Will not match mock measurements
        assert!(matches!(
            specific_measurements.check_measurement(&mock_dcap_measurements(), None).unwrap_err(),
            AttestationError::MeasurementsNotAccepted
        ));

        // Will not match another attestation type
        assert!(matches!(
            specific_measurements
                .check_measurement(&MultiMeasurements::NoAttestation, None)
                .unwrap_err(),
            AttestationError::MeasurementsNotAccepted
        ));

        // A non-specific measurement fails
        assert!(matches!(
            specific_measurements
                .check_measurement(&MultiMeasurements::Azure(HashMap::new()), None)
                .unwrap_err(),
            AttestationError::MeasurementsNotAccepted
        ));
    }

    #[tokio::test]
    async fn test_read_measurements_file_non_specific() {
        // This specifies a particular attestation type, but not specific
        // measurements
        let allowed_attestation_type =
            MeasurementPolicy::from_file("test-assets/measurements_2.json".into()).await.unwrap();

        allowed_attestation_type.check_measurement(&mock_dcap_measurements(), None).unwrap();

        // Will not match another attestation type
        assert!(matches!(
            allowed_attestation_type
                .check_measurement(&MultiMeasurements::NoAttestation, None)
                .unwrap_err(),
            AttestationError::MeasurementsNotAccepted
        ));
    }

    #[test]
    fn register_policies_infer_attestation_type_without_platform_metadata() {
        let dcap_policy = MeasurementPolicy::single_attestation_type(AttestationType::DcapTdx);
        dcap_policy.check_measurement(&mock_dcap_measurements(), None).unwrap();

        let azure_policy = MeasurementPolicy::single_attestation_type(AttestationType::AzureTdx);
        azure_policy.check_measurement(&MultiMeasurements::Azure(HashMap::new()), None).unwrap();
    }

    #[test]
    fn gcp_policy_rejects_dcap_labeled_measurements() {
        let policy = MeasurementPolicy::single_attestation_type(AttestationType::GcpTdx);
        let measurements = mock_dcap_measurements();
        let gcp_metadata = PlatformMetadata {
            attestation_type: attest_types::AttestationType::GcpTdx,
            ram_bytes: 0,
            num_disks: 0,
            acpi: None,
            dm_verity_boot: false,
            smbios_handoff: None,
        };

        policy.check_measurement(&measurements, Some(&gcp_metadata)).unwrap();
        assert!(matches!(
            policy.check_measurement(&measurements, None).unwrap_err(),
            AttestationError::MeasurementsNotAccepted
        ));
    }

    #[test]
    fn dcap_policy_accepts_gcp_labeled_measurements() {
        // Policy files written before GCP was distinguished from bare metal
        // label GCP hosts `dcap-tdx`, so those records must still accept a
        // peer reporting `gcp-tdx`
        let policy = MeasurementPolicy::single_attestation_type(AttestationType::DcapTdx);
        let measurements = mock_dcap_measurements();
        let gcp_metadata = PlatformMetadata {
            attestation_type: attest_types::AttestationType::GcpTdx,
            ram_bytes: 0,
            num_disks: 0,
            acpi: None,
            dm_verity_boot: false,
            smbios_handoff: None,
        };

        policy.check_measurement(&measurements, Some(&gcp_metadata)).unwrap();
    }

    #[test]
    fn test_gcp_image_hash_measurement_policy_accepts_matching_measurements() {
        fn decode_hash(input: &str) -> [u8; 48] {
            hex::decode(input).unwrap().try_into().unwrap()
        }

        // Result of measuring a flashbox-l1 image
        let image_hashes = DcapImageHashes {
            uki_authenticode: decode_hash(
                "fcaceb6d87694746ba2d93a87ef4209f2a7629b7f400097b93241e80b9ec3e1e80f9a4cd8028e6a83f297ea5de8d9abc",
            ),
            kernel_authenticode: decode_hash(
                "b6c5133268aa8b440509f3d53ee855a5cd3aeb6441eb109a9f27f14c43bce3e2383856df4af876501ceeb4c9a3b15f0c",
            ),
            cmdline_hash: decode_hash(
                "e03b89abf354a38976537b7a9138fd312e4cbf73b61eebc44086491701b1d167b9f6cb97a922325866c93e0834723d87",
            ),
            initrd_hash: decode_hash(
                "a5b3d4742045e7d08aa19953c35098e784826b01a84f60568fa69f1a848dafd96ec98b8df616d6142779c9b97318166b",
            ),
            gpt_disk_guid_hash: decode_hash(
                "180bac1af9c35cc15e909623c005289539b4da2840d9c9b658fd4968ea4f03e0159402d03da1afc9035e0db30804e282",
            ),
            pe_sections: None,
        };
        let policy = MeasurementPolicy {
            accepted_measurements: vec![MeasurementRecord {
                measurement_id: "image-hash-policy".to_string(),
                attestation_type: AttestationType::GcpTdx,
                measurements: ExpectedMeasurements::Image(image_hashes.clone()),
            }],
        };
        let platform_metadata = PlatformMetadata {
            attestation_type: attest_types::AttestationType::GcpTdx,
            ram_bytes: 4 * 1024 * 1024 * 1024,
            num_disks: 1,
            acpi: Some(AcpiHashes { loader: [0x11; 48], rsdp: [0x22; 48], tables: [0x33; 48] }),
            dm_verity_boot: false,
            smbios_handoff: None,
        };
        let firmware = gcp_firmware_fixture();
        let expected_measurements =
            expected_dcap_registers(&image_hashes, &platform_metadata, Some(&firmware)).unwrap();

        let measurements = MultiMeasurements::Dcap(DcapMeasurements::new(
            expected_measurements.mrtd.unwrap(),
            expected_measurements.rtmr0.unwrap(),
            expected_measurements.rtmr1,
            expected_measurements.rtmr2,
            mock_tdx::MOCK_RTMR3,
        ));

        policy.check_measurement(&measurements, Some(&platform_metadata)).unwrap();
    }

    #[test]
    fn test_bare_metal_image_hash_policy_checks_image_registers() {
        let image_hashes = DcapImageHashes {
            uki_authenticode: [0x11; 48],
            kernel_authenticode: [0x22; 48],
            cmdline_hash: [0x33; 48],
            initrd_hash: [0x44; 48],
            gpt_disk_guid_hash: [0x55; 48],
            pe_sections: Some([0x66; 48]),
        };
        let platform_metadata = PlatformMetadata {
            attestation_type: ImageAttestationType::SelfHostedTdx,
            ram_bytes: 4 * 1024 * 1024 * 1024,
            num_disks: 0,
            acpi: Some(AcpiHashes { loader: [0x77; 48], rsdp: [0x88; 48], tables: [0x99; 48] }),
            dm_verity_boot: false,
            smbios_handoff: None,
        };
        let firmware = any_trusted_firmware();
        let expected =
            expected_dcap_registers(&image_hashes, &platform_metadata, Some(&firmware)).unwrap();
        let policy = MeasurementPolicy {
            accepted_measurements: vec![MeasurementRecord {
                measurement_id: "bare-metal-image-hash-policy".to_string(),
                attestation_type: AttestationType::DcapTdx,
                measurements: ExpectedMeasurements::Image(image_hashes),
            }],
        };
        let measurements = MultiMeasurements::Dcap(DcapMeasurements::new(
            expected.mrtd.unwrap(),
            expected.rtmr0.unwrap(),
            expected.rtmr1,
            expected.rtmr2,
            [0xcc; 48],
        ));

        policy.check_measurement(&measurements, Some(&platform_metadata)).unwrap();

        assert!(matches!(
            policy.check_measurement(&measurements, None),
            Err(AttestationError::MeasurementsNotAccepted)
        ));

        let ExpectedMeasurements::Image(image_hashes) =
            &policy.accepted_measurements[0].measurements
        else {
            unreachable!();
        };
        let gcp_policy = MeasurementPolicy {
            accepted_measurements: vec![MeasurementRecord {
                measurement_id: "gcp-image-hash-policy".to_string(),
                attestation_type: AttestationType::GcpTdx,
                measurements: ExpectedMeasurements::Image(image_hashes.clone()),
            }],
        };
        assert!(matches!(
            gcp_policy.check_measurement(&measurements, Some(&platform_metadata)),
            Err(AttestationError::MeasurementsNotAccepted)
        ));

        let mut unknown_firmware = measurements.clone();
        let MultiMeasurements::Dcap(dcap) = &mut unknown_firmware else {
            unreachable!();
        };
        dcap.mrtd = [0xaa; 48];
        assert!(matches!(
            policy.check_measurement(&unknown_firmware, Some(&platform_metadata)),
            Err(AttestationError::MeasurementsNotAccepted)
        ));

        let mut wrong_measurements = measurements.clone();
        let MultiMeasurements::Dcap(dcap) = &mut wrong_measurements else {
            unreachable!();
        };
        dcap.rtmr2[0] ^= 1;
        assert!(matches!(
            policy.check_measurement(&wrong_measurements, Some(&platform_metadata)),
            Err(AttestationError::MeasurementsNotAccepted)
        ));
    }

    #[tokio::test]
    async fn test_buildernet_measurements() {
        // Refresh this fixture explicitly with:
        //   sh crates/attestation/test-assets/
        // refresh-buildernet-measurements-fixture.sh
        let policy =
            MeasurementPolicy::from_file("test-assets/buildernet_measurements.json".into())
                .await
                .unwrap();

        assert!(!policy.accepted_measurements.is_empty());

        assert!(matches!(
            policy.check_measurement(&MultiMeasurements::NoAttestation, None).unwrap_err(),
            AttestationError::MeasurementsNotAccepted
        ));

        // A non-specific measurement fails
        assert!(matches!(
            policy.check_measurement(&MultiMeasurements::Azure(HashMap::new()), None).unwrap_err(),
            AttestationError::MeasurementsNotAccepted
        ));
    }

    #[tokio::test]
    async fn test_parse_expected_any() {
        let json = r#"[
            {
                "measurement_id": "test-any",
                "attestation_type": "dcap-tdx",
                "measurements": {
                    "mrtd": {
                        "expected_any": [
                            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                            "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
                        ]
                    }
                }
            }
        ]"#;

        let policy = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec()).unwrap();
        assert_eq!(policy.accepted_measurements.len(), 1);

        let record = &policy.accepted_measurements[0];
        if let ExpectedMeasurements::Dcap(dcap) = &record.measurements {
            let expected = dcap.get(&DcapMeasurementRegister::MRTD).unwrap();
            assert_eq!(expected.len(), 2);
        } else {
            panic!("Expected ExpectedMeasurements::Dcap");
        }
    }

    #[test]
    fn expected_measurements_header_format_round_trips_all_variants() {
        let measurements = [
            ExpectedMeasurements::Image(DcapImageHashes {
                uki_authenticode: [0x11; 48],
                kernel_authenticode: [0x22; 48],
                cmdline_hash: [0x33; 48],
                initrd_hash: [0x44; 48],
                gpt_disk_guid_hash: [0x55; 48],
                pe_sections: None,
            }),
            ExpectedMeasurements::Dcap(HashMap::from([
                (DcapMeasurementRegister::MRTD, vec![[0x66; 48], [0x77; 48]]),
                (DcapMeasurementRegister::RTMR2, vec![[0x88; 48]]),
            ])),
            ExpectedMeasurements::Azure(HashMap::from([
                (4, vec![[0x99; 32], [0xaa; 32]]),
                (11, vec![[0xbb; 32]]),
            ])),
            ExpectedMeasurements::NoAttestation,
        ];

        for expected in measurements {
            let header = expected.to_header_format().unwrap();
            let decoded =
                ExpectedMeasurements::from_header_format(header.to_str().unwrap()).unwrap();

            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn expected_measurements_header_format_rejects_bad_hash_length() {
        let input = serde_json::json!({
            "type": "dcap",
            "measurements": { "0": ["00"] },
        })
        .to_string();

        assert!(matches!(
            ExpectedMeasurements::from_header_format(&input),
            Err(MeasurementFormatError::BadLength)
        ));
    }

    #[tokio::test]
    async fn test_parse_legacy_qemu_attestation_type_as_dcap() {
        let json = r#"[
            {
                "measurement_id": "legacy-qemu",
                "attestation_type": "qemu-tdx",
                "measurements": {
                    "mrtd": {
                        "expected_any": [
                            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                        ]
                    }
                }
            }
        ]"#;

        let policy = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec()).unwrap();
        assert_eq!(policy.accepted_measurements.len(), 1);
        assert!(matches!(
            policy.accepted_measurements[0].measurements,
            ExpectedMeasurements::Dcap(_)
        ));
    }

    /// A JSON policy that pins image-component hashes rather than raw
    /// register values must parse into [`ExpectedMeasurements::Image`]
    /// so the verifier can reconstruct the expected RTMRs from platform
    /// metadata and firmware
    #[tokio::test]
    async fn test_parse_image_hash_policy() {
        let json = r#"[
            {
                "measurement_id": "bare-metal-image-hash-example",
                "attestation_type": "dcap-tdx",
                "dcap_image_hashes": {
                    "uki_authenticode": "fcaceb6d87694746ba2d93a87ef4209f2a7629b7f400097b93241e80b9ec3e1e80f9a4cd8028e6a83f297ea5de8d9abc",
                    "kernel_authenticode": "b6c5133268aa8b440509f3d53ee855a5cd3aeb6441eb109a9f27f14c43bce3e2383856df4af876501ceeb4c9a3b15f0c",
                    "cmdline_hash": "e03b89abf354a38976537b7a9138fd312e4cbf73b61eebc44086491701b1d167b9f6cb97a922325866c93e0834723d87",
                    "initrd_hash": "a5b3d4742045e7d08aa19953c35098e784826b01a84f60568fa69f1a848dafd96ec98b8df616d6142779c9b97318166b",
                    "gpt_disk_guid_hash": "180bac1af9c35cc15e909623c005289539b4da2840d9c9b658fd4968ea4f03e0159402d03da1afc9035e0db30804e282",
                    "pe_sections": "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
                }
            }
        ]"#;

        let policy = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec()).unwrap();
        assert_eq!(policy.accepted_measurements.len(), 1);
        assert_eq!(policy.accepted_measurements[0].attestation_type, AttestationType::DcapTdx);
        let ExpectedMeasurements::Image(image_hashes) =
            &policy.accepted_measurements[0].measurements
        else {
            panic!("expected portable DCAP image hashes");
        };
        assert_eq!(image_hashes.pe_sections, Some([0x11; 48]));
    }

    /// The object emitted by `attest measure portable` is accepted directly
    /// and converted into Azure and DCAP-compatible policy records.
    #[test]
    fn test_parse_attest_measure_portable_output() {
        let json = r#"{
            "kind": "portable",
            "azure": {
                "pcr4": "2bc9d1d583b628bdadfc5dcc918276fd2cfc953103540f7a80e463df97a3abc0",
                "pcr9": "7dc3b202c2dc30993354744188b3d8fda892360270548f43ce73dce507a060de",
                "pcr11": "7b609d7233463bbb35ac89f5faabc24769ccc185ecd5f6adb2cf5c4944dd59a7"
            },
            "dcap": {
                "uki_authenticode": "7336449f945aea776f2e5ed2e2552f88e1eed8467b1736523a436971cb83496277bb484a7cf6e986f5127d19e8ee187b",
                "kernel_authenticode": "b6c5133268aa8b440509f3d53ee855a5cd3aeb6441eb109a9f27f14c43bce3e2383856df4af876501ceeb4c9a3b15f0c",
                "cmdline_hash": "e03b89abf354a38976537b7a9138fd312e4cbf73b61eebc44086491701b1d167b9f6cb97a922325866c93e0834723d87",
                "initrd_hash": "5f2f98964c8ff86f79a17d53afc26f1cf8d03964f0309b474ec9bb1b99c5a180fbe54a636631ab2fab29d8d5b1be0bae",
                "gpt_disk_guid_hash": "488fa3f08aae01c1a46b497319e8a7d3b7335c9ff4f4d7fe6a3dd62c844b03de22157c0303be58f10e3152687778e68d"
            }
        }"#;

        let policy = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec()).unwrap();
        assert_eq!(policy.accepted_measurements.len(), 2);

        let azure = &policy.accepted_measurements[0];
        assert!(azure.measurement_id.is_empty());
        assert_eq!(azure.attestation_type, AttestationType::AzureTdx);
        let ExpectedMeasurements::Azure(registers) = &azure.measurements else {
            panic!("expected Azure measurements");
        };
        let expected_pcr4: [u8; 32] =
            hex::decode("2bc9d1d583b628bdadfc5dcc918276fd2cfc953103540f7a80e463df97a3abc0")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(registers[&4], vec![expected_pcr4]);

        let dcap = &policy.accepted_measurements[1];
        assert!(dcap.measurement_id.is_empty());
        assert_eq!(dcap.attestation_type, AttestationType::DcapTdx);
        let ExpectedMeasurements::Image(image_hashes) = &dcap.measurements else {
            panic!("expected portable DCAP image hashes");
        };
        assert_eq!(
            image_hashes.uki_authenticode,
            hex::decode(
                "7336449f945aea776f2e5ed2e2552f88e1eed8467b1736523a436971cb83496277bb484a7cf6e986f5127d19e8ee187b"
            )
            .unwrap()
            .as_slice()
        );
    }

    #[test]
    fn test_parse_attest_measure_portable_output_without_azure() {
        let json = r#"{
            "kind": "portable",
            "azure": null,
            "dcap": {
                "uki_authenticode": "7336449f945aea776f2e5ed2e2552f88e1eed8467b1736523a436971cb83496277bb484a7cf6e986f5127d19e8ee187b",
                "kernel_authenticode": "b6c5133268aa8b440509f3d53ee855a5cd3aeb6441eb109a9f27f14c43bce3e2383856df4af876501ceeb4c9a3b15f0c",
                "cmdline_hash": "e03b89abf354a38976537b7a9138fd312e4cbf73b61eebc44086491701b1d167b9f6cb97a922325866c93e0834723d87",
                "initrd_hash": "5f2f98964c8ff86f79a17d53afc26f1cf8d03964f0309b474ec9bb1b99c5a180fbe54a636631ab2fab29d8d5b1be0bae",
                "gpt_disk_guid_hash": "488fa3f08aae01c1a46b497319e8a7d3b7335c9ff4f4d7fe6a3dd62c844b03de22157c0303be58f10e3152687778e68d"
            }
        }"#;

        let policy = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec()).unwrap();
        assert_eq!(policy.accepted_measurements.len(), 1);
        assert_eq!(policy.accepted_measurements[0].attestation_type, AttestationType::DcapTdx);
        assert!(matches!(
            policy.accepted_measurements[0].measurements,
            ExpectedMeasurements::Image(_)
        ));
    }

    #[test]
    fn test_parse_single_legacy_record_object() {
        let json = r#"{
            "attestation_type": "dcap-tdx"
        }"#;

        let policy = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec()).unwrap();
        assert_eq!(policy.accepted_measurements.len(), 1);
        assert!(matches!(
            policy.accepted_measurements[0].measurements,
            ExpectedMeasurements::Dcap(_)
        ));
    }

    #[test]
    fn test_parse_legacy_record_with_kind_metadata() {
        let json = r#"{
            "kind": "application-policy",
            "attestation_type": "dcap-tdx"
        }"#;

        let policy = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec()).unwrap();
        assert_eq!(policy.accepted_measurements.len(), 1);
        assert!(matches!(
            policy.accepted_measurements[0].measurements,
            ExpectedMeasurements::Dcap(_)
        ));
    }

    #[test]
    fn test_parse_attest_measure_azure_output() {
        let json = serde_json::json!({
            "kind": "azure",
            "pcr4": "11".repeat(32),
            "pcr9": "22".repeat(32),
            "pcr11": "33".repeat(32),
        });

        let policy =
            MeasurementPolicy::from_json_bytes(serde_json::to_vec(&json).unwrap()).unwrap();
        assert_eq!(policy.accepted_measurements.len(), 1);

        let ExpectedMeasurements::Azure(registers) = &policy.accepted_measurements[0].measurements
        else {
            panic!("expected Azure measurements");
        };
        assert_eq!(registers.len(), 3);
        assert_eq!(registers[&4], vec![[0x11; 32]]);
        assert_eq!(registers[&9], vec![[0x22; 32]]);
        assert_eq!(registers[&11], vec![[0x33; 32]]);
    }

    #[test]
    fn test_reject_attest_measure_dcap_output() {
        let json = serde_json::json!({
            "kind": "dcap",
            "rtmr1": "44".repeat(48),
            "rtmr2": "55".repeat(48),
        });

        let result = MeasurementPolicy::from_json_bytes(serde_json::to_vec(&json).unwrap());
        assert!(matches!(result, Err(MeasurementFormatError::UnsafeAttestMeasureDcapOutput)));
    }

    #[test]
    fn test_parse_array_of_attest_measure_portable_outputs() {
        let portable = attest_measure_portable_json(true);
        let json = serde_json::to_vec(&[portable.clone(), portable]).unwrap();

        let policy = MeasurementPolicy::from_json_bytes(json).unwrap();
        assert_eq!(policy.accepted_measurements.len(), 4);
        assert!(matches!(
            policy.accepted_measurements[0].measurements,
            ExpectedMeasurements::Azure(_)
        ));
        assert!(matches!(
            policy.accepted_measurements[1].measurements,
            ExpectedMeasurements::Image(_)
        ));
        assert!(matches!(
            policy.accepted_measurements[2].measurements,
            ExpectedMeasurements::Azure(_)
        ));
        assert!(matches!(
            policy.accepted_measurements[3].measurements,
            ExpectedMeasurements::Image(_)
        ));
    }

    #[test]
    fn test_parse_mixed_legacy_and_attest_measure_array() {
        let json = serde_json::to_vec(&[
            attest_measure_portable_json(false),
            serde_json::json!({ "attestation_type": "azure-tdx" }),
        ])
        .unwrap();

        let policy = MeasurementPolicy::from_json_bytes(json).unwrap();
        assert_eq!(policy.accepted_measurements.len(), 2);
        assert!(matches!(
            policy.accepted_measurements[0].measurements,
            ExpectedMeasurements::Image(_)
        ));
        assert!(matches!(
            policy.accepted_measurements[1].measurements,
            ExpectedMeasurements::Azure(_)
        ));
    }

    /// A record cannot specify both raw register values and image-component
    /// hashes as they express the same intent through different schemas.
    #[tokio::test]
    async fn test_parse_rejects_both_measurements_and_dcap_image_hashes() {
        let json = r#"[
            {
                "attestation_type": "gcp-tdx",
                "measurements": {
                    "mrtd": {
                        "expected_any": [
                            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                        ]
                    }
                },
                "dcap_image_hashes": {
                    "uki_authenticode": "fcaceb6d87694746ba2d93a87ef4209f2a7629b7f400097b93241e80b9ec3e1e80f9a4cd8028e6a83f297ea5de8d9abc",
                    "kernel_authenticode": "b6c5133268aa8b440509f3d53ee855a5cd3aeb6441eb109a9f27f14c43bce3e2383856df4af876501ceeb4c9a3b15f0c",
                    "cmdline_hash": "e03b89abf354a38976537b7a9138fd312e4cbf73b61eebc44086491701b1d167b9f6cb97a922325866c93e0834723d87",
                    "initrd_hash": "a5b3d4742045e7d08aa19953c35098e784826b01a84f60568fa69f1a848dafd96ec98b8df616d6142779c9b97318166b",
                    "gpt_disk_guid_hash": "180bac1af9c35cc15e909623c005289539b4da2840d9c9b658fd4968ea4f03e0159402d03da1afc9035e0db30804e282"
                }
            }
        ]"#;

        let result = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec());
        assert!(matches!(result, Err(MeasurementFormatError::BothMeasurementsAndDcapImageHashes)));
    }

    /// Using one of the not yet supported attestation types with
    /// dcap_image_hashes fails
    #[tokio::test]
    async fn test_parse_rejects_unsupported_attestation_type_for_image_hashes() {
        let json = r#"[
            {
                "attestation_type": "azure-tdx",
                "dcap_image_hashes": {
                    "uki_authenticode": "fcaceb6d87694746ba2d93a87ef4209f2a7629b7f400097b93241e80b9ec3e1e80f9a4cd8028e6a83f297ea5de8d9abc",
                    "kernel_authenticode": "b6c5133268aa8b440509f3d53ee855a5cd3aeb6441eb109a9f27f14c43bce3e2383856df4af876501ceeb4c9a3b15f0c",
                    "cmdline_hash": "e03b89abf354a38976537b7a9138fd312e4cbf73b61eebc44086491701b1d167b9f6cb97a922325866c93e0834723d87",
                    "initrd_hash": "a5b3d4742045e7d08aa19953c35098e784826b01a84f60568fa69f1a848dafd96ec98b8df616d6142779c9b97318166b",
                    "gpt_disk_guid_hash": "180bac1af9c35cc15e909623c005289539b4da2840d9c9b658fd4968ea4f03e0159402d03da1afc9035e0db30804e282"
                }
            }
        ]"#;

        let result = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec());
        assert!(matches!(
            result,
            Err(MeasurementFormatError::DcapImageHashesUnsupportedAttestationType(_))
        ));
    }

    #[tokio::test]
    async fn test_check_measurement_with_or_semantics() {
        let json = r#"[
            {
                "measurement_id": "test-or",
                "attestation_type": "dcap-tdx",
                "measurements": {
                    "MRTD": {
                        "expected_any": [
                            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                            "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
                        ]
                    }
                }
            }
        ]"#;

        let policy = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec()).unwrap();
        let platform_metadata = self_hosted_platform_metadata();

        // First value should match
        let measurements1 = test_dcap_measurements([0u8; 48], [0u8; 48]);
        assert!(policy.check_measurement(&measurements1, Some(&platform_metadata)).is_ok());

        // Second value should also match
        let measurements2 = test_dcap_measurements([0x11u8; 48], [0u8; 48]);
        assert!(policy.check_measurement(&measurements2, Some(&platform_metadata)).is_ok());

        // Different value should not match
        let measurements3 = test_dcap_measurements([0x22u8; 48], [0u8; 48]);
        assert!(policy.check_measurement(&measurements3, Some(&platform_metadata)).is_err());
    }

    #[tokio::test]
    async fn test_parse_both_expected_and_expected_any_error() {
        let json = r#"[
            {
                "attestation_type": "dcap-tdx",
                "measurements": {
                    "0": {
                        "expected": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "expected_any": ["111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"]
                    }
                }
            }
        ]"#;

        let result = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec());
        assert!(matches!(result, Err(MeasurementFormatError::BothExpectedAndExpectedAny(_))));
    }

    #[tokio::test]
    async fn test_parse_neither_expected_nor_expected_any_error() {
        let json = r#"[
            {
                "attestation_type": "dcap-tdx",
                "measurements": {
                    "0": {}
                }
            }
        ]"#;

        let result = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec());
        assert!(matches!(result, Err(MeasurementFormatError::NoExpectedValue(_))));
    }

    #[tokio::test]
    async fn test_parse_empty_expected_any_error() {
        let json = r#"[
            {
                "attestation_type": "dcap-tdx",
                "measurements": {
                    "0": {
                        "expected_any": []
                    }
                }
            }
        ]"#;

        let result = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec());
        assert!(matches!(result, Err(MeasurementFormatError::EmptyExpectedAny(_))));
    }

    #[tokio::test]
    async fn test_mixed_expected_and_expected_any_in_different_registers() {
        let json = r#"[
            {
                "measurement_id": "mixed-test",
                "attestation_type": "dcap-tdx",
                "measurements": {
                    "0": {
                        "expected": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                    },
                    "1": {
                        "expected_any": [
                            "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
                            "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"
                        ]
                    }
                }
            }
        ]"#;

        let policy = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec()).unwrap();
        let platform_metadata = self_hosted_platform_metadata();

        // Both match (single + first of any)
        let measurements1 = test_dcap_measurements([0u8; 48], [0x11u8; 48]);
        assert!(policy.check_measurement(&measurements1, Some(&platform_metadata)).is_ok());

        // Both match (single + second of any)
        let measurements2 = test_dcap_measurements([0u8; 48], [0x22u8; 48]);
        assert!(policy.check_measurement(&measurements2, Some(&platform_metadata)).is_ok());

        // Single matches but any doesn't
        let measurements3 = test_dcap_measurements([0u8; 48], [0x33u8; 48]);
        assert!(policy.check_measurement(&measurements3, Some(&platform_metadata)).is_err());
    }

    #[tokio::test]
    async fn test_parse_case_insensitive_named_dcap_registers() {
        let json = r#"[
            {
                "measurement_id": "named-registers",
                "attestation_type": "dcap-tdx",
                "measurements": {
                    "mrtd": {
                        "expected_any": ["000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"]
                    },
                    "RTMR0": {
                        "expected_any": ["111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"]
                    },
                    "rTmR1": {
                        "expected_any": ["222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"]
                    },
                    "rtmr2": {
                        "expected_any": ["333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333"]
                    },
                    "RTMR3": {
                        "expected_any": ["444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444"]
                    }
                }
            }
        ]"#;

        let policy = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec()).unwrap();
        let record = &policy.accepted_measurements[0];

        if let ExpectedMeasurements::Dcap(dcap) = &record.measurements {
            assert_eq!(dcap.keys().collect::<HashSet<_>>().len(), 5);
            assert!(dcap.contains_key(&DcapMeasurementRegister::MRTD));
            assert!(dcap.contains_key(&DcapMeasurementRegister::RTMR0));
            assert!(dcap.contains_key(&DcapMeasurementRegister::RTMR1));
            assert!(dcap.contains_key(&DcapMeasurementRegister::RTMR2));
            assert!(dcap.contains_key(&DcapMeasurementRegister::RTMR3));
        } else {
            panic!("Expected ExpectedMeasurements::Dcap");
        }
    }

    #[tokio::test]
    async fn test_parse_mixed_numeric_and_named_dcap_registers() {
        let json = r#"[
            {
                "measurement_id": "mixed-keys",
                "attestation_type": "dcap-tdx",
                "measurements": {
                    "0": {
                        "expected_any": ["000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"]
                    },
                    "rtmr0": {
                        "expected_any": ["111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"]
                    }
                }
            }
        ]"#;

        let policy = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec()).unwrap();
        let record = &policy.accepted_measurements[0];

        if let ExpectedMeasurements::Dcap(dcap) = &record.measurements {
            assert!(dcap.contains_key(&DcapMeasurementRegister::MRTD));
            assert!(dcap.contains_key(&DcapMeasurementRegister::RTMR0));
        } else {
            panic!("Expected ExpectedMeasurements::Dcap");
        }
    }

    #[tokio::test]
    async fn test_parse_invalid_named_dcap_register_error() {
        let json = r#"[
            {
                "attestation_type": "dcap-tdx",
                "measurements": {
                    "rtmr4": {
                        "expected_any": ["000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"]
                    }
                }
            }
        ]"#;

        let result = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec());
        assert!(matches!(result, Err(MeasurementFormatError::BadRegisterIndex)));
    }

    #[tokio::test]
    async fn test_parse_azure_pcr_prefixed_registers() {
        let json = r#"[
            {
                "measurement_id": "azure-pcr-prefixed",
                "attestation_type": "azure-tdx",
                "measurements": {
                    "pcr4": {
                        "expected_any": ["1111111111111111111111111111111111111111111111111111111111111111"]
                    },
                    "pcr9": {
                        "expected_any": ["2222222222222222222222222222222222222222222222222222222222222222"]
                    },
                    "pcr11": {
                        "expected_any": ["3333333333333333333333333333333333333333333333333333333333333333"]
                    }
                }
            }
        ]"#;

        let policy = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec()).unwrap();
        let record = &policy.accepted_measurements[0];

        if let ExpectedMeasurements::Azure(azure) = &record.measurements {
            assert_eq!(azure.keys().collect::<HashSet<_>>(), HashSet::from([&4, &9, &11]));
        } else {
            panic!("Expected ExpectedMeasurements::Azure");
        }
    }

    #[tokio::test]
    async fn test_parse_case_insensitive_azure_pcr_prefix() {
        let json = r#"[
            {
                "measurement_id": "azure-case-insensitive",
                "attestation_type": "azure-tdx",
                "measurements": {
                    "PCR4": {
                        "expected_any": ["1111111111111111111111111111111111111111111111111111111111111111"]
                    },
                    "PcR9": {
                        "expected_any": ["2222222222222222222222222222222222222222222222222222222222222222"]
                    }
                }
            }
        ]"#;

        let policy = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec()).unwrap();
        let record = &policy.accepted_measurements[0];

        if let ExpectedMeasurements::Azure(azure) = &record.measurements {
            assert_eq!(azure.keys().collect::<HashSet<_>>(), HashSet::from([&4, &9]));
        } else {
            panic!("Expected ExpectedMeasurements::Azure");
        }
    }

    #[tokio::test]
    async fn test_parse_mixed_numeric_and_prefixed_azure_pcr_keys() {
        let json = r#"[
            {
                "measurement_id": "azure-mixed-keys",
                "attestation_type": "azure-tdx",
                "measurements": {
                    "4": {
                        "expected_any": ["1111111111111111111111111111111111111111111111111111111111111111"]
                    },
                    "pcr9": {
                        "expected_any": ["2222222222222222222222222222222222222222222222222222222222222222"]
                    }
                }
            }
        ]"#;

        let policy = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec()).unwrap();
        let record = &policy.accepted_measurements[0];

        if let ExpectedMeasurements::Azure(azure) = &record.measurements {
            assert_eq!(azure.keys().collect::<HashSet<_>>(), HashSet::from([&4, &9]));
        } else {
            panic!("Expected ExpectedMeasurements::Azure");
        }
    }

    #[tokio::test]
    async fn test_parse_invalid_prefixed_azure_pcr_key_error() {
        let json = r#"[
            {
                "attestation_type": "azure-tdx",
                "measurements": {
                    "pcr24": {
                        "expected_any": ["1111111111111111111111111111111111111111111111111111111111111111"]
                    }
                }
            }
        ]"#;

        let result = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec());
        assert!(matches!(result, Err(MeasurementFormatError::BadRegisterIndex)));
    }

    /// Checks that the Debug implementation for MultiMeasurements displays
    /// them as hex
    #[test]
    fn test_multi_measurements_debug_prints_hex() {
        let register_value = [0xabu8; 48];
        let dcap = test_dcap_measurements(register_value, [0u8; 48]);
        let dcap_debug = format!("{dcap:?}");
        assert!(dcap_debug.contains("DCAP"));
        assert!(dcap_debug.contains(&hex::encode(register_value)));
        assert!(!dcap_debug.contains(&format!("{register_value:?}")));

        let azure_register_value = [0xabu8; 32];
        let azure = MultiMeasurements::Azure(HashMap::from([(9u32, azure_register_value)]));
        let azure_debug = format!("{azure:?}");
        assert!(azure_debug.contains("Azure"));
        assert!(azure_debug.contains(&hex::encode(azure_register_value)));
        assert!(!azure_debug.contains(&format!("{azure_register_value:?}")));
    }

    #[tokio::test]
    async fn test_from_file_or_url_rejects_non_loopback_http() {
        let result =
            MeasurementPolicy::from_file_or_url("http://example.com/measurements.json".into())
                .await;

        assert!(matches!(
            result,
            Err(MeasurementFormatError::InsecureHttpNotLoopback(url))
                if url == "http://example.com/measurements.json"
        ));
    }

    #[tokio::test]
    async fn test_from_file_or_url_allows_http_localhost() {
        let result =
            MeasurementPolicy::from_file_or_url("http://localhost:1/measurements.json".into())
                .await;

        assert!(matches!(result, Err(MeasurementFormatError::Reqwest(_))));
    }

    #[tokio::test]
    async fn test_from_file_or_url_allows_http_ipv4_loopback() {
        let result =
            MeasurementPolicy::from_file_or_url("http://127.0.0.1:1/measurements.json".into())
                .await;

        assert!(matches!(result, Err(MeasurementFormatError::Reqwest(_))));
    }

    #[tokio::test]
    async fn test_from_file_or_url_allows_http_ipv6_loopback() {
        let result =
            MeasurementPolicy::from_file_or_url("http://[::1]:1/measurements.json".into()).await;

        assert!(matches!(result, Err(MeasurementFormatError::Reqwest(_))));
    }
}
