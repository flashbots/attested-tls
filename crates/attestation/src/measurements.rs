//! Measurements and policy for enforcing them when validating a remote
//! attestation
use std::{collections::HashMap, fmt, fmt::Formatter, net::IpAddr, path::PathBuf};

use dcap_qvl::quote::Report;
use http::{HeaderValue, header::InvalidHeaderValue, uri::InvalidUri};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use crate::{AttestationError, AttestationType, dcap::DcapVerificationError};

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

/// Parse a list of hex strings into fixed-size byte arrays
fn parse_hex_values<const N: usize>(
    values: impl IntoIterator<Item = String>,
) -> Result<Vec<[u8; N]>, MeasurementFormatError> {
    values
        .into_iter()
        .map(|value| hex::decode(value)?.try_into().map_err(|_| MeasurementFormatError::BadLength))
        .collect()
}

/// Parse a DCAP measurement field from either a single string or an array
fn parse_dcap_measurement_value<const N: usize>(
    value: &Value,
    register_name: &str,
) -> Result<Vec<[u8; N]>, MeasurementFormatError> {
    match value {
        Value::String(hex_value) => parse_hex_values::<N>(vec![hex_value.clone()]),
        Value::Array(values) => {
            if values.is_empty() {
                return Err(MeasurementFormatError::EmptyExpectedAny(register_name.to_string()));
            }

            let hex_values = values
                .iter()
                .map(|value| {
                    value.as_str().map(|s| s.to_owned()).ok_or_else(|| {
                        MeasurementFormatError::Json(serde_json::Error::io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("expected hex string for register '{register_name}'"),
                        )))
                    })
                })
                .collect::<Result<Vec<String>, MeasurementFormatError>>()?;

            parse_hex_values::<N>(hex_values)
        }
        _ => Err(MeasurementFormatError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected string or array for register '{register_name}'"),
        )))),
    }
}

/// Represents a set of measurements values for one of the supported CVM
/// platforms
#[derive(Clone, PartialEq)]
pub enum MultiMeasurements {
    Dcap(HashMap<DcapMeasurementRegister, [u8; 48]>),
    Azure(HashMap<u32, [u8; 32]>),
    NoAttestation,
}

impl fmt::Debug for MultiMeasurements {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dcap(measurements) => {
                f.debug_tuple("DCAP").field(&DcapHexDebug(measurements)).finish()
            }
            Self::Azure(measurements) => {
                f.debug_tuple("Azure").field(&AzureHexDebug(measurements)).finish()
            }
            Self::NoAttestation => f.write_str("NoAttestation"),
        }
    }
}

/// Used to display DCAP measurements as hex
struct DcapHexDebug<'a>(&'a HashMap<DcapMeasurementRegister, [u8; 48]>);

impl fmt::Debug for DcapHexDebug<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut entries: Vec<_> = self.0.iter().collect();
        entries.sort_by_key(|(register, _)| (*register).clone() as u8);

        let mut map = f.debug_map();
        for (register, value) in entries {
            let hex_value = hex::encode(value);
            map.entry(register, &hex_value);
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
#[derive(Debug, Clone, PartialEq)]
pub enum ExpectedMeasurements {
    Dcap(HashMap<DcapMeasurementRegister, Vec<[u8; 48]>>),
    Azure(HashMap<u32, Vec<[u8; 32]>>),
    NoAttestation,
}

impl MultiMeasurements {
    /// Convert to the JSON format used in HTTP headers
    pub fn to_header_format(&self) -> Result<HeaderValue, MeasurementFormatError> {
        let measurements_map = match self {
            MultiMeasurements::Dcap(dcap_measurements) => dcap_measurements
                .iter()
                .map(|(register, value)| ((register.clone() as u8).to_string(), hex::encode(value)))
                .collect(),
            MultiMeasurements::Azure(azure_measurements) => azure_measurements
                .iter()
                .map(|(index, value)| (index.to_string(), hex::encode(value)))
                .collect(),
            MultiMeasurements::NoAttestation => HashMap::new(),
        };

        Ok(HeaderValue::from_str(&serde_json::to_string(&measurements_map)?)?)
    }

    /// Parse the JSON used in HTTP headers
    pub fn from_header_format(
        input: &str,
        attestation_type: AttestationType,
    ) -> Result<Self, MeasurementFormatError> {
        let measurements_map: HashMap<u8, String> = serde_json::from_str(input)?;

        Ok(match attestation_type {
            AttestationType::None => Self::NoAttestation,
            AttestationType::AzureTdx => Self::Azure(
                measurements_map
                    .into_iter()
                    .map(|(k, v)| {
                        Ok((
                            k as u32,
                            hex::decode(v)?
                                .try_into()
                                .map_err(|_| MeasurementFormatError::BadLength)?,
                        ))
                    })
                    .collect::<Result<_, MeasurementFormatError>>()?,
            ),
            AttestationType::DcapTdx | AttestationType::GcpTdx | AttestationType::QemuTdx => {
                let measurements_map = measurements_map
                    .into_iter()
                    .map(|(k, v)| {
                        Ok((
                            k.try_into()?,
                            hex::decode(v)?
                                .try_into()
                                .map_err(|_| MeasurementFormatError::BadLength)?,
                        ))
                    })
                    .collect::<Result<_, MeasurementFormatError>>()?;
                Self::Dcap(measurements_map)
            }
        })
    }

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
        Ok(Self::Dcap(HashMap::from([
            (DcapMeasurementRegister::MRTD, report.mr_td),
            (DcapMeasurementRegister::RTMR0, report.rt_mr0),
            (DcapMeasurementRegister::RTMR1, report.rt_mr1),
            (DcapMeasurementRegister::RTMR2, report.rt_mr2),
            (DcapMeasurementRegister::RTMR3, report.rt_mr3),
        ])))
    }

    pub fn from_pcrs<'a>(pcrs: impl Iterator<Item = &'a [u8; 32]>) -> Self {
        Self::Azure(pcrs.copied().enumerate().map(|(index, value)| (index as u32, value)).collect())
    }
}

/// Mock TDX measurement values used in tests
#[cfg(any(test, feature = "mock"))]
pub fn mock_dcap_measurements() -> MultiMeasurements {
    MultiMeasurements::Dcap(HashMap::from([
        (DcapMeasurementRegister::MRTD, mock_tdx::MOCK_MRTD),
        (DcapMeasurementRegister::RTMR0, mock_tdx::MOCK_RTMR0),
        (DcapMeasurementRegister::RTMR1, mock_tdx::MOCK_RTMR1),
        (DcapMeasurementRegister::RTMR2, mock_tdx::MOCK_RTMR2),
        (DcapMeasurementRegister::RTMR3, mock_tdx::MOCK_RTMR3),
    ]))
}

/// An error when converting measurements / to or from HTTP header format
#[derive(Error, Debug)]
pub enum MeasurementFormatError {
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Missing value: {0}")]
    MissingValue(String),
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
}

/// An accepted measurement value given in the measurements file
#[derive(Clone, Debug, PartialEq)]
pub struct MeasurementRecord {
    /// An identifier, for example the name and version of the corresponding
    /// OS image
    pub measurement_id: String,
    /// The expected measurement register values
    pub measurements: ExpectedMeasurements,
}

impl MeasurementRecord {
    pub fn allow_no_attestation() -> Self {
        Self {
            measurement_id: "Allow no attestation".to_string(),
            measurements: ExpectedMeasurements::NoAttestation,
        }
    }

    pub fn allow_any_measurement(attestation_type: AttestationType) -> Self {
        Self {
            measurement_id: format!("Any measurement for {attestation_type}"),
            measurements: match attestation_type {
                AttestationType::None => ExpectedMeasurements::NoAttestation,
                AttestationType::AzureTdx => ExpectedMeasurements::Azure(HashMap::new()),
                AttestationType::DcapTdx | AttestationType::GcpTdx | AttestationType::QemuTdx => {
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
                MeasurementRecord::allow_any_measurement(AttestationType::QemuTdx),
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
                MeasurementRecord::allow_any_measurement(AttestationType::QemuTdx),
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
    /// they are acceptable
    pub fn check_measurement(
        &self,
        measurements: &MultiMeasurements,
    ) -> Result<(), AttestationError> {
        if self.accepted_measurements.iter().any(|measurement_record| match measurements {
            MultiMeasurements::Dcap(dcap_measurements) => {
                if let ExpectedMeasurements::Dcap(expected) = &measurement_record.measurements {
                    // All measurements in our policy must be given and must match
                    for (k, v) in expected.iter() {
                        match dcap_measurements.get(k) {
                            Some(actual_value) if v.iter().any(|v| actual_value == v) => {}
                            _ => return false,
                        }
                    }
                    return true;
                }
                false
            }
            MultiMeasurements::Azure(azure_measurements) => {
                if let ExpectedMeasurements::Azure(expected) = &measurement_record.measurements {
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
        }) {
            Ok(())
        } else {
            Err(AttestationError::MeasurementsNotAccepted)
        }
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

        let json_value: Value = serde_json::from_slice(&json_bytes)?;

        let measurement_policy = match json_value {
            Value::Array(records) => {
                let records_simple: Vec<MeasurementRecordSimple> =
                    serde_json::from_value(Value::Array(records))?;

                let mut measurement_policy = Vec::new();

                for record in records_simple {
                    let attestation_type = serde_json::from_value::<AttestationType>(
                        Value::String(record.attestation_type),
                    )?;

                    if let Some(measurements) = record.measurements {
                        let expected_measurements = match attestation_type {
                            AttestationType::None => ExpectedMeasurements::NoAttestation,
                            AttestationType::AzureTdx => {
                                let azure_measurements =
                                    measurements
                                        .iter()
                                        .map(|(index_str, entry)| {
                                            let index = parse_azure_pcr_index(index_str)?;
                                            Ok((
                                                index,
                                                parse_measurement_entry::<32>(entry, index_str)?,
                                            ))
                                        })
                                        .collect::<Result<
                                            HashMap<u32, Vec<[u8; 32]>>,
                                            MeasurementFormatError,
                                        >>()?;
                                ExpectedMeasurements::Azure(azure_measurements)
                            }
                            AttestationType::DcapTdx |
                            AttestationType::GcpTdx |
                            AttestationType::QemuTdx => ExpectedMeasurements::Dcap(
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
                            ),
                        };

                        measurement_policy.push(MeasurementRecord {
                            measurement_id: record.measurement_id.unwrap_or_default(),
                            measurements: expected_measurements,
                        });
                    } else {
                        measurement_policy
                            .push(MeasurementRecord::allow_any_measurement(attestation_type));
                    };
                }

                measurement_policy
            }
            Value::Object(measurements) => {
                let mut dcap_measurements = HashMap::new();

                for (register_name, value) in measurements {
                    match register_name.as_str() {
                        "mrconfigid" | "xfam" | "tdattributes" => continue,
                        _ => {
                            let register =
                                DcapMeasurementRegister::from_policy_key(&register_name).map_err(
                                    |_| {
                                        MeasurementFormatError::Json(
                                            serde_json::Error::io(std::io::Error::new(
                                                std::io::ErrorKind::InvalidData,
                                                format!(
                                                    "unknown dstack-mr measurement field '{register_name}'"
                                                ),
                                            )),
                                        )
                                    },
                                )?;

                            dcap_measurements.insert(
                                register,
                                parse_dcap_measurement_value::<48>(&value, &register_name)?,
                            );
                        }
                    }
                }

                if dcap_measurements.is_empty() {
                    return Err(MeasurementFormatError::NoExpectedValue(
                        "dstack-mr measurements".to_string(),
                    ));
                }

                vec![MeasurementRecord {
                    measurement_id: "dstack-mr-gcp".to_string(),
                    measurements: ExpectedMeasurements::Dcap(dcap_measurements),
                }]
            }
            _ => {
                return Err(MeasurementFormatError::Json(serde_json::Error::io(
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "measurement policy must be a JSON array or object",
                    ),
                )));
            }
        };

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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

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
            specific_measurements.check_measurement(&mock_dcap_measurements()).unwrap_err(),
            AttestationError::MeasurementsNotAccepted
        ));

        // Will not match another attestation type
        assert!(matches!(
            specific_measurements.check_measurement(&MultiMeasurements::NoAttestation).unwrap_err(),
            AttestationError::MeasurementsNotAccepted
        ));

        // A non-specific measurement fails
        assert!(matches!(
            specific_measurements
                .check_measurement(&MultiMeasurements::Azure(HashMap::new()))
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

        allowed_attestation_type.check_measurement(&mock_dcap_measurements()).unwrap();

        // Will not match another attestation type
        assert!(matches!(
            allowed_attestation_type
                .check_measurement(&MultiMeasurements::NoAttestation)
                .unwrap_err(),
            AttestationError::MeasurementsNotAccepted
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
            policy.check_measurement(&MultiMeasurements::NoAttestation).unwrap_err(),
            AttestationError::MeasurementsNotAccepted
        ));

        // A non-specific measurement fails
        assert!(matches!(
            policy.check_measurement(&MultiMeasurements::Azure(HashMap::new())).unwrap_err(),
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

        // First value should match
        let measurements1 =
            MultiMeasurements::Dcap(HashMap::from([(DcapMeasurementRegister::MRTD, [0u8; 48])]));
        assert!(policy.check_measurement(&measurements1).is_ok());

        // Second value should also match
        let measurements2 =
            MultiMeasurements::Dcap(HashMap::from([(DcapMeasurementRegister::MRTD, [0x11u8; 48])]));
        assert!(policy.check_measurement(&measurements2).is_ok());

        // Different value should not match
        let measurements3 =
            MultiMeasurements::Dcap(HashMap::from([(DcapMeasurementRegister::MRTD, [0x22u8; 48])]));
        assert!(policy.check_measurement(&measurements3).is_err());
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

        // Both match (single + first of any)
        let measurements1 = MultiMeasurements::Dcap(HashMap::from([
            (DcapMeasurementRegister::MRTD, [0u8; 48]),
            (DcapMeasurementRegister::RTMR0, [0x11u8; 48]),
        ]));
        assert!(policy.check_measurement(&measurements1).is_ok());

        // Both match (single + second of any)
        let measurements2 = MultiMeasurements::Dcap(HashMap::from([
            (DcapMeasurementRegister::MRTD, [0u8; 48]),
            (DcapMeasurementRegister::RTMR0, [0x22u8; 48]),
        ]));
        assert!(policy.check_measurement(&measurements2).is_ok());

        // Single matches but any doesn't
        let measurements3 = MultiMeasurements::Dcap(HashMap::from([
            (DcapMeasurementRegister::MRTD, [0u8; 48]),
            (DcapMeasurementRegister::RTMR0, [0x33u8; 48]),
        ]));
        assert!(policy.check_measurement(&measurements3).is_err());
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
    async fn test_parse_dstack_mr_gcp_measurements() {
        /// Decode a 48-byte hex string for the test fixture
        fn hex_48(value: &str) -> [u8; 48] {
            hex::decode(value).unwrap().try_into().unwrap()
        }

        let json = r#"{
          "rtmr1": "cdf855b56d27967473b885164b3910ab4d81f3db0bd50e114593bd5fd91cf55760de7776c93f4724cefeaf5ac0843e62",
          "rtmr2": "438337a98c597535940941a3d9913e04a76d84e4ebf69dbb89e1addc8bae7183579685f0ef3144875dba7d933d9dcabf",
          "rtmr3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
          "rtmr0": [
            "c07820997dc2a5e1cc67b05e89852c1a72289e0ec82034bee5b3605cd759328853a758a346522651956afe9222914235",
            "c6975b4a5d66fd88bce4d449ed161e0800ce0f5bcd6a3246f2c83407e230474ff56e6e8d5bc9e9d95cf692d458257954",
            "8256ae5bb15489ebb0181f9935fe00625751e879d4e3b0a111aaba48da31e5cdd82f379cf4b97411618b02ce1deba1fd",
            "46af3396ed9969f670f69142f7b74514598b0f25bb66fc3094402c2de37f4f7493d83cc0860416d3e50f7dda1c34f658",
            "c0f93df02880d6c1dc1a5104e04ef691bc41cdc9da49f8834cc1cdc10acdb557758371d19d2466b560be7a66643953fd",
            "6927bd0230ca2dba4ad21ee68c1f7e018660d5ad6a99e185eac8adc1f05dd6eeb10178d2a744d22cd14b8945b454712b",
            "b90ca4eb0badc04128035ad62f1d1e792f1ca40c99ce25e3cce13f8167eb6265e890c65097518e9f8f5af91519d60d73",
            "c3940a1a1f6709fed6d90c34698cb91767fa6261f4469fdcf6da5e36c6f2493fdfd34bc2d1a9f726a17ed88a79b33561",
            "8530903ec5cb9aad1737c2bf0e9df958ec0a3ede63fe556415990192b4def86a50d8f6869b6283141b13dd4848b0cea2",
            "9efb7193464610d63fbd948901998eda998b3e47e9a0abb72857ba948dcbacd3a17ee75e5081455dccaae208b8294bd9",
            "5c942d2f4a08acd594b7d8914362835dcbb12994aedc2128abecf5585807cb8886faf7b9b32611cd4e63eac269632560",
            "284f209fece0d49331f2e411c46f6debc3be698bd8587264c90ab0dbdf651046aef3badaae9a7983ea0855a7dabdfa00",
            "8d5f7f704ccba0a63157f1ec1214c7f043005b045adae261e0581951965a96350d6196f38751b5dd0e72fca181817efa",
            "123ad184172b44083b191b12557f3c923416d8e654ffb390736db331ff2a5bce6c89d14d62cf70e113b98d8f13e78519",
            "8ae3d7af48afa0f30fd700a58ca84cd5e0054fbe011d9ed228e30a17db456987e63c6dfd71437aac33ffb9d796088d70",
            "3fdfcb2bbf25c9e535f7e4724b1cee79666824cab1565f985d2e1e0218818d538cf6f3bfa5c623c13d6226ae51ea8cd6",
            "640b92712990cc8aab4f3786611a8acc3180525abd42a31c06eb7611b8c54a72247dfe8a7a93d3c922f771797a7932de",
            "7c8fc1dd62391d416ac64174b833f821b59738d816d96168483300127608e0cf3345840b5bd9325c125dd6b2f595f1b0",
            "a191d8250215e05e31fc42fa00f4b7a8729e1fb83b3dacb3def3989b9eaa3f8d199b96759477ce20bbd47c909b6b984c",
            "633eeb1778affe65d1b3633527395763602c06e9d7aea52a2a6d5073c33ee1fe78f3a83aeb58edd036de681eee3d1f0f",
            "b372a4eac4561e3a8d92028a38e8860a63d7e69c7fcab250aa49d1c951c94b49d0abbe87c353fcd14651f64ac5dde055",
            "90d7dbdb795d66669ff44aff1f8ea0de13f5362f1dec68f17fca60364fcc019de18b246c9e173c09102360442dba3261",
            "8292abcf17f665c5f63e158a5fd7f2e160ac5b5ae4811532d93c3b5f38a53adebebddaf531aca4ef91d9fb68fb4312a8",
            "e1d0235496f93f9475bf0b26d33da5c15831cfc94104d6bea7ab82db027c5f1e917d47dda6953eefae7dcb20ab6f75c4"
          ],
          "mrtd": [
            "a5844e88897b70c318bef929ef4dfd6c7304c52c4bc9c3f39132f0fdccecf3eb5bab70110ee42a12509a31c037288694",
            "8370d8f6d02f2d13e211e91c93fde923049522b241425a29a7bf0071ef49b250af4ef49d852fa3e10065d1b51dfce8fb",
            "feb7486608382c1ff0e15b4648ddc0acea6ca974eb53e3529f4c4bd5ffbaa20bf335cb75965cea65fe473aed9647c162"
          ],
          "mrconfigid": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
          "xfam": "e700060000000000",
          "tdattributes": "0000001000000000"
        }"#;

        let policy = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec()).unwrap();
        assert_eq!(policy.accepted_measurements.len(), 1);

        let record = &policy.accepted_measurements[0];
        if let ExpectedMeasurements::Dcap(dcap) = &record.measurements {
            assert_eq!(dcap.len(), 5);
            assert_eq!(dcap.get(&DcapMeasurementRegister::MRTD).unwrap().len(), 3);
            assert_eq!(dcap.get(&DcapMeasurementRegister::RTMR0).unwrap().len(), 24);
            assert_eq!(dcap.get(&DcapMeasurementRegister::RTMR1).unwrap().len(), 1);
            assert_eq!(dcap.get(&DcapMeasurementRegister::RTMR2).unwrap().len(), 1);
            assert_eq!(dcap.get(&DcapMeasurementRegister::RTMR3).unwrap().len(), 1);

            let measurements1 = MultiMeasurements::Dcap(HashMap::from([
                (
                    DcapMeasurementRegister::MRTD,
                    hex_48(
                        "a5844e88897b70c318bef929ef4dfd6c7304c52c4bc9c3f39132f0fdccecf3eb5bab70110ee42a12509a31c037288694",
                    ),
                ),
                (
                    DcapMeasurementRegister::RTMR0,
                    hex_48(
                        "c07820997dc2a5e1cc67b05e89852c1a72289e0ec82034bee5b3605cd759328853a758a346522651956afe9222914235",
                    ),
                ),
                (
                    DcapMeasurementRegister::RTMR1,
                    hex_48(
                        "cdf855b56d27967473b885164b3910ab4d81f3db0bd50e114593bd5fd91cf55760de7776c93f4724cefeaf5ac0843e62",
                    ),
                ),
                (
                    DcapMeasurementRegister::RTMR2,
                    hex_48(
                        "438337a98c597535940941a3d9913e04a76d84e4ebf69dbb89e1addc8bae7183579685f0ef3144875dba7d933d9dcabf",
                    ),
                ),
                (
                    DcapMeasurementRegister::RTMR3,
                    hex_48(
                        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    ),
                ),
            ]));
            assert!(policy.check_measurement(&measurements1).is_ok());

            let measurements2 = MultiMeasurements::Dcap(HashMap::from([
                (
                    DcapMeasurementRegister::MRTD,
                    hex_48(
                        "8370d8f6d02f2d13e211e91c93fde923049522b241425a29a7bf0071ef49b250af4ef49d852fa3e10065d1b51dfce8fb",
                    ),
                ),
                (
                    DcapMeasurementRegister::RTMR0,
                    hex_48(
                        "e1d0235496f93f9475bf0b26d33da5c15831cfc94104d6bea7ab82db027c5f1e917d47dda6953eefae7dcb20ab6f75c4",
                    ),
                ),
                (
                    DcapMeasurementRegister::RTMR1,
                    hex_48(
                        "cdf855b56d27967473b885164b3910ab4d81f3db0bd50e114593bd5fd91cf55760de7776c93f4724cefeaf5ac0843e62",
                    ),
                ),
                (
                    DcapMeasurementRegister::RTMR2,
                    hex_48(
                        "438337a98c597535940941a3d9913e04a76d84e4ebf69dbb89e1addc8bae7183579685f0ef3144875dba7d933d9dcabf",
                    ),
                ),
                (
                    DcapMeasurementRegister::RTMR3,
                    hex_48(
                        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    ),
                ),
            ]));
            assert!(policy.check_measurement(&measurements2).is_ok());

            let measurements3 = MultiMeasurements::Dcap(HashMap::from([
                (
                    DcapMeasurementRegister::MRTD,
                    hex_48(
                        "a5844e88897b70c318bef929ef4dfd6c7304c52c4bc9c3f39132f0fdccecf3eb5bab70110ee42a12509a31c037288694",
                    ),
                ),
                (
                    DcapMeasurementRegister::RTMR0,
                    hex_48(
                        "c07820997dc2a5e1cc67b05e89852c1a72289e0ec82034bee5b3605cd759328853a758a346522651956afe9222914235",
                    ),
                ),
                (
                    DcapMeasurementRegister::RTMR1,
                    hex_48(
                        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    ),
                ),
                (
                    DcapMeasurementRegister::RTMR2,
                    hex_48(
                        "438337a98c597535940941a3d9913e04a76d84e4ebf69dbb89e1addc8bae7183579685f0ef3144875dba7d933d9dcabf",
                    ),
                ),
                (
                    DcapMeasurementRegister::RTMR3,
                    hex_48(
                        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    ),
                ),
            ]));
            assert!(policy.check_measurement(&measurements3).is_err());
        } else {
            panic!("Expected ExpectedMeasurements::Dcap");
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
        let dcap = MultiMeasurements::Dcap(HashMap::from([(
            DcapMeasurementRegister::MRTD,
            register_value,
        )]));
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
