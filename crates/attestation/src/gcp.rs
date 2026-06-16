use std::{
    collections::HashMap,
    io::Read,
    sync::{Arc, RwLock},
};

use attest_measure::dcap::DcapFirmware;
use serde::Deserialize;
use thiserror::Error;

const GCS_FIRMWARE_LIST_URL: &str =
    "https://storage.googleapis.com/storage/v1/b/gce_tcb_integrity/o";
const GCS_FIRMWARE_PREFIX: &str = "ovmf_x64_csm/tdx/";
const GCS_FIRMWARE_MAX_RESULTS: &str = "1000";

#[derive(Clone, Debug, Default)]
pub(crate) struct GcpFirmwareCache {
    cache: Arc<RwLock<HashMap<[u8; 48], attest_measure::dcap::DcapFirmware>>>,
}

#[derive(Debug, Error)]
pub enum GcpFirmwareCacheError {
    #[error("HTTP: {0}")]
    Http(String),
    #[error("response body was not valid UTF-8")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("listing JSON: {0}")]
    Listing(#[from] serde_json::Error),
    #[error("invalid GCP firmware object name: {0}")]
    ObjectName(String),
    #[error("invalid MRTD hex in object name: {0}")]
    Mrtd(String),
    #[error("firmware: {0}")]
    Firmware(#[from] attest_measure::dcap::GoogleError),
}

#[derive(Debug, Deserialize)]
struct GcsObjectsResponse {
    #[serde(default)]
    items: Vec<GcsObject>,
}

#[derive(Debug, Deserialize)]
struct GcsObject {
    name: String,
}

impl GcpFirmwareCache {
    pub(crate) fn new() -> Self {
        Self { cache: Default::default() }
    }

    pub(crate) fn prewarm() -> Result<Self, GcpFirmwareCacheError> {
        let cache = Self::new();
        for mrtd in fetch_known_mrtds()? {
            cache.get_or_fetch(mrtd)?;
        }
        Ok(cache)
    }

    pub(crate) fn get_or_fetch(
        &self,
        mrtd: [u8; 48],
    ) -> Result<DcapFirmware, attest_measure::dcap::GoogleError> {
        if let Some(firmware) = self.cache.read().unwrap().get(&mrtd).cloned() {
            return Ok(firmware);
        }

        let firmware = DcapFirmware::from_google(mrtd)?;
        self.cache.write().unwrap().insert(mrtd, firmware.clone());
        Ok(firmware)
    }
}

fn fetch_known_mrtds() -> Result<Vec<[u8; 48]>, GcpFirmwareCacheError> {
    let response = ureq::get(GCS_FIRMWARE_LIST_URL)
        .query("prefix", GCS_FIRMWARE_PREFIX)
        .query("maxResults", GCS_FIRMWARE_MAX_RESULTS)
        .call()
        .map_err(|err| GcpFirmwareCacheError::Http(err.to_string()))?;
    let mut reader = response.into_reader();
    let mut body = Vec::new();
    reader.read_to_end(&mut body).map_err(|err| GcpFirmwareCacheError::Http(err.to_string()))?;
    parse_known_mrtds(&body)
}

fn parse_known_mrtds(body: &[u8]) -> Result<Vec<[u8; 48]>, GcpFirmwareCacheError> {
    let body = String::from_utf8(body.to_vec())?;
    let objects: GcsObjectsResponse = serde_json::from_str(&body)?;

    let mut mrtds = Vec::new();
    for object in objects.items {
        if let Some(mrtd) = parse_mrtd_from_object_name(&object.name)? {
            mrtds.push(mrtd);
        }
    }

    if mrtds.is_empty() {
        return Err(GcpFirmwareCacheError::ObjectName(
            "no GCP firmware objects were discovered during prewarm".to_string(),
        ));
    }

    Ok(mrtds)
}

fn parse_mrtd_from_object_name(name: &str) -> Result<Option<[u8; 48]>, GcpFirmwareCacheError> {
    if !name.starts_with(GCS_FIRMWARE_PREFIX) || !name.ends_with(".binarypb") {
        return Ok(None);
    }

    let hex = &name[GCS_FIRMWARE_PREFIX.len()..name.len() - ".binarypb".len()];
    let bytes = hex::decode(hex).map_err(|_| GcpFirmwareCacheError::Mrtd(name.to_string()))?;
    let mrtd: [u8; 48] =
        bytes.try_into().map_err(|_| GcpFirmwareCacheError::Mrtd(name.to_string()))?;
    Ok(Some(mrtd))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn dump_gcs_firmware_listing() {
        let response = ureq::get(GCS_FIRMWARE_LIST_URL)
            .query("prefix", GCS_FIRMWARE_PREFIX)
            .query("maxResults", GCS_FIRMWARE_MAX_RESULTS)
            .call()
            .unwrap();
        let mut reader = response.into_reader();
        let mut body = Vec::new();
        reader.read_to_end(&mut body).unwrap();
        println!("{}", String::from_utf8(body).unwrap());
    }

    #[test]
    fn parse_known_mrtds_fixture() {
        let body = include_bytes!("../test-assets/gcp-known-firmware.json");
        let mrtds = parse_known_mrtds(body).unwrap();

        assert_eq!(mrtds.len(), 78);
        assert_eq!(
            hex::encode(mrtds[0]),
            "038de02f6584df60c9ad245045aecf6f0b9d90018eeff5736357334c37965b1cd5bf09032a94e6b721f34fa8973a1086"
        );
        assert_eq!(
            hex::encode(mrtds[1]),
            "0622b08df0d75dbce72c4870879daec46898227536ad12473ed73dbed8b3f6f7ab834f76f656196b5a92d715027890a6"
        );
    }
}
