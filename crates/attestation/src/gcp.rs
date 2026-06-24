use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use attest_measure::dcap::DcapFirmware;
use thiserror::Error;

/// Maps MRTD values to GCP firmware to avoid re-fetching on subsequent
/// verification
#[derive(Clone, Debug, Default)]
pub(crate) struct GcpFirmwareCache {
    cache: Arc<RwLock<HashMap<[u8; 48], attest_measure::dcap::DcapFirmware>>>,
}

impl GcpFirmwareCache {
    pub(crate) fn new() -> Self {
        Self { cache: Default::default() }
    }

    /// Retrieve firmware from cache or fetch if not present
    pub(crate) fn get_or_fetch(
        &self,
        mrtd: [u8; 48],
    ) -> Result<DcapFirmware, GcpFirmwareCacheError> {
        if let Some(firmware) =
            self.cache.read().map_err(|_| GcpFirmwareCacheError::CacheLock)?.get(&mrtd).cloned()
        {
            return Ok(firmware);
        }

        let firmware = DcapFirmware::from_google(mrtd)?;
        self.cache
            .write()
            .map_err(|_| GcpFirmwareCacheError::CacheLock)?
            .insert(mrtd, firmware.clone());
        Ok(firmware)
    }
}

#[derive(Debug, Error)]
pub(crate) enum GcpFirmwareCacheError {
    #[error("Cache lock poisoned")]
    CacheLock,
    #[error("Firmware fetch: {0}")]
    Firmware(#[from] attest_measure::dcap::GoogleError),
}
