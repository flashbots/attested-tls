//! Google Cloud Platform specific attestation logic

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
    cache: Arc<RwLock<HashMap<[u8; 48], DcapFirmware>>>,
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

        let firmware = fetch_firmware(mrtd)?;
        self.cache
            .write()
            .map_err(|_| GcpFirmwareCacheError::CacheLock)?
            .insert(mrtd, firmware.clone());
        Ok(firmware)
    }
}

/// Fetch firmware from Google. If we are running inside a mutli-threaded
/// tokio runtime the blocking HTTP fetch is wrapped in `spawn_blocking`
pub(crate) fn fetch_firmware(mrtd: [u8; 48]) -> Result<DcapFirmware, GcpFirmwareCacheError> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle)
            if matches!(handle.runtime_flavor(), tokio::runtime::RuntimeFlavor::MultiThread) =>
        {
            tokio::task::block_in_place(|| {
                handle.block_on(async move {
                    tokio::task::spawn_blocking(move || DcapFirmware::from_google(mrtd))
                        .await
                        .map_err(|err| GcpFirmwareCacheError::Join(err.to_string()))?
                        .map_err(GcpFirmwareCacheError::from)
                })
            })
        }
        _ => DcapFirmware::from_google(mrtd).map_err(GcpFirmwareCacheError::from),
    }
}

#[derive(Debug, Error)]
pub(crate) enum GcpFirmwareCacheError {
    #[error("Cache lock poisoned")]
    CacheLock,
    #[error("Firmware fetch: {0}")]
    Firmware(#[from] attest_measure::dcap::GoogleError),
    #[error("Firmware fetch task join: {0}")]
    Join(String),
}

#[cfg(test)]
mod tests {
    use attest_measure::dcap::DcapFirmware;
    use attest_types::{AcpiHashes, DcapImageHashes};
    use dcap_qvl::quote::Quote;

    use crate::{
        PlatformMetadata,
        dcap::{get_quote_input_data, verify_dcap_attestation_with_given_timestamp},
        gcp::GcpFirmwareCache,
        measurements::{ExpectedMeasurements, MeasurementPolicy, MeasurementRecord},
    };

    /// Timestamp used with test fixture
    const GCP_TDX_PORTABLE_FIXTURE_TIMESTAMP: u64 = 1_782_809_233;

    /// Create a firmware cache with given firmware loaded
    fn create_cache_with_firmware(firmware: DcapFirmware) -> GcpFirmwareCache {
        let cache = GcpFirmwareCache::new();
        cache.cache.write().unwrap().insert(firmware.mrtd, firmware);
        cache
    }

    fn decode_dcap_hash(input: &str) -> [u8; 48] {
        hex::decode(input).unwrap().try_into().unwrap()
    }

    /// Image hashes associated with test fixture
    fn gcp_portable_image_hashes() -> DcapImageHashes {
        DcapImageHashes {
            uki_authenticode: decode_dcap_hash(
                "82500f977e16a1e3fd47db792ac9c9fdd69caa73d8e719fe4489416355f23f5d0863ad796febfc1241bc3e868c3649a6",
            ),
            kernel_authenticode: decode_dcap_hash(
                "b2a6076ae199d325e553a5102cf1f4a18b5e67e36b33261ef20352052199ec5853b5133c0231b16f1198bb086f1cbfac",
            ),
            cmdline_hash: decode_dcap_hash(
                "e03b89abf354a38976537b7a9138fd312e4cbf73b61eebc44086491701b1d167b9f6cb97a922325866c93e0834723d87",
            ),
            initrd_hash: decode_dcap_hash(
                "99251a9997f552ce98364e3f7311ca47471e299b6fdb31226d738a10577959ab741cc2e7b8c268236153de568265d3f2",
            ),
            gpt_disk_guid_hash: decode_dcap_hash(
                "488fa3f08aae01c1a46b497319e8a7d3b7335c9ff4f4d7fe6a3dd62c844b03de22157c0303be58f10e3152687778e68d",
            ),
        }
    }

    /// Platform metadata associated with test fixture
    fn gcp_portable_platform_metadata() -> PlatformMetadata {
        PlatformMetadata {
            attestation_type: attest_types::AttestationType::GcpTdx,
            ram_bytes: 17_179_869_184,
            num_disks: 1,
            acpi: Some(AcpiHashes {
                loader: decode_dcap_hash(
                    "f60c35e53bb21b4675cfa8db310ec88e38cd369d8d463acdde815122fa8b893b8896a5783b538856693ed7645ddb897e",
                ),
                rsdp: decode_dcap_hash(
                    "509dcfe10beb5d470c40f25e30895370948831b9cf79db15d977e7bba8eb42f7200212071ad8b19d6011759779eced5a",
                ),
                tables: decode_dcap_hash(
                    "0bb0afa008873bdc20dee0f741da7896c2bfeee94ae52e9bdbf94bc87c32d04a4b1f1d824490f1dae574ff6d4e4bb0b3",
                ),
            }),
        }
    }

    #[tokio::test]
    async fn test_gcp_tdx_portable_policy_with_stored_collateral() {
        let attestation_bytes: &'static [u8] =
            include_bytes!("../test-assets/gcp-tdx-1782809233226668671");
        let collateral_bytes: &'static [u8] =
            include_bytes!("../test-assets/gcp-tdx-collateral-1782809233226668671.yaml");
        let firmware_bytes: &'static [u8] =
            include_bytes!("../test-assets/gcp-tdx-firmware-1782809233226668671.yaml");

        let expected_input_data = {
            let quote = Quote::parse(attestation_bytes).unwrap();
            get_quote_input_data(quote.report)
        };

        let collateral = serde_saphyr::from_slice(collateral_bytes).unwrap();
        let firmware = serde_saphyr::from_slice(firmware_bytes).unwrap();
        let measurements = verify_dcap_attestation_with_given_timestamp(
            attestation_bytes.to_vec(),
            expected_input_data,
            None,
            Some(collateral),
            GCP_TDX_PORTABLE_FIXTURE_TIMESTAMP,
            false,
        )
        .await
        .unwrap();

        let measurement_policy = MeasurementPolicy {
            accepted_measurements: vec![MeasurementRecord {
                measurement_id: "gcp-tdx-portable-image-hashes".to_string(),
                measurements: ExpectedMeasurements::Image(gcp_portable_image_hashes()),
            }],
        };
        let gcp_firmware_cache = create_cache_with_firmware(firmware);

        measurement_policy
            .check_measurement_with_gcp_cache(
                &measurements,
                Some(&gcp_portable_platform_metadata()),
                Some(&gcp_firmware_cache),
            )
            .unwrap();
    }
}
