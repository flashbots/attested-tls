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
                loader: [
                    246, 12, 53, 229, 59, 178, 27, 70, 117, 207, 168, 219, 49, 14, 200, 142, 56,
                    205, 54, 157, 141, 70, 58, 205, 222, 129, 81, 34, 250, 139, 137, 59, 136, 150,
                    165, 120, 59, 83, 136, 86, 105, 62, 215, 100, 93, 219, 137, 126,
                ],
                rsdp: [
                    80, 157, 207, 225, 11, 235, 93, 71, 12, 64, 242, 94, 48, 137, 83, 112, 148,
                    136, 49, 185, 207, 121, 219, 21, 217, 119, 231, 187, 168, 235, 66, 247, 32, 2,
                    18, 7, 26, 216, 177, 157, 96, 17, 117, 151, 121, 236, 237, 90,
                ],
                tables: [
                    11, 176, 175, 160, 8, 135, 59, 220, 32, 222, 224, 247, 65, 218, 120, 150, 194,
                    191, 238, 233, 74, 229, 46, 155, 219, 249, 75, 200, 124, 50, 208, 74, 75, 31,
                    29, 130, 68, 144, 241, 218, 229, 116, 255, 109, 78, 75, 176, 179,
                ],
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
                Some(gcp_portable_platform_metadata()),
                Some(&gcp_firmware_cache),
            )
            .unwrap();
    }
}
