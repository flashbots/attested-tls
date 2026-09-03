//! Trusted self-hosted TDX firmware used to reconstruct MRTD and RTMR0.

use std::collections::HashMap;

use attest_measure::dcap::DcapFirmware;
use once_cell::sync::Lazy;

// Read the JSON created by build.rs from included trusted firmware blobs
static TRUSTED_FIRMWARE_BY_MRTD: Lazy<HashMap<[u8; 48], DcapFirmware>> = Lazy::new(|| {
    let firmware: Vec<DcapFirmware> =
        serde_json::from_str(include_str!(concat!(env!("OUT_DIR"), "/trusted-firmware.json")))
            .expect("build script generated invalid trusted firmware");
    firmware.into_iter().map(|firmware| (firmware.mrtd, firmware)).collect()
});

/// Look up a trusted self-hosted firmware image by the MRTD in a TDX quote.
pub(crate) fn firmware_for_mrtd(mrtd: [u8; 48]) -> Option<DcapFirmware> {
    TRUSTED_FIRMWARE_BY_MRTD.get(&mrtd).cloned()
}

/// Get some arbitrary trusted firmware to use in tests
#[cfg(test)]
pub(crate) fn any_trusted_firmware() -> DcapFirmware {
    TRUSTED_FIRMWARE_BY_MRTD.values().next().expect("at least one trusted firmware").clone()
}

#[cfg(test)]
mod tests {
    use super::{TRUSTED_FIRMWARE_BY_MRTD, firmware_for_mrtd};

    #[test]
    fn generated_firmware_is_indexed_by_mrtd() {
        assert!(!TRUSTED_FIRMWARE_BY_MRTD.is_empty());
        for (mrtd, expected) in TRUSTED_FIRMWARE_BY_MRTD.iter() {
            let firmware = firmware_for_mrtd(*mrtd).expect("firmware should be trusted");
            assert_eq!(firmware.mrtd, expected.mrtd);
        }
    }

    #[test]
    fn unknown_mrtd_is_not_trusted() {
        assert!(firmware_for_mrtd([0xff; 48]).is_none());
    }
}
