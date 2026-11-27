use anyhow::Context;
use attestation::{AttestationEvidence, AttestationType};

/// Generates evidence for the configured local TDX platform.
#[derive(Debug, Clone)]
pub struct AttestationGenerator {
    attestation_type: AttestationType,
    #[cfg(any(test, feature = "mock"))]
    mock: bool,
}

impl AttestationGenerator {
    /// Configure the platform for quote generation.
    pub fn new(attestation_type: AttestationType) -> anyhow::Result<Self> {
        anyhow::ensure!(
            attestation_type != AttestationType::None,
            "Quote generation requires dcap-tdx or gcp-tdx"
        );
        Ok(Self {
            attestation_type,
            #[cfg(any(test, feature = "mock"))]
            mock: false,
        })
    }

    /// Generate mock DCAP evidence for tests without TDX hardware.
    #[cfg(any(test, feature = "mock"))]
    pub fn mock() -> Self {
        Self { attestation_type: AttestationType::DcapTdx, mock: true }
    }

    /// Generate a quote bound to the report data and collect platform
    /// metadata.
    pub fn generate_attestation(
        &self,
        report_data: [u8; 64],
    ) -> anyhow::Result<AttestationEvidence> {
        #[cfg(any(test, feature = "mock"))]
        if self.mock {
            return Ok(AttestationEvidence {
                quote: mock_tdx::generate_mock_tdx_quote(report_data)
                    .map_err(|error| anyhow::anyhow!("Cannot create mock quote: {error}"))?,
                platform: attestation::PlatformMetadata {
                    attestation_type: self.attestation_type.try_into()?,
                    ram_bytes: 0,
                    num_disks: 0,
                    acpi: None,
                    smbios_handoff: None,
                    dm_verity_boot: false,
                },
            });
        }

        let platform = attest_measure::platform::metadata_for(self.attestation_type.try_into()?)
            .context("Cannot retrieve platform metadata")?;
        let quote = tdx_attest::get_quote(&report_data).context("TDX quote generation")?;
        tracing::info!("Generated TDX quote of {} bytes", quote.len());
        Ok(AttestationEvidence { quote, platform })
    }
}
