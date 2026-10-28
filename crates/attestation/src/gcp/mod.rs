//! Google Cloud Platform related attestation verification logic
mod firmware;
mod identity;
mod provenance;

pub(crate) use firmware::{GcpFirmwareCache, fetch_firmware};
pub use identity::{GcpInstanceIdentity, GcpInstanceIdentityError};
pub(crate) use identity::{collect_identity, verify_instance};
pub(crate) use provenance::{GcpProvenanceChecker, GcpProvenanceError};
