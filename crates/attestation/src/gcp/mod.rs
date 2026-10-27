//! Google Cloud Platform related attestation verification logic
mod firmware;
mod identity;
mod provenance;

pub(crate) use firmware::{GcpFirmwareCache, fetch_firmware};
pub(crate) use identity::verify_instance;
pub use identity::{GcpInstanceIdentity, GcpInstanceIdentityError};
pub(crate) use provenance::{GcpProvenanceChecker, GcpProvenanceError};
