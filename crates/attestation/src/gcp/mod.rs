//! Google Cloud Platform related attestation verification logic
mod firmware;
mod provenance;

pub(crate) use firmware::{GcpFirmwareCache, fetch_firmware};
pub(crate) use provenance::{GcpProvenanceChecker, GcpProvenanceError};
