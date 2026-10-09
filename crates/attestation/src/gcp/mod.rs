//! Google Cloud Platform related attestation verification logic
mod endorsement;
mod firmware;
mod provenance;

pub(crate) use endorsement::GcpEndorsementChecker;
pub use endorsement::{
    GCE_CC_TCB_ROOT_DER,
    GCE_CC_TCB_ROOT_NAME,
    GcpEndorsementError,
    GcpFirmwareEndorsement,
};
pub(crate) use firmware::{GcpFirmwareCache, fetch_firmware};
pub(crate) use provenance::{GcpProvenanceChecker, GcpProvenanceError};
