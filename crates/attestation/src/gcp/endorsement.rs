//! The root Google signs its GCP firmware endorsements under

/// `GCE-cc-tcb-root_1.crt` from `https://pki.goog/cloud_integrity/`, DER
pub const GCE_CC_TCB_ROOT_DER: &[u8] = include_bytes!("../../assets/GCE-cc-tcb-root_1.crt");
/// The pinned root's published name
pub const GCE_CC_TCB_ROOT_NAME: &str = "GCE-cc-tcb-root_1";

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};
    use x509_parser::prelude::*;

    use super::*;

    #[test]
    fn the_pinned_root_is_the_published_one() {
        assert_eq!(
            hex::encode(Sha256::digest(GCE_CC_TCB_ROOT_DER)),
            "e876bc6978bf4f3da445f98a0a82363c8c0bae5a1fc033c6df65846a6cb0f18c"
        );
        let (_, root) = X509Certificate::from_der(GCE_CC_TCB_ROOT_DER).unwrap();
        assert_eq!(root.subject(), root.issuer());
    }
}
