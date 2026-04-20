//! Exercises the SessionExporter trait against a deterministic test double.
//!
//! This test locks in the trait shape only — the rustls-backed implementation
//! lives behind the `rustls-exporter` feature and has its own test
//! (`rustls_exporter.rs`).

use std::sync::Mutex;

use attestation::session_exporter::{ExportError, SessionExporter};

struct FakeExporter {
    label_seen: Mutex<Option<Vec<u8>>>,
    context_seen: Mutex<Option<Option<Vec<u8>>>>,
    fill_byte: u8,
}

impl SessionExporter for FakeExporter {
    fn export_keying_material(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<(), ExportError> {
        *self.label_seen.lock().unwrap() = Some(label.to_vec());
        *self.context_seen.lock().unwrap() = Some(context.map(<[u8]>::to_vec));
        out.fill(self.fill_byte);
        Ok(())
    }
}

#[test]
fn exporter_is_called_with_given_label_and_fills_output() {
    let exporter = FakeExporter {
        label_seen: Mutex::new(None),
        context_seen: Mutex::new(None),
        fill_byte: 0xAB,
    };
    let mut out = [0u8; 32];
    exporter.export_keying_material(b"attested-oss/v1/session", None, &mut out).unwrap();

    assert_eq!(out, [0xABu8; 32]);
    assert_eq!(
        exporter.label_seen.lock().unwrap().as_deref(),
        Some(b"attested-oss/v1/session".as_ref())
    );
    assert_eq!(exporter.context_seen.lock().unwrap().as_ref().unwrap().as_deref(), None);
}

#[test]
fn exporter_propagates_context_argument() {
    let exporter = FakeExporter {
        label_seen: Mutex::new(None),
        context_seen: Mutex::new(None),
        fill_byte: 0x00,
    };
    let mut out = [0u8; 16];
    exporter
        .export_keying_material(b"label", Some(b"context-bytes"), &mut out)
        .unwrap();
    assert_eq!(
        exporter.context_seen.lock().unwrap().as_ref().unwrap().as_deref(),
        Some(b"context-bytes".as_ref())
    );
}
