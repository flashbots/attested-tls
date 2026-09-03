//! Pure-Rust parsing of the TPM 2.0 `TPMS_ATTEST` structure.
//!
//! Quote verification only needs two fields of a quote-type attestation
//! structure: `extraData` (the caller-provided nonce) and the attested
//! `pcrDigest`. `TPMS_ATTEST` is a flat, big-endian structure frozen by
//! the TPM 2.0 Library Specification (Part 2: Structures, section 10.12),
//! so it can be parsed here without the tss-esapi FFI stack. This keeps
//! quote verification free of native TPM library dependencies and
//! portable to platforms without tpm2-tss.
//!
//! This parser is implemented directly from the TPM 2.0 specification; a
//! differential test checks it against tss-esapi's unmarshalling on a
//! captured Azure vTPM quote.

use thiserror::Error;

/// TPM_GENERATED_VALUE, the magic constant leading every TPMS_ATTEST
/// (TPM 2.0 spec Part 2, section 6.2).
const TPM_GENERATED_VALUE: u32 = 0xff54_4347;

/// TPM_ST_ATTEST_QUOTE, the tag of quote-type attestation structures
/// (TPM 2.0 spec Part 2, section 6.9).
const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

/// TPM_ALG_SHA256, the only PCR bank a quote may select here: the PCR
/// values travel as `[u8; 32]`, so no other digest size can be carried
/// (TPM 2.0 spec Part 2, section 6.3).
const TPM_ALG_SHA256: u16 = 0x000b;

/// Maximum octets accepted in a `pcrSelect` bitmap. The spec bounds it by
/// PCR_SELECT_MAX, the octets needed for the TPM's own PCR count (TPM 2.0
/// spec Part 2, section 10.6.2); four covers 32 registers, more than any
/// TPM allocates. Bounding it keeps one attacker-supplied byte from
/// deciding how much work the expansion below does.
const MAX_SIZE_OF_SELECT: usize = 4;

#[derive(Error, Debug)]
pub enum AttestError {
    #[error("buffer too short for TPMS_ATTEST field")]
    Truncated,
    #[error("TPMS_ATTEST magic is not TPM_GENERATED_VALUE")]
    Magic,
    #[error("TPMS_ATTEST is not a quote")]
    NotAQuote,
    #[error("quote selects {0} PCR banks; exactly one SHA-256 bank is required")]
    PcrSelectionBanks(u32),
    #[error("quote selects PCR bank with hash algorithm {0:#06x}, not SHA-256")]
    PcrSelectionAlgorithm(u16),
    #[error("pcrSelect bitmap is {0} octets; at most 4 are allowed")]
    PcrSelectionSize(usize),
    #[error("trailing bytes after TPMS_ATTEST")]
    TrailingData,
}

/// The quote-relevant fields of a marshalled `TPMS_ATTEST` structure.
#[derive(Debug)]
pub(crate) struct TpmsAttest {
    extra_data: Vec<u8>,
    pcr_digest: Vec<u8>,
    selected_pcrs: Vec<u32>,
}

impl TpmsAttest {
    /// Parse a marshalled TPMS_ATTEST, accepting only quote-type
    /// attestation structures (TPM_ST_ATTEST_QUOTE).
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, AttestError> {
        let mut reader = Reader { bytes, offset: 0 };
        if reader.read_u32()? != TPM_GENERATED_VALUE {
            return Err(AttestError::Magic);
        }
        if reader.read_u16()? != TPM_ST_ATTEST_QUOTE {
            return Err(AttestError::NotAQuote);
        }
        // qualifiedSigner: TPM2B_NAME
        reader.read_tpm2b()?;
        // extraData: TPM2B_DATA
        let extra_data = reader.read_tpm2b()?.to_vec();
        // clockInfo: TPMS_CLOCK_INFO (clock, resetCount, restartCount,
        // safe)
        reader.skip(8 + 4 + 4 + 1)?;
        // firmwareVersion: UINT64
        reader.skip(8)?;
        // attested.quote: TPMS_QUOTE_INFO, starting with the pcrSelect
        // list (TPML_PCR_SELECTION)
        let selection_count = reader.read_u32()?;
        // Exactly one bank, and it has to be SHA-256. The values a quote
        // carries alongside this structure are fixed-width `[u8; 32]`, so a
        // second bank would have no room and a different algorithm would
        // not fit at all. Refusing beats guessing: which value
        // belongs to which register is what a measurement policy is
        // compared against.
        if selection_count != 1 {
            return Err(AttestError::PcrSelectionBanks(selection_count));
        }
        // TPMS_PCR_SELECTION: hash algorithm, sizeofSelect, pcrSelect
        let hash_algorithm = reader.read_u16()?;
        if hash_algorithm != TPM_ALG_SHA256 {
            return Err(AttestError::PcrSelectionAlgorithm(hash_algorithm));
        }
        let size_of_select = reader.read_u8()? as usize;
        if size_of_select > MAX_SIZE_OF_SELECT {
            return Err(AttestError::PcrSelectionSize(size_of_select));
        }
        let selection_bitmap = reader.take(size_of_select)?;
        // pcrSelect is a bitmap, LSB first within each octet: octet i bit j
        // selects PCR i * 8 + j (TPM 2.0 spec Part 2, section 10.6.2).
        //
        // Ascending order is what lets a caller pair this list with the
        // values a quote ships, and the quote's own signature is what
        // enforces it: the TPM computes pcrDigest over the selected values
        // concatenated in selection order, which is ascending by register.
        // A sender that reorders the values it ships therefore fails the
        // digest comparison in `TpmQuote::verify_pcrs`. The pairing means
        // nothing until that comparison has run.
        let selected_pcrs = (0..size_of_select * 8)
            .filter(|pcr| selection_bitmap[pcr / 8] & (1 << (pcr % 8)) != 0)
            .map(|pcr| pcr as u32)
            .collect();
        // attested.quote.pcrDigest: TPM2B_DIGEST
        let pcr_digest = reader.read_tpm2b()?.to_vec();
        if reader.offset != bytes.len() {
            return Err(AttestError::TrailingData);
        }
        Ok(Self { extra_data, pcr_digest, selected_pcrs })
    }

    /// The `extraData` field: caller-provided qualifying data (the nonce).
    pub(crate) fn extra_data(&self) -> &[u8] {
        &self.extra_data
    }

    /// The attested `pcrDigest`: digest of the selected PCR values.
    pub(crate) fn pcr_digest(&self) -> &[u8] {
        &self.pcr_digest
    }

    /// The PCR registers this quote attests, ascending — the registers the
    /// quote's values belong to, in the order they arrive.
    pub(crate) fn selected_pcrs(&self) -> &[u32] {
        &self.selected_pcrs
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], AttestError> {
        let end = self.offset.checked_add(len).ok_or(AttestError::Truncated)?;
        let bytes = self.bytes.get(self.offset..end).ok_or(AttestError::Truncated)?;
        self.offset = end;
        Ok(bytes)
    }

    fn skip(&mut self, len: usize) -> Result<(), AttestError> {
        self.take(len).map(|_| ())
    }

    fn read_u8(&mut self) -> Result<u8, AttestError> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, AttestError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn read_u32(&mut self) -> Result<u32, AttestError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    /// Read a size-prefixed TPM2B buffer (16-bit big-endian size followed
    /// by that many bytes).
    fn read_tpm2b(&mut self) -> Result<&'a [u8], AttestError> {
        let size = self.read_u16()? as usize;
        self.take(size)
    }
}

/// Marshalling helpers shared by the tests of this module and of
/// `tpm_quote`, which needs quotes over selections other than the usual
/// PCRs 0-23.
#[cfg(test)]
pub(crate) mod test_support {
    use super::{TPM_ALG_SHA256, TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE};

    /// The SHA-256 bank identifier, for building selections over
    /// registers other than the usual 0-23.
    pub(crate) const SHA256_BANK: u16 = TPM_ALG_SHA256;

    /// A single SHA-256 TPMS_PCR_SELECTION of PCRs 0-23, what an Azure
    /// vTPM quote carries.
    pub(crate) const ALL_24_PCRS: &[(u16, &[u8])] = &[(TPM_ALG_SHA256, &[0xff, 0xff, 0xff])];

    /// A `pcrSelect` bitmap selecting the given registers: octet i bit j
    /// selects PCR i * 8 + j.
    pub(crate) fn pcr_bitmap(registers: &[u32]) -> Vec<u8> {
        let octets = registers.iter().map(|pcr| pcr / 8 + 1).max().unwrap_or(0) as usize;
        let mut bitmap = vec![0u8; octets];
        for pcr in registers {
            bitmap[(pcr / 8) as usize] |= 1 << (pcr % 8);
        }
        bitmap
    }

    /// Marshal a quote-type TPMS_ATTEST over the given PCR selections.
    pub(crate) fn build_attest(
        extra_data: &[u8],
        selections: &[(u16, &[u8])],
        pcr_digest: &[u8],
    ) -> Vec<u8> {
        build_attest_tagged(
            TPM_GENERATED_VALUE,
            TPM_ST_ATTEST_QUOTE,
            extra_data,
            selections,
            pcr_digest,
        )
    }

    /// As [`build_attest`], with the leading magic and structure tag under
    /// the caller's control.
    pub(crate) fn build_attest_tagged(
        magic: u32,
        attest_type: u16,
        extra_data: &[u8],
        selections: &[(u16, &[u8])],
        pcr_digest: &[u8],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&magic.to_be_bytes());
        bytes.extend_from_slice(&attest_type.to_be_bytes());
        // qualifiedSigner: TPM2B_NAME with a 4-byte name
        bytes.extend_from_slice(&4u16.to_be_bytes());
        bytes.extend_from_slice(&[0xaa; 4]);
        // extraData: TPM2B_DATA
        bytes.extend_from_slice(&(extra_data.len() as u16).to_be_bytes());
        bytes.extend_from_slice(extra_data);
        // clockInfo + firmwareVersion
        bytes.extend_from_slice(&[0; 8 + 4 + 4 + 1]);
        bytes.extend_from_slice(&[0; 8]);
        // attested.quote.pcrSelect: TPML_PCR_SELECTION
        bytes.extend_from_slice(&(selections.len() as u32).to_be_bytes());
        for (hash_algorithm, bitmap) in selections {
            // TPMS_PCR_SELECTION: hash algorithm, sizeofSelect, pcrSelect
            bytes.extend_from_slice(&hash_algorithm.to_be_bytes());
            bytes.push(bitmap.len() as u8);
            bytes.extend_from_slice(bitmap);
        }
        // pcrDigest: TPM2B_DIGEST
        bytes.extend_from_slice(&(pcr_digest.len() as u16).to_be_bytes());
        bytes.extend_from_slice(pcr_digest);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::{test_support::*, *};

    #[test]
    fn parses_quote_fields() {
        let extra_data = b"challenge";
        let pcr_digest = [0x42; 32];
        let bytes = build_attest(extra_data, ALL_24_PCRS, &pcr_digest);
        let attest = TpmsAttest::parse(&bytes).unwrap();
        assert_eq!(attest.extra_data(), extra_data);
        assert_eq!(attest.pcr_digest(), pcr_digest);
        assert_eq!(attest.selected_pcrs(), (0..24).collect::<Vec<u32>>().as_slice());
    }

    /// `pcrSelect` is a bitmap, LSB first within each octet, and the
    /// registers it names come out ascending: that order is what pairs a
    /// quote's values with their registers.
    #[test]
    fn reads_the_selected_registers_off_the_bitmap() {
        let registers = [0, 1, 4, 7, 8, 15, 16, 23];
        let bytes = build_attest(b"x", &[(TPM_ALG_SHA256, &pcr_bitmap(&registers))], &[0; 32]);
        let attest = TpmsAttest::parse(&bytes).unwrap();
        assert_eq!(attest.selected_pcrs(), registers);
    }

    #[test]
    fn rejects_bad_magic() {
        let bytes =
            build_attest_tagged(0xdeadbeef, TPM_ST_ATTEST_QUOTE, b"x", ALL_24_PCRS, &[0; 32]);
        assert!(matches!(TpmsAttest::parse(&bytes), Err(AttestError::Magic)));
    }

    #[test]
    fn rejects_non_quote_attestation() {
        // TPM_ST_ATTEST_CERTIFY
        let bytes = build_attest_tagged(TPM_GENERATED_VALUE, 0x8017, b"x", ALL_24_PCRS, &[0; 32]);
        assert!(matches!(TpmsAttest::parse(&bytes), Err(AttestError::NotAQuote)));
    }

    /// The values a quote carries are fixed-width SHA-256 digests in one
    /// list, so a second bank has nowhere to put its values.
    #[test]
    fn rejects_more_than_one_pcr_bank() {
        let sha1 = (0x0004u16, &[0xff, 0xff, 0xff][..]);
        let bytes = build_attest(b"x", &[ALL_24_PCRS[0], sha1], &[0; 32]);
        assert!(matches!(TpmsAttest::parse(&bytes), Err(AttestError::PcrSelectionBanks(2))));
    }

    #[test]
    fn rejects_a_bank_that_is_not_sha256() {
        let sha384 = (0x000cu16, &[0xff, 0xff, 0xff][..]);
        let bytes = build_attest(b"x", &[sha384], &[0; 32]);
        assert!(matches!(
            TpmsAttest::parse(&bytes),
            Err(AttestError::PcrSelectionAlgorithm(0x000c))
        ));
    }

    /// One attacker-supplied byte must not decide how many registers the
    /// expansion walks.
    #[test]
    fn rejects_an_oversized_pcr_select_bitmap() {
        let bytes = build_attest(b"x", &[(TPM_ALG_SHA256, &[0xff; 5][..])], &[0; 32]);
        assert!(matches!(TpmsAttest::parse(&bytes), Err(AttestError::PcrSelectionSize(5))));
    }

    /// A hostile selection count is refused before anything is read on the
    /// strength of it.
    #[test]
    fn rejects_implausible_pcr_selection_count() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
        bytes.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes()); // qualifiedSigner
        bytes.extend_from_slice(&0u16.to_be_bytes()); // extraData
        bytes.extend_from_slice(&[0; 8 + 4 + 4 + 1 + 8]); // clockInfo + firmwareVersion
        bytes.extend_from_slice(&u32::MAX.to_be_bytes()); // pcrSelect count
        assert!(matches!(TpmsAttest::parse(&bytes), Err(AttestError::PcrSelectionBanks(u32::MAX))));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = build_attest(b"x", ALL_24_PCRS, &[0; 32]);
        bytes.push(0);
        assert!(matches!(TpmsAttest::parse(&bytes), Err(AttestError::TrailingData)));
    }

    #[test]
    fn rejects_truncation_at_every_length() {
        let bytes = build_attest(b"x", ALL_24_PCRS, &[0; 32]);
        for len in 0..bytes.len() {
            assert!(
                matches!(TpmsAttest::parse(&bytes[..len]), Err(AttestError::Truncated)),
                "unexpected result at length {len}"
            );
        }
    }
}
