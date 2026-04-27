# attestation

Attestation generation and verification for confidential VMs, plus measurement
policy handling.

This crate provides:

- Attestation type detection (`none`, `dcap-tdx`, `gcp-tdx`, and `azure-tdx`
  when enabled)
- Attestation generation and verification for DCAP and (optionally) Azure
- Parsing and evaluation of measurement policies

## Runtime Requirements

Verification uses the [`pccs`](../pccs) crate for collateral caching and
background refresh. As a result, constructing an `AttestationVerifier` with
PCCS enabled and calling verification APIs, including
`verify_attestation_sync()`, is expected to happen from within a Tokio runtime,
and will panic if called outside of one.

Note that the synchronous verification API is synchronous in its return type,
but it still relies on Tokio-backed background tasks for PCCS pre-warm
and cache refresh.

## Feature flags

### `azure`

Enables Microsoft Azure vTPM attestation support (generation and verification),
through `tss-esapi`.

This feature requires [tpm2](https://tpm2-software.github.io) and `openssl` to
be installed. On Debian-based systems tpm2 is provided by
[`libtss2-dev`](https://packages.debian.org/trixie/libtss2-dev), and on nix
`tpm2-tss`. This dependency is currently not packaged for MacOS, meaning
currently it is not possible to compile or run with the `azure` feature on
MacOS.

This feature is disabled by default. Note that without this feature,
verification of azure attestations is not possible and azure attestations will
be rejected with an error.

*** Note ***

Azure is known to use an outdated FMSPC `90C06F000000` which will cause
verifications to fail.  A workaround is provided which will allow this, but it
must be explicitly enabled via the `override_azure_outdated_tcb` flag on
`AttestationVerifier`.

### `mock`

Enables mock quote support via `tdx-quote` for tests and development on non-TDX
hardware. Do not use in production.  Disabled by default.

## Attestation Types

These are the attestation type names used in the measurements file.

- `none` - No attestation provided
- `gcp-tdx` - DCAP TDX on Google Cloud Platform
- `azure-tdx` - TDX on Azure, with vTPM attestation
- `qemu-tdx` - TDX on Qemu (no cloud platform)
- `dcap-tdx` - DCAP TDX (platform not specified)

Local attestation types can be automatically detected. This works by initially
attempting an Azure attestation, and if it fails attempting a DCAP attestation,
and if that fails assume no CVM attestation.  On detecting DCAP, a call to the
Google Cloud metadata API is used to detect whether we are on Google Cloud.

In the case of attestation types `dcap-tdx`, `gcp-tdx`, and `qemu-tdx`, a
standard DCAP attestation is generated using the `configfs-tsm` linux filesystem
interface. This means that the binary must be run with access to
`/sys/kernel/config/tsm/report` which on many systems requires sudo.

Alternatively, an external 'attestation provider service' URL can be provided
which outsources the attestation generation to another process.

When verifying DCAP attestations, the Intel PCS is used to retrieve collateral
unless a PCCS URL is provided via a command line argument. If outdated TCB is
used, the quote will fail to verify.  For special cases where outdated TCB
should be allowed, a custom override function can be passed when verifying which
may modify collateral before it is validated against the TCB.

## Measurements File

Accepted measurements for the remote party can be specified in a JSON file
containing an array of objects, each of which specifies an accepted attestation
type and set of measurements.

This aims to match the formatting used by `cvm-reverse-proxy`.

These objects have the following fields:

- `measurement_id` - a name used to describe the entry. For example the name and
  version of the CVM OS image that these measurements correspond to.
- `attestation_type` - a string containing one of the attestation types
  (confidential computing platforms) described below.
- `measurements` - an object with fields referring to the five measurement
  registers. Field names are the same as for the measurement headers (see
  below).

Each measurement register entry supports two mutually exclusive fields:

- `expected_any` - **(recommended)** an array of hex-encoded measurement values.
  The attestation is accepted if the actual measurement matches **any** value in
  the list (OR semantics).
- `expected` - **(deprecated)** a single hex-encoded measurement value. Retained
  for backwards compatibility but `expected_any` should be preferred.

Example using `expected_any` (recommended):

```JSON
[
  {
    "measurement_id": "dcap-tdx-example",
    "attestation_type": "dcap-tdx",
    "measurements": {
      "mrtd": {
        "expected_any": [
          "47a1cc074b914df8596bad0ed13d50d561ad1effc7f7cc530ab86da7ea49ffc03e57e7da829f8cba9c629c3970505323"
        ]
      },
      "rtmr0": {
        "expected_any": [
          "da6e07866635cb34a9ffcdc26ec6622f289e625c42c39b320f29cdf1dc84390b4f89dd0b073be52ac38ca7b0a0f375bb"
        ]
      },
      "rtmr1": {
        "expected_any": [
          "a7157e7c5f932e9babac9209d4527ec9ed837b8e335a931517677fa746db51ee56062e3324e266e3f39ec26a516f4f71"
        ]
      },
      "rtmr2": {
        "expected_any": [
          "e63560e50830e22fbc9b06cdce8afe784bf111e4251256cf104050f1347cd4ad9f30da408475066575145da0b098a124"
        ]
      },
      "rtmr3": {
        "expected_any": [
          "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ]
      }
    }
  }
]
```

The `expected_any` field is useful when multiple measurement values should be
accepted for a register (e.g., for different versions of the firmware):

```JSON
{
  "mrtd": {
    "expected_any": [
      "47a1cc074b914df8596bad0ed13d50d561ad1effc7f7cc530ab86da7ea49ffc03e57e7da829f8cba9c629c3970505323",
      "abc123def456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    ]
  }
}
```

<details> <summary>Legacy format using deprecated <code>expected</code>
field</summary>

The `expected` field is deprecated but still supported for backwards
compatibility:

```JSON
[
  {
    "measurement_id": "dcap-tdx-example",
    "attestation_type": "dcap-tdx",
    "measurements": {
      "mrtd": {
        "expected": "47a1cc074b914df8596bad0ed13d50d561ad1effc7f7cc530ab86da7ea49ffc03e57e7da829f8cba9c629c3970505323"
      }
    }
  }
]
```

</details>

The only mandatory field is `attestation_type`. If an attestation type is
specified, but no measurements, *any* measurements will be accepted for this
attestation type. The measurements can still be checked up-stream by the source
client or target service using header injection described below. But it is then
up to these external programs to reject unacceptable measurements.

### Measurement field names

For Azure vTMP attestations, the preferred field names are PCR register
indexes prefixed with `pcr` or `PCR`. For example the following specifies PCRs
4 and 9:

```JSON
{
    "measurement_id": "cvm-image-azure-tdx.rootfs-20241107200854.wic.vhd",
    "attestation_type": "azure-tdx",
    "measurements": {
        "pcr4": {
            "expected_any": ["1b8cd655f5ebdf50bedabfb5db6b896a0a7c56de54f318103a2de1e7cea57b6b"]
        },
        "pcr9": {
            "expected_any": ["992465f922102234c196f596fdaba86ea16eaa4c264dc425ec26bc2d1c364472"]
        }
    }
}
```

Legacy numeric field names are still supported for backwards compatibility:

- `"4"` - PCR 4
- `"9"` - PCR 9
- `"11"` - PCR 11
- and so on for valid PCR indices `0` through `23`

All other attestation types are DCAP based. In measurement-policy JSON, the
preferred field names are the register names and they are matched
case-insensitively:

- `mrtd` - MRTD
- `rtmr0` - RTMR0
- `rtmr1` - RTMR1
- `rtmr2` - RTMR2
- `rtmr3` - RTMR3

Legacy numeric field names are still supported for backwards compatibility:

- "0" - MRTD
- "1" - RTMR0
- "2" - RTMR1
- "3" - RTMR2
- "4" - RTMR3
