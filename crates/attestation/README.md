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
PCCS enabled and calling verification APIs is expected to happen from within a
Tokio runtime and might panic if called outside of one.

Note that although some of the verification API methods are synchronous (for
example `verify_attestation_sync`), still their functionality depends on
Tokio-backed background tasks such as PCCS pre-warm and cache refresh.

## Feature flags

### `azure-attester`

Enables generation of Microsoft Azure vTPM attestation evidence on Azure TDX
CVMs, through `tss-esapi`. Implies `azure-verifier`, giving full Azure
attestation support.

This feature requires [tpm2](https://tpm2-software.github.io) and `openssl` to
be installed. On Debian-based systems tpm2 is provided by
[`libtss2-dev`](https://packages.debian.org/trixie/libtss2-dev), and on nix
`tpm2-tss`. This dependency is currently not packaged for MacOS, meaning
currently it is not possible to compile or run with the `azure-attester`
feature on MacOS.

**Note:** Azure support is currently **not actively maintained** as we do not
have production CVMs deployed on Azure and so are unlikely to notice when this
implementation of Azure attestation generation or verification ceases to work.
Use at your own risk.

All Azure features are disabled by default. Without `azure-verifier`,
verification of azure attestations is not possible and azure attestations will
be rejected with an error.

### `azure-verifier`

Enables verification of Microsoft Azure vTPM attestation evidence.
Verification is pure computation over the evidence bytes; it requires
`openssl` but no TPM stack, and builds and runs on any platform, including
MacOS.

*** Note ***

Azure is known to use an outdated FMSPC `90C06F000000` which will cause
verifications to fail.  A workaround is provided which will allow this, but it
must be explicitly enabled via the `override_azure_outdated_tcb` flag on
`AttestationVerifier`.

### `mock`

Enables mock quote support via the local `mock-tdx` crate for tests and
development on non-TDX hardware.

Do not use in production. Disabled by default.

## Attestation Types

These are the attestation type names used in the measurements file.

- `none` - No attestation provided
- `gcp-tdx` - DCAP TDX on Google Cloud Platform
- `azure-tdx` - TDX on Azure, with vTPM attestation
- `dcap-tdx` - DCAP TDX (platform not specified)

Local attestation types can be automatically detected. This works by initially
attempting an Azure attestation, and if it fails attempting a DCAP attestation,
and if that fails assume no CVM attestation.  On detecting DCAP, a call to the
Google Cloud metadata API is used to detect whether we are on Google Cloud.

In the case of attestation types `dcap-tdx` and `gcp-tdx`, a
standard DCAP attestation is generated using the `configfs-tsm` linux filesystem
interface. This means that the binary must be run with access to
`/sys/kernel/config/tsm/report` which on many systems requires sudo.  If
configfs-tsm is unavailable, quote generation via vSOCK to the QGS will be
attempted.

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
- `dcap_image_hashes` - an alternative to `measurements` that pins the hashes
  of the boot components (UKI, kernel, initrd, cmdline, GPT disk GUID) rather
  than raw register values. The verifier reconstructs the expected RTMRs at
  check time from these hashes and platform-fetched firmware. See
  [Portable measurement policies](#portable-measurement-policies) below.

A record may set either `measurements` or `dcap_image_hashes`, not both.

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
specified with neither `measurements` nor `dcap_image_hashes`, *any*
measurements will be accepted for this attestation type. The measurements can
still be checked up-stream by the source client or target service using header
injection for example. But it is then up to external programs to reject
unacceptable measurements.

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

### Portable measurement policies

The `measurements` format above specifies register values, so any change
to platform-injected values (firmware, RAM size, disk count, ACPI tables)
changes the expected register values even when the OS image is unchanged.

The `dcap_image_hashes` alternative allows you to specify the OS image's 
boot-component hashes instead, and the verifier reconstructs the expected
register values from those hashes plus platform metadata available at
attestation verification time. The same policy record then matches the same OS
images across platform variants.

This can be done with the `attest measure` CLI from
[Easy-TEE/attest](https://github.com/Easy-TEE/attest) which outputs five
hex-encoded SHA-384 values and, for images using a recent systemd EFI stub, one
additional optional value:

- `uki_authenticode` - authenticode hash of the UKI (unified kernel image)
- `kernel_authenticode` - authenticode hash of the kernel binary
- `cmdline_hash` - hash of the kernel command line
- `initrd_hash` - hash of the initramfs
- `gpt_disk_guid_hash` - hash derived from GPT partition GUIDs
- `pe_sections` - optional accumulated hash of the UKI PE sections measured by
  recent systemd EFI stubs

Example:

```JSON
[
  {
    "measurement_id": "flashbox-l1-v1.0.0",
    "attestation_type": "dcap-tdx",
    "dcap_image_hashes": {
      "uki_authenticode": "fcaceb6d87694746ba2d93a87ef4209f2a7629b7f400097b93241e80b9ec3e1e80f9a4cd8028e6a83f297ea5de8d9abc",
      "kernel_authenticode": "b6c5133268aa8b440509f3d53ee855a5cd3aeb6441eb109a9f27f14c43bce3e2383856df4af876501ceeb4c9a3b15f0c",
      "cmdline_hash": "e03b89abf354a38976537b7a9138fd312e4cbf73b61eebc44086491701b1d167b9f6cb97a922325866c93e0834723d87",
      "initrd_hash": "a5b3d4742045e7d08aa19953c35098e784826b01a84f60568fa69f1a848dafd96ec98b8df616d6142779c9b97318166b",
      "gpt_disk_guid_hash": "180bac1af9c35cc15e909623c005289539b4da2840d9c9b658fd4968ea4f03e0159402d03da1afc9035e0db30804e282"
    }
  }
]
```

#### Supported attestation types for portable measurements

Portable policies work with the `"dcap-tdx"` and `"gcp-tdx"` attestation types.
`"dcap-tdx"` accepts DCAP evidence from any platform, including GCP and
bare-metal TDX, while `"gcp-tdx"` restricts the record to GCP. For bare-metal
DCAP TDX, the verifier reconstructs and checks the image-dependent RTMR1 and
RTMR2 registers. For GCP, it additionally fetches the platform firmware blob
from Google's metadata service (keyed by MRTD) and reconstructs MRTD and RTMR0.

The JSON object emitted directly by `attest measure portable` is also accepted
as a measurement policy. Its optional `azure` PCR values and its `dcap` image
hashes are converted into an Azure TDX record and a generic DCAP record
respectively. It can be supplied on its own or as an element of a policy array,
including an array mixed with records in the policy format described above:

```JSON
{
  "kind": "portable",
  "azure": {
    "pcr4": "<64 hex characters>",
    "pcr9": "<64 hex characters>",
    "pcr11": "<64 hex characters>"
  },
  "dcap": {
    "uki_authenticode": "<96 hex characters>",
    "kernel_authenticode": "<96 hex characters>",
    "cmdline_hash": "<96 hex characters>",
    "initrd_hash": "<96 hex characters>",
    "gpt_disk_guid_hash": "<96 hex characters>"
  }
}
```

The non-portable `"kind": "azure"` output from `attest measure` is accepted in
the same places and pins PCRs 4, 9, and 11. The `"kind": "dcap"` output is
rejected because it only pins RTMR1 and RTMR2, leaving the other DCAP registers
unconstrained. Use the portable output or an explicit measurement policy
instead.
