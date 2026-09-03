# Trusted OVMF firmware

Every `.fd` file in this directory is a verifier trust root for self-hosted TDX
portable measurement policies. Its filename identifies it for build errors and
provenance documentation.

At build time, `build.rs` parses each complete firmware blob and checks its
computed MRTD for uniqueness. It emits a compact description containing only
MRTD, the configuration firmware volume hash, and the HOB template. Production
binaries embed that generated description, not the complete blob.

## Ubuntu OVMF.inteltdx.fd 2025.02-8ubuntu3.2

- Asset: `OVMF.inteltdx.2025.02-8ubuntu3.2.fd`
- Ubuntu package: `ovmf-inteltdx` version `2025.02-8ubuntu3.2`
- Package URL:
  <https://archive.ubuntu.com/ubuntu/pool/main/e/edk2/ovmf-inteltdx_2025.02-8ubuntu3.2_all.deb>
- Package SHA-256:
  `5667e225cc5dedc7d14e9e572e19ed6c138179d79d7a6e9e3630f4beeb67a71b`
- Firmware path in package: `/usr/share/ovmf/OVMF.inteltdx.fd`
- Firmware SHA-256:
  `c4cb73edc27a378abbb55add5f3f326a76ce59fc046fe390fb50dac55b70a6da`
- MRTD:
  `ea216f26cc4ef0571dce29f0111c6dadfddcd86d032dbf990258456fe4d27799e8b72777fc05f532b1ebd597289d924d`
- Package copyright and license information: [`COPYRIGHT`](COPYRIGHT)

## Fedora OVMF.inteltdx.fd 20260213-6.fc44

- Asset: `edk2-ovmf-20260213-6.fc44.noarch.OVMF.inteltdx.fd`
- Fedora package: `edk2-ovmf` version `20260213-6.fc44`
- Package URL:
  <https://kojipkgs.fedoraproject.org/packages/edk2/20260213/6.fc44/noarch/edk2-ovmf-20260213-6.fc44.noarch.rpm>
- Package SHA-256:
  `0ab52ddd63208ca18073fb6357a3433d972f889d3f4d8da16049385949aa34e6`
- Firmware path in package: `/usr/share/edk2/ovmf/OVMF.inteltdx.fd`
- Firmware SHA-256:
  `5f89870e13794d708e50ede0f7112c44e361773c751cb47c6819ece56552306a`
- MRTD:
  `1b4be140773d8dad689732c1997ef06d89f435ea5b4c9de4115077ccd95ddfee94ac1a5bfd3e119b5b265e5b7a7d1617`
- Package license expression: Apache-2.0 AND (BSD-2-Clause OR
  GPL-2.0-or-later) AND BSD-2-Clause-Patent AND BSD-4-Clause AND ISC AND
  LicenseRef-Fedora-Public-Domain

To add another accepted firmware, place the exact `.fd` provenance asset in
this directory and document its source and checksums below. The build discovers
it automatically and fails if the blob cannot be parsed or its computed MRTD
is already present.
