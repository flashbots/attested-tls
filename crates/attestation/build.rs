//! Reads pinned trusted OVMF firmware to get [DcapFirmware] from them
//! without embedding the whole firmware blob in the binary.
use std::{collections::HashSet, env, fs, path::PathBuf};

use attest_measure::dcap::DcapFirmware;

const FIRMWARE_DIR: &str = "assets/ovmf";
const GENERATED_FIRMWARE: &str = "trusted-firmware.json";

fn main() {
    // Gate for the Azure evidence generation code. It takes a cfg rather
    // than the `azure-attester` feature alone because it only compiles
    // where az-tdx-vtpm and tss-esapi resolve, so this condition has to
    // stay identical to their target table in Cargo.toml. The
    // CARGO_CFG_TARGET_* vars describe the target rather than the build
    // host, which keeps the two in agreement when cross-compiling. The
    // check-cfg goes outside the branch: the name is expected on every
    // target, including those where the code it gates is switched off.
    println!("cargo::rustc-check-cfg=cfg(azure_attester_x86_64_linux)");
    if env::var_os("CARGO_FEATURE_AZURE_ATTESTER").is_some() &&
        env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") &&
        env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64")
    {
        println!("cargo::rustc-cfg=azure_attester_x86_64_linux");
    }

    println!("cargo:rerun-if-changed={FIRMWARE_DIR}");

    let mut paths = fs::read_dir(FIRMWARE_DIR)
        .expect("failed to read trusted firmware directory")
        .map(|entry| entry.expect("failed to read trusted firmware directory entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "fd"))
        .collect::<Vec<_>>();
    paths.sort();
    assert!(!paths.is_empty(), "trusted firmware directory contains no .fd files");

    let mut seen_mrtds = HashSet::new();
    let firmware = paths
        .iter()
        .map(|path| {
            let name = path
                .file_name()
                .expect("trusted firmware path must have a filename")
                .to_string_lossy();
            println!("cargo:rerun-if-changed={}", path.display());

            let blob = fs::read(path)
                .unwrap_or_else(|err| panic!("failed to read trusted firmware {name}: {err}"));
            let firmware = DcapFirmware::from_blob(&blob, false)
                .unwrap_or_else(|err| panic!("failed to parse trusted firmware {name}: {err}"));
            assert!(seen_mrtds.insert(firmware.mrtd), "duplicate trusted MRTD for {name}");
            firmware
        })
        .collect::<Vec<_>>();

    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"))
        .join(GENERATED_FIRMWARE);
    fs::write(output, serde_json::to_vec(&firmware).expect("failed to serialize firmware"))
        .expect("failed to write generated trusted firmware");
}
