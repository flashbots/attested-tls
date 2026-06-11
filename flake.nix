{
  description = "Nitro attestation benchmark image and vsock output helper";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" ];

      forAllSystems = f:
        builtins.listToAttrs (map
          (system: {
            name = system;
            value = f system;
          })
          systems);
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
          };

          src = pkgs.runCommandLocal "nitro-attestation-bench-src" { } ''
            mkdir -p "$out/crates"
            cp -R ${./crates/attestation} "$out/crates/attestation"
            cp -R ${./crates/pccs} "$out/crates/pccs"
            cp -R ${./crates/mock-tdx} "$out/crates/mock-tdx"
            cp ${./Cargo.lock} "$out/Cargo.lock"
            cat > "$out/Cargo.toml" <<'EOF'
            [workspace]
            resolver = "3"

            members = [
              "crates/attestation",
              "crates/pccs",
              "crates/mock-tdx",
            ]

            [workspace.lints.rust]
            unreachable_pub = "deny"

            [workspace.lints.clippy]
            manual_let_else = "warn"
            match_same_arms = "warn"
            uninlined_format_args = "warn"
            unused_async = "warn"

            [workspace.dependencies]
            attestation = { path = "crates/attestation" }
            mock-tdx = { path = "crates/mock-tdx" }
            rustls = { version = "0.23.37", default-features = false, features = ["brotli"] }
            tokio = { version = "1.50.0", features = ["default"] }
            tokio-rustls = { version = "0.26.4", default-features = false }
            dcap-qvl = { git = "https://github.com/Phala-Network/dcap-qvl.git", rev = "f1dcc65371e941a7b83e3234833d23a1fb232ab1" }
            pccs = { path = "crates/pccs" }
            EOF
          '';

          lockFile = pkgs.runCommandLocal "nitro-attestation-bench-lock" { nativeBuildInputs = [ pkgs.python3 ]; } ''
            python3 - "$out" ${./Cargo.lock} <<'PY'
            import sys

            dst, src = sys.argv[1], sys.argv[2]

            def should_drop(section: list[str]) -> bool:
                text = "".join(section)
                return (
                    'name = "dcap-qvl"' in text
                    and 'source = "registry+https://github.com/rust-lang/crates.io-index"' in text
                )

            section = []
            with open(src, "r", encoding="utf-8") as input_file, open(dst, "w", encoding="utf-8") as output_file:
                for line in input_file:
                    if line.strip() == "[[package]]":
                        if section and not should_drop(section):
                            output_file.writelines(section)
                        section = [line]
                    else:
                        section.append(line)

                if section and not should_drop(section):
                    output_file.writelines(section)
            PY
          '';

          attestationBench = pkgs.rustPlatform.buildRustPackage {
            pname = "nitro-attestation-bench";
            version = "0.0.1";
            inherit src;
            cargoHash = pkgs.lib.fakeHash;

            cargoLock = {
              lockFile = lockFile;
              outputHashes = {
                "dcap-qvl-0.3.12" = "sha256-rLTp5wIhXRAcBtJb7lfd1TAg7yPRnwa0cBa1YT4LwKU=";
                "ra-tls-0.5.11" = "sha256-q6Vrlx4N7Ce2EQTQH+0HCSEzFZmY8PzDHxrO8L3kMsQ=";
                "tdx-attest-0.5.8" = "sha256-KEauakj53LrhKTc0yYp5SM8ec0cFNm4YVuHCJYiPQjw=";
                "tdx-attest-0.5.11" = "sha256-q6Vrlx4N7Ce2EQTQH+0HCSEzFZmY8PzDHxrO8L3kMsQ=";
              };
            };

            cargoBuildFlags = [
              "-p"
              "attestation"
              "--bin"
              "nitro_attestation_bench"
            ];

            doCheck = false;

            nativeBuildInputs = with pkgs; [
              pkg-config
            ];

            buildInputs = with pkgs; [
              openssl
              tpm2-tss
            ];
          };

          benchRunner = pkgs.writeTextFile {
            name = "nitro-bench-runner";
            executable = true;
            destination = "/bin/nitro-bench-runner";
            text = ''
              #!${pkgs.python3}/bin/python3
              import os
              import socket
              import subprocess
              import sys
              import time

              bench = "${attestationBench}/bin/nitro_attestation_bench"
              count = os.environ.get("BENCH_COUNT", "8")
              rounds = os.environ.get("BENCH_ROUNDS", "1")
              cid = int(os.environ.get("VSOCK_CID", "3"))
              port = int(os.environ.get("VSOCK_PORT", "5005"))
              retries = int(os.environ.get("VSOCK_RETRIES", "10"))
              retry_delay = float(os.environ.get("VSOCK_RETRY_DELAY_SECS", "1"))

              proc = subprocess.run(
                  [bench, count, rounds],
                  capture_output=True,
              )

              payload = (proc.stdout or b"") + (proc.stderr or b"")
              sys.stdout.buffer.write(payload)
              sys.stdout.buffer.flush()

              last_error = None
              for attempt in range(1, retries + 1):
                  try:
                      sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
                      sock.connect((cid, port))
                      sock.sendall(payload)
                      sock.shutdown(socket.SHUT_WR)
                      sock.close()
                      last_error = None
                      break
                  except OSError as err:
                      last_error = err
                      if attempt < retries:
                          time.sleep(retry_delay)

              if last_error is not None:
                  print(f"vsock send failed: {last_error}", file=sys.stderr)

              raise SystemExit(proc.returncode)
            '';
          };

          vsockListener = pkgs.writeTextFile {
            name = "nitro-vsock-listener";
            executable = true;
            destination = "/bin/nitro-vsock-listener";
            text = ''
              #!${pkgs.python3}/bin/python3
              import socket
              import sys

              port = int(sys.argv[1]) if len(sys.argv) > 1 else 5005
              cid_any = getattr(socket, "VMADDR_CID_ANY", 0xFFFFFFFF)

              listener = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
              listener.bind((cid_any, port))
              listener.listen(1)

              print(f"listening on vsock port {port}", file=sys.stderr)
              conn, _ = listener.accept()
              with conn:
                  while True:
                      chunk = conn.recv(65536)
                      if not chunk:
                          break
                      sys.stdout.buffer.write(chunk)
                      sys.stdout.buffer.flush()
            '';
          };

          benchImage = pkgs.dockerTools.buildImage {
            name = "nitro-attestation-bench";
            tag = "latest";
            copyToRoot = pkgs.buildEnv {
              name = "nitro-attestation-bench-root";
              paths = [
                attestationBench
                benchRunner
                pkgs.python3
              ];
              pathsToLink = [ "/bin" ];
            };

            config = {
              Cmd = [ "/bin/nitro-bench-runner" ];
              WorkingDir = "/tmp";
            };
          };
        in
        {
          inherit attestationBench benchImage vsockListener;

          default = benchImage;
          nitro-attestation-bench = attestationBench;
          nitro-attestation-bench-image = benchImage;
          nitro-vsock-listener = vsockListener;
        });

      apps = forAllSystems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
          };
          listener = self.packages.${system}.nitro-vsock-listener;
        in
        {
          listen = {
            type = "app";
            program = "${listener}/bin/nitro-vsock-listener";
          };
        });

      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
          };
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              openssl
              pkg-config
              tpm2-tss
            ];
          };
        });

      formatter = forAllSystems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
          };
        in
        pkgs.nixpkgs-fmt);
    };
}
