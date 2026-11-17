#!/bin/sh

set -eu

curl -fsSL https://measurements.builder.flashbots.net |
  jq '[.[] | select(.attestation_type == "dcap-tdx" or .attestation_type == "gcp-tdx")]' \
  > "$(dirname "$0")/buildernet_measurements.json"
