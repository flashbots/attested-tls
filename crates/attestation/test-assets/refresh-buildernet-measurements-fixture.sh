#!/bin/sh

set -eu

response=$(curl -fsSL https://measurements.builder.flashbots.net)
measurements=$(printf '%s\n' "$response" |
  jq '[.[] | select(.attestation_type == "dcap-tdx" or .attestation_type == "gcp-tdx")]')
printf '%s\n' "$measurements" > "$(dirname "$0")/buildernet_measurements.json"
