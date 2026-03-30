#!/bin/sh

set -eu

curl -fsSL https://measurements.builder.flashbots.net \
  > "$(dirname "$0")/buildernet_measurements.json"
