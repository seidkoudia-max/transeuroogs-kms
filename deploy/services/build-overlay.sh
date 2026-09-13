#!/usr/bin/env bash
# Small derivative of the exact installed image; no upstream dependency rebuild.
set -euo pipefail
[[ $(hostname) == lima-transeuroogs-tfs ]] || exit 1
root=/opt/transeuroogs
source="$root/service-release"
[[ -f "$source/release.json" && -f "$source/bin/kms" ]] || exit 1
python3 "$source/deploy/services/build.py"
