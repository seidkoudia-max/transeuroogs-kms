#!/bin/sh
set -eu
count=64
if [ -f /state/private/state.enc ]; then
    count=0
fi
exec /bin/kms --listen=0.0.0.0:8443 --config=/config/kms.json \
    --pki-dir=/run/kms-pki --synthetic-keys="$count" --synthetic-ttl=24h
