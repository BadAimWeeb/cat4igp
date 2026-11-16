#!/bin/sh
set -eu
umask 077

# Secrets stay on the mounted volume rather than in container configuration.
if [ -n "${CONTROL_PRIVATE_NETWORK_KEY_FILE:-}" ]; then
    if [ -n "${CONTROL_PRIVATE_NETWORK_KEY:-}" ]; then
        echo 'Set only one of CONTROL_PRIVATE_NETWORK_KEY and CONTROL_PRIVATE_NETWORK_KEY_FILE' >&2
        exit 1
    fi
    CONTROL_PRIVATE_NETWORK_KEY=$(cat "$CONTROL_PRIVATE_NETWORK_KEY_FILE")
    export CONTROL_PRIVATE_NETWORK_KEY
fi

exec /usr/bin/cat4igp-server "$@"
