#!/bin/sh
# Runnable against any staged package: sh check.sh ROOT SERVICE_RELATIVE_PATH
set -eu
test "$#" -eq 2
test -x "$1/usr/bin/cat4igp-client"
test -f "$1/$2"
test "$(stat -c %a "$1/etc/cat4igp/client.toml")" = 600
test "$(stat -c %a "$1/var/lib/cat4igp-client")" = 700