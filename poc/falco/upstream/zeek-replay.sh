#!/usr/bin/env bash
set -euo pipefail

if (( $# != 2 )); then
    echo "usage: bash zeek-replay.sh CAPTURE NEW_LOG_DIRECTORY" >&2
    exit 2
fi
capture=$(realpath -e -- "$1")
[[ -f $capture ]] || { echo "expected a capture file: $capture" >&2; exit 1; }
mkdir -- "$2"
logs=$(realpath -e -- "$2")
image=zeek/zeek@sha256:a25a3c38497c5492dd4391c09595f0842b46a608fad4180df18549c754797f23
exec docker run --rm --network none --platform linux/amd64 --user "$(id -u):$(id -g)" \
    -v "$capture:/input.pcap:ro" -v "$logs:/logs" -w /logs \
    --entrypoint /usr/local/zeek/bin/zeek "$image" -r /input.pcap policy/misc/scan LogAscii::use_json=T
