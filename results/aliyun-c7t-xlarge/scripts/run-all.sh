#!/usr/bin/env bash
set -euo pipefail
if (( $# != 5 || EUID != 0 )); then
    echo 'usage: sudo bash run-all.sh PACKAGE BUILD LIVE PROBE_BUILD BATCH' >&2
    exit 2
fi
s=$(cd "$(dirname "$0")" && pwd)
package=$(realpath "$1")
build=$(realpath "$2")
live=$(realpath "$3")
probe=$(realpath "$4")
mkdir -p -- "$5"
batch=$(realpath "$5")
exec 9>"$batch/.run-all.lock"
flock -n 9

stage() {
    local dir=$1
    shift
    if [[ -f "$dir/.complete" ]]; then return; fi
    if [[ -e "$dir" ]]; then mv -T -- "$dir" "$(mktemp -d "$dir.partial.XXXXXXXX")"; fi
    "$@"
    touch "$dir/.complete"
}

stage "$batch/preflight" bash "$s/check-host.sh" "$batch/preflight" --build "$build"
stage "$batch/preflight-probe" bash "$s/check-host.sh" "$batch/preflight-probe" --build "$probe"
python3 "$s/bench.py" all --package "$package" --build "$build" --live "$live" --out "$batch"
stage "$batch/e7" python3 "$s/memory-bench.py" --package "$package" --build "$probe" --out "$batch/e7"
stage "$batch/e8" python3 "$s/replay-bench.py" --package "$package" --build "$build" --out "$batch/e8"
stage "$batch/summary" python3 "$s/summarize.py" "$batch"
cd "$batch"
find . -type f ! -name SHA256SUMS ! -name '.sums.tmp' ! -name '.run-all.lock' -print0 |
    LC_ALL=C sort -z | xargs -0 -r sha256sum > .sums.tmp
mv .sums.tmp SHA256SUMS
sha256sum --quiet -c SHA256SUMS
