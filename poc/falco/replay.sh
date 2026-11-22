#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
package=$(realpath "${1:?usage: bash replay.sh FALCO_PACKAGE BUILD_DIR NEW_RUN_DIRECTORY}")
build=$(realpath "${2:?missing build directory}")
mkdir "${3:?missing run directory}"
cd "$3"
export TZ=UTC
export FALCO_HOSTNAME=falco-sgx-fixture
cp "$here/reference.yaml" "$package/etc/falco/falco_rules.yaml" .
ln -s "$package/usr/share/falco/plugins/libcontainer.so" .
python3 "$here/fixture.py"
sha256sum falco_rules.yaml reference.yaml reference.scap expected.json > inputs.sha256
"$package/usr/bin/falco" --version > versions.txt
"$package/usr/bin/falco" -c reference.yaml -L > native-rules.json 2>native-rules.log
"$package/usr/bin/falco" -c reference.yaml > native-alerts.jsonl 2>native.log
"$package/usr/bin/falco" -c reference.yaml > native-repeat.jsonl 2>native-repeat.log
cmp native-alerts.jsonl native-repeat.jsonl
"$build/bin/falco-sgx" "$build/falco-enclave.signed" reference.yaml reference.scap falco_rules.yaml \
    >sgx-alerts.jsonl 2>sgx.log
python3 "$here/compare.py" . | tee comparison.json
