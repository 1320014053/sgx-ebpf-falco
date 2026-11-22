#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
package=$(realpath "${1:?usage: check-container.sh FALCO_PACKAGE BUILD_DIR LIVE_BUILD_DIR NEW_RUN_DIRECTORY}")
build=$(realpath "${2:?missing build directory}")
live=$(realpath "${3:?missing live build directory}")
mkdir "${4:?missing run directory}"
cd "$(realpath "$4")"
export TZ=UTC FALCO_HOSTNAME=falco-sgx-container
cp "$package/etc/falco/falco_rules.yaml" .
ln -s "$package/usr/share/falco/plugins/libcontainer.so" .
sed -e 's|containerd: {enabled: false}|containerd: {enabled: true, sockets: [/run/containerd/containerd.sock]}|' \
    -e 's|extra_fields: \[evt.num, evt.type, thread.tid\]|extra_fields: [evt.num, evt.type, thread.tid, container.id, container.full_id, container.type, container.image.repository, container.privileged]|' \
    "$here/reference.yaml" >reference.yaml

mkdir -p rootfs/bin rootfs/tmp
cp /bin/busybox rootfs/bin/
for command in sh sleep cp; do ln -s busybox "rootfs/bin/$command"; done
cc -O2 -static -Wall -Wextra "$here/live/container-workload.c" -o rootfs/bin/workload
printf 'int main(void) { return 0; }\n' | cc -O2 -static -x c - -o rootfs/bin/noop
for command in nc debugfs; do ln rootfs/bin/noop "rootfs/bin/$command"; done
tar --numeric-owner --owner=0 --group=0 -C rootfs -cf layer.tar .
python3 - <<'PY'
import hashlib
import json
from pathlib import Path

layer = hashlib.sha256(Path("layer.tar").read_bytes()).hexdigest()
config = {
    "architecture": "amd64", "os": "linux", "config": {"Env": ["PATH=/bin"]},
    "rootfs": {"type": "layers", "diff_ids": ["sha256:" + layer]},
}
Path("config.json").write_text(json.dumps(config))
Path("manifest.json").write_text(json.dumps([{
    "Config": "config.json", "RepoTags": ["localhost/falco-poc/fixture:1"], "Layers": ["layer.tar"]
}]))
PY
tar -cf fixture-image.tar config.json manifest.json layer.tar
sudo -n ctr --namespace falco-poc images import fixture-image.tar >image-import.log

cat >workload.sh <<'SH'
set -euo pipefail
image=localhost/falco-poc/fixture:1
regular=$(printf '%s' "$PWD/regular" | sha256sum | cut -d' ' -f1)
privileged=$(printf '%s' "$PWD/privileged" | sha256sum | cut -d' ' -f1)
script -qefc "ctr --namespace falco-poc run --rm --tty $image $regular /bin/sh -ec 'sleep 2; cp /bin/noop /tmp/new-binary; /tmp/new-binary; /bin/workload'" /dev/null >regular.log
ctr --namespace falco-poc run --rm --privileged "$image" "$privileged" /bin/sh -ec \
    'sleep 2; /bin/workload privileged' >privileged.log
SH

sudo -n env TZ="$TZ" FALCO_HOSTNAME="$FALCO_HOSTNAME" timeout 75 \
    "$live/falco-live" "$build/falco-enclave.signed" reference.yaml 4096 reference.scap falco_rules.yaml \
    -- bash "$PWD/workload.sh" >sgx-alerts.jsonl 2>sgx.log

sha256sum falco_rules.yaml reference.yaml reference.scap >inputs.sha256
"$package/usr/bin/falco" --version >versions.txt
"$package/usr/bin/falco" -c reference.yaml -L >native-rules.json 2>native-rules.log
"$package/usr/bin/falco" -c reference.yaml >native-alerts.jsonl 2>native.log
python3 "$here/compare.py" . --captured | tee comparison.json

mkdir replayed
ln -s ../native-alerts.jsonl ../native-rules.json ../versions.txt replayed/
"$build/bin/falco-sgx" "$build/falco-enclave.signed" reference.yaml reference.scap falco_rules.yaml \
    >replayed/sgx-alerts.jsonl 2>replayed/sgx.log
python3 "$here/compare.py" replayed --captured | tee replayed/comparison.json

python3 - <<'PY' | tee container-check.json
import hashlib
import json
from collections import Counter
from pathlib import Path

expected = {
    "Terminal shell in container", "Netcat Remote Code Execution in Container",
    "Packet socket created in container", "Redirect STDOUT/STDIN to Network Connection in Container",
    "Linux Kernel Module Injection Detected", "Debugfs Launched in Privileged Container",
    "Detect release_agent File Container Escapes", "Drop and execute new binary in container",
}
alerts = [json.loads(line) for line in Path("sgx-alerts.jsonl").read_text().splitlines()]
rules = Counter(row["rule"] for row in alerts)
missing = sorted(expected - rules.keys())
metadata = {}
for row in alerts:
    fields = row["output_fields"]
    if fields.get("container.full_id") and fields.get("container.type") == "containerd":
        metadata[fields["container.full_id"]] = {
            key: fields.get(key) for key in ("container.type", "container.image.repository", "container.privileged")
        }
rows = [json.loads(line) for line in Path("sgx.log").read_text().splitlines() if line.startswith("{")]
driver = next(row for row in rows if row.get("mode") == "modern_ebpf")
enclave = next(row for row in rows if row.get("mode") == "live")
assert driver["driver_drops"] == enclave["format_rejected"] == 0
assert driver["driver_events"] == enclave["accepted"] == enclave["records"]
assert driver["consumer"] == driver["producer"] == enclave["consumer"] == enclave["producer"]
assert enclave["snapshot_bytes"] + enclave["trace_bytes"] == Path("reference.scap").stat().st_size
expected_privilege = {
    hashlib.sha256(f"{Path.cwd()}/{name}".encode()).hexdigest(): privileged
    for name, privileged in (("regular", False), ("privileged", True))
}
assert {cid: fields["container.privileged"] for cid, fields in metadata.items()} == expected_privilege
assert all(values["container.image.repository"] == "localhost/falco-poc/fixture" for values in metadata.values())
assert not missing, missing
print(json.dumps({"pass": True, "missing_rules": missing, "alerts_by_rule": rules,
                  "container_metadata": metadata, "driver": driver, "enclave": enclave}, indent=2))
PY
