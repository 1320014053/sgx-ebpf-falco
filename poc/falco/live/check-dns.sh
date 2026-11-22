#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
package=$(realpath "${1:?usage: check-dns.sh FALCO_PACKAGE BUILD_DIR LIVE_BUILD_DIR NEW_RUN_DIRECTORY}")
build=$(realpath "${2:?missing enclave build directory}")
live=$(realpath "${3:?missing live build directory}")
mkdir "${4:?missing run directory}"
cd "$(realpath "$4")"
export TZ=UTC FALCO_HOSTNAME=falco-sgx-dns

upstream=$(awk '$1 == "nameserver" {print $2; exit}' /etc/resolv.conf)
printf 'nameserver 127.0.0.42\noptions timeout:1 attempts:2\n' >resolv.conf
printf '127.0.0.1 a.falco-dns.test\n::1 aaaa.falco-dns.test\n' >initial.hosts
cp initial.hosts live.hosts
sudo -n systemd-run --unit=falco-dns-test --property=Restart=no -- /usr/sbin/dnsmasq \
    --keep-in-foreground --conf-file=/dev/null --no-resolv --no-hosts --cache-size=0 \
    --user="$(id -un)" --group="$(id -gn)" \
    --bind-interfaces --listen-address=127.0.0.42 --server="$upstream" \
    --local=/falco-dns.test/ --addn-hosts="$PWD/live.hosts" \
    --log-queries=extra --log-facility="$PWD/resolver.log"
trap 'sudo -n systemctl stop falco-dns-test' EXIT
for _ in $(seq 1 20); do
    if test -s resolver.log; then break; fi
    sleep 0.2
done
test -s resolver.log
with_dns() {
    sudo -n unshare --mount --propagation private bash -c 'mount --bind "$1" /etc/resolv.conf; shift; exec "$@"' \
        bash "$PWD/resolv.conf" env TZ="$TZ" FALCO_HOSTNAME="$FALCO_HOSTNAME" "$@"
}
with_dns python3 - <<'PY' >dns.hosts
import socket

for name in ("a.falco-dns.test", "aaaa.falco-dns.test", "example.com"):
    addresses = {row[4][0] for row in socket.getaddrinfo(name, None)}
    if name == "a.falco-dns.test":
        assert addresses == {"127.0.0.1"}, addresses
    if name == "aaaa.falco-dns.test":
        assert addresses == {"::1"}, addresses
    for address in sorted(addresses):
        print(address, name)
PY
sed -E 's/^hosts:.*/hosts: files/' /etc/nsswitch.conf >nsswitch.replay.conf
cp "$package/etc/falco/falco_rules.yaml" .
ln -s "$package/usr/share/falco/plugins/libcontainer.so" .
sed -e 's|rules_files: \[falco_rules.yaml\]|rules_files: [falco_rules.yaml, dns-cases.yaml]|' \
    -e 's|extra_fields: \[evt.num, evt.type, thread.tid\]|extra_fields: [evt.num, evt.type, thread.tid, fd.sip, fd.sip.name, proc.args]|' \
    "$here/reference.yaml" >reference.yaml

cat >dns-cases.yaml <<'YAML'
- macro: poc_dns_connect
  condition: evt.type=connect and evt.rawres=0 and proc.args startswith "dns-client.py "
YAML
while read -r label case_prefix domain; do
    cat <<YAML
- rule: POC DNS $label
  desc: Verify DNS address matching in the test client.
  condition: poc_dns_connect and fd.sip.name="$domain" and proc.args contains " $case_prefix"
  output: DNS test match | process=%proc.cmdline destination=%fd.sip name=%fd.sip.name
  priority: NOTICE
YAML
done >>dns-cases.yaml <<'CASES'
A dns-a- a.falco-dns.test
AAAA dns-v6 aaaa.falco-dns.test
missing dns-missing missing.falco-dns.test
public dns-public example.com
CASES
cat >>dns-cases.yaml <<'YAML'
- rule: POC DNS test connection
  desc: Confirm that the test connection reached Falco.
  condition: poc_dns_connect
  output: DNS test connection | process=%proc.cmdline destination=%fd.sip
  priority: NOTICE
YAML

cat >dns-client.py <<'PY'
import socket
import sys

address = sys.argv[2]
family = socket.AF_INET6 if ":" in address else socket.AF_INET
with socket.socket(family, socket.SOCK_STREAM) as listener:
    listener.bind((address, 0))
    listener.listen(1)
    with socket.socket(family, socket.SOCK_STREAM) as client:
        client.connect(listener.getsockname())
        listener.accept()[0].close()
PY
cat >workload.sh <<'SH'
set -euo pipefail
if [[ $1 == refresh ]]; then
    python3 dns-client.py dns-a-before 127.0.0.1
    printf '127.0.0.2 a.falco-dns.test\n::1 aaaa.falco-dns.test\n' >live.hosts
    systemctl kill --signal=HUP falco-dns-test
    sleep 17
    python3 dns-client.py dns-a-old-after 127.0.0.1
    python3 dns-client.py dns-a-new-after 127.0.0.2
else
    python3 dns-client.py dns-a-right 127.0.0.1
    python3 dns-client.py dns-a-wrong 127.0.0.2
    python3 dns-client.py dns-v6 ::1
    python3 dns-client.py dns-missing 127.0.0.1
    python3 dns-client.py dns-public 127.0.0.1
fi
SH

start=$(sudo -n awk 'END { print NR }' resolver.log)
with_dns timeout 90 "$live/falco-live" "$build/falco-enclave.signed" reference.yaml 16384 reference.scap \
    falco_rules.yaml dns-cases.yaml -- bash "$PWD/workload.sh" static >sgx-alerts.jsonl 2>sgx.log
sudo -n tail -n "+$((start + 1))" resolver.log >static-resolver.log
grep -F 'query[A] a.falco-dns.test' static-resolver.log >/dev/null
grep -F 'query[AAAA] aaaa.falco-dns.test' static-resolver.log >/dev/null
grep -E 'missing\.falco-dns\.test is NXDOMAIN' static-resolver.log >/dev/null
grep -F 'forwarded example.com' static-resolver.log >/dev/null
grep -F 'reply example.com is ' static-resolver.log >/dev/null

sha256sum falco_rules.yaml dns-cases.yaml reference.yaml reference.scap dns.hosts >inputs.sha256
"$package/usr/bin/falco" --version >versions.txt
"$package/usr/bin/falco" -c reference.yaml -L >native-rules.json 2>native-rules.log
sudo -n unshare --mount --propagation private bash -c '
    mount --bind "$1" /etc/hosts
    mount --bind "$2" /etc/nsswitch.conf
    shift 2
    exec "$@"
' bash "$PWD/dns.hosts" "$PWD/nsswitch.replay.conf" runuser -u "$(id -un)" -- \
    env TZ="$TZ" FALCO_HOSTNAME="$FALCO_HOSTNAME" "$package/usr/bin/falco" -c reference.yaml \
    >native-alerts.jsonl 2>native.log
python3 "$here/compare.py" . --captured | tee comparison.json
mkdir replayed
ln -s ../native-alerts.jsonl ../native-rules.json ../versions.txt replayed/
"$build/bin/falco-sgx" "$build/falco-enclave.signed" reference.yaml reference.scap --dns-hosts dns.hosts \
    falco_rules.yaml dns-cases.yaml >replayed/sgx-alerts.jsonl 2>replayed/sgx.log
python3 "$here/compare.py" replayed --captured | tee replayed/comparison.json

with_dns timeout 90 "$live/falco-live" "$build/falco-enclave.signed" reference.yaml 16384 - \
    falco_rules.yaml dns-cases.yaml -- bash "$PWD/workload.sh" refresh >refresh-alerts.jsonl 2>refresh.log
cp initial.hosts live.hosts
sudo -n systemctl kill --signal=HUP falco-dns-test
sleep 1
with_dns timeout 90 bash -eu -c '
    "$1" -c reference.yaml -o engine.kind=modern_ebpf -o engine.modern_ebpf.disable_iterators=true \
        -o base_syscalls.all=true \
        >native-refresh-alerts.jsonl 2>native-refresh.log &
    capture=$!
    trap "kill -INT $capture 2>/dev/null || true" EXIT
    for _ in $(seq 1 30); do
        kill -0 "$capture"
        if grep -q "with modern BPF probe" native-refresh.log; then break; fi
        sleep 1
    done
    grep -q "with modern BPF probe" native-refresh.log
    sleep 8
    bash workload.sh refresh
    sleep 2
    kill -INT "$capture"
    wait "$capture"
' bash "$package/usr/bin/falco"

python3 - <<'PY' | tee dns-check.json
import json
from collections import defaultdict
from pathlib import Path

def cases(path):
    result = defaultdict(list)
    for line in Path(path).read_text().splitlines():
        if line.startswith("{"):
            row = json.loads(line)
            if row["rule"].startswith("POC DNS "):
                result[row["rule"].removeprefix("POC DNS ")].append(row["output_fields"]["proc.args"].split()[1])
    return dict(result)

static = cases("sgx-alerts.jsonl")
refresh = cases("refresh-alerts.jsonl")
native = cases("native-refresh-alerts.jsonl")
assert static == {
    "A": ["dns-a-right"], "AAAA": ["dns-v6"],
    "test connection": ["dns-a-right", "dns-a-wrong", "dns-v6", "dns-missing", "dns-public"],
}, static
assert refresh == native == {
    "A": ["dns-a-before", "dns-a-new-after"],
    "test connection": ["dns-a-before", "dns-a-old-after", "dns-a-new-after"],
}, (refresh, native)
capture = {}
for filename in ("sgx.log", "refresh.log"):
    stats = [json.loads(line) for line in Path(filename).read_text().splitlines() if line.startswith("{")]
    driver = next(row for row in stats if row.get("mode") == "modern_ebpf")
    enclave = next(row for row in stats if row.get("mode") == "live")
    assert driver["driver_drops"] == enclave["format_rejected"] == 0
    assert driver["driver_events"] == enclave["accepted"] == enclave["records"]
    assert driver["consumer"] == driver["producer"] == enclave["consumer"] == enclave["producer"]
    capture[filename] = {"records": driver["driver_events"], "drain_ms": driver["drain_ms"]}
print(json.dumps({"pass": True, "static": static, "refresh": refresh, "native_refresh": native,
                  "capture": capture}, indent=2))
PY
