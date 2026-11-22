#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
package=$(realpath "${1:?usage: check-kubernetes.sh FALCO_PACKAGE BUILD_DIR LIVE_BUILD_DIR NEW_RUN_DIRECTORY K3S}")
build=$(realpath "${2:?missing enclave build directory}")
live=$(realpath "${3:?missing live build directory}")
k3s=$(realpath "${5:?missing K3s binary}")
cri_socket=${CRI_SOCKET:-/run/containerd/containerd.sock}
export KUBECONFIG=$(realpath "${KUBECONFIG:?set KUBECONFIG to the test cluster configuration}")
mkdir "${4:?missing run directory}"
cd "$(realpath "$4")"
export TZ=UTC FALCO_HOSTNAME=falco-sgx-kubernetes
kubectl() { sudo -n env KUBECONFIG="$KUBECONFIG" "$k3s" kubectl "$@"; }
with_dns() {
    sudo -n unshare --mount --propagation private bash -c 'mount --bind "$1" "$2"; shift 2; exec "$@"' \
        bash "$1" "$2" env TZ="$TZ" FALCO_HOSTNAME="$FALCO_HOSTNAME" KUBECONFIG="$KUBECONFIG" "${@:3}"
}

kubectl create namespace falco-poc --dry-run=client -o yaml | kubectl apply -f -
for namespace in falco-poc kube-system; do
    cat >"$namespace-pod.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: falco-poc-connect
  namespace: $namespace
spec:
  automountServiceAccountToken: false
  containers:
    - name: fixture
      image: localhost/falco-poc/fixture:1
      imagePullPolicy: Never
      command: ["/bin/busybox", "sleep", "600"]
YAML
done
kubectl apply -f falco-poc-pod.yaml
trap 'kubectl delete -f falco-poc-pod.yaml -f kube-system-pod.yaml --ignore-not-found --wait=false >/dev/null' EXIT
kubectl wait --for=condition=Ready -f falco-poc-pod.yaml --timeout=100s
api=$(kubectl -n default get svc kubernetes -o 'jsonpath={.spec.clusterIP}')
dns=$(kubectl -n kube-system get svc kube-dns -o 'jsonpath={.spec.clusterIP}')
fqdn=kubernetes.default.svc.cluster.local
printf '%s %s\n' "$api" "$dns" >services.txt
printf 'nameserver %s\noptions timeout:1 attempts:2\n' "$dns" >resolv.conf
address=$(with_dns "$PWD/resolv.conf" /etc/resolv.conf getent ahostsv4 "$fqdn" | awk '{print $1}' | sort -u)
test "$address" = "$api"
printf '127.0.0.1 localhost\n::1 localhost\n%s %s\n' "$address" "$fqdn" >dns.hosts

cp "$package/etc/falco/falco_rules.yaml" .
ln -s "$package/usr/share/falco/plugins/libcontainer.so" .
sed -e 's|rules_files: \[falco_rules.yaml\]|rules_files: [falco_rules.yaml, cases.yaml]|' \
    -e "s|cri: {enabled: false}|cri: {enabled: true, sockets: [$cri_socket]}|" \
    -e 's|extra_fields: \[evt.num, evt.type, thread.tid\]|extra_fields: [evt.num, evt.type, thread.tid, fd.sip, fd.sport, fd.sip.name, k8s.ns.name, k8s.pod.name, k8s.pod.uid, container.full_id, container.type, container.image.repository, container.privileged]|' \
    "$here/reference.yaml" >reference.yaml
cat >cases.yaml <<'YAML'
- rule: POC Kubernetes test connection
  desc: Record the connection for each test case.
  condition: evt.type=connect and proc.name in (busybox, nc) and fd.sport in (443, 53)
  output: Kubernetes test connection | process=%proc.cmdline destination=%fd.sip port=%fd.sport result=%evt.rawres
  priority: NOTICE
YAML
cat >workload.sh <<'SH'
set -euo pipefail
k3s=$1
api=$2
dns=$3
phase=$4
"$k3s" kubectl apply -f kube-system-pod.yaml >>"$phase-workload.log" 2>&1
"$k3s" kubectl wait --for=condition=Ready -f kube-system-pod.yaml --timeout=50s >>"$phase-workload.log" 2>&1
for namespace in falco-poc kube-system; do
    "$k3s" kubectl -n "$namespace" get pod falco-poc-connect \
        -o 'jsonpath={.metadata.namespace} {.metadata.name} {.metadata.uid} {.status.containerStatuses[0].containerID} {.status.containerStatuses[0].image}{"\n"}'
done >"$phase-pod-identities.txt"
for target in "falco-poc $api 443" "falco-poc $dns 53" "kube-system $api 443"; do
    read -r namespace address port <<<"$target"
    "$k3s" kubectl -n "$namespace" exec falco-poc-connect -- /bin/busybox nc -w 2 "$address" "$port" \
        </dev/null >>"$phase-workload.log" 2>&1
done
SH

check_cases() {
    python3 - "$1" "$2" <<'PY'
import json
import sys
from pathlib import Path

api, dns = Path("services.txt").read_text().split()
pods = {
    (ns, name): (uid, *cid.split("://", 1), image)
    for ns, name, uid, cid, image in (line.split() for line in Path(sys.argv[2]).read_text().splitlines())
}
rows = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines() if line.startswith("{")]
cases = []
hits = []
for row in rows:
    if row["rule"] not in {"POC Kubernetes test connection", "Contact K8S API Server From Container"}:
        continue
    fields = row["output_fields"]
    pod = (fields["k8s.ns.name"], fields["k8s.pod.name"])
    assert pod in pods, fields
    uid, runtime, cid, image = pods[pod]
    assert (fields["k8s.pod.uid"], fields["container.type"], fields["container.full_id"]) == (uid, runtime, cid), fields
    assert fields["container.image.repository"] == image.rsplit(":", 1)[0], fields
    assert fields["container.privileged"] is False, fields
    case = {
        "namespace": pod[0], "pod": pod[1], "pod_uid": fields["k8s.pod.uid"],
        "container_id": cid, "runtime": runtime, "image": image, "privileged": fields["container.privileged"],
        "destination": fields["fd.sip"],
        "port": fields["fd.sport"], "dns_name": fields["fd.sip.name"],
    }
    if row["rule"] == "POC Kubernetes test connection":
        cases.append(case)
    else:
        hits.append(case)

expected = {("falco-poc", api, 443), ("falco-poc", dns, 53), ("kube-system", api, 443)}
observed = {(case["namespace"], case["destination"], case["port"]) for case in cases}
assert observed == expected, cases
assert len(hits) == 1 and hits[0]["namespace"] == "falco-poc" and hits[0]["destination"] == api, hits
assert hits[0]["dns_name"] == "kubernetes.default.svc.cluster.local", hits
print(json.dumps({"pass": True, "cases": cases, "official_alerts": hits}, indent=2))
PY
}

with_dns "$PWD/resolv.conf" /etc/resolv.conf timeout 90 bash -eu -c '
    "$1" -c reference.yaml -o engine.kind=modern_ebpf -o engine.modern_ebpf.disable_iterators=true \
        -o base_syscalls.all=true \
        >native-live-alerts.jsonl 2>native-live.log &
    capture=$!
    trap "kill -INT $capture 2>/dev/null || true" EXIT
    for _ in $(seq 1 30); do
        kill -0 "$capture"
        if grep -q "with modern BPF probe" native-live.log; then break; fi
        sleep 1
    done
    grep -q "with modern BPF probe" native-live.log
    sleep 8
    bash workload.sh "$2" "$3" "$4" native
    sleep 2
    kill -INT "$capture"
    wait "$capture"
' bash "$package/usr/bin/falco" "$k3s" "$api" "$dns"
check_cases native-live-alerts.jsonl native-pod-identities.txt | tee native-live-check.json
kubectl delete -f kube-system-pod.yaml --wait=true --timeout=35s

with_dns "$PWD/resolv.conf" /etc/resolv.conf timeout 90 \
    "$live/falco-live" "$build/falco-enclave.signed" reference.yaml 16384 reference.scap falco_rules.yaml cases.yaml \
    -- bash "$PWD/workload.sh" "$k3s" "$api" "$dns" sgx >sgx-alerts.jsonl 2>sgx.log
check_cases sgx-alerts.jsonl sgx-pod-identities.txt | tee live-check.json

sha256sum falco_rules.yaml cases.yaml reference.yaml reference.scap dns.hosts >inputs.sha256
"$package/usr/bin/falco" --version >versions.txt
"$package/usr/bin/falco" -c reference.yaml -L >native-rules.json 2>native-rules.log
with_dns "$PWD/dns.hosts" /etc/hosts runuser -u "$(id -un)" -- \
    "$package/usr/bin/falco" -c reference.yaml >native-alerts.jsonl 2>native.log
python3 "$here/compare.py" . --captured | tee comparison.json

mkdir replayed
ln -s ../native-alerts.jsonl ../native-rules.json ../versions.txt replayed/
"$build/bin/falco-sgx" "$build/falco-enclave.signed" reference.yaml reference.scap --dns-hosts dns.hosts \
    falco_rules.yaml cases.yaml >replayed/sgx-alerts.jsonl 2>replayed/sgx.log
python3 "$here/compare.py" replayed --captured | tee replayed/comparison.json

python3 - <<'PY' | tee ring-check.json
import json
from pathlib import Path

stats = [json.loads(line) for line in Path("sgx.log").read_text().splitlines() if line.startswith("{")]
driver = next(row for row in stats if row.get("mode") == "modern_ebpf")
enclave = next(row for row in stats if row.get("mode") == "live")
assert driver["driver_drops"] == enclave["format_rejected"] == 0
assert driver["driver_events"] == enclave["accepted"] == enclave["records"]
assert driver["consumer"] == driver["producer"] == enclave["consumer"] == enclave["producer"]
print(json.dumps({"pass": True, "driver": driver, "enclave": enclave}, indent=2))
PY
