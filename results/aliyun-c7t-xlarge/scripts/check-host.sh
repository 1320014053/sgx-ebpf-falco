#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() { echo "usage: bash check-host.sh OUTDIR [--build FALCO_BUILD_DIR] [--sim]" >&2; exit 2; }
(( $# )) || usage
out=$1
shift
build=
mode=hardware
while (( $# )); do
    case "$1" in
        --build) (( $# >= 2 )) || usage; build=$(realpath -m -- "$2"); shift 2 ;;
        --sim) mode=sim; shift ;;
        *) usage ;;
    esac
done
if [[ -n $build ]]; then
    falco=$(cd "$(dirname "$0")/../../../poc/falco" && pwd)
fi
mkdir -p -- "$(dirname -- "$out")"
mkdir -- "$out"
cd -- "$out"
out=$PWD
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

uname -a > uname.txt
cat /etc/os-release > os-release
lscpu > lscpu.txt
nproc > nproc.txt
free -b > free.txt
getconf PAGESIZE > page-size.txt
dmesg 2>dmesg-error.txt | grep -i sgx > dmesg-sgx.txt || true

cc -O2 -x c -o "$work/probe" - <<'C'
#include <cpuid.h>
#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    unsigned a, b, c, d;
    __cpuid_count(1, 0, a, b, c, d);
    printf("{\"PCID\":%u,", (c >> 17) & 1);
    __cpuid_count(7, 0, a, b, c, d);
    printf("\"SGX\":%u,\"SGX_LC\":%u,\"PKS\":%u,\"INVPCID\":%u,",
           (b >> 2) & 1, (c >> 30) & 1, (c >> 31) & 1, (b >> 10) & 1);
    __cpuid_count(0x12, 0, a, b, c, d);
    printf("\"SGX1\":%u,\"SGX2\":%u}\n", a & 1, (a >> 1) & 1);

    union bpf_attr attr = { .map_type = BPF_MAP_TYPE_RINGBUF, .max_entries = sysconf(_SC_PAGESIZE) };
    int fd = syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    printf("%d\n", fd < 0 ? errno : 0);
    if (fd >= 0) close(fd);
    return 0;
}
C
"$work/probe" > probe.txt

launch_status=
if [[ -n $build ]]; then
    cd "$work"
    python3 "$falco/fixture.py"
    cat > falco_rules.yaml <<'YAML'
- rule: Preflight exec
  desc: Identify execve events in the replay fixture.
  condition: evt.type=execve and evt.dir=<
  output: Preflight exec %proc.name
  priority: NOTICE
YAML
    launch_status=0
    FALCO_SGX_REPORT=1 "$build/bin/falco-sgx" "$build/falco-enclave.signed" \
        "$falco/reference.yaml" reference.scap falco_rules.yaml > "$out/alerts.jsonl" 2> "$out/report.log" || launch_status=$?
    cd "$out"
fi

python3 - "$mode" "$build" "$launch_status" "$work" <<'PY'
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

mode, build, status, work = sys.argv[1:]
facts = {"mode": mode, "uname": Path("uname.txt").read_text().strip(),
         "nproc": int(Path("nproc.txt").read_text()), "page_size": int(Path("page-size.txt").read_text()),
         "btf_readable": os.access("/sys/kernel/btf/vmlinux", os.R_OK),
         "sgx_enclave": Path("/dev/sgx_enclave").is_char_device(),
         "sgx_provision": Path("/dev/sgx_provision").is_char_device()}
cpu, ring_errno = Path("probe.txt").read_text().splitlines()
facts["cpuid"] = cpu = json.loads(cpu)
ring_errno = int(ring_errno)
facts["bpf_ringbuf"] = (True if ring_errno == 0 else
                        False if ring_errno in (errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP) else None)
facts["bpf_ringbuf_errno"] = ring_errno
epc_nodes = {str(p): int(p.read_text()) for p in Path("/sys/devices/system/node").glob("node*/x86/sgx_total_bytes")}
ranges = re.findall(r"EPC section (0x[\da-f]+)-(0x[\da-f]+)", Path("dmesg-sgx.txt").read_text(), re.I)
facts["epc_sysfs_bytes"] = epc_nodes
facts["epc_bytes"] = (sum(epc_nodes.values()) if epc_nodes else
                      sum(int(end, 16) - int(start, 16) + 1 for start, end in ranges) if ranges else None)

errors = []
checks = facts["checks"] = {"hardware_sgx": "sim" if mode == "sim" else
                            bool(cpu["SGX"] and cpu["SGX1"] and cpu["SGX_LC"] and facts["sgx_enclave"]),
                            "debug_zero": None, "measurements_match": None}
if checks["hardware_sgx"] is False:
    errors.append("hardware SGX unavailable (need SGX, SGX1, SGX_LC and /dev/sgx_enclave)")
if mode == "sim":
    checks["debug_zero"] = checks["measurements_match"] = "sim"
if build:
    facts["falco_exit"] = int(status)
    if facts["falco_exit"]:
        errors.append("falco-sgx failed; see report.log")
    if mode == "hardware":
        checks["debug_zero"] = checks["measurements_match"] = False
        report = re.search(r"^REPORT DEBUG=(\d) MRENCLAVE=([a-f0-9]{64}) MRSIGNER=([a-f0-9]{64})$",
                           Path("report.log").read_text(errors="replace"), re.M)
        if report:
            facts["report"] = {"debug": int(report[1]), "mrenclave": report[2], "mrsigner": report[3]}
            checks["debug_zero"] = report[1] == "0"
        image = Path(build) / "falco-enclave.signed"
        section = Path(work) / "oeinfo.bin"
        try:
            subprocess.run(["objcopy", "-O", "binary", "--only-section=.oeinfo", image, section], check=True)
            data = section.read_bytes()
            offset = data.index(bytes.fromhex("06000000e10000000000010000000000"))
            sig = data[offset:offset + 1808]
            if len(sig) != 1808:
                raise ValueError("truncated SIGSTRUCT")
            mr = sig[960:992].hex()
            signer = hashlib.sha256(sig[128:512]).hexdigest()
            facts["signed_image"] = {"mrenclave": mr, "mrsigner": signer}
            checks["measurements_match"] = bool(report and (mr, signer) == (report[2], report[3]))
        except (OSError, ValueError, subprocess.CalledProcessError) as exc:
            errors.append(f"cannot read signed image identity: {exc}")
        if not checks["debug_zero"]:
            errors.append("missing hardware REPORT or DEBUG is set")
        if not checks["measurements_match"]:
            errors.append("REPORT measurements do not match the signed image")

facts["errors"] = errors
facts["pass"] = not errors
Path("preflight.json").write_text(json.dumps(facts, indent=2) + "\n")
for error in errors:
    print(error, file=sys.stderr)
sys.exit(bool(errors))
PY
