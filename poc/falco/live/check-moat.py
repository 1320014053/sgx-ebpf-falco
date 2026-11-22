"""Check live Falco alerts in the project's existing SGX Simulation enclave on MOAT."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import yaml


def workload(uid, gid):
    # falco-live is our parent. Capture the kernel's map metadata before dropping privileges.
    rings = {}
    for fd in Path(f"/proc/{os.getppid()}/fdinfo").iterdir():
        fields = dict(line.split(":", 1) for line in fd.read_text().splitlines() if ":" in line)
        if fields.get("map_type", "").strip() == "27":  # BPF_MAP_TYPE_RINGBUF
            ring_id = int(fields["map_id"])
            rings[ring_id] = {"id": ring_id, "type": "ringbuf", "max_entries": int(fields["max_entries"])}
    Path("kernel-rings.json").write_text(json.dumps(list(rings.values())) + "\n")
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    reads = []
    for name in ("control", "marker"):
        path = Path(name).resolve()
        fd = os.open(path, os.O_RDONLY)
        try:
            first, second = bytearray(4), bytearray(64)
            count = os.readv(fd, [first, second])
            assert (first + second)[:count] == b"MOAT readv marker\n"
        finally:
            os.close(fd)
        reads.append({"file": str(path), "pid": os.getpid(), "fd": fd, "bytes": count, "uid": os.getuid()})
    Path("workload.json").write_text(json.dumps(reads) + "\n")


def check_marker():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path, help="official Falco package directory")
    parser.add_argument("enclave_build", type=Path, help="existing enclave build directory")
    parser.add_argument("live_build", type=Path, help="existing falco-live build directory")
    parser.add_argument("output", type=Path, help="new run directory")
    args = parser.parse_args()
    package, build, live = (p.resolve() for p in (args.package, args.enclave_build, args.live_build))
    script = Path(__file__).resolve()
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    os.chdir(output)
    for name in ("control", "marker"):
        Path(name).write_bytes(b"MOAT readv marker\n")
    rules = []
    for event in ("openat", "readv"):
        rules.append({
            "rule": "MOAT marker " + event,
            "desc": "Observe a controlled file read in the MOAT guest",
            "condition": f'evt.type = {event} and proc.name = python3 and fd.name = "{output / "marker"}"',
            "output": "marker (syscall=%evt.type command=%proc.name pid=%proc.pid file=%fd.name fd=%fd.num result=%evt.rawres)",
            "priority": "NOTICE",
            "source": "syscall",
        })
    Path("marker-rules.yaml").write_text(yaml.safe_dump(rules, sort_keys=False))
    config = yaml.safe_load((script.parents[1] / "reference.yaml").read_text())
    config["rules_files"] = ["marker-rules.yaml"]
    config["base_syscalls"] = {"all": True}
    Path("replay.yaml").write_text(yaml.safe_dump(config, sort_keys=False))
    config["engine"] = {"kind": "modern_ebpf", "modern_ebpf": {"disable_iterators": True}}
    Path("live.yaml").write_text(yaml.safe_dump(config, sort_keys=False))
    Path("libcontainer.so").symlink_to(package / "usr/share/falco/plugins/libcontainer.so")

    host = live / "falco-live"
    enclave = build / "falco-enclave.signed"
    native = package / "usr/bin/falco"
    replay = build / "bin/falco-sgx"
    trace = Path("reference.scap")
    env = dict(os.environ, TZ="UTC", FALCO_HOSTNAME="moat-sgx-sim")
    live_cmd = ["sudo", "-n", "env", "TZ=UTC", "FALCO_HOSTNAME=moat-sgx-sim", host, enclave,
                "live.yaml", "8192", trace, "marker-rules.yaml", "--", "/usr/bin/python3", script,
                "--workload", str(os.getuid()), str(os.getgid())]
    for label, cmd in (
        ("enclave-live", live_cmd),
        ("native-replay", [native, "-c", "replay.yaml"]),
        ("enclave-replay", [replay, enclave, "replay.yaml", trace, "marker-rules.yaml"]),
    ):
        with open(label + ".jsonl", "w") as out, open(label + ".log", "w") as log:
            subprocess.run(cmd, stdout=out, stderr=log, env=env, check=True, timeout=180)

    def records(file):
        return [json.loads(line) for line in Path(file).read_text().splitlines() if line.startswith("{")]

    control, marker = json.loads(Path("workload.json").read_text())
    assert control["uid"] == marker["uid"] == os.getuid() != 0
    assert control["bytes"] == marker["bytes"] == 18
    alerts = records("enclave-live.jsonl")
    assert [a["rule"] for a in alerts] == ["MOAT marker openat", "MOAT marker readv"]
    for alert, event, result in zip(alerts, ("openat", "readv"), (marker["fd"], marker["bytes"])):
        fields = alert["output_fields"]
        assert alert["source"] == "syscall" and fields["evt.type"] == event
        assert fields["fd.name"] == marker["file"] and fields["proc.name"] == "python3"
        assert (fields["proc.pid"], fields["fd.num"], fields["evt.rawres"]) == (marker["pid"], marker["fd"], result)
    assert alerts == records("native-replay.jsonl") == records("enclave-replay.jsonl")
    diag = records("enclave-live.log")
    driver = next(row for row in diag if row.get("mode") == "modern_ebpf")
    consumer = next(row for row in diag if row.get("mode") == "live")
    rings = json.loads(Path("kernel-rings.json").read_text())
    ring, = (r for r in rings if r["id"] == driver["map_id"])
    assert ring["max_entries"] == driver["ring_bytes"] == 8 * 1024 * 1024
    assert driver["data_ecalls"] == 1 and driver["trace_ocalls"] > 0
    assert driver["driver_drops"] == consumer["discarded"] == consumer["format_rejected"] == 0
    assert driver["driver_events"] == consumer["records"] == consumer["accepted"] > 0
    assert driver["producer"] == driver["consumer"] == consumer["producer"] == consumer["consumer"]
    assert consumer["alerts"] == len(alerts) and consumer["event_types"]["readv"] > 0
    assert consumer["snapshot_bytes"] + consumer["trace_bytes"] == trace.stat().st_size
    taint = int(Path("/proc/sys/kernel/tainted").read_text())
    assert not taint & ((1 << 7) | (1 << 9))
    sha = {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in (host, enclave, replay, native, trace)}
    result = {"kernel": os.uname().release, "taint": taint, "ring": ring, "driver": driver,
              "enclave": consumer, "native_and_enclave_replay_match": True, "sha256": sha}
    Path("check.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"PASS {result['kernel']}, ring {ring['id']} ({ring['max_entries']} bytes), "
          f"{consumer['accepted']} accepted records, {len(alerts)} live alerts matched both replays")


if __name__ == "__main__":
    if sys.argv[1:2] == ["--workload"]:
        workload(int(sys.argv[2]), int(sys.argv[3]))
    else:
        check_marker()
