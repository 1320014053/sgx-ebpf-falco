"""Run as root on x86-64 Linux with the Falco and bpftool binaries as arguments."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("falco")
parser.add_argument("bpftool")
parser.add_argument("--default-buffer", action="store_true",
                    help="Check Falco's default 8 MiB ring; the compatibility run uses 1 MiB.")
args = parser.parse_args()
falco, bpftool = args.falco, args.bpftool
buffer_settings = {"disable_iterators": True}
if not args.default_buffer:
    buffer_settings["buf_size_preset"] = 1
expected_bytes = (8 if args.default_buffer else 1) * 1024 * 1024


def lookup_slot_id(table, key):
    key_bytes = [f"{byte:02x}" for byte in key.to_bytes(4, "little")]
    entry = json.loads(subprocess.check_output(
        [bpftool, "-j", "map", "lookup", "id", str(table["id"]), "key", "hex", *key_bytes]
    ))
    value = entry.get("formatted", entry)["value"]
    if isinstance(value, list):
        return int.from_bytes(bytes(int(b, 0) for b in value), "little")
    return value


work = Path(tempfile.mkdtemp(prefix="moat-modern-"))
marker = work / "marker"
marker.write_bytes(b"MOAT readv marker\n")
expected = {"MOAT marker open": ("openat", "cat"), "MOAT marker readv": ("readv", "python3")}
pids = {rule: set() for rule in expected}
rules = work / "rules.yaml"
rules.write_text("".join(
    f"""- rule: {rule}
  desc: Observe a controlled marker file access
  condition: evt.type = {event} and proc.name = {command} and fd.name = "{marker}"
  output: "marker (syscall=%evt.type command=%proc.name pid=%proc.pid file=%fd.name result=%evt.rawres)"
  priority: NOTICE
  source: syscall
""" for rule, (event, command) in expected.items()
))
config = work / "falco.yaml"
config.write_text(f"""rules_files: [{rules}]
engine:
  kind: modern_ebpf
  modern_ebpf: {json.dumps(buffer_settings)}
base_syscalls: {{all: true}}
plugins: []
load_plugins: []
webserver: {{enabled: false}}
watch_config_files: false
log_stderr: true
log_syslog: false
syslog_output: {{enabled: false}}
stdout_output: {{enabled: true}}
json_output: true
""")

readv = """import os, sys
with open(sys.argv[1], "rb", buffering=0) as stream:
    a, b = bytearray(4), bytearray(64)
    n = os.readv(stream.fileno(), [a, b])
    if (a + b)[:n] != b"MOAT readv marker\\n":
        sys.exit("readv returned unexpected marker data")
"""
print("Kernel", os.uname().release, "marker", marker, flush=True)
print("Falco SHA256", hashlib.sha256(Path(falco).read_bytes()).hexdigest(), flush=True)
subprocess.run([falco, "--version"], check=True)
out = work / "events.log"
log = work / "falco.log"
matches = {}
with out.open("w") as stdout, log.open("w") as stderr:
    proc = subprocess.Popen([falco, "-U", "-c", str(config)], stdout=stdout, stderr=stderr)
    try:
        deadline = time.monotonic() + 100
        while proc.poll() is None and time.monotonic() < deadline:
            if "with modern BPF probe" in log.read_text():
                for rule, command in (("MOAT marker open", ["/bin/cat", str(marker)]),
                                      ("MOAT marker readv", ["/usr/bin/python3", "-c", readv, str(marker)])):
                    if rule in matches:
                        continue
                    child = subprocess.Popen(command, stdout=subprocess.DEVNULL)
                    pids[rule].add(child.pid)
                    if child.wait() != 0:
                        raise RuntimeError(f"Marker reader for {rule} failed")
            time.sleep(1)
            for line in out.read_text().splitlines():
                if not (line.startswith("{") and line.endswith("}")):
                    continue
                event = json.loads(line)
                rule = event.get("rule")
                if rule not in expected or event.get("source") != "syscall":
                    continue
                fields = event["output_fields"]
                if ((fields["evt.type"], fields["proc.name"]) == expected[rule]
                        and fields["fd.name"] == str(marker) and int(fields["proc.pid"]) in pids[rule]
                        and (rule != "MOAT marker readv" or int(fields["evt.rawres"]) == marker.stat().st_size)):
                    matches[rule] = line
            if matches.keys() == expected.keys():
                break

        if matches.keys() != expected.keys():
            raise RuntimeError(f"Missing live alerts: {sorted(expected.keys() - matches.keys())}")
        owned_maps = set()
        owned_progs = set()
        for fd in Path(f"/proc/{proc.pid}/fdinfo").iterdir():
            try:
                lines = fd.read_text().splitlines()
            except FileNotFoundError:
                continue
            for line in lines:
                if line.startswith("map_id:"):
                    owned_maps.add(int(line.split()[1]))
                elif line.startswith("prog_id:"):
                    owned_progs.add(int(line.split()[1]))
        programs = json.loads(subprocess.check_output([bpftool, "-j", "prog", "show"]))
        ids = {}
        for prog in programs:
            name = prog.get("name")
            if prog["id"] in owned_progs and name in {"sys_exit", "openat_x", "readv_x", "preadv_x"}:
                print("PROG", json.dumps({k: prog.get(k) for k in ("name", "id", "type", "jited", "bytes_jited")}))
                if not prog["jited"]:
                    raise RuntimeError(f"{name} has no JIT image")
                ids[name] = prog["id"]
        maps = json.loads(subprocess.check_output([bpftool, "-j", "map", "show"]))
        outer, = (m for m in maps if m["id"] in owned_maps and m["name"] == "ringbuf_maps"
                  and m["type"] == "array_of_maps")
        ring_id = lookup_slot_id(outer, 0)
        ring, = (m for m in maps if m["id"] == ring_id)
        print("RING", json.dumps({"outer_id": outer["id"], "cpu": 0, "id": ring_id,
                                  "type": ring["type"], "bytes": ring["max_entries"]}))
        if ring["type"] != "ringbuf" or ring["max_entries"] != expected_bytes:
            raise RuntimeError(f"Expected a {expected_bytes}-byte Falco ring")
        table, = (m for m in maps if m["id"] in owned_maps and m["name"] == "syscall_exit_tail_table"[:15]
                  and m["type"] == "prog_array")
        # The x86-64 syscall number for readv is 19.
        value = lookup_slot_id(table, 19)
        print("TAIL", json.dumps({"map_id": table["id"], "slot": 19, "program_id": value}))
        if value != ids["readv_x"]:
            raise RuntimeError("The readv tail-call slot does not point to readv_x")
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
        proc.wait(timeout=15)
        print(log.read_text(), end="")
        for rule, line in matches.items():
            print("ALERT", line)
            print("TRIGGERS", rule, *sorted(pids[rule]))
if proc.returncode:
    sys.exit(proc.returncode)
if args.default_buffer:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        remaining = json.loads(subprocess.check_output([bpftool, "-j", "map", "show"]))
        if all(m["id"] != ring_id for m in remaining):
            print("RELEASED ring", ring_id)
            break
        time.sleep(0.2)
    else:
        raise RuntimeError(f"Ring {ring_id} is still registered after Falco stopped")
# Linux sets taint bits 7 and 9 for a kernel Oops and warning, respectively.
if int(Path("/proc/sys/kernel/tainted").read_text()) & ((1 << 7) | (1 << 9)):
    raise RuntimeError("Guest kernel recorded an Oops or warning")
