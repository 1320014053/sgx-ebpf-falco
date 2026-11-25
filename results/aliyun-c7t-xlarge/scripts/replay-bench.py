"""E8. Time one native and one signed-enclave replay per fixed input size."""

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import struct
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[3]
FALCO = ROOT / "poc/falco"
OLD = ROOT / "results/aliyun-c7t-large/runs/20261123T073338Z-31ff86016fe5"
LIMIT = 64 * 1024**2


def sha256(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def write_json(path, obj):
    path.write_text(json.dumps(obj, indent=2) + "\n")


def arguments(description):
    parser = argparse.ArgumentParser(description=description)
    for name in ("package", "build", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--sim", action="store_true", help="use a simulation build")
    parser.add_argument("--quick", action="store_true", help="use smoke-test input sizes")
    args = parser.parse_args()
    args.package, args.build, args.out = (p.resolve() for p in (args.package, args.build, args.out))
    if args.out.exists():
        parser.error(f"output already exists: {args.out}")
    args.out.mkdir(parents=True)
    image = args.build / "falco-enclave.signed"
    write_json(args.out / "artifacts.json", {str(p): sha256(p) for p in (
        image, args.build / "bin/falco-sgx", args.package / "usr/bin/falco",
        args.package / "etc/falco/falco_rules.yaml", args.package / "usr/share/falco/plugins/libcontainer.so")})
    return args


def write_summary(out, rows):
    write_json(out / "summary.json", rows)
    with (out / "summary.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(dict.fromkeys(k for row in rows for k in row)))
        writer.writeheader()
        writer.writerows(rows)


def setup_workdir(work, args, plugin=False):
    work.mkdir()
    links = {"falco_rules.yaml": args.package / "etc/falco/falco_rules.yaml",
             "libcontainer.so": args.package / "usr/share/falco/plugins/libcontainer.so"}
    if plugin:
        links.update({"libraven_zeek.so": args.build / "lib/libraven_zeek.so",
                      "raven_zeek_rules.yaml": FALCO / "plugin/rules.yaml"})
    for name, path in links.items():
        (work / name).symlink_to(path)


def plugin_command(args, mode, option, config):
    if mode == "native":
        return [args.package / "usr/bin/falco", "-c", config, "-o", "engine.kind=modern_ebpf",
                "--enable-source", "raven_zeek"]
    inputs = ["events.jsonl"] if option == "--plugin-stream" else ["events.jsonl", "packets.pcap"]
    return [args.build / "bin/falco-sgx", args.build / "falco-enclave.signed", config,
            "reference.scap", option, *inputs, "falco_rules.yaml", "raven_zeek_rules.yaml"]


def measure(args, raw, work, cmd, mode, hostname, *, markers=False, discard=False):
    raw.mkdir()
    command = ["/usr/bin/time", "-q", "-f", "%U %S %M %w %c %I %O", "-o",
               str(raw / "resources.txt"), *map(str, cmd)]
    env = dict(os.environ, TZ="UTC", LC_ALL="C", FALCO_HOSTNAME=hostname)
    if mode == "sgx":
        # The hardware host emits a local REPORT and rejects DEBUG=1. Simulation
        # compiles out this path, so absence/presence also checks the chosen mode.
        env["FALCO_SGX_REPORT"] = "1"
    stdout = Path(os.devnull) if discard else raw / "alerts.jsonl"
    write_json(raw / "command.json", dict(argv=command, cwd=str(work), stdout=str(stdout),
               env={k: env[k] for k in ("TZ", "LC_ALL", "FALCO_HOSTNAME", "FALCO_SGX_REPORT") if k in env}))
    ready = finished = identity = None
    with stdout.open("wb") as output, (raw / "stderr.log").open("wb") as log:
        begin = time.monotonic_ns()
        with subprocess.Popen(command, cwd=work, env=env, stdout=output, stderr=subprocess.PIPE) as proc:
            for line in proc.stderr:
                stamp = time.monotonic_ns()
                if markers:
                    if ready is None and (b"Replaying events from the capture file" in line if mode == "native"
                                          else b'"loaded_rules"' in line):
                        ready = stamp
                    if ready is not None and finished is None and (
                            b"Syscall event drop monitoring" in line if mode == "native"
                            else b'"events"' in line and b'"alerts"' in line):
                        finished = stamp
                if line.startswith(b"REPORT "):
                    identity = line.decode().strip()
                log.write(line)
            rc = proc.wait()
        end = time.monotonic_ns()
    if rc:
        raise RuntimeError(f"{raw.name} exited {rc}, see {raw / 'stderr.log'}")
    user, system, rss, voluntary, involuntary, reads, writes = (raw / "resources.txt").read_text().split()
    row = dict(trial=raw.name, mode=mode, wall_s=(end - begin) / 1e9, user_s=float(user),
               sys_s=float(system), peak_rss_kib=int(rss), voluntary_switches=int(voluntary),
               involuntary_switches=int(involuntary), input_blocks=int(reads), output_blocks=int(writes))
    if mode == "sgx":
        if args.sim:
            if identity:
                raise ValueError(f"{raw.name}: hardware REPORT in a simulation trial")
            row["enclave_mode"] = "simulation"
        else:
            report = re.fullmatch(r"REPORT DEBUG=0 MRENCLAVE=([0-9a-f]{64}) MRSIGNER=([0-9a-f]{64})", identity or "")
            if not report:
                raise ValueError(f"{raw.name}: missing DEBUG=0 hardware REPORT, see stderr.log")
            row.update(enclave_mode="hardware", debug=0, mrenclave=report[1], mrsigner=report[2])
    if markers:
        if ready is None or finished is None or finished <= ready:
            raise ValueError(f"{raw.name}: missing or unordered replay timing markers, see stderr.log")
        row.update(cold_to_ready_s=(ready - begin) / 1e9, ready_to_summary_s=(finished - ready) / 1e9,
                   ready_to_exit_s=(end - ready) / 1e9)
    return row


def make_scap(reference, count, path):
    data = reference.read_bytes()
    offset = 0
    blocks = []
    while offset < len(data):
        kind, size = struct.unpack_from("<II", data, offset)
        if size < 12 or offset + size > len(data) or struct.unpack_from("<I", data, offset + size - 4)[0] != size:
            raise ValueError("invalid reference SCAP block")
        if kind == 0x216:
            if not blocks:
                prefix = data[:offset]
            blocks.append(data[offset:offset + size])
        elif blocks:
            raise ValueError("unexpected metadata inside reference event section")
        offset += size
    if len(blocks) != 60:
        raise ValueError(f"expected 60 reference events, found {len(blocks)}")
    copies, remainder = divmod(count, len(blocks))
    expected_size = len(prefix) + copies * sum(map(len, blocks)) + sum(map(len, blocks[:remainder]))
    if expected_size > LIMIT:
        raise ValueError(f"{count} events need {expected_size} bytes, above the 64 MiB SCAP limit")
    with path.open("xb") as out:
        out.write(prefix)
        for copy in range(copies + bool(remainder)):
            chunk = bytearray()
            for block in (blocks if copy < copies else blocks[:remainder]):
                start = len(chunk)
                chunk.extend(block)
                ts, = struct.unpack_from("<Q", block, 10)
                struct.pack_into("<Q", chunk, start + 10, ts + copy * 3_000_000_000)
            out.write(chunk)
    if path.stat().st_size != expected_size:
        raise ValueError(f"incomplete SCAP: {path}")


def alert_hash(path, plugin=False):
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        for line in stream:
            if not line.startswith(b"{"):
                continue
            row = json.loads(line)
            if plugin:
                if row["source"] != "raven_zeek":
                    continue
                raw = row["output_fields"]["rz.result"]
                result = json.loads(raw)
                result.pop("id", None)
                for field in ("output", "message"):
                    if field in row:
                        row[field] = row[field].replace(raw, "<result>")
                row["output_fields"]["rz.result"] = result
            digest.update(json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            count += 1
    return count, digest.hexdigest()


def plugin_replay(args):
    source = OLD / "bulk/falco-live-detectors-r01/recorded"
    files = ("events.jsonl", "packets.pcap", "reference.scap")
    missing = [name for name in (*files, "alerts.jsonl") if not (source / name).is_file()]
    if missing:
        raise FileNotFoundError(f"missing from {source}: {', '.join(missing)}")
    work = args.out / "plugin-inputs"
    setup_workdir(work, args, plugin=True)
    hashes = {name: sha256(source / name) for name in files}
    archived = json.loads((OLD / "raw/plugin-replay-native-r01/metrics.json").read_text())
    if hashes != archived["inputs"]:
        raise ValueError("recorded plugin input differs from the 287-event/92-packet fixture")
    for name in files:
        (work / name).symlink_to(source / name)
    native = (FALCO / "plugin/replay.yaml").read_text().replace('"format":"replay"', '"format":"replay","host_capture":true')
    (work / "native.yaml").write_text(native)
    (work / "live.yaml").symlink_to(FALCO / "plugin/live.yaml")
    write_json(work / "inputs.json", {**hashes, **{n: sha256(work / n) for n in (
        "live.yaml", "native.yaml", "raven_zeek_rules.yaml", "libraven_zeek.so")}})
    project = runpy.run_path(str(FALCO / "live/check-detectors.py"))["detector_results"]
    live = project(source / "alerts.jsonl")
    rows = []
    for mode in ("native", "sgx"):
        raw = args.out / f"plugin-{mode}"
        cmd = plugin_command(args, mode, "--plugin-host", "native.yaml" if mode == "native" else "live.yaml")
        row = measure(args, raw, work, cmd, mode, "falco-rz-live")
        alerts = raw / "alerts.jsonl"
        count, digest = alert_hash(alerts, plugin=True)
        row.update(events=archived["normalized_events"], packets=archived["packets"], alerts=count,
                   normalized_alert_sha256=digest, matches_live=project(alerts) == live)
        rows.append(row)
    return rows


def main():
    args = arguments(__doc__)
    fixed = args.out / "reference"
    fixed.mkdir()
    subprocess.run([sys.executable, FALCO / "fixture.py"], cwd=fixed, check=True)
    rows = []
    sizes = (60, 300, 600, 3000, 6000) if args.quick else (60, 30_000, 100_000, 300_000, 600_000)
    for n in sizes:
        work = args.out / f"input-{n}"
        setup_workdir(work, args)
        (work / "reference.yaml").symlink_to(FALCO / "reference.yaml")
        scap = work / "reference.scap"
        make_scap(fixed / "reference.scap", n, scap)
        hashes = {name: sha256(work / name) for name in ("reference.scap", "reference.yaml", "falco_rules.yaml")}
        write_json(work / "inputs.json", hashes)
        trials = [("native", ""), ("sgx", "")]
        if n == sizes[3]:
            trials.extend([("native", "-devnull"), ("native", "-file")])
        pair = []
        for mode, suffix in trials:
            raw = args.out / f"{mode}-{n}{suffix}"
            cmd = ([args.package / "usr/bin/falco", "-c", "reference.yaml"] if mode == "native" else
                   [args.build / "bin/falco-sgx", args.build / "falco-enclave.signed", "reference.yaml",
                    "reference.scap", "falco_rules.yaml"])
            discard = suffix == "-devnull"
            row = measure(args, raw, work, cmd, mode, "falco-sgx-fixture", markers=True, discard=discard)
            count, digest = (None, None) if discard else alert_hash(raw / "alerts.jsonl")
            row.update(events=n, scap_sha256=hashes["reference.scap"], scap_bytes=scap.stat().st_size,
                       events_per_second=n / row["ready_to_summary_s"], alerts=count,
                       normalized_alert_sha256=digest, stdout_destination="devnull" if discard else "file",
                       stdout_bytes=None if discard else (raw / "alerts.jsonl").stat().st_size)
            pair.append(row)
        expected = pair[0]["normalized_alert_sha256"]
        for row in pair:
            digest = row["normalized_alert_sha256"]
            row["normalized_alert_hash_equal"] = (digest == expected and pair[1]["normalized_alert_sha256"] == expected
                                                  and pair[0]["alerts"] > 0) if digest is not None else None
        rows.extend(pair)
        write_summary(args.out, rows)

    plugin = plugin_replay(args)
    equal = plugin[0]["normalized_alert_sha256"] == plugin[1]["normalized_alert_sha256"]
    for row in plugin:
        row["normalized_alert_hash_equal"] = equal
    rows.extend(plugin)
    write_summary(args.out, rows)
    if any(row.get("normalized_alert_hash_equal") is False or row.get("matches_live") is False for row in rows):
        raise SystemExit("replay parity check failed, see summary.csv")


if __name__ == "__main__":
    main()
