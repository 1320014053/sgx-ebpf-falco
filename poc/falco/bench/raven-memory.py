"""Measure RAVEN full-evidence replay in the Falco release and signed SGX Simulation enclave."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import time


BLOCK = 10_000
SAMPLE_KEYS = ("events", "nodes", "edges", "edge_ids", "tree_pids", "ledger_pids", "detections",
               "enclave_used", "enclave_peak", "enclave_capacity", "rss", "anonymous_rss")


def sha256(path):
    with path.open("rb") as stream:
        value = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def event(case, i):
    group, step = divmod(i - 1, 4)
    read = i % BLOCK == BLOCK - 1
    if case == "repeat":
        pid, path = 2000, "/etc/cron.d/rz-memory.conf"
        kind = "process_exec" if i == 1 else "file_access" if read else "file_modify"
    else:
        pid, path = 10_000 + group, f"/etc/cron.d/rz-memory-{group:07}.conf"
        kind = ("process_exec", "file_modify", "file_access" if read else "file_modify", "process_exit")[step]
    row = dict(event_id=f"ring-{i}", ts=1_700_000_000 + i / 1000, event_type=kind, pid=pid,
               ppid=1, exe="/usr/bin/cp", user="1000", uid=1000, euid=1000)
    if kind in ("file_access", "file_modify"):
        row.update(file_path=path, file_op="open" if read else "write")
    return row


def expected_counts(case, n):
    if not n:
        return (0, 0, 0)
    if case == "repeat":
        return 5, 5, n + 2
    groups = n // 4
    return 2 * groups + 3, 4 * groups + n // BLOCK, 5 * groups


def samples(log, case, mode, n):
    result = []
    for line in log.read_text().splitlines():
        if line.startswith("RZMEM "):
            _, phase, *fields = line.split()
            if len(fields) != len(SAMPLE_KEYS):
                raise ValueError(line)
            sample = dict(zip(SAMPLE_KEYS, map(int, fields)), phase=phase)
            if phase in ("events", "start", "settled"):
                actual = tuple(sample[k] for k in ("nodes", "edges", "edge_ids"))
                assert actual == expected_counts(case, sample["events"]), (case, sample)
                assert sample["detections"] == sample["events"] // BLOCK
            if mode == "sgx":
                assert 0 < sample["enclave_used"] <= sample["enclave_peak"] <= sample["enclave_capacity"]
            assert sample["rss"] >= sample["anonymous_rss"] > 0
            result.append(sample)
    phases = ["start"] + ["events"] * (n // BLOCK) + ["settled"] + (["flushed"] if mode == "sgx" else [])
    assert [s["phase"] for s in result] == phases, result
    assert [s["events"] for s in result if s["phase"] == "events"] == list(range(BLOCK, n + 1, BLOCK))
    return result


def verify_output(path, case, n):
    digest = hashlib.sha256()
    sizes = []
    reads = [f"ring-{i}" for i in range(BLOCK - 1, n, BLOCK)]
    writes = [f"ring-{i}" for i in range(2, n + 1) if i % BLOCK != BLOCK - 1] if case == "repeat" else []
    detection_ids = set()
    with path.open("rb") as stream:
        for line in stream:
            if not line.startswith(b"{"):
                continue
            alert = json.loads(line)
            if alert["source"] != "raven_zeek":
                continue
            raw = alert["output_fields"].pop("rz.result")
            row = json.loads(raw)
            signal = (len(sizes) + 1) * BLOCK - 1
            assert row["rule"] == "sensitive_access_chain" and row["state"] == "active"
            assert [e["id"] for e in row["events"]] == [f"ring-{signal}"]
            edges = {e["type"]: e for e in row["reconstruction"]["graph"]["edges"]}
            assert set(edges) == {"accessed", "modified"}
            assert edges["accessed"]["event_ids"] == (reads if case == "repeat" else [f"ring-{signal}"])
            assert edges["modified"]["event_ids"] == (writes if case == "repeat" else [f"ring-{signal-1}"])
            generated = row.pop("id")
            assert re.fullmatch(r"det-[a-f0-9]{12}", generated) and generated not in detection_ids
            detection_ids.add(generated)
            for field in ("output", "message"):
                if field in alert:
                    assert raw in alert[field]
                    alert[field] = alert[field].replace(raw, "<result>")
            digest.update(json.dumps([alert, row], sort_keys=True, separators=(",", ":")).encode() + b"\n")
            sizes.append(dict(event=signal, payload_bytes=len(raw.encode()), alert_bytes=len(line.rstrip(b"\r\n"))))
    assert len(sizes) == n // BLOCK, (case, len(sizes))
    return dict(alerts=len(sizes), max_payload_bytes=max(s["payload_bytes"] for s in sizes),
                max_alert_bytes=max(s["alert_bytes"] for s in sizes), per_alert=sizes,
                ordered_alert_sha256=digest.hexdigest())


def verify_upstream(source, out):
    replay = Path(__file__).resolve().parents[1] / "upstream/raven-replay.py"
    result = {}
    for case in ("repeat", "churn"):
        path = out / (case + "-upstream.jsonl")
        with path.open("xb") as stream:
            subprocess.run([sys.executable, "-B", replay, out / (case + ".jsonl")],
                           env=dict(os.environ, TZ="UTC", PYTHONPATH=str(source)), stdout=stream, check=True)
        counts = {}
        for mode in ("native", "sgx"):
            falco_path = out / f"{case}-{mode}-release-0/output.jsonl"
            with falco_path.open("rb") as falco, path.open("rb") as oracle:
                count = 0
                for line in falco:
                    if not line.startswith(b"{"):
                        continue
                    alert = json.loads(line)
                    if alert["source"] != "raven_zeek":
                        continue
                    actual = json.loads(alert["output_fields"]["rz.result"])
                    expected = json.loads(next(oracle))
                    assert expected["rule_source"].endswith("/" + actual["rule_source"])
                    expected["rule_source"] = actual["rule_source"]
                    for row in (expected, actual):
                        detection_id = row.pop("id")
                        assert re.fullmatch(r"det-[a-f0-9]{12}", detection_id)
                    assert actual == expected, (case, mode, count + 1)
                    count += 1
                assert not oracle.readline(), (case, mode)
                counts[mode] = count
        result[case] = dict(matching_complete_records=counts)
    return result


def run(case, mode, artifact, build, paths, name, n):
    here, package, baseline, out = paths
    cwd = out / name
    cwd.mkdir()
    links = {"events.jsonl": out / (case + ".jsonl"), "packets.pcap": out / "empty.pcap",
             "libcontainer.so": baseline / "libcontainer.so", "libraven_zeek.so": build / "lib/libraven_zeek.so",
             "reference.scap": baseline / "reference.scap", "falco_rules.yaml": baseline / "falco_rules.yaml",
             "raven_zeek_rules.yaml": here / "plugin/rules.yaml", "falco.yaml": here / "plugin/replay.yaml"}
    for target, source in links.items():
        (cwd / target).symlink_to(source)
    if mode == "native":
        cmd = [package / "usr/bin/falco", "-c", "falco.yaml", "-o", "engine.kind=modern_ebpf",
               "--enable-source", "raven_zeek"]
    else:
        cmd = [build / "bin/falco-sgx", build / "falco-enclave.signed", "falco.yaml", "reference.scap",
               "--plugin", "events.jsonl", "packets.pcap", "falco_rules.yaml", "raven_zeek_rules.yaml"]
    start = time.monotonic()
    with (cwd / "output.jsonl").open("xb") as stdout, (cwd / "process.log").open("xb") as stderr:
        result = subprocess.run(["/usr/bin/time", "-q", "-f", "%M", "-o", "maxrss.kib", *cmd],
                                cwd=cwd, env=dict(os.environ, TZ="UTC", FALCO_HOSTNAME="raven-memory"),
                                stdout=stdout, stderr=stderr)
    elapsed = time.monotonic() - start
    if result.returncode:
        raise RuntimeError(f"{name} exited {result.returncode}: {(cwd/'process.log').read_text()[-1500:]}")
    output = verify_output(cwd / "output.jsonl", case, n)
    checkpoints = samples(cwd / "process.log", case, mode, n) if artifact == "profile" else []
    hwm = int((cwd / "maxrss.kib").read_text().strip()) * 1024
    assert hwm > 0
    row = dict(workload=case, mode=mode, artifact=artifact, run=name, wall_seconds=round(elapsed, 3),
               process_peak_rss=hwm, checkpoints=checkpoints, **output)
    (cwd / "measurements.json").write_text(json.dumps(row, indent=2) + "\n")
    print(name, "verified", output["alerts"], "alerts, max", output["max_alert_bytes"], "bytes, peak RSS", hwm, flush=True)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("package", "release", "profile", "baseline", "out"):
        parser.add_argument(arg, type=Path)
    parser.add_argument("--events", type=int, default=100_000)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--upstream", type=Path, help="also check both release outputs against this pinned RAVEN source")
    args = parser.parse_args()
    if args.events < BLOCK or args.events % BLOCK or args.repeats < 1:
        parser.error("use a positive multiple of 10000 events and at least one repeat")
    package, release, profile, baseline, out = (getattr(args, k).resolve() for k in ("package", "release", "profile", "baseline", "out"))
    here = Path(__file__).resolve().parents[1]
    out.mkdir()
    (out / "empty.pcap").write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    inputs = {}
    for case in ("repeat", "churn"):
        path = out / (case + ".jsonl")
        with path.open("xb") as stream:
            for i in range(1, args.events + 1):
                stream.write(json.dumps(event(case, i), separators=(",", ":")).encode() + b"\n")
        inputs[case] = dict(bytes=path.stat().st_size, sha256=sha256(path))
    builds = {"release": release, "profile": profile}
    binaries = {k: {str(rel): sha256(b / rel) for rel in ("lib/libraven_zeek.so", "bin/falco-sgx", "falco-enclave.signed")}
                for k, b in builds.items()}
    binaries["falco"] = sha256(package / "usr/bin/falco")
    runs = []
    for iteration in range(args.repeats + 1):
        artifact = "profile" if iteration else "release"
        for case in ("repeat", "churn"):
            for mode in (("native", "sgx") if iteration % 2 == 0 else ("sgx", "native")):
                name = f"{case}-{mode}-{artifact}-{iteration}"
                row = run(case, mode, artifact, builds[artifact], (here, package, baseline, out), name, args.events)
                same_case = next((r for r in runs if r["workload"] == case), None)
                if same_case:
                    for field in ("ordered_alert_sha256", "per_alert"):
                        assert row[field] == same_case[field], (name, field)
                runs.append(row)
    report = dict(events_per_workload=args.events, profile_repeats=args.repeats, inputs=inputs,
                  binaries_sha256=binaries, machine=os.uname().release, runs=runs)
    if args.upstream:
        report["upstream"] = verify_upstream(args.upstream.resolve(), out)
    (out / "measurements.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
