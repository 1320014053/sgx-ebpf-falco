"""Check the two native replay entry points against the pinned upstream implementations."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys

from raven.correlation_engine import CorrelationEngine
from raven.scenario_lab import DATASET_KEYS, get_dataset, playground
from controls import write_controls


here = Path(__file__).resolve().parent
run = Path(sys.argv[1]).resolve()
run.mkdir()
summary = {"raven": {}}
subprocess.run([sys.executable, "-B", "-m", "raven.cli", "scenarios", "--outdir", str(run)], check=True)


def replay(capture, *args, rejection=None):
    output = capture.with_suffix(".detections.jsonl")
    with output.open("x") as stream:
        result = subprocess.run([sys.executable, "-B", str(here / "raven-replay.py"), str(capture), *args],
                                stdout=stream, stderr=subprocess.PIPE if rejection else None, text=True)
    if rejection:
        if result.returncode != 1 or rejection not in result.stderr or output.stat().st_size:
            raise AssertionError(f"unexpected RAVEN rejection for {capture.name}: {result.stderr}")
        capture.with_suffix(".stderr").write_text(result.stderr)
    else:
        result.check_returncode()
    return [json.loads(line) for line in output.read_text().splitlines()]


for key in (*DATASET_KEYS, "idle"):
    scenario = playground() if key == "idle" else get_dataset(key)
    capture = run / f"scenario_{key}.jsonl"
    if key == "idle":
        capture.write_text("".join(json.dumps(event.to_dict()) + "\n" for event in scenario.events))

    # The oracle takes upstream scenario objects directly, independently of the file collector.
    reference = CorrelationEngine(tier="full")
    for event in scenario.events:
        reference.on_event(event)
    reference.settle_context(force=True)
    expected = [d.to_dict() for d in reference.detections]
    actual = replay(capture)
    for rows in (expected, actual):
        for row in rows:
            del row["id"]  # upstream assigns a new UUID per detection on each run
    if actual != expected:
        raise SystemExit(f"RAVEN differed from the upstream engine on scenario {key}")
    summary["raven"][key] = {"active": len(reference.active_detections()),
                           "context_filtered": reference.context_filtered_count()}

# Use the upstream adapter's numeric timestamp format and its supported process_exec shape.
tetragon = run / "tetragon.jsonl"
with tetragon.open("x") as stream:
    for event in get_dataset("B").events:
        stream.write(json.dumps({"ts": event.ts, event.event_type: {
            "process": {"pid": event.pid, "binary": event.exe}, "parent": {"pid": event.ppid}}}) + "\n")
rows = replay(tetragon, "--format", "tetragon")
if [(d["rule"], d["state"], [e["pid"] for e in d["events"]]) for d in rows] != [
        ("server_spawns_shell", "active", [22, 220])]:
    raise SystemExit("RAVEN Tetragon replay mismatch")
summary["tetragon"] = {"active": len(rows)}

pcap = run / "healthchecks.pcap"
subprocess.run([sys.executable, "-B", str(here / "scan-fixture.py"), str(pcap)], check=True)
subprocess.run(["bash", str(here / "zeek-replay.sh"), str(pcap), str(run / "zeek")], check=True)
notices = [json.loads(line) for line in (run / "zeek/notice.log").read_text().splitlines()]
fixtures = here.parent / "tests/fixtures"
oracle = fixtures / "zeek-notices.jsonl"
if notices != [json.loads(line) for line in oracle.read_text().splitlines()]:
    raise SystemExit("Zeek differed from the recorded upstream notices")
with (run / "zeek/conn.log").open() as stream:
    connections = sum(1 for line in stream if line.strip())
if connections != 90:
    raise SystemExit(f"expected 90 connections, got {connections}")
summary["zeek"] = {"connections": connections, "notices": [n["note"] for n in notices]}
write_controls(run)
(run / "F.jsonl").write_text("".join(json.dumps(e.to_dict(), ensure_ascii=False)+"\n" for e in get_dataset("F").events))
review = json.loads((fixtures / "upstream-parity-review.json").read_text())
summary["review_inputs"] = {}
for case in review["cases"]:
    name = case["case"]
    suffix = ".jsonl" if case["engine"] == "RAVEN" else ".pcap"
    capture = run / (name + suffix)
    digest = hashlib.sha256(capture.read_bytes()).hexdigest()
    if digest != case["input_sha256"]:
        raise AssertionError(f"{name} differs from reviewed input: {digest}")
    summary["review_inputs"][name] = digest
    if name == "tetragon-rfc3339":
        replay(capture, "--format", "tetragon", rejection="could not convert string to float: '2025-01-01T12:00:00Z'")
    elif suffix == ".jsonl":
        replay(capture)
replay(run / "boundaries.jsonl")
replay(run / "tetragon-mixed.jsonl", "--format", "tetragon")
for case, expected_count in {"states": 2, "epochs": 2, "suppression-expiry": 3, "ipv6-vlan": 1,
                             "reverse-eof": 1, "fragments": 1, "pcapng": 1}.items():
    subprocess.run(["bash", str(here / "zeek-replay.sh"), str(run / (case + ".pcap")), str(run / case)], check=True)
    case_rows = [json.loads(line) for line in (run / case / "notice.log").read_text().splitlines()]
    if [n["note"] for n in case_rows] != ["Scan::Port_Scan"] * expected_count:
        raise SystemExit(f"unexpected original Zeek notices in {case}")
for case in ("successful-handshakes", "reordered-successful-handshakes", "ppp-serial-handshakes",
             "nanosecond-healthchecks", "ppp-serial-healthchecks", "ppp-serial-ipv6", "ppp-serial-mpls",
             "pcapng-submicrosecond"):
    logs = run / case
    subprocess.run(["bash", str(here / "zeek-replay.sh"), str(run / (case + ".pcap")), str(logs)], check=True)
    notice_log = logs / "notice.log"
    expected, count = [], 15
    if case.endswith("healthchecks"):
        expected, count = notices, 90
    elif not case.endswith("handshakes"):
        expected = [json.loads(s) for s in (run / "ipv6-vlan/notice.log").read_text().splitlines()]
    actual = [json.loads(s) for s in notice_log.read_text().splitlines()] if notice_log.exists() else []
    if actual != expected or len((logs / "conn.log").read_text().splitlines()) != count:
        raise AssertionError(f"unexpected original Zeek notices or connection count in {case}")
(run / "comparison.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
