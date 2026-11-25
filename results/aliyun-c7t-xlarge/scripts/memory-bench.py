"""E7. Use a build with memory-probe.patch applied to poc/falco before compilation.

The signed enclave and shared plugin both need the patch. RAVEN's retention
probe is already built in. Zeek samples classic PCAP replay through the same
retention_report() path with retention_metrics enabled in the input config.
"""

import json
from pathlib import Path
import runpy
import struct
import subprocess
import sys


SCRIPTS = Path(__file__).resolve().parent
replay = runpy.run_path(str(SCRIPTS / "replay-bench.py"))
FALCO = replay["FALCO"]
retention = runpy.run_path(str(FALCO / "bench/raven-retention.py"))
sessions = runpy.run_path(str(SCRIPTS / "zeek-sessions.py"))
EVENTS = 1_000_000


def raven_metrics(raw, case, mode, source):
    events = source["events"]
    verified = retention["verify_alerts"](raw / "alerts.jsonl", case, events, True)
    samples = retention["metrics"](raw / "stderr.log")
    finish = next(s for s in samples if s["phase"] == "finish")
    checkpoints = [s["seen"] for s in samples if s["phase"] in ("start", "events")]
    if (checkpoints != list(range(0, events + 1, 10_000)) or finish["seen"] != events
            or finish["ordinal_ids"] != events or finish["hash"] != source["order"]
            or finish["evicted"] + finish["observations"] != events or finish["resets"] or finish["skipped"]
            or finish["published"] != verified["alerts"] or verified["alerts"] != events // 10_000):
        raise ValueError(f"{raw.name}: incomplete RAVEN stream or alert delivery")
    collects = [s for s in samples if s["phase"] == "collected"]
    field = "heap" if mode == "sgx" else "rss"
    baseline = [s[field] for s in collects if s["seen"] >= events // 2]
    if len(collects) != finish["cycles"] or len(baseline) < 2:
        raise ValueError(f"{raw.name}: insufficient post-reclaim samples")
    peak = max(s["heap_peak"] for s in samples) if mode == "sgx" else None
    if mode == "sgx" and not peak:
        raise ValueError("missing trusted heap peak")
    return dict(events=events, alerts=verified["alerts"], alert_sha256=verified["alert_sha256"],
                max_alert_bytes=verified["max_alert_bytes"], reclaim_count=finish["cycles"],
                baseline_samples=len(baseline), baseline_metric=field, baseline_min_bytes=min(baseline),
                baseline_max_bytes=max(baseline), baseline_span_bytes=max(baseline) - min(baseline),
                trusted_heap_peak_bytes=peak)


def zeek_metrics(raw, mode, half_open, complete):
    samples = [s for s in retention["metrics"](raw / "stderr.log") if s["phase"].startswith("zeek_")]
    if not samples:
        raise ValueError(f"{raw.name}: missing Zeek probe, apply memory-probe.patch and rebuild the plugin and enclave")
    n = half_open + 6 * complete + sessions["TAIL"]
    regular = [s for s in samples if s["phase"] == "zeek_packets"]
    if [s["packets"] for s in regular] != list(range(10_000, n + 1, 10_000)):
        raise ValueError(f"{raw.name}: missing packet checkpoints")
    at_syn_peak = next(s for s in regular if s["packets"] == half_open)
    before, after, finish = (next(s for s in samples if s["phase"] == p)
                             for p in ("zeek_before_gap", "zeek_after_expiry", "zeek_finish"))
    if (at_syn_peak["connections"] != half_open or before["connections"] <= 0
            or before["packets"] != n - sessions["TAIL"] or after["packets"] != n or finish["packets"] != n
            or after["capture_time"] - before["capture_time"] < sessions["GAP_SECONDS"] or after["connections"]):
        raise ValueError(f"{raw.name}: connection-state creation or capture-time expiry check failed")
    alerts, digest = replay["alert_hash"](raw / "alerts.jsonl", plugin=True)
    if alerts:
        raise ValueError(f"{raw.name}: {alerts} unexpected detector alerts")
    peak = max(s["heap_peak"] for s in samples) if mode == "sgx" else None
    if mode == "sgx" and not 0 < after["heap"] <= peak:
        raise ValueError(f"{raw.name}: invalid allocator sample")
    return dict(packets=n, alerts=alerts, alert_sha256=digest, trusted_heap_peak_bytes=peak,
                trusted_heap_after_expiry_bytes=after.get("heap"), connections_at_syn_peak=at_syn_peak["connections"],
                connections_before_gap=before["connections"], connections_after_expiry=after["connections"])


def main():
    args = replay["arguments"](__doc__)
    inputs = args.out / "inputs"
    retention["generate"](inputs, 40_000 if args.quick else EVENTS)
    manifest = json.loads((inputs / "inputs.json").read_text())
    subprocess.run([sys.executable, FALCO / "fixture.py"], cwd=inputs, check=True)
    (inputs / "empty.jsonl").touch()
    (inputs / "empty.pcap").write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
    half_open, complete = (10_000, 8000) if args.quick else (sessions["HALF_OPEN"], sessions["COMPLETE"])
    sessions["generate"](inputs / "zeek.pcap", half_open, complete)
    rows = []
    for case in ("repeat", "churn", "zeek"):
        work = args.out / f"input-{case}"
        replay["setup_workdir"](work, args, plugin=True)
        (work / "reference.scap").symlink_to(inputs / "reference.scap")
        (work / "events.jsonl").symlink_to(inputs / ("empty.jsonl" if case == "zeek" else case + ".jsonl"))
        (work / "packets.pcap").symlink_to(inputs / ("zeek.pcap" if case == "zeek" else "empty.pcap"))
        params = dict(events="events.jsonl", pcap="packets.pcap", format="replay" if case == "zeek" else "stream",
                      retention_metrics=True)
        if args.quick and case != "zeek":
            params["history_bytes"] = 1024**2
        config = (FALCO / "plugin/replay.yaml").read_text()
        original = '{"events":"events.jsonl","pcap":"packets.pcap","format":"replay"}'
        if config.count(original) != 1:
            raise ValueError("unexpected open_params in plugin/replay.yaml")
        (work / "falco.yaml").write_text(config.replace(original, json.dumps(params, separators=(",", ":"))))
        hashes = {n: replay["sha256"](work / n) for n in ("events.jsonl", "packets.pcap", "reference.scap",
                  "falco.yaml", "falco_rules.yaml", "raven_zeek_rules.yaml", "libraven_zeek.so")}
        replay["write_json"](work / "inputs.json", hashes)
        if case != "zeek" and hashes["events.jsonl"] != manifest[case]["sha256"]:
            raise ValueError(f"input hash differs from {case} generator manifest")
        pair = []
        for mode in ("native", "sgx"):
            raw = args.out / f"{case}-{mode}"
            cmd = replay["plugin_command"](args, mode, "--plugin" if case == "zeek" else "--plugin-stream", "falco.yaml")
            row = replay["measure"](args, raw, work, cmd, mode, "raven-retention")
            metrics = (zeek_metrics(raw, mode, half_open, complete) if case == "zeek"
                       else raven_metrics(raw, case, mode, manifest[case]))
            row.update(workload=case, input_sha256=hashes["packets.pcap" if case == "zeek" else "events.jsonl"], **metrics)
            pair.append(row)
        equal = pair[0]["alert_sha256"] == pair[1]["alert_sha256"]
        for row in pair:
            row["normalized_alert_hash_equal"] = equal
        rows.extend(pair)
        replay["write_summary"](args.out, rows)
    if not all(row["normalized_alert_hash_equal"] for row in rows):
        raise SystemExit("memory replay alert parity check failed, see summary.csv")


if __name__ == "__main__":
    main()
