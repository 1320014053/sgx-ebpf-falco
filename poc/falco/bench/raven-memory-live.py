"""Local filesystem workload for the signed enclave's live eBPF memory measurement."""

import json
import os
from pathlib import Path
import sys
import tempfile


def access(path):
    os.close(os.open(path, os.O_RDONLY))


def workload(case, directory):
    if case == "repeat":
        path = directory / "repeat"
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        for i in range(1, 20_001):
            os.pwrite(fd, b"x", 0)
            if i % 10_000 == 0:
                access(path)
        os.close(fd)
    elif case == "churn":
        for i in range(1, 5_001):
            child = os.fork()
            if not child:
                try:
                    path = directory / f"file-{i}"
                    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    os.write(fd, b"x")
                    os.close(fd)
                    if i % 2_500 == 0:
                        access(path)
                except OSError:
                    os._exit(1)
                os._exit(0)
            _, status = os.waitpid(child, 0)
            if os.waitstatus_to_exitcode(status):
                raise RuntimeError(f"workload child {i} failed")
    else:
        raise ValueError(case)


def summarize(directory):
    case = directory.name
    checkpoints, diagnostics, marked = [], {}, []
    total = largest = 0
    for line in (directory / "process.log").read_text().splitlines():
        if line.startswith("RZMEM live_"):
            _, phase, events, *fields = line.split()
            used, peak, capacity, rss, anonymous = map(int, fields[-5:])
            checkpoints.append(dict(phase=phase, events=int(events), enclave_used=used, enclave_peak=peak,
                                    enclave_capacity=capacity, rss=rss, anonymous_rss=anonymous))
        elif line.startswith("{"):
            row = json.loads(line)
            if row.get("mode") in ("live", "modern_ebpf"):
                diagnostics[row["mode"]] = row
    ring, driver = diagnostics["live"], diagnostics["modern_ebpf"]
    assert ring["consumer"] == ring["producer"] == driver["consumer"] == driver["producer"]
    assert not any((ring["discarded"], ring["format_rejected"], driver["driver_drops"], driver["packet_drops"]))
    assert checkpoints[0]["phase"] == "live_start" and checkpoints[-1]["phase"] == "live_flushed"
    assert checkpoints[-1]["events"] == ring["raven_events"] >= 20_000
    assert [c["events"] for c in checkpoints[1:-1]] == list(range(10_000, ring["raven_events"] + 1, 10_000))
    with (directory / "alerts.jsonl").open("rb") as stream:
        for line in stream:
            alert = json.loads(line)
            if alert["source"] != "raven_zeek":
                continue
            total += 1
            size = len(line.rstrip(b"\r\n"))
            largest = max(largest, size)
            raw = alert["output_fields"]["rz.result"]
            row = json.loads(raw)
            if row.get("rule") != "sensitive_access_chain":
                continue
            event = row["events"][0]
            path = Path(event["file_path"])
            if not str(path).startswith("/root/rzmem-") or path.name not in ("repeat", "file-2500", "file-5000"):
                continue
            edges = {edge["type"]: edge for edge in row["reconstruction"]["graph"]["edges"]}
            position = len(marked) + 1
            expected_reads = position if case == "repeat" else 1
            expected_writes = position * 10_000 + 1 if case == "repeat" else 2
            assert edges["accessed"]["event_ids"][-1] == event["id"]
            for name, count in (("accessed", expected_reads), ("modified", expected_writes)):
                ids = [int(v.removeprefix("ring-")) for v in edges[name]["event_ids"]]
                assert ids == sorted(set(ids)) and len(ids) == count and edges[name]["count"] == count
            marked.append(dict(event=event["id"], pid=event["pid"], path=str(path), accessed=expected_reads,
                               modified=expected_writes, alert_bytes=size, payload_bytes=len(raw.encode())))
    assert len(marked) == 2, marked
    return dict(checkpoints=checkpoints, process_peak_rss=int((directory / "maxrss.kib").read_text()) * 1024,
                raven_zeek_alerts=total, max_alert_bytes=largest, workload_alerts=marked, capture=diagnostics)


if __name__ == "__main__":
    if sys.argv[1] == "--summarize":
        print(json.dumps(summarize(Path(sys.argv[2])), indent=2))
    else:
        # The RAVEN sensitive-file rule recognizes /root/. All accesses use this new directory.
        with tempfile.TemporaryDirectory(prefix="rzmem-", dir="/root") as tmp:
            workload(sys.argv[1], Path(tmp))
