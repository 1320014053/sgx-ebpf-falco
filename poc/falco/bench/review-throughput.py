import argparse
import json
import subprocess
import tempfile
import time
from pathlib import Path


def measure(replay, chains, background, path, profile):
    with path.open("w") as events:
        for i in range(chains):
            parent = 10000 + 2 * i
            for pid, ppid, exe in ((parent, 1, "/usr/sbin/nginx"),
                                   (parent + 1, parent, "/bin/sh")):
                print(json.dumps(dict(event_id=f"exec-{pid}", ts=1000 + i / 1000,
                                      event_type="process_exec", pid=pid, ppid=ppid, exe=exe)), file=events)
        for i in range(background):
            print(json.dumps(dict(event_id=f"file-{i}", ts=1100 + i / background,
                                  event_type="file_access", pid=42, ppid=1, exe="/bin/cat",
                                  file_path="/opt/fixture.txt", file_op="open")), file=events)

    start = time.monotonic()
    command = [replay, "stream", path]
    if profile:
        command.append(str(2 * chains))
    with tempfile.TemporaryFile() as diagnostics, subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=diagnostics) as process:
        count = 0
        for line in process.stdout:
            row = json.loads(line)
            if row["rule"] != "server_spawns_shell" or row["state"] != "active":
                raise ValueError(f"unexpected detection: {row['rule']} {row['state']}")
            count += 1
        if process.wait():
            diagnostics.seek(0)
            raise RuntimeError(diagnostics.read().decode(errors="replace"))
        diagnostics.seek(0)
        detail = {}
        if profile:
            for line in diagnostics:
                if line.startswith(b"REVIEW "):
                    interval = json.loads(line[7:])
                    assert interval["background"] == background
                    detail["background_per_second"] = background / interval["seconds"]
                if line.startswith(b"RZRET "):
                    sample = json.loads(line[6:])
                    if sample["phase"] == "finish":
                        detail.update({key: sample[key] for key in ("review_calls", "settle_calls", "lineage_calls")})
    elapsed = time.monotonic() - start
    if count != chains:
        raise ValueError(f"expected {chains} detections, received {count}")
    print(json.dumps(dict(chains=chains, background=background, seconds=elapsed,
                          events_per_second=(2 * chains + background) / elapsed, **detail)), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("replay", type=Path)
    parser.add_argument("--chains", type=int, nargs="+", default=[0, 10, 100, 1000])
    parser.add_argument("--background", type=int, default=10000)
    parser.add_argument("--profile", action="store_true", help="measure background processing separately from chain creation")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as temp:
        for n in args.chains:
            measure(args.replay.resolve(), n, args.background, Path(temp) / "events.jsonl", args.profile)
