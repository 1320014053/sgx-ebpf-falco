#!/usr/bin/env python3
import argparse
import csv
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description="Record QEMU TCG + SGX SIM runs; timings are not hardware SGX performance.")
parser.add_argument("--repeats", type=int, default=5)
parser.add_argument("--count", type=int, default=10000)
parser.add_argument("--interval-us", type=int, default=1000)
parser.add_argument("--output", type=Path, default=Path("../results/runs.csv"))
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
args.output.parent.mkdir(parents=True, exist_ok=True)
with args.output.open("w", newline="") as stream:
    writer = None
    for repeat in range(1, args.repeats + 1):
        for mode in ("baseline", "host", "ecall", "batch", "direct"):
            output = subprocess.check_output(
                ["bash", str(root / "scripts/run.sh"), "--mode", mode,
                 "--count", str(args.count), "--interval-us", str(args.interval_us)],
                text=True, timeout=300,
            )
            row = {"repeat": repeat, **json.loads(output)}
            if writer is None:
                writer = csv.DictWriter(stream, fieldnames=row.keys())
                writer.writeheader()
            writer.writerow(row)
            stream.flush()
            print(output.strip(), flush=True)
