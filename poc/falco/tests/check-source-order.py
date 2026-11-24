"""Check both live sources against the same mixed ring replayed by the single analyzer."""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
from runpy import run_path
import struct
import subprocess
import sys
import tempfile
from zipfile import ZipFile


falco = Path(__file__).resolve().parents[1]
checks = run_path(str(falco / "plugin/check.py"))


def write_input():
    fixture = run_path(str(falco / "fixture.py"))
    fixture["write_fixture"]()
    capture = Path("reference.scap").read_bytes()
    records = []
    pos = 0
    while pos < len(capture):
        kind, size = struct.unpack_from("<II", capture, pos)
        if kind == 0x216:
            if not records:
                Path("snapshot.scap").write_bytes(capture[:pos])
            records.append(capture[pos:pos + size])
        pos += size
    records.insert(0, fixture["execve"](0, 100, 1, "/usr/sbin/httpd"))
    ring = []
    for frame in records:
        length, = struct.unpack_from("<I", frame, 26)
        ring.append(struct.pack("<II", length, 0) + frame[10:10 + length] + bytes(-length % 8))
    with ZipFile(falco / "tests/fixtures/regression.zip") as archive:
        ring.insert(2, archive.read("history/inputs/timer-queue-30.bin"))
    Path("ring.bin").write_bytes(b"".join(ring))


def fingerprints(alerts, events):
    plugin = [a for a in alerts if a["source"] == "raven_zeek"]
    raw = [a["output_fields"]["rz.result"] for a in plugin]
    records = checks["canonical"]([json.loads(r) for r in raw], checks["fixed_ids"](events, False), stream=True)
    for alert, original, record in zip(plugin, raw, records):
        for field in ("output", "message"):
            assert original in alert[field]
            alert[field] = alert[field].replace(original, "<result>")
        alert["output_fields"]["rz.result"] = record
    by_source = defaultdict(list)
    for alert in alerts:
        data = json.dumps(alert, sort_keys=True, separators=(",", ":")).encode()
        by_source[alert["source"]].append(hashlib.sha256(data).hexdigest())
    return dict(by_source)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("replay_ring", "enclave", "rules"):
        parser.add_argument(name, type=lambda p: Path(p).resolve(strict=True))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as directory:
        os.chdir(directory)
        write_input()
        for name, source in (("live.yaml", falco / "plugin/live.yaml"), ("falco_rules.yaml", args.rules),
                             ("raven_zeek_rules.yaml", falco / "plugin/rules.yaml")):
            Path(name).symlink_to(source)
        run = subprocess.run([args.replay_ring, args.enclave, "0", "0", "falco_rules.yaml", "raven_zeek_rules.yaml"],
                             env=dict(os.environ, TZ="UTC", FALCO_HOSTNAME="mixed-fixture"), capture_output=True)
        if run.returncode:
            sys.exit(run.stderr.decode(errors="replace"))
        actual = fingerprints([json.loads(line) for line in run.stdout.splitlines()], Path("events.jsonl"))
    # Complete Falco alerts from 6b8a940, in order within each source.
    expected = {
        "syscall": ["7c00047779dc69e8c054d66f414ec9d864ff97fb3d3a7b14c2e8376a92ac6083",
                    "7d1436b323a2eae1374118253d80dcc9d060e890cde9fe3acaf1f6967f3c521a"],
        "raven_zeek": ["091f88bedd2007f0e9ef13ee9f6e3f6164e0a60033d2d1e639a7a8e5062ade8d",
                       "9ee5f94e1ec852101760d7e1282f0b033350b18f5b157d4a648c9dc825449b48"],
    }
    observed = Counter(h for rows in actual.values() for h in rows)
    assert observed == Counter(h for rows in expected.values() for h in rows), actual
    assert actual == expected, actual
    print("PASS complete alert multiset and ordered syscall and raven_zeek alerts")


if __name__ == "__main__":
    main()
