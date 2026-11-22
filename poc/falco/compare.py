#!/usr/bin/env python3
import json
import sys
from collections import Counter
from pathlib import Path


def alerts(path):
    rows = []
    for line in path.read_text().splitlines():
        if line.startswith("Events detected:"):
            break
        if line.strip():
            rows.append(json.loads(line))
    return rows


run = Path(sys.argv[1])
captured = sys.argv[2:] == ["--captured"]
native = alerts(run / "native-alerts.jsonl")
enclave = alerts(run / "sgx-alerts.jsonl")
if len(native) != len(enclave) or not native:
    sys.exit(f"alert counts: native={len(native)}, enclave={len(enclave)}")

for i, (left, right) in enumerate(zip(native, enclave), 1):
    if left != right:
        for key in sorted(left.keys() | right.keys()):
            if left.get(key) != right.get(key):
                print(f"alert {i} ({left['rule']}), {key}: {left.get(key)!r} != {right.get(key)!r}",
                      file=sys.stderr)
        sys.exit(1)
    if any(left["output_fields"].get(field) is None for field in ("evt.num", "evt.type", "thread.tid")):
        sys.exit(f"alert {i} has no complete triggering event identity")

described = json.loads((run / "native-rules.json").read_text())
expected = [rule["info"]["name"] for rule in described["rules"] if rule["info"]["enabled"]]
diagnostics = [json.loads(line) for line in (run / "sgx.log").read_text().splitlines() if line.startswith("{")]
loaded = next(row for row in diagnostics if "enabled" in row)
versions = dict(tuple(part.strip() for part in line.split(":", 1))
                for line in (run / "versions.txt").read_text().splitlines() if ":" in line)
if (versions["Falco version"] != "0.45.2" or loaded["engine"] != versions["Engine"] or
        loaded["libs"] != versions["Libs version"]):
    sys.exit("native and enclave engine versions differ from the pinned baseline")
if (loaded["required_engine_version"] != described["required_engine_version"] or
        loaded["loaded_rules"] != len(described["rules"]) or loaded["enabled"] != expected):
    sys.exit("native and enclave rule inventories differ")

counts = Counter(row["rule"] for row in native)
if not captured:
    expected = json.loads((run / "expected.json").read_text())
    for rule, tids in expected["original"].items():
        actual = [row["output_fields"]["thread.tid"] for row in native if row["rule"] == rule]
        if actual != tids:
            sys.exit(f"{rule}: expected tids {tids}, got {actual}")

print(json.dumps({"pass": True, "matched_alerts": len(native), "loaded_rules": loaded["loaded_rules"],
                  "enabled_rules": len(loaded["enabled"]), "alerts_by_rule": counts}, indent=2))
