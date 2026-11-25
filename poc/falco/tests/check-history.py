"""Replay the independent historical cases against their recorded reference results."""

import argparse
import hashlib
import json
import os
from pathlib import Path
from runpy import run_path
import shutil
import struct
import subprocess
import tempfile
from zipfile import ZipFile


here = Path(__file__).resolve().parent
plugin = here.parent / "plugin"
checks = run_path(str(plugin / "check.py"))


def rows(raw):
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def replays(cases, archive, suite):
    for case in cases:
        if (case["mode"] == "ring") != (suite == "ring"):
            continue
        payload = archive.read(case["input"])
        yield case, payload, None
        if suite != "ring":
            continue
        yield case, payload, "raven" if case["translated"] else "zeek"
        if case["name"] != "timer-queue-30":
            continue
        # Keep the SYNs and remove the three trailing 72-byte ACK records at +8, +9 and +10 s.
        syns = payload[:-3 * 72]
        # Use the first execve from the same process snapshot at the original Notice time.
        syscalls = archive.read("history/inputs/boundary-benign.bin")
        size, = struct.unpack_from("<I", syscalls)
        execve = bytearray(syscalls[:8 + ((size + 7) & ~7)])
        struct.pack_into("<Q", execve, 8, 1_700_000_008_000_000_000)
        tick_case = dict(case, name="timer-queue-30-syscall-tick", realtime_ns=1_700_000_010_000_000_000)
        yield tick_case, syns + execve, "zeek"


def run_case(case, payload, only, archive, args, cwd):
    expected = rows(archive.read(case["expected"])) if case["expected"] else []
    mode = case["mode"]
    if mode == "ring":
        (cwd / "ring.bin").write_bytes(payload)
        (cwd / "snapshot.scap").write_bytes(archive.read(case["snapshot"]))
        config = (plugin / "live.yaml").read_text()
        if only:
            both = "    init_config: {raven: true, zeek: true}\n"
            checks["compare"]("live config template entry count", config.count(both), 1)
            disabled = "zeek" if only == "raven" else "raven"
            config = config.replace(both, both.replace(f"{disabled}: true", f"{disabled}: false"))
        (cwd / "live.yaml").write_text(config)
        shutil.copyfile(plugin / "rules.yaml", cwd / "raven_zeek_rules.yaml")
        shutil.copyfile(args.rules, cwd / "falco_rules.yaml")
        command = [args.binary, args.enclave, str(case.get("collector_pid", 0)), str(case.get("realtime_ns", 0)),
                   "falco_rules.yaml", "raven_zeek_rules.yaml"]
        if only == "zeek":
            command.append("--no-record-events")
    else:
        capture = cwd / Path(case["input"]).name
        capture.write_bytes(payload)
        command = [args.binary, mode, capture]
    proc = subprocess.run(command, cwd=cwd, capture_output=True, env=dict(os.environ, TZ="UTC"))
    if proc.returncode != case["exit"]:
        raise AssertionError(f"exit {proc.returncode}, expected {case['exit']}. {proc.stderr.decode(errors='replace')[-220:]}")
    actual = rows(proc.stdout)
    if mode == "ring":
        capture = cwd / "events.jsonl"
        if args.strict or only:
            stats = next((json.loads(line) for line in proc.stderr.splitlines()
                          if line.startswith(b"{") and json.loads(line).get("mode") == "live"), None)
            if stats is None:
                raise AssertionError("missing live stats")
            if only:
                checks["compare"]("enabled detectors", stats.get("detectors"),
                                  {"raven": only == "raven", "zeek": only == "zeek"})
            if args.strict and any(stats["errors"].values()):
                raise AssertionError(f"live errors: {stats['errors']}")
        if only != "zeek":
            translated = rows(archive.read(case["translated"])) if case["translated"] else []
            checks["compare"]("translated events", rows(capture.read_bytes()), translated)
        actual = [json.loads(a["output_fields"]["rz.result"]) for a in actual if a["source"] == "raven_zeek"]
    checks["compare"]("alert count", len(actual), len(expected))
    fixed = checks["fixed_ids"](capture, False) if mode in ("raven", "stream", "ring") and only != "zeek" else set()
    streaming = mode in ("stream", "ring")
    normalize = checks["canonical"]
    checks["compare"]("ordered alerts", normalize(actual, fixed, stream=streaming),
                      normalize(expected, fixed, stream=streaming))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="suite", required=True)
    detector = modes.add_parser("detector", help="test the C++ file, event stream and IP packet interfaces")
    detector.add_argument("binary", type=Path, help="replay-detector")
    ring = modes.add_parser("ring", help="test a signed SGX Simulation enclave with saved ring records")
    ring.add_argument("--strict", action="store_true", help="fail on recovered live processing errors")
    ring.add_argument("binary", type=Path, help="replay-ring")
    ring.add_argument("enclave", type=Path, help="falco-enclave.signed")
    ring.add_argument("rules", type=Path, help="official falco_rules.yaml")
    args = parser.parse_args()
    args.binary = args.binary.resolve(strict=True)
    if args.suite == "ring":
        args.enclave = args.enclave.resolve(strict=True)
        args.rules = args.rules.resolve(strict=True)

    fixtures = here / "fixtures"
    manifest = json.loads((fixtures / "history.json").read_bytes())
    package = fixtures / manifest["archive"]
    checks["compare"]("fixture SHA-256", hashlib.sha256(package.read_bytes()).hexdigest(), manifest["sha256"])
    passed = failed = 0
    with ZipFile(package) as archive:
        for case, payload, only in replays(manifest["cases"], archive, args.suite):
            name = f"{case['mode']}/{case['name']}"
            if only:
                name += f"/{only}-only"
            with tempfile.TemporaryDirectory() as tmp:
                try:
                    run_case(case, payload, only, archive, args, Path(tmp))
                except (AssertionError, ValueError) as exc:
                    previous = " (previously differed)" if case.get("previously_differed") else ""
                    print(f"FAIL {name}{previous}: {exc}", flush=True)
                    failed += 1
                else:
                    print(f"PASS {name}", flush=True)
                    passed += 1
    print(f"{passed} passed, {failed} differed from the reference")
    return int(failed != 0)


if __name__ == "__main__":
    raise SystemExit(main())
