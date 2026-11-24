"""Verify detector output while the producer is still running, with and without test captures."""

import errno
import getpass
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time


def workload(live, gate):
    with tempfile.TemporaryDirectory() as tmp:
        worker = shutil.copy2(live / "httpd", Path(tmp) / "worker")
        subprocess.run([live / "httpd", worker], check=True)
    # Each destination belongs to this test. Bound, non-listening sockets return ECONNREFUSED.
    destinations = []
    try:
        for _ in range(15):
            endpoint = socket.socket()
            endpoint.bind(("127.0.0.1", 0))
            destinations.append(endpoint)
        port = destinations[0].getsockname()[1]
        for last_octet in range(2, 26):
            endpoint = socket.socket()
            endpoint.bind((f"127.0.0.{last_octet}", port))
            destinations.append(endpoint)
        for endpoint in destinations:
            with socket.socket() as client:
                if client.connect_ex(endpoint.getsockname()) != errno.ECONNREFUSED:
                    raise RuntimeError("expected a refused loopback connection")
        (gate.parent / "waiting").touch()
        deadline = time.monotonic() + 25
        while not gate.exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("workload exited without receiving live detector acknowledgements")
            time.sleep(0.05)
    finally:
        for endpoint in destinations:
            endpoint.close()


def detector_results(path):
    raven, notices = {}, []
    for line in path.read_text().splitlines():
        if not line.startswith("{"):
            continue
        alert = json.loads(line)
        if alert["source"] != "raven_zeek":
            continue
        row = json.loads(alert["output_fields"]["rz.result"])
        if "note" in row:
            notices.append(row)
        else:
            key = row["rule"], tuple(e["id"] for e in row["events"])
            raven[key] = (row["state"], row["risk"], row["breakdown"], row["events"])
    return raven, notices


def check(package, build, live, out, strict=False):
    here = Path(__file__).resolve().parent
    out.mkdir()
    shutil.copy2(here.parent / "plugin/live.yaml", out / "live.yaml")
    shutil.copy2(here.parent / "plugin/rules.yaml", out / "raven_zeek_rules.yaml")
    shutil.copy2(package / "etc/falco/falco_rules.yaml", out)
    summary = {"kernel": os.uname().release}
    for name, record in (("ring-only", False), ("recorded", True)):
        cwd = out / name
        cwd.mkdir()
        for path in ("live.yaml", "falco_rules.yaml", "raven_zeek_rules.yaml"):
            (cwd / path).symlink_to(out / path)
        cmd = ([] if os.geteuid() == 0 else ["sudo", "-n"]) + ["env", "TZ=UTC", "FALCO_HOSTNAME=falco-rz-live", "FALCO_SGX_REPORT=1",
               live / "falco-live", build / "falco-enclave.signed", "live.yaml", "4096",
               "reference.scap" if record else "-"]
        if record:
            cmd.extend(["--record-inputs", "events.jsonl", "packets.pcap"])
        gate = cwd / "release"
        cmd.extend(["falco_rules.yaml", "raven_zeek_rules.yaml"])
        fixture = [sys.executable, Path(__file__).resolve(), "--workload", live, gate]
        if record:
            cmd.extend(["--", "runuser", "-u", getpass.getuser(), "--", *fixture])
        found = set()
        external = collector_pid = None
        with (cwd / "alerts.jsonl").open("xb") as output, (cwd / "live.log").open("xb") as err:
            with subprocess.Popen(cmd, cwd=cwd, stdout=output, stderr=err) as proc:
                try:
                    deadline = time.monotonic() + 120
                    while proc.poll() is None and time.monotonic() < deadline:
                        if not record and external is None:
                            for line in (cwd / "live.log").read_bytes().splitlines(keepends=True):
                                if line.startswith(b'{"mode":"capture_ready",') and line.endswith(b"\n"):
                                    collector_pid = json.loads(line)["pid"]
                                    external = subprocess.Popen(fixture, cwd=cwd)
                                    break
                        if (cwd / "waiting").exists():
                            for line in (cwd / "alerts.jsonl").read_bytes().splitlines(keepends=True):
                                if not line.endswith(b"\n"):
                                    continue
                                alert = json.loads(line)
                                if alert["source"] != "raven_zeek":
                                    continue
                                row = json.loads(alert["output_fields"]["rz.result"])
                                if row.get("rule") == "server_spawns_shell" and row["root_exe"] == "httpd":
                                    found.add(row["rule"])
                                if row.get("note") == "Scan::Port_Scan" and row["src"] == row["dst"] == "127.0.0.1":
                                    found.add(row["note"])
                                if row.get("note") == "Scan::Address_Scan" and row["src"] == "127.0.0.1":
                                    found.add(row["note"])
                            if len(found) == 3:
                                break
                        time.sleep(0.1)
                    if len(found) != 3 or proc.poll() is not None:
                        raise AssertionError(f"{name}: before workload release saw {sorted(found)}; see {cwd / 'live.log'}")
                finally:
                    gate.touch()
                    if collector_pid is not None and proc.poll() is None:
                        subprocess.run(["sudo", "-n", "kill", "-TERM", str(collector_pid)], check=True)
                    elif not record and proc.poll() is None:
                        proc.terminate()
                    if external is not None and external.wait(timeout=30) != 0:
                        raise RuntimeError("external workload failed")
                if proc.wait(timeout=45) != 0:
                    raise RuntimeError(f"{name}: live consumer failed")
        lines = (cwd / "live.log").read_text().splitlines()
        summary["enclave_mode"] = "SGX hardware DEBUG=0" if any(s.startswith("REPORT DEBUG=0 ") for s in lines) else "SGX Simulation"
        logs = [json.loads(s) for s in lines if s.startswith("{")]
        ring = next(r for r in logs if r.get("mode") == "live")
        if strict and any(ring["errors"].values()):
            raise AssertionError(f"live errors: {ring['errors']}")
        driver = next(r for r in logs if r.get("mode") == "modern_ebpf")
        assert driver["data_ecalls"] == 5
        assert ring["raven_events"] > 0 and ring["packet_records"] == driver["packet_submitted"] > 0
        assert driver["driver_events"] + ring["packet_records"] == ring["accepted"] == ring["records"]
        assert driver["consumer"] == driver["producer"] == ring["consumer"] == ring["producer"]
        assert not any((driver["driver_drops"], driver["packet_drops"], ring["discarded"], ring["format_rejected"]))
        assert all((cwd / p).exists() == record for p in ("events.jsonl", "packets.pcap", "reference.scap"))
        result = {"before_workload_exit": sorted(found), "syscall_records": driver["driver_events"],
                  "raven_events": ring["raven_events"], "packets": ring["packet_records"],
                  "driver_drops": driver["driver_drops"], "packet_drops": driver["packet_drops"],
                  "discarded": ring["discarded"], "format_rejected": ring["format_rejected"],
                  "map_id": driver["map_id"], "drained_position": ring["consumer"],
                  "stopped_by": "workload exit" if record else "SIGTERM",
                  "input_files": ["events.jsonl", "packets.pcap", "reference.scap"] if record else []}
        if record:
            events = (cwd / "events.jsonl").read_text().splitlines()
            assert len(events) == ring["raven_events"] and all(json.loads(e)["event_id"] for e in events)
            packets = (cwd / "packets.pcap").read_bytes()
            assert struct.unpack_from("<I", packets)[0] == 0xa1b23c4d
            pos, count = 24, 0
            while pos < len(packets):
                _, _, cap, wire = struct.unpack_from("<4I", packets, pos)
                assert 0 < cap <= wire and pos + 16 + cap <= len(packets)
                pos += 16 + cap
                count += 1
            assert count == ring["packet_records"]
            cmd = [build / "bin/falco-sgx", build / "falco-enclave.signed", "live.yaml", "reference.scap",
                   "--plugin-host", "events.jsonl", "packets.pcap", "falco_rules.yaml", "raven_zeek_rules.yaml"]
            with (cwd / "replay.jsonl").open("xb") as output, (cwd / "replay.log").open("xb") as log:
                subprocess.run(cmd, cwd=cwd, stdout=output, stderr=log,
                               env=dict(os.environ, TZ="UTC", FALCO_HOSTNAME="falco-rz-live"), check=True)
            def official_alerts(name):
                alerts = map(json.loads, (cwd / name).read_text().splitlines())
                return [alert for alert in alerts if alert["source"] == "syscall"]

            assert official_alerts("alerts.jsonl") == official_alerts("replay.jsonl"), "ordered syscall alerts differ"
            replay_config = (here.parent / "plugin/replay.yaml").read_text().replace(
                '"format":"replay"', '"format":"replay","host_capture":true')
            (cwd / "native.yaml").write_text(replay_config)
            (cwd / "libcontainer.so").symlink_to(package / "usr/share/falco/plugins/libcontainer.so")
            (cwd / "libraven_zeek.so").symlink_to(build / "lib/libraven_zeek.so")
            with (cwd / "native.jsonl").open("xb") as output, (cwd / "native.log").open("xb") as log:
                subprocess.run([package / "usr/bin/falco", "-c", "native.yaml", "-o", "engine.kind=modern_ebpf",
                                "--enable-source", "raven_zeek"], cwd=cwd, stdout=output, stderr=log,
                               env=dict(os.environ, TZ="UTC"), check=True)
            observed = detector_results(cwd / "alerts.jsonl")
            assert observed == detector_results(cwd / "replay.jsonl"), "enclave replay differs from live detection"
            assert observed == detector_results(cwd / "native.jsonl"), "native replay differs from live detection"
            result["recorded_replay"] = ["enclave", "native"]
        summary[name] = result
    (out / "comparison.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


if __name__ == "__main__":
    if sys.argv[1] == "--workload":
        workload(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        strict = sys.argv[1] == "--strict"
        if strict:
            del sys.argv[1]
        if len(sys.argv) != 5:
            sys.exit("usage: check-detectors.py FALCO_PACKAGE BUILD_DIR LIVE_BUILD_DIR NEW_RUN_DIRECTORY")
        print(json.dumps(check(*(Path(p).resolve() for p in sys.argv[1:]), strict=strict), indent=2))
