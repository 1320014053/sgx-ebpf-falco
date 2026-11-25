"""Verify live detector selection, alerts before workload exit, and recorded replay."""

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
        with socket.socket() as listener, socket.socket() as client:
            listener.bind(("127.0.0.26", port))
            listener.listen()
            client.connect(listener.getsockname())
            peer, _ = listener.accept()
            peer.close()
        marker = gate.parent / "raven-file-marker"
        marker.write_bytes(b"raven write\n")
        assert marker.read_bytes() == b"raven write\n"
        marker.chmod(0o700)
        child = subprocess.Popen(["/bin/true", "raven-process-marker"])
        assert child.wait() == 0
        sudo = [] if os.geteuid() == 0 else ["sudo", "-n"]
        uid_pid = subprocess.check_output([*sudo, sys.executable, "-I", "-S", "-c",
                                          "import os; os.setuid(65534); print(os.getpid())"])
        (gate.parent / "markers.json").write_text(json.dumps({
            "pid": os.getpid(), "child": child.pid, "uid_pid": int(uid_pid), "port": port,
        }))
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


def check_raven_inputs(cwd, count):
    marker = json.loads((cwd / "markers.json").read_text())
    events = [json.loads(line) for line in (cwd / "events.jsonl").read_text().splitlines()]
    assert len(events) == count and all(e["event_id"] for e in events)
    expected = [
        {"event_type": "process_fork", "pid": marker["child"], "ppid": marker["pid"]},
        {"event_type": "process_exec", "pid": marker["child"], "args": ["raven-process-marker"]},
        {"event_type": "process_exit", "pid": marker["child"]},
        {"event_type": "net_listen", "pid": marker["pid"], "dst_port": marker["port"]},
        {"event_type": "net_connect", "pid": marker["pid"], "dst_port": marker["port"], "dst_ip": "127.0.0.26"},
        {"event_type": "privilege_change", "pid": marker["uid_pid"], "uid": 0, "euid": 65534},
    ]
    for op in ("open", "create", "write", "chmod"):
        row = {"event_type": "file_access" if op == "open" else "file_modify", "file_op": op,
               "file_path": str(cwd / "raven-file-marker"), "pid": marker["pid"]}
        if op == "chmod":
            row["metadata"] = {"created_executable": True}
        expected.append(row)
    for row in expected:
        assert any(all(e.get(k) == v for k, v in row.items()) for e in events), (cwd, row)
    return expected


def check(package, build, live, out, strict=False):
    here = Path(__file__).resolve().parent
    out.mkdir()
    shutil.copy2(here.parent / "plugin/live.yaml", out / "live.yaml")
    shutil.copy2(here.parent / "plugin/rules.yaml", out / "raven_zeek_rules.yaml")
    shutil.copy2(package / "etc/falco/falco_rules.yaml", out)
    summary = {"kernel": os.uname().release}
    template = (out / "live.yaml").read_text()
    both = "{raven: true, zeek: true}"
    raven_only = "{zeek: false}"
    zeek_only = """'{"raven":false}'"""
    entry = "  - name: raven_zeek\n    init_config: "
    assert template.count(entry + both + "\n") == 1
    rules = ["falco_rules.yaml", "raven_zeek_rules.yaml"]
    sudo = [] if os.geteuid() == 0 else ["sudo", "-n"]
    collector = ["env", "TZ=UTC", "FALCO_HOSTNAME=falco-rz-live", "FALCO_SGX_REPORT=1",
                 live / "falco-live", build / "falco-enclave.signed", "live.yaml", "4096"]

    def prepare_run(name, settings):
        cwd = out / name
        cwd.mkdir()
        (cwd / "live.yaml").write_text(template.replace(entry + both + "\n", entry + settings + "\n"))
        for path in rules:
            (cwd / path).symlink_to(out / path)
        return cwd

    for name, settings, raven, zeek in (("ring-only", both, True, True), ("recorded", both, True, True),
                                       ("raven-only", raven_only, True, False), ("zeek-only", zeek_only, False, True)):
        cwd = prepare_run(name, settings)
        expected = set()
        if raven:
            expected.add("server_spawns_shell")
        if zeek:
            expected.update(("Scan::Port_Scan", "Scan::Address_Scan"))
        record = name == "recorded"
        # A stuck drain must not leave the Popen context waiting forever after proc.wait() times out.
        cmd = [*sudo, "timeout", "--kill-after=10", "240", *collector, "reference.scap" if record else "-"]
        if record:
            cmd.extend(["--record-inputs", "events.jsonl", "packets.pcap"])
        elif name == "raven-only":
            cmd.extend(["--record-inputs", "events.jsonl", "-"])
        gate = cwd / "release"
        cmd.extend(rules)
        fixture = [sys.executable, Path(__file__).resolve(), "--workload", live, gate]
        if record:
            packets = cwd / "packets.pcap"
            packets.write_bytes(b"existing PCAP")
            occupied = subprocess.run([*cmd, "--", "/bin/true"], cwd=cwd, capture_output=True)
            assert occupied.returncode == 1 and b"could not create the detector test PCAP" in occupied.stderr
            assert packets.read_bytes() == b"existing PCAP"
            assert not any((cwd / p).exists() for p in ("reference.scap", "events.jsonl"))
            packets.unlink()
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
                            if expected <= found:
                                break
                        time.sleep(0.1)
                    if found != expected or proc.poll() is not None:
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
        if not raven:
            selection, = (r for r in logs if r.get("mode") == "event_selection")
            assert selection["raven_added"] == []
        ring = next(r for r in logs if r.get("mode") == "live")
        if strict and any(ring["errors"].values()):
            raise AssertionError(f"live errors: {ring['errors']}")
        driver = next(r for r in logs if r.get("mode") == "modern_ebpf")
        assert driver["data_ecalls"] == 5
        assert ring["detectors"]["raven"] is raven and ring["detectors"]["zeek"] is zeek
        assert (ring["raven_events"] > 0 if raven else ring["raven_events"] == 0), f"{name}: RAVEN event count"
        assert ring["packet_records"] == driver["packet_submitted"]
        assert (ring["packet_records"] > 0 if zeek else ring["packet_records"] == 0), f"{name}: packet count"
        raven_alerts, zeek_notices = detector_results(cwd / "alerts.jsonl")
        assert bool(raven_alerts) == raven and bool(zeek_notices) == zeek, f"{name}: unexpected detector output"
        assert driver["driver_events"] + ring["packet_records"] == ring["accepted"] == ring["records"]
        assert driver["consumer"] == driver["producer"] == ring["consumer"] == ring["producer"]
        assert not any((driver["driver_drops"], driver["packet_drops"], ring["discarded"], ring["format_rejected"]))
        inputs = (["events.jsonl"] if record or name == "raven-only" else [])
        if record:
            inputs.extend(["packets.pcap", "reference.scap"])
        assert all((cwd / p).exists() == (p in inputs) for p in ("events.jsonl", "packets.pcap", "reference.scap"))
        result = {"before_workload_exit": sorted(found), "syscall_records": driver["driver_events"],
                  "detectors": ring["detectors"], "packet_submitted": driver["packet_submitted"],
                  "raven_events": ring["raven_events"], "packets": ring["packet_records"],
                  "driver_drops": driver["driver_drops"], "packet_drops": driver["packet_drops"],
                  "discarded": ring["discarded"], "format_rejected": ring["format_rejected"],
                  "map_id": driver["map_id"], "drained_position": ring["consumer"],
                  "stopped_by": "workload exit" if record else "SIGTERM",
                  "input_files": inputs}
        if "events.jsonl" in inputs:
            result["raven_markers"] = check_raven_inputs(cwd, ring["raven_events"])
        if record:
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
            observed = raven_alerts, zeek_notices
            assert observed == detector_results(cwd / "replay.jsonl"), "enclave replay differs from live detection"
            assert observed == detector_results(cwd / "native.jsonl"), "native replay differs from live detection"
            result["recorded_replay"] = ["enclave", "native"]
        summary[name] = result
    for name, settings, recording, keywords in (
        ("both-disabled", "{raven: false, zeek: false}", [], ("raven_zeek", "load_plugins")),
        ("unknown-key", "{unknown_detector: true}", [], ("unknown_detector",)),
        ("non-boolean", '{raven: "false"}', [], ("raven", "bool")),
        ("record-disabled-zeek", raven_only, ["--record-inputs", "-", "packets.pcap"], ("zeek", "packet")),
        ("record-disabled-raven", zeek_only, ["--record-inputs", "events.jsonl", "-"], ("raven", "event")),
    ):
        cwd = prepare_run(name, settings)
        cmd = [*sudo, "timeout", "--kill-after=10", "120", *collector, "reference.scap", *recording, *rules]
        log = cwd / "live.log"
        with log.open("xb") as output:
            proc = subprocess.run(cmd, cwd=cwd, stdout=output, stderr=subprocess.STDOUT)
        lines = log.read_text().lower().splitlines()
        assert proc.returncode not in (0, 124, 137), f"{name}: expected startup failure; see {log}"
        assert not any('"capture_ready"' in line for line in lines), f"{name}: capture started; see {log}"
        assert any(all(word in line for word in keywords) for line in lines), f"{name}: expected {keywords}; see {log}"
        assert not any((cwd / p).exists() for p in ("reference.scap", *recording[1:]) if p != "-"), f"{name}: rejected run left captures"
        summary[name] = {"returncode": proc.returncode}
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
            sys.exit("usage: check-detectors.py [--strict] FALCO_PACKAGE BUILD_DIR LIVE_BUILD_DIR NEW_RUN_DIRECTORY")
        print(json.dumps(check(*(Path(p).resolve() for p in sys.argv[1:]), strict=strict), indent=2))
