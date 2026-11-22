"""Compare the Falco shared plugin and the same plugin in SGX SIM with pinned offline oracles."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
from itertools import takewhile
from runpy import run_path
from zipfile import ZipFile


def rows(path, falco_stdout=False):
    lines = path.read_text().splitlines()
    if falco_stdout:
        lines = takewhile(lambda line: not line.startswith("Events detected:"), lines)
    return [json.loads(line) for line in lines if line.strip()]


def canonical(records, fixed, *, stream=False):
    events, detections = {}, {}

    def event_id(value):
        if value in fixed:
            return value
        if not re.fullmatch("[a-f0-9]{12}", value):
            raise ValueError(f"invalid generated event ID {value}")
        return events.setdefault(value, f"generated-{len(events)}")

    result = copy.deepcopy(records)
    for row in result:
        if "note" in row:
            continue
        value = row.pop("id")
        if not re.fullmatch("det-[0-9a-f]{12}", value) or (not stream and value in detections):
            raise ValueError(f"invalid detection ID {value}")
        number = detections.setdefault(value, len(detections))
        if stream:
            row["id"] = number
        path = "raven/rules/rule_defs/temporal.yaml"
        if row["rule_source"] != path and not row["rule_source"].endswith("/" + path):
            raise ValueError(row["rule_source"])
        row["rule_source"] = path
        for event in row["events"]:
            event["id"] = event_id(event["id"])
        for edge in row["reconstruction"]["graph"]["edges"]:
            edge["event_ids"] = [event_id(i) for i in edge["event_ids"]]
    return result


def compare(label, actual, expected):
    if actual == expected:
        return
    if isinstance(actual, (dict, list)) and type(actual) is type(expected):
        if isinstance(actual, dict) and actual.keys() == expected.keys():
            for key in expected:
                compare(f"{label}.{key}", actual[key], expected[key])
        elif isinstance(actual, list) and len(actual) == len(expected):
            for i, (left, right) in enumerate(zip(actual, expected)):
                compare(f"{label}[{i}]", left, right)
    raise AssertionError(f"{label}: {str(actual)[:220]} != {str(expected)[:220]}")


def fixed_ids(events, tetragon):
    return set() if tetragon else {e["event_id"] for row in rows(events)
                                  for e in row.get("events", [row]) if e.get("event_id")}


def run_case(name, events, pcap, expected, tetragon=False, rejection=None):
    cwd = output / name
    cwd.mkdir()
    for dest, source in {"events.jsonl": events, "packets.pcap": pcap, "reference.scap": baseline / "reference.scap",
                         "falco_rules.yaml": baseline / "falco_rules.yaml", "raven_zeek_rules.yaml": here / "rules.yaml",
                         "libcontainer.so": baseline / "libcontainer.so", "libraven_zeek.so": build / "lib/libraven_zeek.so"}.items():
        (cwd / dest).symlink_to(source)
    cfg = (here / "replay.yaml").read_text()
    (cwd / "falco.yaml").write_text(cfg.replace('"replay"', '"tetragon"') if tetragon else cfg)
    commands = {
        "native": [package / "usr/bin/falco", "-c", "falco.yaml", "-o", "engine.kind=modern_ebpf", "--enable-source", "raven_zeek"],
        "sgx": [build / "bin/falco-sgx", build / "falco-enclave.signed", "falco.yaml", "reference.scap",
                "--plugin-tetragon" if tetragon else "--plugin", "events.jsonl", "packets.pcap", "falco_rules.yaml", "raven_zeek_rules.yaml"]}
    fixed = fixed_ids(events, tetragon) if any("note" not in r for r in expected) else set()
    oracle = canonical(expected, fixed)
    native_metadata = None
    observed = {}
    for mode, command in commands.items():
        with (cwd / f"{mode}.jsonl").open("x") as out, (cwd / f"{mode}.log").open("x") as err:
            result = subprocess.run(command, cwd=cwd, env=environment, stdout=out, stderr=err)
        if rejection:
            compare(name + "." + mode + ".exit", result.returncode, 1)
            log = (cwd / f"{mode}.log").read_text()
            for message in (rejection,) if isinstance(rejection, str) else rejection:
                if message not in log:
                    raise AssertionError(f"{name}.{mode} missing diagnostic {message!r}")
        else:
            result.check_returncode()
        alerts = rows(cwd / f"{mode}.jsonl", falco_stdout=mode == "native")
        if mode == "sgx":
            compare(name + ".syscall", [a for a in alerts if a["source"] == "syscall"], official)
        plugin = [a for a in alerts if a["source"] == "raven_zeek"]
        compare(name + ".total", len(alerts), len(plugin) + (len(official) if mode == "sgx" else 0))
        records, metadata = [], []
        for alert in plugin:
            raw = alert["output_fields"].pop("rz.result")
            row = json.loads(raw)
            records.append(row)
            for field in ("output", "message"):
                if field in alert:
                    if raw not in alert[field]:
                        raise AssertionError(f"{field} lost result")
                    alert[field] = alert[field].replace(raw, "<result>")
            metadata.append(alert)
            rule = ({"Scan::Port_Scan": "Zeek port scan", "Scan::Address_Scan": "Zeek address scan"}[row["note"]]
                    if "note" in row else "RAVEN active detection" if row["state"] == "active" else "RAVEN context review")
            compare(name + ".rule", alert["rule"], rule)
        actual = canonical(records, fixed)
        compare(name + "." + mode, actual, oracle)
        observed[mode] = (result.returncode, actual)
        if mode == "native":
            native_metadata = metadata
        else:
            compare(name + ".falco_fields", metadata, native_metadata)
    if rejection:
        summary[name] = {"rejected_by": ["native", "sgx"], "exit": 1, "plugin_alerts": len(expected), "diagnostic": rejection}
    else:
        summary[name] = {"official": len(official), "active": sum(r.get("state") == "active" for r in oracle),
                         "context_filtered": sum(r.get("state") == "context_filtered" for r in oracle),
                         "notices": [r["note"] for r in oracle if "note" in r]}
    print(name, json.dumps(summary[name]), flush=True)
    return observed


def original_result(name, capture, raven, tetragon=False):
    directory = output / "upstream" / name
    directory.mkdir(parents=True)
    if raven:
        command = [sys.executable, "-B", here.parent / "upstream/raven-replay.py", capture]
        if tetragon:
            command.extend(["--format", "tetragon"])
    else:
        command = ["bash", here.parent / "upstream/zeek-replay.sh", capture, directory / "logs"]
    with (directory / "stdout").open("xb") as out, (directory / "stderr").open("xb") as err:
        rc = subprocess.run(command, env=environment, stdout=out, stderr=err).returncode
    result = directory / ("stdout" if raven else "logs/notice.log")
    return rc, rows(result) if result.exists() else []


def check_structure_review(manifest_path, no_events, empty):
    manifest = json.loads(manifest_path.read_text())
    evidence = manifest_path.parent / manifest["evidence"]["file"]
    compare("structure archive SHA-256", hashlib.sha256(evidence.read_bytes()).hexdigest(), manifest["evidence"]["sha256"])
    inputs = output / "inputs"
    inputs.mkdir()
    with ZipFile(evidence) as archive:
        for name, case in manifest["cases"].items():
            member = case["input_file"]
            capture = inputs / Path(member).name
            raw = archive.read(member)
            compare(name + ".input SHA-256", hashlib.sha256(raw).hexdigest(), case["input_sha256"])
            capture.write_bytes(raw)
            expected = [json.loads(line) for line in archive.read(f"cases/{name}/original.rows.jsonl").splitlines()]
            raven = case["format"] != "zeek"
            run_case(name, capture if raven else no_events, empty if raven else capture, expected,
                     tetragon=case["format"] == "tetragon", rejection=case["diagnostic"] if case["upstream"]["exit"] else None)
    (output / "comparison.json").write_text(json.dumps(summary, indent=2) + "\n")


def check_lifecycle_review(manifest_path, no_events, empty):
    manifest = json.loads(manifest_path.read_text())
    evidence = manifest_path.parent / manifest["evidence"]["file"]
    compare("lifecycle archive SHA-256", hashlib.sha256(evidence.read_bytes()).hexdigest(), manifest["evidence"]["sha256"])
    with ZipFile(evidence) as archive:
        for name, case in manifest["new_file_cases"].items():
            raven = case["engine"] == "RAVEN"
            capture = output / (name + (".jsonl" if raven else ".pcap"))
            raw = archive.read("inputs/" + capture.name)
            compare(name + ".input SHA-256", hashlib.sha256(raw).hexdigest(), case["input_sha256"])
            capture.write_bytes(raw)
            log = f"runs/{name}/" + ("upstream.out" if raven else "notice.log")
            expected = [json.loads(line) for line in archive.read(log).splitlines()] if log in archive.namelist() else []
            compare(name + ".upstream records", len(expected), case["upstream_records"])
            run_case(name, capture if raven else no_events, empty if raven else capture, expected)
        notice = json.loads(archive.read("runs/timer-queue-reply-30/notice.log"))
    # With 200 background connections, the pinned policy publishes on the following packet.
    source = (output / "timer-queue-reply-360.pcap").read_bytes()
    pos = 24
    data = bytearray(source[:pos])
    for index in range(360):
        end = pos + 16 + struct.unpack_from("<I", source, pos + 8)[0]
        if index < 200:
            data.extend(source[pos:end])
        pos = end
    capture = output / "timer-queue-reply-200.pcap"
    capture.write_bytes(data + source[pos:])
    notice["ts"] = 1700000008.001
    run_case("timer-queue-reply-200", no_events, capture, [notice])
    for name, fields in (("null-name-without-exe", {"exe_name": None}),
                         ("numeric-name-with-exe", {"exe": "/bin/sh", "exe_name": 7})):
        capture = output / (name + ".jsonl")
        capture.write_text(json.dumps({"event_type": "process_exec", **fields}) + "\n")
        run_case(name, capture, empty, [], rejection="type must be string")
    (output / "comparison.json").write_text(json.dumps(summary, indent=2) + "\n")


def check_behavior(manifest_path, no_events, empty):
    manifest = json.loads(manifest_path.read_text())
    archive_path = manifest_path.parent / manifest["evidence_archive"]["file"]
    def digest(data):
        return hashlib.sha256(data).hexdigest()

    compare("archive SHA-256", digest(archive_path.read_bytes()), manifest["evidence_archive"]["sha256"])
    inputs = output / "inputs"
    inputs.mkdir()
    known = "duplicate-after-601s"
    rejected = {"tetragon-invalid-numeric-id": "invalid Tetragon pid", "tetragon-rfc3339": "could not convert string to float",
                "pcapng-mixed-linktypes": "PCAPNG interfaces have different link types"}
    cases = {}
    with ZipFile(archive_path) as archive:
        for case in manifest["cases"]:
            name = case["case"]
            capture = inputs / Path(case["input_file"]).name
            raw = archive.read(case["input_file"])
            compare(name + ".input SHA-256", digest(raw), case["input_sha256"])
            capture.write_bytes(raw)
            raven = case["engine"] == "RAVEN"
            tetragon = raven and name.startswith("tetragon-")
            events, packets = (capture, empty) if raven else (no_events, capture)
            fixed = fixed_ids(events, tetragon)
            rc, expected = original_result(name, capture, raven, tetragon)
            upstream = canonical(expected, fixed)
            archived = [json.loads(line) for line in archive.read(case["upstream_output_file"]).splitlines()]
            compare(name + ".original", (rc, upstream), (case["upstream_exit"], canonical(archived, fixed)))
            if name == known:
                expected = [json.loads(line) for line in archive.read(case["current_output_file"]).splitlines()]
            observed = run_case(name, events, packets, expected, tetragon, rejected[name] if rc else None)
            modes = {}
            for mode, (status, records) in {"upstream": (rc, upstream), **observed}.items():
                ordered = json.dumps(records, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
                modes[mode] = {"exit": status, "records": len(records), "ordered_sha256": digest(ordered),
                               "matches_upstream": (status, records) == (rc, upstream)}
                if mode != "upstream":
                    compare(name + "." + mode + ".parity", modes[mode]["matches_upstream"], name != known)
            cases[name] = {"engine": case["engine"], "input_sha256": digest(raw), **modes}
    compare("reviewed inputs", len(cases), 45)
    binaries = [package / "usr/bin/falco", build / "lib/libraven_zeek.so", build / "bin/falco-sgx", build / "falco-enclave.signed"]
    report = {"references": manifest["references"], "input_archive_sha256": manifest["evidence_archive"]["sha256"],
              "binaries_sha256": {p.name: digest(p.read_bytes()) for p in binaries},
              "known_difference": known, "summary": {m: sum(c[m]["matches_upstream"] for c in cases.values())
                                                      for m in ("native", "sgx")}, "cases": cases}
    (output / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")


def check_parity_audit(manifest_path, no_events, empty):
    manifest = json.loads(manifest_path.read_text())
    evidence = manifest_path.parent / manifest["evidence"]["file"]
    compare("supplemental archive SHA-256", hashlib.sha256(evidence.read_bytes()).hexdigest(), manifest["evidence"]["sha256"])
    inputs = output / "inputs"
    inputs.mkdir()
    with ZipFile(evidence) as archive:
        for case in manifest["extra_inputs"]:
            name = case["case"]
            raven = case["engine"] == "RAVEN"
            tetragon = name.startswith("tetragon-")
            capture = inputs / (name + (".jsonl" if raven else ".pcap"))
            raw = archive.read("inputs/" + capture.name)
            compare(name + ".input SHA-256", hashlib.sha256(raw).hexdigest(), case["input_sha256"])
            capture.write_bytes(raw)
            rc, expected = original_result(name, capture, raven, tetragon)
            fixed = fixed_ids(capture, tetragon) if raven else set()
            archived = [json.loads(line) for line in archive.read(f"outputs/{name}/upstream.jsonl").splitlines()]
            compare(name + ".upstream", (rc, canonical(expected, fixed)), (case["original"]["exit"], canonical(archived, fixed)))
            if name == "maintenance-older-context":
                expected = [json.loads(line) for line in archive.read(f"outputs/{name}/cpp.jsonl").splitlines()]
            run_case(name, capture if raven else no_events, empty if raven else capture, expected, tetragon,
                     ("RAVEN input:", "invalid Tetragon port") if rc else None)
    notices = rows(output / "upstream/classic-2.3/logs/notice.log")
    events = inputs / "tetragon-port-plain.jsonl"
    detections = rows(output / "upstream/tetragon-port-plain/stdout")
    packets = inputs / "classic-2.3.pcap"
    run_case("combined-2.3", events, packets, detections + notices, True)
    scenario_b = rows(reference / "scenario_B.detections.jsonl")
    compare("scenario B and PCAP 2.3 counts", (len(scenario_b), len(notices)), (1, 2))
    run_case("combined-2.3-scenario-B", reference / "scenario_B.jsonl", packets, scenario_b + notices)
    bad_events = inputs / "bad.jsonl"
    bad_events.write_bytes(b'{"events":')
    bad_pcap = inputs / "bad.pcap"
    bad_pcap.write_bytes(empty.read_bytes() + b"!")
    raven_error, zeek_error = "RAVEN input: RAVEN line 1", "Zeek input: truncated PCAP packet header"
    run_case("bad-raven-good-zeek", bad_events, packets, notices, rejection=raven_error)
    run_case("good-raven-bad-zeek", events, bad_pcap, detections, True, zeek_error)
    run_case("both-invalid", bad_events, bad_pcap, [], rejection=(raven_error, zeek_error))
    bad_port = inputs / "bad-port.jsonl"
    bad_port.write_text(json.dumps({"process_listen": {"port": "1"*300 + "/tcp"}}))
    run_case("both-invalid-long-diagnostic", bad_port, bad_pcap, [], True, ("invalid Tetragon port", zeek_error))
    run_case("missing-raven", inputs / "absent.jsonl", packets, notices, rejection="RAVEN input: cannot open capture")
    run_case("missing-zeek", events, inputs / "absent.pcap", detections, True, "Zeek input: cannot open capture")
    run_case("zero-byte-pcap", events, no_events, detections, True, "Zeek input: truncated PCAP header")

    for name, value, rc in [("listen-plain", "443", 0), ("listen-separated", "4_43", 0), ("listen-trailing-text", "443/tcp", 1)]:
        source = rows(events)
        next(row["process_listen"] for row in source if "process_listen" in row)["port"] = value
        capture = inputs / (name + ".jsonl")
        capture.write_text("".join(json.dumps(row) + "\n" for row in source))
        status, wanted = original_result(name, capture, True, True)
        compare(name + ".original", status, rc)
        if not rc:
            listening = [e["dst"] for r in wanted for e in r["reconstruction"]["graph"]["edges"] if e["type"] == "listening"]
            compare(name + ".port", listening, ["port:443"])
        run_case(name, capture, empty, wanted, True, ("RAVEN input:", "invalid Tetragon port") if rc else None)

    def frames(capture):
        raw = capture.read_bytes()
        pos = 24
        while pos < len(raw):
            sec, us, size, _ = struct.unpack_from("<4I", raw, pos)
            yield sec, us, raw[pos+16:pos+16+size]
            pos += 16 + size

    def verify_pcap(name, data, wanted):
        capture = inputs / (name + ".pcap")
        capture.write_bytes(data)
        rc, actual = original_result(name, capture, False)
        compare(name + ".original", (rc, actual), (0, wanted))
        run_case(name, no_events, capture, actual)

    for name, endian, order in [("2.3-modern", "<", "modern"), ("2.3-swapped", "<", "swapped"), ("2.3-mixed-be", ">", "mixed")]:
        data = bytearray(struct.pack(endian + "IHHIIII", 0xa1b2c3d4, 2, 3, 0, 0, 65535, 1))
        for i, (sec, us, frame) in enumerate(frames(packets)):
            cap, wire = len(frame), len(frame) + 12
            if order == "swapped" or (order == "mixed" and i % 2):
                cap, wire = wire, cap
            data.extend(struct.pack(endian + "4I", sec, us, cap, wire) + frame)
        verify_pcap(name, data, notices)

    for name, protocol in [("pppoe-vlan-ipv6", 0x0057), ("pppoe-non-ip", 0xc021), ("pppoe-short", None)]:
        data = bytearray(empty.read_bytes())
        for sec, us, frame in frames(reference / "ipv6-vlan.pcap"):
            inner = frame[18:]
            header = struct.pack("!BBHH", 0x11, 0, 1, len(inner)+2)
            body = header[:4] if protocol is None else header + struct.pack("!H", protocol) + inner
            wrapped = frame[:16] + b"\x88\x64" + body
            data.extend(struct.pack("<4I", sec, us, len(wrapped), len(wrapped)) + wrapped)
        verify_pcap(name, data, rows(reference / "ipv6-vlan/notice.log") if protocol == 0x0057 else [])

    # End the idle sessions with a reset so their survival is observable through both public Falco entry points.
    frame = run_path(str(here.parent / "upstream/scan-fixture.py"))["frame"]
    records = []
    for source, port, finish, refresh in [(1, 21, 420, False), (2, 22, 420, False), (3, 23, 420, False),
                                          (4, 513, 420, False), (5, 80, 420, False), (6, 22, 3650, False),
                                          (7, 22, 3650, True)]:
        for i in range(25):
            client, server, sport = f"192.0.2.{source}", f"198.51.100.{i+1}", 45000+i
            for sec, us, reverse, seq, ack, flags in [(1, 0, False, 100, 0, 2), (1, 1, True, 200, 101, 18),
                    (1, 2, False, 101, 201, 16), (finish, 3, False, 101, 201, 20)]:
                ends = (server, client, port, sport) if reverse else (client, server, sport, port)
                records.append((sec, 100*i+us, frame(*ends, seq, ack, flags)))
            if refresh:
                records.append((3500, 100*i, frame(client, server, sport, port, 101, 201, 16)))
    data = bytearray(empty.read_bytes())
    for sec, us, packet in sorted(records):
        data.extend(struct.pack("<4I", 1700000000+sec, us, len(packet), len(packet)) + packet)
    capture = inputs / "interactive-idle.pcap"
    capture.write_bytes(data)
    rc, wanted = original_result("interactive-idle", capture, False)
    compare("interactive-idle.original", (rc, sorted((r["src"], r["p"]) for r in wanted)),
            (0, [(f"192.0.2.{i}", port) for i, port in [(1,21), (2,22), (3,23), (4,513), (7,22)]]))
    run_case("interactive-idle", no_events, capture, wanted)
    (output / "comparison.json").write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("package", "build", "falco_run", "reference_run", "new_run"):
        parser.add_argument(arg, type=Path)
    parser.add_argument("--live-build", type=Path, help="also verify the local ring workload and the plugin on one enclave handle")
    parser.add_argument("--behavior-review", type=Path, help="run the archived 45 inputs and pinned originals using the review manifest")
    parser.add_argument("--structure-review", type=Path, help="replay the structure parity cases against their archived upstream outputs")
    parser.add_argument("--lifecycle-review", type=Path, help="check lifecycle replay against pinned upstream outputs and invalid-name controls")
    parser.add_argument("--parity-audit", type=Path, help="check the eight audit inputs and regressions for the five fixes")
    args = parser.parse_args()
    package, build, baseline, reference, output = [p.resolve() for p in (
        args.package, args.build, args.falco_run, args.reference_run, args.new_run)]
    here = Path(__file__).resolve().parent
    official = rows(baseline / "native-alerts.jsonl", falco_stdout=True)
    environment = dict(os.environ, TZ="UTC", FALCO_HOSTNAME=official[0]["hostname"])
    output.mkdir()
    summary = {}
    pcap = reference / "healthchecks.pcap"
    empty = output / "empty.pcap"
    empty.write_bytes(pcap.read_bytes()[:24])
    no_events = output / "empty.jsonl"
    no_events.touch()
    if args.structure_review:
        check_structure_review(args.structure_review.resolve(), no_events, empty)
        sys.exit(0)
    if args.lifecycle_review:
        check_lifecycle_review(args.lifecycle_review.resolve(), no_events, empty)
        sys.exit(0)
    if args.behavior_review:
        check_behavior(args.behavior_review.resolve(), no_events, empty)
        sys.exit(0)
    if args.parity_audit:
        check_parity_audit(args.parity_audit.resolve(), no_events, empty)
        sys.exit(0)
    notices = rows(reference / "zeek/notice.log")
    run_case("empty", no_events, empty, [])
    run_case("tetragon-mixed", reference / "tetragon-mixed.jsonl", empty,
             rows(reference / "tetragon-mixed.detections.jsonl"), True)
    tetragon = rows(reference / "tetragon.jsonl")
    tetragon[0]["process_exec"]["process"]["container"] = {"image": None}
    nullable = output / "tetragon-null-image.jsonl"
    nullable.write_text("".join(json.dumps(row) + "\n" for row in tetragon))
    run_case("tetragon-null-image", nullable, empty, rows(reference / "tetragon.detections.jsonl"), True)
    for name, data, capture, diagnostic in [
            ("bad-json", b'{"events":', empty.read_bytes(), "RAVEN line 1"),
            ("bad-pcap", b"", empty.read_bytes() + b"\x00", "truncated PCAP packet header")]:
        events, packets = output / (name + ".jsonl"), output / (name + ".pcap")
        events.write_bytes(data)
        packets.write_bytes(capture)
        run_case(name, events, packets, [], rejection=diagnostic)
    for name, data, expected, error in [
            ("short-pcap-tail", pcap.read_bytes()[:-1], notices, "invalid PCAP packet length"),
            ("short-pcapng-tail", (reference / "pcapng.pcap").read_bytes() + b"\x00",
             rows(reference / "pcapng/notice.log"), "truncated PCAPNG block"),
            ("pcap-error-before-timeout", (reference / "reverse-eof.pcap").read_bytes() + b"\x00",
             [], "truncated PCAP packet header")]:
        packets = output / (name + ".pcap")
        packets.write_bytes(data)
        run_case(name, no_events, packets, expected, rejection=error)
    for case in ("F", "numeric-new-user", "utc-second-boundary", "special-purpose-ipv4"):
        run_case("review-" + case, reference / (case + ".jsonl"), empty, rows(reference / (case + ".detections.jsonl")))
    run_case("review-tetragon-rfc3339", reference / "tetragon-rfc3339.jsonl", empty, [], tetragon=True,
             rejection="could not convert string to float: '2025-01-01T12:00:00Z'")
    for case in ("healthchecks", "successful-handshakes", "reordered-successful-handshakes", "ppp-serial-handshakes",
                 "nanosecond-healthchecks", "ppp-serial-healthchecks", "ppp-serial-ipv6", "ppp-serial-mpls",
                 "pcapng-submicrosecond"):
        log = reference / ("zeek" if case == "healthchecks" else case) / "notice.log"
        run_case("review-" + case, no_events, reference / (case + ".pcap"), rows(log) if log.exists() else [])
    for key in (*"ABCDEFG", "idle", "tetragon"):
        stem = "tetragon" if key == "tetragon" else "scenario_" + key
        expected = rows(reference / (stem + ".detections.jsonl"))
        run_case(key, reference / (stem + ".jsonl"), empty if key == "idle" else pcap,
                 expected + ([] if key == "idle" else notices), key == "tetragon")
    original = json.loads((baseline / "native-rules.json").read_text())
    names = [r["info"]["name"] for r in original["rules"] if r["info"]["enabled"]]
    loaded = next(json.loads(line)["enabled"] for line in (output / "A/sgx.log").read_text().splitlines()
                  if line.startswith("{") and "enabled" in json.loads(line))
    compare("enabled Falco rules", set(loaded), set(names) | {
        "RAVEN active detection", "RAVEN context review", "Zeek address scan", "Zeek port scan"})
    for case in ("states", "epochs", "suppression-expiry", "ipv6-vlan", "reverse-eof", "fragments", "pcapng"):
        notice_file = reference / case / "notice.log"
        expected = rows(notice_file) if notice_file.exists() else []
        run_case(case, reference / "boundaries.jsonl", reference / (case + ".pcap"),
                 rows(reference / "boundaries.detections.jsonl") + expected)
    if args.live_build:
        live_out = output / "live"
        subprocess.run([sys.executable, here.parent / "live/check-detectors.py", package, build,
                        args.live_build.resolve(), live_out], check=True)
        summary["live"] = json.loads((live_out / "comparison.json").read_text())
    (output / "comparison.json").write_text(json.dumps(summary, indent=2) + "\n")
