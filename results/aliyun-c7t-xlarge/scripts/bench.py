"""Run one timed point at a time on the Linux Falco benchmark host."""
import argparse
from bisect import bisect_left
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import csv
import datetime
import json
import math
import os
from pathlib import Path
import re
import shlex
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time

HERE = Path(__file__).resolve().parent
FALCO = HERE.parents[2] / "poc/falco"
SGX = ("S1", "S2", "S3", "S4")
MATRIX = dict(e1=("N1", *SGX), e2=SGX, e3=("S1", "S1-spin"),
              e4=("B0", "N1", *SGX), e5=("N1", *SGX, "S1-spin", "S1-buf"),
              e6=("N1", *SGX, "S1-spin"))
SECOND = 10**9


def read_json(path):
    return json.loads(path.read_text())


def write_json(path, data):
    with path.open("x") as out:
        json.dump(data, out, indent=2, allow_nan=False)
        out.write("\n")


def falco_config(args, config, work):
    if config == "B0":
        (work / "falco.yaml").write_text("# B0 runs without a collector.\n")
        return []
    rules = ["falco_rules.yaml"]
    (work / rules[0]).symlink_to(args.package / "etc/falco" / rules[0])
    if config == "N1":
        yaml = (FALCO / "reference.yaml").read_text().replace(
            "  kind: replay\n  replay:\n    capture_file: reference.scap",
            "  kind: modern_ebpf\n  modern_ebpf:\n    cpus_for_each_buffer: 0\n    buf_size_preset: 4")
        (work / "libcontainer.so").symlink_to(args.package / "usr/share/falco/plugins/libcontainer.so")
        yaml += ("\nwebserver: {enabled: false}\n"
                 "metrics: {enabled: true, interval: 1s, output_file: native-metrics.jsonl, "
                 "output_rule: false, kernel_event_counters_enabled: true, include_empty_values: true, "
                 "libbpf_stats_enabled: false}\n")
        cmd = [args.package / "usr/bin/falco", "-c", "falco.yaml"]
    else:
        raven, zeek = config in ("S2", "S4"), config in ("S3", "S4")
        yaml = (FALCO / "plugin/live.yaml").read_text()
        if raven or zeek:
            rules.append("raven_zeek_rules.yaml")
            (work / rules[-1]).symlink_to(FALCO / "plugin/rules.yaml")
            yaml = yaml.replace("{raven: true, zeek: true}",
                                f"{{raven: {str(raven).lower()}, zeek: {str(zeek).lower()}}}")
        else:
            yaml = yaml.replace(", raven_zeek_rules.yaml]", "]").replace(", raven_zeek]", "]")
            yaml = yaml.replace("  - name: raven_zeek\n    init_config: {raven: true, zeek: true}\n", "")
        yaml += f"\nidle: {'spin' if config == 'S1-spin' else 'sleep'}\n"
        cmd = [args.live / "falco-live", args.build / "falco-enclave.signed",
               "falco.yaml", "8192", "-", *rules]
    yaml += f"base_syscalls: {{all: false}}\nbuffered_outputs: {str(config == 'S1-buf').lower()}\n"
    (work / "falco.yaml").write_text(yaml)
    return list(map(str, cmd))


def cpu_snapshot(pid):
    system = list(map(int, Path("/proc/stat").read_text().splitlines()[0].split()[1:9]))
    stamp = time.monotonic_ns()
    threads = {}
    process = 0
    if pid:
        proc = Path("/proc") / str(pid)
        fields = (proc / "stat").read_text().rsplit(")", 1)[1].split()
        process = int(fields[11]) + int(fields[12])
        for task in (proc / "task").iterdir():
            try:
                role = (task / "comm").read_text().strip()
                fields = (task / "stat").read_text().rsplit(")", 1)[1].split()
            except (FileNotFoundError, ProcessLookupError):
                continue  # A thread exited between listing and reading its counters.
            threads[(task.name, fields[19])] = (role, int(fields[11]) + int(fields[12]))
    return stamp, process, threads, system


def cpu_metrics(samples, work, start, seconds):
    if samples[0][0] > start or samples[-1][0] < start + seconds * SECOND:
        raise ValueError("CPU samples do not bracket the producer window")
    hz = os.sysconf("SC_CLK_TCK")
    bins = [Counter() for _ in range(seconds)]
    raw = []
    for (a, pa, ta, sa), (b, pb, tb, sb) in zip(samples, samples[1:]):
        delta = Counter()
        for tid, (role, ticks) in tb.items():
            delta["thread:" + role] += ticks - ta.get(tid, (role, 0))[1]
        delta["process"] = pb - pa
        machine = [y - x for x, y in zip(sa, sb)]
        delta["system_all"] = sum(machine)
        delta["system"] = sum(machine) - machine[3] - machine[4]
        raw.append((a, b, delta))
        first = max(0, (a-start) // SECOND)
        last = min(seconds-1, (b-start) // SECOND)
        for i in range(first, last+1):
            left, right = start+i*SECOND, start+(i+1)*SECOND
            overlap = min(b, right) - max(a, left)
            if overlap > 0:
                for role, ticks in delta.items():
                    bins[i][role] += ticks * (overlap / (b-a))
    roles = sorted(set().union(*bins) - {"system_all"})
    metrics = dict(cpu_sample_seconds=seconds, clock_ticks_per_s=hz)
    with (work / "cpu.csv").open("x", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(["start_ns", "end_ns", "role", "ticks", "cpu_pct"])
        for a, b, delta in raw:
            for role, ticks in sorted(delta.items()):
                writer.writerow([a, b, role, ticks, 100*ticks/hz/((b-a) / SECOND)])
    for role in roles:
        series = [100 * b[role] / hz for b in bins]
        prefix = role.removeprefix("thread:") if role.startswith("thread:") else role + "_total"
        name = f"cpu_{prefix}_pct"
        metrics[name] = statistics.mean(series)
        metrics[name + "_min"] = min(series)
        metrics[name + "_median"] = statistics.median(series)
        metrics[name + "_max"] = max(series)
    metrics["collector_cpu_pct"] = metrics["cpu_process_total_pct"]
    total = sum(b["system_all"] for b in bins)
    metrics["system_busy_pct"] = 100 * sum(b["system"] for b in bins) / total if total else None
    return metrics


def stop_process(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def read_alerts(pipe, out):
    arrivals = {}
    plugin_count = 0
    for line in pipe:
        now = time.monotonic_ns()
        out.write(line)
        if b"sgxbench_" not in line and b"raven_zeek" not in line and b'"rz.' not in line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("source") == "raven_zeek" or "rz.result" in row.get("output_fields", {}):
            plugin_count += 1
        if row.get("rule") == "Run shell untrusted":
            label = re.search(r"\bsgxbench_[a-z0-9_]+\b", row.get("output_fields", {}).get("proc.cmdline", ""))
            if label:
                arrivals.setdefault(label[0], now)
    return arrivals, plugin_count


def read_stats(pipe, out, tick_file, ready):
    stats, ticks = {}, []
    for line in pipe:
        stamp = time.monotonic_ns()
        out.write(line)
        if not line.startswith(b"{"):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        mode = row.get("mode")
        if mode == "live_tick":
            ticks.append(row)
            tick_file.write(line)
        elif mode:
            stats[mode] = row
        if mode == "capture_ready":
            stats["ready_ns"] = stamp
            ready.set()
    return stats, ticks


def native_sample(stream, proc, work, offset, through, ticks, dest):
    # Falco's evt.time is Unix time in ns. Keep its source timestamp as well.
    until = time.monotonic() + (120 if not ticks else 10)
    while time.monotonic() < until:
        if proc.poll() is not None:
            raise RuntimeError(f"native Falco exited with {proc.returncode} while waiting for metrics")
        if stream is None and (work / "native-metrics.jsonl").exists():
            stream = (work / "native-metrics.jsonl").open("rb")
        if stream is not None:
            pos = stream.tell()
            line = stream.readline()
            if line.endswith(b"\n"):
                fields = json.loads(line)["output_fields"]
                t = fields["evt.time"]
                row = dict(mode="native_tick", mono_ns=t - offset, realtime_ns=t,
                           driver_events=fields["scap.n_evts"], driver_drops=fields["scap.n_drops"])
                ticks.append(row)
                dest.write((json.dumps(row) + "\n").encode())
                if row["mono_ns"] >= through:
                    return stream
                continue
            stream.seek(pos)
        time.sleep(.01)
    raise RuntimeError("timed out waiting for native kernel counters")


def sgx_metrics(stats, config, reasons):
    live, driver = stats["live"], stats["modern_ebpf"]
    raven, zeek = config in ("S2", "S4"), config in ("S3", "S4")
    selected = stats["event_selection"]["selected"]
    if not isinstance(selected, list) or len(selected) != (80 if raven else 72):
        reasons.append(f"unexpected selected syscall set: {selected}")
    if live["detectors"] != {"raven": raven, "zeek": zeek}:
        reasons.append(f"unexpected detector flags: {live['detectors']}")
    errors = live["errors"]
    if not isinstance(errors, dict) or not errors or any(errors.values()):
        reasons.append(f"enclave errors: {errors}")
    for row in (driver, live):
        if row["consumer"] != row["producer"]:
            reasons.append(f"{row['mode']} consumer/producer mismatch")
    for field in ("format_rejected", "trace_bytes"):
        if live[field] != 0:
            reasons.append(f"{field}={live[field]}")
    received = live["accepted"] - live["packet_records"]
    return dict(selected_count=len(selected), detectors=live["detectors"], errors=errors,
                received=received, offered=received + driver["driver_drops"],
                **{k: driver[k] for k in ("driver_events", "driver_drops", "packet_drops",
                                           "drain_ms", "capture_ms", "sleep_ocalls")},
                **{k: live[k] for k in ("packet_records", "ingest_stalls", "peak_blocks", "idle_polls",
                                        "raven_events", "format_rejected", "trace_bytes", "consumer",
                                        "producer", "alerts", "alert_flushes")})


def window_metrics(rows, start, seconds):
    # Resample cumulative snapshots onto exact one-second workload bins. Never
    # extrapolate a missing endpoint or treat the short final tick as a full second.
    stamps = [r["mono_ns"] for r in rows]
    if not stamps or start < stamps[0] or start + seconds * SECOND > stamps[-1]:
        raise ValueError("counter snapshots do not bracket the timed window")
    if any(y <= x for x, y in zip(stamps, stamps[1:])):
        raise ValueError("counter timestamps are not strictly increasing")
    intervals = [(b-a)/SECOND for a, b in zip(stamps, stamps[1:])]
    metrics = dict(counter_samples=len(rows), max_counter_interval_s=max(intervals))
    counters = {"received": [r["driver_events"] - r["driver_drops"] for r in rows],
                "driver_drops": [r["driver_drops"] for r in rows]}
    if "packet_submitted" in rows[-1]:
        counters["packet_records"] = [r["packet_submitted"] for r in rows]
        counters["packet_drops"] = [r["packet_dropped"] for r in rows]
    for name, values in counters.items():
        points = []
        for i in range(seconds + 1):
            t = start + i * SECOND
            j = bisect_left(stamps, t)
            if stamps[j] == t:
                points.append(values[j])
            else:
                fraction = (t - stamps[j-1]) / (stamps[j] - stamps[j-1])
                points.append(values[j-1] + fraction * (values[j] - values[j-1]))
        rates = [b-a for a, b in zip(points, points[1:])]
        metrics["window_" + name] = points[-1] - points[0]
        metrics[name + "_s"] = statistics.mean(rates)
        for label, func in (("min", min), ("median", statistics.median), ("max", max)):
            metrics[f"{name}_s_{label}"] = func(rates)
    metrics["offered_s"] = metrics["received_s"] + metrics["driver_drops_s"]
    return metrics


def marker_metrics(work, arrivals, start, end):
    delays = []
    count = 0
    with (work / "markers.tsv").open("x") as out:
        out.write("marker\ttrigger_ns\talert_ns\n")
        for line in (work / "triggers.tsv").read_text().splitlines():
            label, trigger = line.split()
            if not start <= int(trigger) < end:
                continue
            count += 1
            arrival = arrivals.get(label)
            out.write(f"{label}\t{trigger}\t{arrival or ''}\n")
            if arrival is not None:
                delays.append((arrival - int(trigger)) / 1e6)
    delays.sort()
    m = dict(markers=count, paired=len(delays), missing=count-len(delays))
    for p in (50, 95, 99):
        m[f"alert_p{p}_ms"] = delays[math.ceil(len(delays)*p/100)-1] if delays else None
    return m


def request_metrics(producer, seconds):
    count = producer["requests"]
    metrics = dict(requests=count, requests_s=count / seconds)
    rates = producer["requests_by_second"]
    metrics.update(requests_s_min=min(rates), requests_s_median=statistics.median(rates),
                   requests_s_max=max(rates))
    for p in (95, 99):
        rank = math.ceil(count*p/100)
        cumulative = 0
        for us, n in producer["latency_histogram_us"]:
            cumulative += n
            if cumulative >= rank:
                metrics[f"request_p{p}_ms"] = us / 1000
                break
    return metrics


def measure(args, work, exp, config, point, rate, seconds, binaries):
    command = falco_config(args, config, work)
    marker_interval = {"e3": .1, "e5": .05}.get(exp) if point != "cal6250" else None
    reasons = []
    result = dict(experiment=exp, config=config, point=point, duration_s=seconds,
                  mode="simulation" if args.sim else "hardware", load_rate=rate,
                  single_run=True, started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    env = dict(os.environ, TZ="UTC", FALCO_HOSTNAME="falco-bench")
    if config.startswith("S"):
        env["FALCO_LIVE_STATS_MS"] = "1000"
    with ExitStack() as stack:
        commands = stack.enter_context((work / "command.txt").open("x", buffering=1))
        commands.write(f"# collector mode: {result['mode']}; cwd: this run directory\n")

        def launch(cmd, **kwargs):
            cmd = list(map(str, cmd))
            prefix = ""
            if kwargs.get("user"):
                prefix = "runuser -u nobody -- "
            elif cmd == command:
                prefix = "env TZ=UTC FALCO_HOSTNAME=falco-bench "
                if config.startswith("S"):
                    prefix += "FALCO_LIVE_STATS_MS=1000 "
            commands.write(prefix + shlex.join(cmd) + "\n")
            proc = subprocess.Popen(cmd, cwd=work, env=env, **kwargs)
            stack.callback(stop_process, proc)
            return proc

        tick_file = stack.enter_context((work / "ticks.jsonl").open("xb"))
        stdout = stack.enter_context((work / "stdout.log").open("xb"))
        stderr = stack.enter_context((work / "stderr.log").open("xb"))
        load_err = stack.enter_context((work / "workload-stderr.log").open("xb"))
        client = marker = collector = None
        if exp in ("e4", "e5"):
            server = launch([sys.executable, HERE / "http-load.py", "serve"],
                            stdout=subprocess.PIPE, stderr=load_err)
            port = int(server.stdout.readline())
            client = launch([sys.executable, HERE / "http-load.py", "client", port, seconds,
                             "producer.json", "--rate", 10 if exp == "e5" else 0, "--gate"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=load_err)
            if client.stdout.readline().strip() != b"ready":
                raise RuntimeError("HTTP clients failed to establish two connections")
        if marker_interval:
            triggers = stack.enter_context((work / "triggers.tsv").open("xb"))
            marker = launch([binaries / "httpd", "sgxbench_" + config.lower().replace("-", "_"),
                             marker_interval, seconds, "--gate"], user="nobody", group="nogroup", extra_groups=[],
                            stdin=subprocess.PIPE, stdout=triggers, stderr=load_err)

        ready = threading.Event()
        native_ticks = []
        real_offset = time.time_ns() - time.monotonic_ns()
        if command:
            pool = stack.enter_context(ThreadPoolExecutor(max_workers=2))
            collector = launch(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            alerts_reader = pool.submit(read_alerts, collector.stdout, stdout)
            stats_reader = pool.submit(read_stats, collector.stderr, stderr, tick_file, ready)
            if config == "N1":
                native_file = native_sample(None, collector, work, real_offset, 0, native_ticks, tick_file)
                stack.callback(native_file.close)
            else:
                until = time.monotonic() + 120
                while not ready.wait(.05):
                    if collector.poll() is not None or time.monotonic() > until:
                        raise RuntimeError("falco-live did not report capture_ready")

        pid = collector.pid if collector else None
        samples = [cpu_snapshot(pid)]
        begin = time.monotonic_ns()
        if marker:
            marker.stdin.write(b"1")
            marker.stdin.close()
        if client:
            client.stdin.write(b"1")
            client.stdin.close()
        elif exp != "e6":
            program = "tcp-load" if exp == "e2" else "falco-load"
            client = launch([binaries / program, rate, seconds, "producer.json"], stderr=load_err)
        else:
            commands.write(f"# idle for {seconds} s\n")
        for i in range(1, seconds + 1):
            due = begin + i * SECOND
            time.sleep(max(0, (due-time.monotonic_ns()) / SECOND))
            samples.append(cpu_snapshot(pid))
        if client and client.wait(timeout=15):
            reasons.append(f"workload exit {client.returncode}")
        finish = time.monotonic_ns()
        if exp == "e6":
            write_json(work / "producer.json", dict(start_ns=begin, stop_ns=begin+seconds*SECOND))
        producer = read_json(work / "producer.json")
        start = producer["start_ns"]
        end = start + seconds * SECOND
        if samples[-1][0] < end:
            samples.append(cpu_snapshot(pid))
        result.update(window_start_ns=start, window_stop_ns=end, dispatch_ns=begin,
                      producer_exit_observed_ns=finish)
        if collector:
            if config == "N1":
                native_sample(native_file, collector, work, real_offset, end, native_ticks, tick_file)
            collector.send_signal(signal.SIGTERM)
            if collector.wait(timeout=120):
                reasons.append(f"collector exit {collector.returncode}")
            arrivals, plugin_alerts = alerts_reader.result()
            stats, ticks = stats_reader.result()
            result["raven_zeek_alerts"] = plugin_alerts
            if exp == "e2" and plugin_alerts:
                reasons.append(f"{plugin_alerts} unexpected raven_zeek alerts")
            try:
                if config == "N1":
                    ticks = native_ticks
                else:
                    result.update(sgx_metrics(stats, config, reasons))
                    if not ticks:
                        raise ValueError("no live_tick samples")
                    ready_ns = stats["ready_ns"]
                    if ready_ns < ticks[0]["mono_ns"]:
                        ticks = [dict(mono_ns=ready_ns, driver_events=0, driver_drops=0,
                                      packet_submitted=0, packet_dropped=0), *ticks]
                result.update(window_metrics(ticks, start, seconds))
                if config == "N1":
                    # Preserve integral observed counts and their actual bracketing
                    # interval separately from the interpolated workload-window rates.
                    lo = next(r for r in reversed(ticks) if r["mono_ns"] <= start)
                    hi = next(r for r in ticks if r["mono_ns"] >= end)
                    offered = hi["driver_events"] - lo["driver_events"]
                    drops = hi["driver_drops"] - lo["driver_drops"]
                    result.update(offered=offered, driver_drops=drops, received=offered-drops,
                                  capture_ms=(hi["mono_ns"]-lo["mono_ns"])/1e6,
                                  native_counter_start_ns=lo["mono_ns"], native_counter_stop_ns=hi["mono_ns"],
                                  packet_drops=0, packet_records=0, window_packet_records=0,
                                  ingest_stalls=None, peak_blocks=None, drain_ms=None)
            except (KeyError, ValueError, TypeError) as exc:
                reasons.append(f"invalid capture evidence: {exc}")
        if marker:
            if marker.wait(timeout=10):
                reasons.append(f"marker exit {marker.returncode}")
            result.update(marker_metrics(work, arrivals, start, end))
            result["scheduled_markers"] = round(seconds / marker_interval)
            if not result["paired"]:
                reasons.append("no timed marker paired with the Run shell untrusted rule")
        result.update(cpu_metrics(samples, work, start, seconds))
        if config.startswith("S"):
            roles = ["fl-ingest", "fl-analysis", "fl-writer"]
            if config in ("S2", "S3", "S4"):
                roles.append("fl-detect")
            for role in roles:
                if f"cpu_{role}_pct" not in result:
                    reasons.append(f"no CPU samples for {role}")
        if "requests" in producer:
            result.update(request_metrics(producer, seconds))
            if not producer["requests"] or producer["errors"]:
                reasons.append("HTTP workload failed or completed no requests")
            else:
                for field, label in (("received", "records"), ("packet_records", "packets")):
                    count = result.get("window_" + field)
                    result[label + "_per_request"] = count / producer["requests"] if count is not None else None
            if exp == "e4":
                baseline = args.out / "e4/B0-http/metrics.json"
                base = result if config == "B0" else read_json(baseline) if baseline.exists() else {}
                rps = base.get("requests_s") if base.get("valid", True) else None
                result["drop_vs_b0_pct"] = 100 * (1-result["requests_s"]/rps) if rps else None
        for field in ("pairs", "connections", "failed", "wall_ns", "cpu_ns", "sources", "port"):
            if field in producer:
                result[field] = producer[field]
        if "connections" in producer:
            result["connections_s"] = producer["connections"] / (producer["wall_ns"] / SECOND)
        if producer.get("pairs") and "received" in result:
            count = result["window_received"] if config == "N1" else result["received"]
            result["records_per_pair"] = count / producer["pairs"]
        if "raven_events" in result:
            result["raven_events_s"] = result["raven_events"] / (result["capture_ms"] / 1000)
    result.update(valid=not reasons, reasons=reasons)
    return result


def index_trial(out, path, row):
    index = out / "trials.csv"
    relative = path.relative_to(out).as_posix()
    if index.exists():
        with index.open(newline="") as stream:
            if any(r["metrics"] == relative for r in csv.DictReader(stream)):
                return
    fields = ["experiment", "config", "point", "duration_s", "mode", "valid", "received", "driver_drops",
              "packet_records", "packet_drops", "collector_cpu_pct", "metrics", "reasons"]
    with index.open("a", newline="") as stream:
        writer = csv.DictWriter(stream, fields, extrasaction="ignore")
        if not stream.tell():
            writer.writeheader()
        reasons = [*row["reasons"]]
        if "alert_context" in row:
            reasons.append(row["alert_context"])
        writer.writerow(dict(row, metrics=relative, reasons=" | ".join(reasons)))


def run_point(args, exp, config, point, rate=None, target=None, ratio=None, seconds=None):
    seconds = seconds or args.duration
    directory = args.out / exp / f"{config}-{point}"
    metrics = directory / "metrics.json"
    mode = "simulation" if args.sim else "hardware"
    if metrics.exists():
        row = read_json(metrics)
        if (row["duration_s"], row["mode"], row["load_rate"]) != (seconds, mode, rate):
            raise ValueError(f"{metrics} belongs to a different run; supply a new batch directory")
        if not args.dry_run:
            index_trial(args.out, metrics, row)
        if not row["valid"]:
            args.invalid.append(str(metrics))
        print(f"skip {exp}/{directory.name} (complete)", flush=True)
        args.remaining -= 1
        return row
    if args.dry_run:
        raise ValueError(f"missing base point for the E2 supplement preview: {metrics}")
    if exp in ("e1", "e2", "e3"):
        compile_tool(args.binaries, "tcp-load" if exp == "e2" else "falco-load")
    if exp in ("e3", "e5") and point != "cal6250":
        compile_tool(args.binaries, "httpd")
    eta = datetime.datetime.now().astimezone() + datetime.timedelta(
        seconds=max(1, args.remaining) * (args.duration + (statistics.mean(args.overheads) if args.overheads else 5)))
    print(f"run {exp}/{directory.name} ({seconds}s); batch ETA up to {eta:%H:%M:%S %Z}", flush=True)
    start = time.monotonic()
    directory.parent.mkdir(parents=True, exist_ok=True)
    # An interrupted session leaves its partial evidence intact. Only publish a
    # complete trial directory, then reconcile its CSV index on any later resume.
    work = Path(tempfile.mkdtemp(prefix="." + directory.name + ".partial-", dir=directory.parent))
    try:
        row = measure(args, work, exp, config, point, rate, seconds, args.binaries)
        row["target_rate"] = target
        if exp in ("e1", "e2"):
            if point == "unlimited":
                count = row.get("pairs" if exp == "e1" else "connections", 0)
                if exp == "e2":
                    count += row["failed"]
                row["axis_rate"] = (ratio or 1) * count / (row["wall_ns"] / SECOND)
            elif point == "cal6250":
                row["axis_rate"] = rate * row.get("records_per_pair", 0)
            else:
                row["axis_rate"] = target
            if "driver_drops" in row:
                row["lossy"] = bool(row["driver_drops"] or row.get("packet_drops"))
            if args.background_alerts_ok and not row["valid"] and capacity_eligible(row, True):
                row["alert_context"] = "后台告警"
        write_json(work / "metrics.json", row)
        work.chmod(directory.parent.stat().st_mode & 0o777)
        work.rename(directory)
    except BaseException as exc:
        if work.is_dir():
            (work / "failure.txt").write_text(repr(exc) + "\n")
        print(f"incomplete {work}: {exc}", file=sys.stderr, flush=True)
        raise
    index_trial(args.out, metrics, row)
    args.overheads.append(time.monotonic()-start-seconds)
    args.remaining -= 1
    if not row["valid"]:
        args.invalid.append(str(metrics))
        print("invalid " + " | ".join(row["reasons"]), file=sys.stderr)
    return row


def compile_tool(directory, name):
    exe = directory / name
    if not exe.exists():
        src = HERE / (("http-marker" if name == "httpd" else name) + ".c")
        flags = ["-pthread"] if name == "tcp-load" else []
        subprocess.run(["cc", "-O2", *flags, src, "-o", exe], check=True)


def capacity_eligible(row, background_alerts_ok):
    if row["valid"]:
        return True
    alerts = row.get("raven_zeek_alerts", 0)
    return (background_alerts_ok and row["experiment"] == "e2" and alerts > 0
            and row["reasons"] == [f"{alerts} unexpected raven_zeek alerts"])


def capacity(args, exp, config):
    rows = []
    ratio = 1
    if exp == "e1":
        first = run_point(args, exp, config, "cal6250", 6250)
        if not first["valid"] or not first.get("records_per_pair"):
            raise ValueError(f"{config} calibration did not yield a valid records/pair ratio")
        ratio = first["records_per_pair"]
        rows.append(first)
    targets = (50000, 100000, 150000, 200000) if exp == "e1" else (1000, 2000, 4000, 8000, 16000)
    for target in targets:
        if len(rows) >= 2 and all(capacity_eligible(r, args.background_alerts_ok) and r["lossy"]
                                  for r in rows[-2:]):
            break
        rate = max(1, round(target / ratio))
        rows.append(run_point(args, exp, config, str(target), rate, target))
    rows.append(run_point(args, exp, config, "unlimited", 0, ratio=ratio))
    for step in range(2):
        eligible = [r for r in rows if capacity_eligible(r, args.background_alerts_ok)]
        if args.background_alerts_ok and len(eligible) != len(rows):
            break
        lows = [r["axis_rate"] for r in eligible if not r["lossy"]]
        highs = [r["axis_rate"] for r in eligible if r["lossy"]]
        if not lows or not highs or max(lows) >= min(highs):
            break
        target = round((max(lows) + min(highs)) / 2)
        rate = max(1, round(target / ratio))
        if any(r["load_rate"] == rate for r in rows):
            break
        if args.dry_run and not (args.out / exp / f"{config}-bisect{target}" / "metrics.json").exists():
            print(f"plan {exp}/{config}-bisect{target} in [{max(lows):g}, {min(highs):g}]")
            if step == 0:
                print(f"at most one further midpoint: {round((max(lows)+target)/2)} if lossy, "
                      f"{round((target+min(highs))/2)} if lossless")
            break
        rows.append(run_point(args, exp, config, f"bisect{target}", rate, target))
    args.remaining -= len(plan_points(exp)) - len(rows)


def selected_plan(args):
    plan = {}
    for exp, configs in MATRIX.items():
        if args.experiment in ("all", exp):
            plan[exp] = [c for c in configs if not args.configs or c in args.configs]
    return {exp: configs for exp, configs in plan.items() if configs}


def plan_points(exp):
    return {
        "e1": ["cal6250 pairs/s", "50000", "100000", "150000", "200000", "unlimited", "bisect1?", "bisect2?"],
        "e2": ["1000", "2000", "4000", "8000", "16000", "unlimited", "bisect1?", "bisect2?"],
        "e3": ["10000", "50000", "100000"], "e4": ["http"], "e5": ["markers"], "e6": ["idle"],
    }[exp]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("experiment", choices=["all", *MATRIX], nargs="?", default="all")
    for name in ("package", "build", "live", "out"):
        parser.add_argument("--" + name, type=lambda x: Path(x).resolve(), required=True)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--configs", nargs="+", help="configuration IDs, space- or comma-separated")
    parser.add_argument("--sim", action="store_true", help="use the supplied simulation build directories")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--background-alerts-ok", action="store_true",
                        help="use E2 points invalid only for detector alerts in capacity decisions")
    args = parser.parse_args()
    if args.duration < 1:
        parser.error("--duration must be a positive integer")
    if args.configs:
        args.configs = {c for part in args.configs for c in part.split(",")}
        unknown = args.configs.difference(c for configs in MATRIX.values() for c in configs)
        if unknown:
            parser.error("unknown configurations: " + ", ".join(sorted(unknown)))
    plan = selected_plan(args)
    if not plan:
        parser.error("no selected configs apply to this experiment")
    if args.background_alerts_ok and args.experiment != "e2":
        parser.error("--background-alerts-ok applies only to e2")
    if args.dry_run and args.background_alerts_ok:
        args.remaining = len(plan["e2"]) * len(plan_points("e2"))
        args.invalid = []
        for config in plan["e2"]:
            capacity(args, "e2", config)
        return 0
    if args.dry_run:
        for exp, configs in plan.items():
            if exp == "e3":
                print(f"{exp}: reuse E1 S1 cal6250, otherwise one S1 calibration ({min(args.duration, 5)}s)")
            for cfg in configs:
                for point in plan_points(exp):
                    print(f"{exp} {cfg} {point} ({args.duration}s)")
        print("Capacity ladders stop after two consecutive losses; unlimited is measured once, "
              "then up to two bracketed midpoints.")
        return 0
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        parser.error("execute measurements as root in the Linux guest")
    if any(c.startswith("S") for configs in plan.values() for c in configs):
        for directory in (args.live, args.build):
            cache = directory / "CMakeCache.txt"
            if cache.is_file():
                match = re.search(r"^FALCO_SGX_HARDWARE:BOOL=(\S+)$", cache.read_text(), re.M)
                if match and (match[1].upper() in ("ON", "1", "TRUE", "YES")) == args.sim:
                    parser.error(f"{cache} disagrees with the requested hardware/simulation mode")
    args.remaining = sum(len(configs)*len(plan_points(exp)) for exp, configs in plan.items()) + int("e3" in plan)
    args.overheads, args.invalid = [], []
    args.out.mkdir(parents=True, exist_ok=True)
    import fcntl
    with ExitStack() as stack:
        batch_fd = os.open(args.out, os.O_RDONLY)
        stack.callback(os.close, batch_fd)
        fcntl.flock(batch_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        temp = stack.enter_context(tempfile.TemporaryDirectory(prefix="falco-bench-", dir="/tmp"))
        args.binaries = Path(temp)
        args.binaries.chmod(0o755)
        for exp, configs in plan.items():
            if exp == "e3":
                calibration = args.out / "e1/S1-cal6250/metrics.json"
                if calibration.exists():
                    first = read_json(calibration)
                    args.remaining -= 1
                else:
                    first = run_point(args, "e3", "S1", "cal6250", 6250, seconds=min(5, args.duration))
                if (not first["valid"] or not first.get("records_per_pair") or
                        first["mode"] != ("simulation" if args.sim else "hardware")):
                    raise ValueError("E3 requires a valid S1 calibration from the same mode")
                ratio = first["records_per_pair"]
            for config in configs:
                if exp in ("e1", "e2"):
                    capacity(args, exp, config)
                elif exp == "e3":
                    for target in (10000, 50000, 100000):
                        run_point(args, exp, config, str(target), max(1, round(target / ratio)), target)
                else:
                    run_point(args, exp, config, plan_points(exp)[0])
    return int(bool(args.invalid))


if __name__ == "__main__":
    sys.exit(main())
