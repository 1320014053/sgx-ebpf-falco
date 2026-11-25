"""Summarize E1–E6. Each point is one run; min/median/max describe seconds within that run."""
import argparse
import csv
import datetime
import json
from pathlib import Path


def write_table(path, rows):
    if not rows:
        return
    fields = list(dict.fromkeys(k for row in rows for k in row))
    with path.open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v
                             for k, v in row.items()})


def read_trials(batch):
    paths = set()
    if (batch / "trials.csv").is_file():
        with (batch / "trials.csv").open(newline="") as index:
            for row in csv.DictReader(index):
                if row.get("experiment") in {f"e{i}" for i in range(1, 7)} and row.get("metrics"):
                    paths.add(batch / row["metrics"])
    # Recover trials published before an interrupted CSV append; skip staging directories.
    for path in batch.glob("e[1-6]/*/metrics.json"):
        if not path.parent.name.startswith("."):
            paths.add(path)
    result = []
    for path in sorted(paths):
        data = json.loads(path.read_text())
        result.append(dict(data, metrics=path.relative_to(batch).as_posix(), runs=1))
    return result


def point_row(run):
    keys = ["experiment", "config", "point", "runs", "valid", "reasons", "mode", "duration_s",
            "target_rate", "load_rate", "axis_rate", "metrics"]
    row = {k: run[k] for k in keys if k in run}
    row.update({k: v for k, v in run.items() if k not in row and k not in {
        "single_run", "started_utc", "consumer", "producer", "window_start_ns", "window_stop_ns",
        "dispatch_ns", "producer_exit_observed_ns", "native_counter_start_ns", "native_counter_stop_ns"}})
    return row


def limits(rows):
    result = []
    for config in dict.fromkeys(r["config"] for r in rows):
        valid = [r for r in rows if r["config"] == config and r["valid"]]
        zero = [r for r in valid if not r["lossy"]]
        lossy = [r for r in valid if r["lossy"]]
        low = max(zero, key=lambda r: r["axis_rate"], default=None)
        high = min(lossy, key=lambda r: r["axis_rate"], default=None)
        for name, row in (("highest_zero_loss", low), ("first_lossy", high)):
            result.append(dict(config=config, boundary=name, observed=row is not None,
                               nonmonotonic=bool(low and high and low["axis_rate"] >= high["axis_rate"]),
                               **({k: v for k, v in row.items() if k != "config"} if row else {})))
    return result


def plots(directory, groups):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return
    for exp, rows in groups.items():
        rows = [r for r in rows if r["valid"]]
        if not rows:
            continue
        fig, ax = plt.subplots(figsize=(8, 4.5), constrained_layout=True)
        if exp in ("e1", "e2", "e3"):
            for cfg in dict.fromkeys(r["config"] for r in rows):
                points = [r for r in rows if r["config"] == cfg]
                if exp == "e3":
                    points.sort(key=lambda r: r["target_rate"])
                    ax.plot([r["target_rate"] for r in points], [r["alert_p99_ms"] for r in points],
                            "o-", label=cfg)
                else:
                    points.sort(key=lambda r: r["axis_rate"])
                    x = [r["axis_rate"] for r in points]
                    y = [r["received_s"] for r in points]
                    line, = ax.plot(x, y, "o-", label=cfg)
                    ax.vlines(x, [r["received_s_min"] for r in points], [r["received_s_max"] for r in points],
                              color=line.get_color(), alpha=.45)
            ax.set_xlabel("Connections/s" if exp == "e2" else "Target syscall records/s")
            ax.set_ylabel("Alert p99 (ms)" if exp == "e3" else "Received syscall records/s")
            ax.legend()
        else:
            field, label = {"e4": ("requests_s", "HTTP requests/s"),
                            "e5": ("alert_p99_ms", "Alert p99 (ms)"),
                            "e6": ("collector_cpu_pct", "Collector CPU (% of one CPU)")}[exp]
            ax.bar([r["config"] for r in rows], [r[field] for r in rows])
            ax.set_ylabel(label)
        title = f"{exp.upper()} · one run per point"
        if exp in ("e1", "e2"):
            title += " · bars show within-run 1 s min/max"
        ax.set_title(title)
        fig.savefig(directory / f"{exp}.png", dpi=150, bbox_inches="tight")
        plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("batch", type=Path)
    args = parser.parse_args()
    rows = read_trials(args.batch)
    if not rows:
        parser.error("no completed E1–E6 metrics in this batch")
    summary = args.batch / "summary"
    summary.mkdir(exist_ok=True)
    if any((summary / f"e{i}.csv").exists() for i in range(1, 7)):
        # Preserve previously generated tables when resuming a partial batch.
        summary = summary / datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        summary.mkdir()
    groups = {}
    for exp in (f"e{i}" for i in range(1, 7)):
        group = [point_row(r) for r in rows if r["experiment"] == exp and
                 not (exp == "e3" and r["point"] == "cal6250")]
        if not group:
            continue
        group.sort(key=lambda r: (r["config"], r.get("axis_rate") or r.get("target_rate") or 0))
        if exp == "e4":
            baseline = next((r["requests_s"] for r in group if r["config"] == "B0" and r["valid"]), None)
            for row in group:
                row["drop_vs_b0_pct"] = 100*(1-row["requests_s"]/baseline) if baseline and row["valid"] else None
        write_table(summary / f"{exp}.csv", group)
        if exp in ("e1", "e2"):
            write_table(summary / f"{exp}-limits.csv", limits(group))
        groups[exp] = group
    plots(summary, groups)
    print(f"{summary}: each point is one run. Min/median/max are within-run one-second statistics.")
    print("Capacity limits use valid runs and any syscall or packet drops. "
          "Unlimited is positioned by achieved producer rate; E1 converts pairs using the calibrated ratio.")
    print("Received/offered counts cover the actual counter interval. Window rates and per-request values "
          "use one-second counter snapshots interpolated at workload boundaries.")


if __name__ == "__main__":
    main()
