import collections,csv,json
from pathlib import Path
with open("trials.csv", newline="") as idx, open("summary/e2-background-alerts.csv", "x", newline="") as out:
    writer = csv.writer(out)
    writer.writerow("run status valid connections_s received_s packet_records_s driver_drops packet_drops collector_cpu_pct total_alerts root_exe rule alerts".split())
    for entry in csv.DictReader(idx):
        if entry["experiment"] != "e2" or entry["valid"] != "False":
            continue
        p = Path(entry["metrics"])
        row = json.loads(p.read_text())
        n = row["raven_zeek_alerts"]
        assert n > 0 and row["reasons"] == [f"{n} unexpected raven_zeek alerts"], p
        counts = collections.Counter()
        with (p.parent / "stdout.log").open() as f:
            for line in f:
                if line.startswith("{"):
                    raw = json.loads(line).get("output_fields", {}).get("rz.result")
                    if raw:
                        detection = json.loads(raw)
                        counts[detection.get("root_exe", "?"), detection.get("rule", "?")] += 1
        assert sum(counts.values()) == n, p
        for (exe, rule), count in counts.most_common():
            writer.writerow([p.parent, "后台告警", False, row["connections_s"], row["received_s"],
                             row["packet_records_s"], row["driver_drops"], row["packet_drops"],
                             row["collector_cpu_pct"], n, exe, rule, count])
