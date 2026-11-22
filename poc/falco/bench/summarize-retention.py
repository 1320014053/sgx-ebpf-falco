"""Write the measurements and evaluate the published RAVEN retention acceptance limits."""
import json
import hashlib
from collections import Counter
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
mib = 1024**2


def read(relative):
    return json.loads((root/relative).read_text())


def measure(result, field):
    samples = result["samples"]
    end = result["final"]
    warm = [s for s in samples if s.get("seen",0)>=end["seen"]-500000 and s["phase"] in ("events","collected","expired")]
    phases = {p:[s for s in warm if s["phase"]==p] for p in ("collected","expired")}
    cycle_samples = phases["collected"] or phases["expired"]
    memory = [s[field] for s in cycle_samples]
    ordered = [s for s in samples if s["phase"] in ("start","events")]
    sampled_rss = max((s["rss"] for s in samples if "rss" in s),default=0)
    return dict(events=end["seen"],published=end["published"],kept=end["observations"],evicted=end["evicted"],
                time_evicted=end["time_evicted"],budget_evicted=end["budget_evicted"],resets=end["resets"],skipped=end["skipped"],
                cycles=end["cycles"],compared_phase=cycle_samples[0]["phase"] if memory else None,steady_samples=len(memory),
                baseline_range_bytes=[min(memory),max(memory)] if memory else [],
                baseline_span_bytes=max(memory)-min(memory) if memory else None,
                memory_every_10000_bytes=[b[field]-a[field] for a,b in zip(ordered,ordered[1:])],
                warm_seconds=[min(x["seconds"] for x in warm),max(x["seconds"] for x in warm)],
                after_gc_seconds=[min(x["seconds"] for x in cycle_samples),max(x["seconds"] for x in cycle_samples)] if memory else [],
                oldest_including_pins_seconds=[min(s["now"]-s["oldest_retained"] for s in warm if s["oldest_retained"] is not None),
                                               max(s["now"]-s["oldest_retained"] for s in warm if s["oldest_retained"] is not None)],
                process_peak_bytes=max(result["process_peak"],sampled_rss),gnu_time_peak_bytes=result["process_peak"],
                sampled_rss_peak_bytes=sampled_rss or None,heap_peak_bytes=result.get("heap_peak"),
                peak_charge_bytes=max(s.get("peak_charged",0) for s in samples),
                max_alert_bytes=result["max_alert_bytes"],max_payload_bytes=result["max_payload_bytes"],
                input_id_hash=end["hash"],ordinal_ids=end["ordinal_ids"],alerts_sha256=result["alert_sha256"])


report = dict(build_sha256=dict((Path(path).name,sha) for sha,path in
              (line.split(None,1) for line in (root/"binaries.sha256").read_text().splitlines())),
              original_cases=read("parity/comparison.json"), original_100k=read("original/comparison.json"),
              inputs=read("million/inputs.json"),idle_clock_and_duplicate=(root/"idle.result").read_text().strip()=="PASS",
              boundaries={},runs={})
report["limits"] = dict(history_seconds=600,high_bytes=128*mib,low_bytes=96*mib,
                        steady_span_bytes=8*mib,trusted_heap_peak_bytes=384*mib)
for case,manifest in report["inputs"].items():
    report["original_100k"][case]["ordered_alert_sha256"] = {m:read(f"original/{case}-{m}-release-0/result.json")["ordered_alert_sha256"]
                                                               for m in ("native","sgx")}
    digest = hashlib.sha256()
    with (root/"million"/(case+".jsonl")).open("rb") as full, (root/"original"/(case+".jsonl")).open("rb") as old:
        for block in iter(lambda:old.read(1024*1024),b""):
            assert full.read(len(block))==block,case
            digest.update(block)
        manifest["archived_prefix_sha256"]=digest.hexdigest()
        for block in iter(lambda:full.read(1024*1024),b""): digest.update(block)
    assert digest.hexdigest()==manifest["sha256"],case
for case in ("expiry","ancestry","overload","protected"):
    report["boundaries"][case]={}
    for mode in ("native","sgx"):
        record=read(f"boundaries/{case}-{mode}/result.json")
        report["boundaries"][case][mode]=dict(alerts=record["alerts"],alerts_sha256=record["alert_sha256"],
                                               final=record["final"],gaps=[s for s in record["samples"] if s["phase"]=="gap"])
for group in ("repeat","churn","actual-repeat","actual-churn"):
    actual = group.startswith("actual-")
    native = read(f"{group}-native/result.json")
    trusted = read(f"{group if actual else group+'-sgx'}/result.json")
    a,b = measure(native,"rss"),measure(trusted,"heap")
    checks = dict(same_normalized_alerts=all(a[k]==b[k] for k in ("published","alerts_sha256","max_alert_bytes")),
                  same_ordered_input=all(a[k]==b[k] for k in ("events","input_id_hash")),
                  zero_gaps=all(v["skipped"]==v["resets"]==0 for v in (a,b)),
                  within_history_budget=all(v["peak_charge_bytes"]<=128*mib for v in (a,b)),
                  steady_memory=all(v["steady_samples"]>=3 and v["baseline_span_bytes"]<=8*mib for v in (a,b)),
                  within_trusted_heap=b["heap_peak_bytes"]<=384*mib)
    if actual:
        checks["million_real_events"] = a["events"]>=1000000
        ring,driver=trusted["capture"]["live"],trusted["capture"]["modern_ebpf"]
        checks["capture_complete"] = ring["raven_events"]==a["events"] and \
            ring["records"]==ring["accepted"]==driver["driver_events"]+driver["packet_submitted"] and \
            ring["packet_records"]==driver["packet_submitted"] and \
            len({ring["consumer"],ring["producer"],driver["consumer"],driver["producer"]})==1 and \
            all(v==0 for v in (ring["discarded"],ring["format_rejected"],driver["driver_drops"],driver["packet_drops"]))
    else:
        checks["each_input_id"] = a["ordinal_ids"]==b["ordinal_ids"]==a["events"]==1000000
        checks["expected_outputs"] = a["published"]==100
    record=dict(native=a,sgx=b,checks=checks,samples={"native":native["samples"],"sgx":trusted["samples"]})
    if actual:
        for key in ("capture","input_sha256","operations","verified_children","marker_alerts","marker_evidence"): record[key]=trusted[key]
        target_ids = {m["id"] for m in record["marker_evidence"]}
        extra = Counter()
        with (root/group/"alerts.jsonl").open("rb") as output:
            for line in output:
                a = json.loads(line)
                if a["source"]!="raven_zeek": continue
                d = json.loads(a["output_fields"]["rz.result"])
                if "note" in d: continue
                event = d["events"][-1]
                if d["rule"]!="sensitive_access_chain" or event["id"] not in target_ids:
                    extra[d["rule"]+" / "+event["exe"]]+=1
        assert sum(extra.values())+len(target_ids)==trusted["alerts"]
        record["other_alerts_by_rule_and_process"]=dict(extra)
    report["runs"][group]=record
report["passed"]=report["idle_clock_and_duplicate"] and all(all(g["checks"].values()) for g in report["runs"].values())
(root/"retention-results.json").write_text(json.dumps(report,indent=2)+"\n")
for group,g in report["runs"].items(): print(group,g["checks"],flush=True)
sys.exit(0 if report["passed"] else 1)
