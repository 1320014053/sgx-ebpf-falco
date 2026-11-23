"""Regenerate per-trial indices and engineering summaries from immutable measurements."""
import csv
import json
import math
from collections import defaultdict
from pathlib import Path
from statistics import median

base=Path(__file__).resolve().parents[1]
raw=base/"raw"
bulk=base/"bulk"
out=base/"summary"
out.mkdir(exist_ok=True)
def read(p): return json.loads(p.read_text(encoding="utf-8-sig"))
def save(name,rows):
    if not rows: return
    with (out/name).open("w",newline="",encoding="utf-8") as stream:
        writer=csv.DictWriter(stream,fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
def percentile(values,q):
    return sorted(values)[max(0,math.ceil(q*len(values))-1)] if values else None
def histogram_quantile(hist,q):
    target=math.ceil(sum(n for us,n in hist)*q)
    cumulative=0
    for us,n in hist:
        cumulative+=n
        if cumulative>=target: return us/1000
def rows_json(path):
    return [json.loads(line) for line in path.read_text(errors="replace").splitlines() if line.startswith("{")]
def raw_or_bulk(d,name):
    local=d/name
    return local if local.exists() else bulk/d.name/name
trials={}
micro=[]
http=[]
memory=[]
replay=[]
plugin=[]
capacity=[]
latency_samples=defaultdict(list)
for d in sorted(raw.iterdir()):
    meta=d/"trial.json"
    if not meta.exists(): continue
    tr=read(meta)
    trials[d.name]=dict(tr)
    if tr["status"]!="ok": continue
    exp,mode=tr["experiment"],tr["mode"]
    if exp=="getpid":
        v=read(d/"stdout.json")
        sec=v["generator_wall_ns"]/1e9
        wall=v["wall_ns"]/1e9
        assert v["ok"] and sec>=60
        if mode!="baseline":
            assert v["attempted"]==v["submitted"]+v["reserve_failed"]
            assert v["submitted"]==v["processed"]+v["format_rejected"]
        micro.append(dict(trial=d.name,mode=mode,load=tr["load_level"],repeat=tr["repeat"],
            seconds=sec,issued_per_s=v["generator_calls"]/sec,processed_per_s=v["processed"]/wall if mode!="baseline" else None,
            issued=v["generator_calls"],processed=v["processed"],lost=v["reserve_failed"],invalid=v["format_rejected"],
            data_ecalls=v["data_ecalls"],sdk_bytes=v["sdk_input_bytes"],pack_bytes=v["host_pack_bytes"],
            trusted_payload_copy_bytes=v["payload_copy_bytes"],generator_cpu_pct=100*v["generator_cpu_ns"]/v["generator_wall_ns"],
            consumer_cpu_pct=100*v["consumer_cpu_ns"]/v["wall_ns"],host_cpu_pct=100*v["host_cpu_ns"]/v["wall_ns"],
            drain_ms=v["drain_ns"]/1e6))
    elif exp in ("http","alert-latency","idle") and tr["repeat"]!=0:
        v=read(d/"metrics.json")
        w=read(d/"workload.json") if exp!="idle" else {}
        sample=[]
        with (d/"markers.tsv").open() as stream:
            for row in csv.DictReader(stream,delimiter="\t"):
                if row["alert_ns"]:
                    ms=(int(row["alert_ns"])-int(row["trigger_ns"]))/1e6
                    assert ms>=0
                    sample.append(ms)
        assert len(sample)==v["paired"]
        latency_samples[(exp,mode)].extend(sample)
        events=drops=packets=packet_drops=drain=None
        if mode.startswith("hw"):
            s=rows_json(d/"collector.log")
            driver=next(x for x in s if x.get("mode")=="modern_ebpf")
            events,drops,packets,packet_drops,drain=(driver[k] for k in ("driver_events","driver_drops","packet_submitted","packet_drops","drain_ms"))
            assert driver["trace_ocalls"]==0 and driver["consumer"]==driver["producer"]
        elif mode=="native":
            metric_file=raw_or_bulk(d,"native-metrics.jsonl")
            if metric_file.exists():
                sampled=[x["output_fields"] for x in rows_json(metric_file)]
                if sampled:
                    events,drops=(sampled[-1].get(k) for k in ("scap.n_evts","scap.n_drops"))
        duration=(w["stop_ns"]-w["start_ns"])/1e9 if w else v["window_s"]
        hist=w.get("latency_histogram_us")
        if w: assert not w["errors"] and w["requests"]==sum(x[1] for x in hist)
        http.append(dict(trial=d.name,experiment=exp,mode=mode,repeat=tr["repeat"],seconds=duration,
            requests=w.get("requests"),rps=w["requests"]/duration if w else None,
            request_p95_ms=histogram_quantile(hist,.95) if hist else None,request_p99_ms=histogram_quantile(hist,.99) if hist else None,
            collector_cpu_pct=100*v["collector_cpu_s"]/v["window_s"],machine_busy_pct=100*v["system_busy_fraction"],
            source_events=events,source_drops=drops,packets=packets,packet_drops=packet_drops,drain_ms=drain,
            markers=v["markers"],pairs=len(sample),alert_p50_ms=percentile(sample,.5),alert_p95_ms=percentile(sample,.95),
            alert_p99_ms=percentile(sample,.99)))
    elif exp=="falco-capacity" or exp.startswith("capacity-"):
        v=read(d/"metrics.json")
        capacity.append(dict(trial=d.name,experiment=exp,mode=mode,repeat=tr["repeat"],target_pairs_s=tr["load_level"],**v))
    elif exp=="raven-memory":
        v=read(d/"result.json"); z=v["final"]
        assert z["seen"]==int(tr["load_level"]) and v["alerts"]==z["published"]
        memory.append(dict(trial=d.name,mode=mode,workload=tr["workload"],events=z["seen"],alerts=v["alerts"],
            wall_s=tr["measurement_s"],rss_peak_mib=v["process_peak"]/2**20,heap_peak_mib=v.get("heap_peak",0)/2**20 if mode=="sgx" else None,
            final_heap_mib=z.get("heap",0)/2**20 if mode=="sgx" else None,retention_cycles=z["cycles"],evicted=z["evicted"],
            retained=z["observations"],skipped=z["skipped"],resets=z["resets"],alert_digest=v["alert_sha256"],
            peak_charged_mib=z["peak_charged"]/2**20,
            post_gc_span_mib=v["baseline_span_bytes"]/2**20 if v.get("baseline_span_bytes") is not None else None,
            max_alert_bytes=v["max_alert_bytes"],coverage_at_end_s=z["seconds"]))
    elif exp in ("falco-replay","plugin-replay"):
        v=read(d/"metrics.json")
        dst=replay if exp=="falco-replay" else plugin
        dst.append(dict(trial=d.name,mode=mode,repeat=tr["repeat"],load=tr["load_level"],seconds=v["seconds"],
            events=v.get("events",v.get("normalized_events")),packets=v.get("packets"),alerts=v.get("alerts"),
            cold_to_ready_s=v.get("cold_to_ready_s"),ready_to_summary_s=v.get("ready_to_summary_s"),ready_to_exit_s=v.get("ready_to_exit_s"),
            user_s=v.get("user_s",v.get("cpu_user_s")),sys_s=v.get("sys_s",v.get("cpu_sys_s")),peak_rss_kib=v["peak_rss_kib"]))
for name,exp,mode,work,status,code in [
    ("host-preflight-r01","environment","native","host-inventory","ok",0),
    ("getpid-identity-r01","identity","hw","GETPID REPORT and ring","ok",0),
    ("getpid-ring-r02","smoke","hw","GETPID ring","ok",0),
    ("falco-offline-r01","identity","hw","Falco local REPORT","failed",1),
    ("falco-offline-r02","identity-and-parity","native+hw","Falco local REPORT and fixture","ok",0),
    ("falco-live-official-r01","live-parity","native+hw","official rules","ok",0),
    ("falco-live-detectors-r01","live-parity","native+hw","RAVEN and Zeek","ok",0)]:
    if (raw/name).is_dir():
        trials[name]=dict(trial_id=name,experiment=exp,mode=mode,workload=work,load_level="",repeat=int(name[-2:]),
                          status=status,exit_code=code,measurement_s="",raw_path="raw/"+name+"/")
order=("trial_id","experiment","mode","workload","load_level","repeat","status","exit_code","measurement_s","raw_path")
with (base/"trials.csv").open("w",newline="",encoding="utf-8") as stream:
    w=csv.DictWriter(stream,fieldnames=order,extrasaction="ignore")
    w.writeheader(); w.writerows(trials[k] for k in sorted(trials))
save("getpid-trials.csv",micro)
save("http-trials.csv",http)
for n in (100000,1000000):
    for case in ("repeat","churn"):
        pair=[x for x in memory if x["events"]==n and x["workload"]==case]
        if len(pair)==2:
            assert pair[0]["alert_digest"]==pair[1]["alert_digest"]
            assert read(raw/pair[0]["trial"]/"input.json")==read(raw/pair[1]["trial"]/"input.json")
save("memory.csv",memory)
save("capacity.csv",capacity)
save("official-replay.csv",replay)
save("plugin-replay.csv",plugin)
groups=[]
for level in ("low","100k","max"):
    for mode in ("baseline","host","ecall","batch","direct"):
        rows=[x for x in micro if x["mode"]==mode and x["load"]==level]
        if not rows: continue
        group=dict(load=level,mode=mode,n=len(rows),rounds_zero_loss=sum(x["lost"]==0 for x in rows) if mode!="baseline" else None)
        for key in ("issued_per_s","processed_per_s","lost","drain_ms","consumer_cpu_pct"):
            vals=[x[key] for x in rows if x[key] is not None]
            for tag,fn in (("median",median),("min",min),("max",max)):
                group[key+"_"+tag]=fn(vals) if vals else None
        groups.append(group)
save("getpid-groups.csv",groups)
http_groups=[]
for exp in ("http","alert-latency","idle"):
    for mode in ("baseline","native","hw-official","hw-full"):
        rows=[x for x in http if x["mode"]==mode and x["experiment"]==exp]
        if not rows: continue
        sample=latency_samples[exp,mode]
        group=dict(experiment=exp,mode=mode,n=len(rows),markers=sum(x["markers"] for x in rows),paired=len(sample),
                   alert_p50_ms=percentile(sample,.5),alert_p95_ms=percentile(sample,.95),alert_p99_ms=percentile(sample,.99))
        for key in ("rps","request_p95_ms","request_p99_ms","collector_cpu_pct","machine_busy_pct","source_drops","packet_drops"):
            vals=[x[key] for x in rows if x[key] is not None]
            for tag,fn in (("median",median),("min",min),("max",max)):
                group[key+"_"+tag]=fn(vals) if vals else None
        paired_changes=[]
        if exp=="http":
            for x in rows:
                baseline=next((b for b in http if b["mode"]=="baseline" and b["experiment"]==exp and b["repeat"]==x["repeat"]),None)
                if baseline: paired_changes.append((1-x["rps"]/baseline["rps"])*100)
        group["paired_rps_decrease_pct_median"]=median(paired_changes) if paired_changes else None
        http_groups.append(group)
save("http-groups.csv",http_groups)
print("getpid formal",len(micro),"http/latency/idle",len(http),"memory",len(memory),"official replay",len(replay),"plugin replay",len(plugin))
