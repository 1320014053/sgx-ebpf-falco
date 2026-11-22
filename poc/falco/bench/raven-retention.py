"""Run identical RAVEN inputs through standalone Falco and the signed enclave."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

here = Path(__file__).resolve().parents[1]
old = runpy.run_path(str(here / "bench/raven-memory.py"))
MIB = 1024**2


def generate(out, n):
    out.mkdir()
    manifest = {}
    for case in ("repeat", "churn"):
        digest = hashlib.sha256()
        order = 14695981039346656037
        with (out / (case + ".jsonl")).open("xb") as file:
            for i in range(1, n + 1):
                event = old["event"](case, i)
                line = json.dumps(event, separators=(",", ":")).encode() + b"\n"
                file.write(line)
                digest.update(line)
                for b in event["event_id"].encode() + b"\0":
                    order = ((order ^ b) * 1099511628211) & ((1 << 64) - 1)
        manifest[case] = dict(events=n, sha256=digest.hexdigest(), order=str(order))
    (out / "inputs.json").write_text(json.dumps(manifest, indent=2))


def metrics(log):
    return [json.loads(line[6:]) for line in log.read_text().splitlines() if line.startswith("RZRET ")]


def verify_alerts(path, case, n, bounded):
    digest = hashlib.sha256()
    count = largest = largest_payload = 0
    with path.open("rb") as stream:
        for line in stream:
            if not line.startswith(b"{"):
                continue
            alert = json.loads(line)
            if alert["source"] != "raven_zeek":
                continue
            raw = alert["output_fields"].pop("rz.result")
            row = json.loads(raw)
            if "note" in row:
                continue
            del row["id"]
            for k in ("output", "message"):
                if k in alert:
                    assert raw in alert[k]
                    alert[k] = alert[k].replace(raw, "<result>")
            count += 1
            if case in ("repeat","churn"):
                signal = count*10000 - 1
                assert row["rule"] == "sensitive_access_chain" and row["state"] == "active"
                assert [e["id"] for e in row["events"]] == [f"ring-{signal}"]
                edges = {e["type"]: e["event_ids"] for e in row["reconstruction"]["graph"]["edges"]}
                assert set(edges) == {"modified","accessed"}
                if case == "churn":
                    assert edges == {"accessed":[f"ring-{signal}"], "modified":[f"ring-{signal-1}"]}
                elif bounded:
                    cut = row["meta"].get("retention",{}).get("after_sequence",0)
                    assert edges["modified"] == [f"ring-{i}" for i in range(max(cut+1,2),signal) if i%10000 != 9999]
                    reads = [int(x[5:]) for x in edges["accessed"]]
                    assert reads == sorted(set(reads)) and reads[-1] == signal
                    assert all(i%10000 == 9999 for i in reads)
                    assert [i for i in reads if i>cut] == list(range((cut+1)//10000*10000+9999,signal+1,10000))
            largest = max(largest,len(line.rstrip(b"\r\n")))
            largest_payload = max(largest_payload,len(raw.encode()))
            digest.update(json.dumps([row,alert],sort_keys=True,separators=(",",":")).encode()+b"\n")
    if case in ("repeat","churn"):
        assert count == n//10000
    return dict(alerts=count,max_alert_bytes=largest,max_payload_bytes=largest_payload,alert_sha256=digest.hexdigest())


def execute(package, build, baseline, cwd, mode, inputfile, case, n, streaming, high, hostname):
    cwd.mkdir()
    links = {"reference.scap":baseline/"reference.scap", "falco_rules.yaml":baseline/"falco_rules.yaml",
             "libcontainer.so":baseline/"libcontainer.so", "libraven_zeek.so":build/"lib/libraven_zeek.so",
             "raven_zeek_rules.yaml":here/"plugin/rules.yaml", "events.jsonl":inputfile}
    for name, target in links.items():
        (cwd/name).symlink_to(target)
    (cwd/"packets.pcap").write_bytes(bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000"))
    cfg = (here/"plugin/replay.yaml").read_text().replace('"format":"replay"',json.dumps(
        dict(format="stream" if streaming else "replay",history_bytes=high,retention_metrics=True),separators=(",",":"))[1:-1])
    (cwd/"falco.yaml").write_text(cfg)
    if mode == "native":
        cmd = [package/"usr/bin/falco","-c","falco.yaml","-o","engine.kind=modern_ebpf","--enable-source","raven_zeek"]
    else:
        args = ["--plugin-stream","events.jsonl"] if streaming else ["--plugin","events.jsonl","packets.pcap"]
        cmd = [build/"bin/falco-sgx",build/"falco-enclave.signed","falco.yaml","reference.scap",*args,"falco_rules.yaml","raven_zeek_rules.yaml"]
    with (cwd/"alerts.jsonl").open("xb") as output, (cwd/"run.log").open("xb") as log:
        subprocess.run(["/usr/bin/time","-q","-f","%M","-o","maxrss.kib",*cmd],cwd=cwd,stdout=output,stderr=log,
                       env=dict(os.environ,TZ="UTC",FALCO_HOSTNAME=hostname),check=True)
    if not streaming and case in ("repeat","churn"):
        summary = old["verify_output"](cwd/"alerts.jsonl",case,n)
    else:
        summary = verify_alerts(cwd/"alerts.jsonl",case,n,streaming)
    samples = metrics(cwd/"run.log")
    summary.update(mode=mode,case=case,samples=samples,process_peak=int((cwd/"maxrss.kib").read_text())*1024)
    if streaming:
        last = next(x for x in samples if x["phase"]=="finish")
        if n: assert last["seen"] == n
        assert last["published"]==summary["alerts"]
        memory = "rss" if mode=="native" else "heap"
        checkpoints = [s for s in samples if s["phase"] in ("events","start")]
        assert [c["seen"] for c in checkpoints] == list(range(0,last["seen"]+1,10000))
        summary["growth_per_10000_bytes"] = [b[memory]-a[memory] for a,b in zip(checkpoints,checkpoints[1:])]
        if case in ("repeat","churn"):
            assert last["ordinal_ids"] == n
            assert last["hash"] == json.loads((inputfile.parent/"inputs.json").read_text())[case]["order"]
            assert last["evicted"] + last["observations"] == n and last["skipped"] == last["resets"] == 0
            assert max(s.get("peak_charged",0) for s in samples) <= high
        steady_start = max(last["seen"]/2,last["seen"]-500000)
        collected = [s for s in samples if s["phase"]=="collected" and s["seen"]>=steady_start]
        if collected:
            values = [s[memory] for s in collected]
            summary["baseline_span_bytes"] = max(values)-min(values)
            summary["post_gc_seconds"] = [min(s["seconds"] for s in collected),max(s["seconds"] for s in collected)]
        warm = [s["seconds"] for s in samples if s["phase"]=="events" and s["seen"]>=steady_start]
        if warm: summary["warm_seconds"] = [min(warm),max(warm)]
        if mode=="sgx": summary["heap_peak"] = max(s["heap_peak"] for s in samples)
        summary["final"] = last
    (cwd/"result.json").write_text(json.dumps(summary,indent=2)+"\n")
    print(cwd.name, {k:v for k,v in summary.items() if k not in ("samples","final","per_alert","growth_per_10000_bytes")},flush=True)
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action",required=True)
    gen = sub.add_parser("generate")
    gen.add_argument("out",type=Path)
    gen.add_argument("--events",type=int,default=1_000_000)
    run = sub.add_parser("run")
    for arg in ("package","build","baseline","out","input"):
        run.add_argument(arg,type=Path)
    run.add_argument("mode",choices=("sgx","native"))
    run.add_argument("case")
    run.add_argument("--offline",action="store_true")
    run.add_argument("--high",type=int,default=128*MIB)
    run.add_argument("--events",type=int,default=0)
    run.add_argument("--hostname",default="raven-retention")
    args=parser.parse_args()
    if args.action=="generate":
        generate(args.out.resolve(),args.events)
    else:
        execute(args.package.resolve(),args.build.resolve(),args.baseline.resolve(),args.out.resolve(),
                args.mode,args.input.resolve(),args.case,args.events,not args.offline,args.high,args.hostname)
