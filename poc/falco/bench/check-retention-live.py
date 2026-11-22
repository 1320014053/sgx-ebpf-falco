"""Check a real capture against the workload operations and the detector's ordered inputs."""
from array import array
from bisect import bisect_right
from collections import Counter
import hashlib
import json
from pathlib import Path
import runpy
import sys

bench = runpy.run_path(str(Path(__file__).with_name("raven-retention.py")))
directory = Path(sys.argv[1]).resolve()
case, operations = sys.argv[2], int(sys.argv[3])
log = directory / "process.log"
samples = bench["metrics"](log)
diagnostics = {}
for line in log.read_text().splitlines():
    if line.startswith("{"):
        row = json.loads(line)
        if row.get("mode") in ("live", "modern_ebpf"):
            diagnostics[row["mode"]] = row
ring, driver = diagnostics["live"], diagnostics["modern_ebpf"]
assert ring["consumer"] == ring["producer"] == driver["consumer"] == driver["producer"]
assert not any((ring["discarded"],ring["format_rejected"],driver["driver_drops"],driver["packet_drops"])), diagnostics
assert ring["records"] == ring["accepted"]
assert ring["packet_records"] == driver["packet_submitted"]
assert ring["records"] == driver["driver_events"] + driver["packet_submitted"]
finish = next(x for x in samples if x["phase"]=="finish")
assert not finish["resets"] and not finish["skipped"]

digest = hashlib.sha256()
ordered = 14695981039346656037
marks, forks, exits = {}, Counter(), Counter()
groups = operations//4
flags = bytearray(groups+1)
child_pids = array("q",[-1])*(groups+1)
write_seq, write_ids = array("Q"), array("Q")
previous = count = 0
owned = Counter()
with (directory/"events.jsonl").open("rb") as source:
    for count,line in enumerate(source,1):
        digest.update(line)
        e = json.loads(line)
        eid = e["event_id"]
        rid = int(eid.removeprefix("ring-"))
        assert rid > previous, (count,previous,rid)
        previous = rid
        for b in eid.encode()+b"\0":
            ordered = ((ordered ^ b)*1099511628211) & ((1<<64)-1)
        kind, pid = e["event_type"], e["pid"]
        if e.get("exe_name")=="rz-load":
            if kind=="process_fork": forks[pid] += 1
            if kind=="process_exit": exits[pid] += 1
        path = e.get("file_path","")
        if not path.startswith("/root/rz-retention-"): continue
        op = e["file_op"]
        owned[op] += 1
        if case=="repeat":
            assert path.endswith("/repeat")
            if op in ("write","create"):
                write_seq.append(count)
                write_ids.append(rid)
            else:
                assert op=="open" and owned["write"] == (len(marks)+1)*10000
                marks[eid] = (path,pid,len(write_ids))
        else:
            number = int(path.rsplit("file-",1)[1])
            assert 1 <= number <= groups
            if op=="create":
                assert flags[number]==0
                flags[number]=1
                child_pids[number]=pid
            elif op=="write":
                assert flags[number]==1 and child_pids[number]==pid
                flags[number]=2
            else:
                assert op=="open" and flags[number]==2 and number%2500==0
                marks[eid]=(path,pid,2)
if case=="repeat":
    assert owned=={"create":1,"write":operations,"open":operations//10000},owned
else:
    assert owned=={"create":groups,"write":groups,"open":groups//2500},owned
    assert flags.count(2)==groups
    assert all(forks[pid]==exits[pid]==lifetimes for pid,lifetimes in Counter(child_pids[1:]).items())
assert count == ring["raven_events"] == finish["seen"] >= operations
assert str(ordered) == finish["hash"]
assert [x["seen"] for x in samples if x["phase"]=="events"] == list(range(10000,count+1,10000))

output = bench["verify_alerts"](directory/"alerts.jsonl","actual",count,True)
found, marker_evidence = [], []
with (directory/"alerts.jsonl").open("rb") as alerts:
    for line in alerts:
        alert = json.loads(line)
        if alert.get("source")!="raven_zeek": continue
        r = json.loads(alert["output_fields"]["rz.result"])
        if r.get("rule")!="sensitive_access_chain": continue
        event = r["events"][0]
        if event["id"] not in marks: continue
        path,pid,end = marks[event["id"]]
        assert event["file_path"]==path and event["pid"]==pid
        edges = {edge["type"]:edge["event_ids"] for edge in r["reconstruction"]["graph"]["edges"]}
        assert edges["accessed"][-1]==event["id"]
        assert all(int(a[5:])<int(b[5:]) for a,b in zip(edges["accessed"],edges["accessed"][1:]))
        modified = [int(x[5:]) for x in edges["modified"]]
        if case=="repeat":
            cut = r["meta"].get("retention",{}).get("after_sequence",0)
            begin = bisect_right(write_seq,cut,hi=end)
            assert modified == list(write_ids[begin:end]), (event["id"],len(modified),end-begin)
        else:
            assert len(modified)==2 and modified[0]<modified[1]<int(event["id"][5:])
        found.append(event["id"])
        marker_evidence.append(dict(id=event["id"],ts=event["ts"],pid=pid,file=Path(path).name,
                                    modified=len(modified),first_modified=modified[0],last_modified=modified[-1],
                                    accessed=len(edges["accessed"]),retention=r["meta"].get("retention"),
                                    alert_bytes=len(line.rstrip(b"\r\n"))))
assert found == list(marks) and len(found)==operations//10000
assert finish["published"]==output["alerts"]
result = dict(**output,case=case,events=count,ordered_hash=str(ordered),input_sha256=digest.hexdigest(),
              marker_alerts=len(found),marker_evidence=marker_evidence,operations=dict(owned),
              verified_children=groups if case=="churn" else 0,
              capture=diagnostics,samples=samples,final=finish,heap_peak=max(x.get("heap_peak",0) for x in samples),
              process_peak=int((directory/"maxrss.kib").read_text())*1024)
(directory/"result.json").write_text(json.dumps(result,indent=2)+"\n")
print(case,count,owned,len(found),flush=True)
