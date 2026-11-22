"""Force expiry and pressure and check both Falco outputs against independent event IDs."""
import json
from pathlib import Path
import runpy
import sys

run = runpy.run_path(str(Path(__file__).with_name("raven-retention.py")))["execute"]
package, build, baseline, root = (Path(x).resolve() for x in sys.argv[1:])
root.mkdir()


def event(id, ts, kind, pid=12, parent=1, exe="/usr/bin/cp", path=""):
    row = dict(event_id=id, ts=ts, event_type=kind, pid=pid, ppid=parent, exe=exe, uid=1000, euid=1000, user="1000")
    if path:
        row.update(file_path=path, file_op="open" if kind=="file_access" else "write")
    return row


path = "/root/retention-marker"
expiry = [event("exec",99,"process_exec"), event("at-boundary",100,"file_modify",path=path),
          event("inside",101,"file_modify",path=path), event("read-at",700,"file_access",path=path),
          event("read-after",700.01,"file_access",path=path), event("late",99,"file_modify",path=path),
          event("read-last",701,"file_access",path=path), event("exit",702,"process_exit"),
          event("new-exec",1400,"process_exec"), event("new-write",1401,"file_modify",path=path),
          event("new-read",1402,"file_access",path=path)]
ancestry = [event("server",1,"process_exec",50,1,"/usr/bin/nginx"),
            event("shell",1.005,"process_exec",51,50,"/bin/bash"),event("middle",1.01,"process_exec",53,51),
            event("leaf",1.02,"process_exec",52,53),event("middle-exit",1.03,"process_exit",53,51)]
ancestry += [event(f"w{i}",2+i/1000,"file_modify",70,path="/tmp/one") for i in range(500)]
ancestry += [dict(event("out",3,"net_connect",52,53),dst_ip="8.8.8.8",dst_port=80)]
overload = [event("oversize",1,"file_modify",path="/"+"x"*10000),event("recovered",2,"file_access",path=path)]
protected = [event(f"server-{i}",1+i/1000,"process_exec",100+i,1,"/usr/bin/nginx") for i in range(80)]
protected.append(event("after-protected",800,"file_access",path=path))

for name,rows,budget in (("expiry",expiry,128*1024*1024),("ancestry",ancestry,256*1024),
                         ("overload",overload,65536),("protected",protected,128*1024)):
    inputfile = root/(name+".jsonl")
    inputfile.write_text("".join(json.dumps(r)+"\n" for r in rows))
    saved = []
    for mode in ("native","sgx"):
        cwd = root/(name+"-"+mode)
        result = run(package,build,baseline,cwd,mode,inputfile,name,len(rows),True,budget,"retention-test")
        saved.append((result["alert_sha256"],result["final"]["hash"],result["final"]["evicted"]))
        records = []
        for line in (cwd/"alerts.jsonl").read_text().splitlines():
            if not line.startswith("{"): continue
            alert = json.loads(line)
            if alert["source"]=="raven_zeek": records.append(json.loads(alert["output_fields"]["rz.result"]))
        if name=="expiry":
            assert [r["events"][0]["id"] for r in records]==["read-at","read-after","read-last","new-read"]
            expected = [["at-boundary","inside"],["inside"],["inside"],["new-write"]]
            for r,ids in zip(records,expected):
                got = next(e for e in r["reconstruction"]["graph"]["edges"] if e["type"]=="modified")
                assert got["event_ids"]==ids, (r,ids)
                assert r["meta"]["retention"]["reason"]=="time"
        elif name=="ancestry":
            assert result["final"]["cycles"]>0 and result["final"]["resets"]==0
            assert any(r["rule"]=="server_spawns_outbound" and [e["id"] for e in r["events"]]==["server","shell","out"] for r in records)
        elif name=="overload":
            assert result["final"]["resets"]==result["final"]["skipped"]==1 and len(records)==1
            assert records[0]["events"][0]["id"]=="recovered"
            assert [(s["first"],s["last"]) for s in result["samples"] if s["phase"]=="gap"]==[(1,1)]
        else:
            gaps = [s for s in result["samples"] if s["phase"]=="gap"]
            assert len(gaps)==result["final"]["skipped"]==result["final"]["resets"] and gaps
            assert all(s["last"]>s["first"] and s["retained"]>0 and s["reason"]=="protected_budget" for s in gaps)
            assert len(records)==1 and records[0]["events"][0]["id"]=="after-protected"
    assert saved[0]==saved[1],name
print("PASS expiry, exact boundary, late event, PID reuse, ancestry, pressure, protected chains, overload and recovery")
