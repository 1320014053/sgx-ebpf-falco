"""Use local /dev/null open-close pairs to measure sustained Falco ring throughput."""
import json
import math
import os
from pathlib import Path
import statistics
import subprocess
base=Path(__file__).resolve().parent
data=base/"data"
rt=base/"falco-poc"
env=dict(os.environ,TZ="UTC",FALCO_HOSTNAME="falco-capacity",LD_LIBRARY_PATH=str(base/"deps/runtime/usr/lib/x86_64-linux-gnu"))
subprocess.run(["cc","-O2",base/"falco-load.c","-o",base/"falco-load"],check=True)
def sample(mode,rate,seconds,kind,seq):
    tid=f"falco-capacity-{mode}-{kind}-r{seq:02d}"
    d=data/tid
    d.mkdir()
    cfg=data/("http-"+mode+"-r00"+("-retry2" if mode=="hw-full" else ""))/"falco.yaml"
    official=rt/"deps/package/etc/falco/falco_rules.yaml"
    (d/"libcontainer.so").symlink_to(rt/"deps/package/usr/share/falco/plugins/libcontainer.so")
    (d/"falco_rules.yaml").symlink_to(official)
    (d/"raven_zeek_rules.yaml").symlink_to(base/"poc/falco/plugin/rules.yaml")
    cmd=[rt/"build-live/falco-live",rt/"build-ert/falco-enclave.signed",cfg,"8192","-","falco_rules.yaml"]
    if mode=="hw-full": cmd.append("raven_zeek_rules.yaml")
    cmd += ["--",base/"falco-load",str(rate),str(seconds),d/"producer.json"]
    with (d/"alerts.log").open("w") as out, (d/"collector.log").open("w") as err:
        process=subprocess.run(cmd,cwd=d,env=env,stdout=out,stderr=err,timeout=seconds+80)
    pairs=eligible=0
    elapsed=None
    ok=False
    if not process.returncode:
        logs=[json.loads(s) for s in (d/"collector.log").read_text().splitlines() if s.startswith("{")]
        drv=next(v for v in logs if v.get("mode")=="modern_ebpf")
        ring=next(v for v in logs if v.get("mode")=="live")
        prod=json.loads((d/"producer.json").read_text())
        elapsed=prod["wall_ns"]/1e9
        capture=drv["capture_ms"]/1000
        pairs=prod["pairs"]
        kernel_records=ring["accepted"]-ring.get("packet_records",0)
        eligible=kernel_records+drv["driver_drops"]
        metrics=dict(pairs=pairs,producer_seconds=elapsed,capture_s=capture,driver_events=drv["driver_events"],
            kernel_records=kernel_records,driver_drops=drv["driver_drops"],packet_records=ring.get("packet_records",0),
            packet_drops=drv["packet_drops"],discarded=ring["discarded"],invalid=ring["format_rejected"],
            delivered_s=kernel_records/capture,offered_s=eligible/capture,drain_ms=drv["drain_ms"])
        (d/"metrics.json").write_text(json.dumps(metrics,indent=2)+"\n")
        ok=(drv["consumer"]==drv["producer"] and drv["trace_ocalls"]==0 and not ring["format_rejected"])
    meta=dict(trial_id=tid,experiment="falco-capacity" if kind=="target" else "capacity-"+kind,mode=mode,
        workload="open-close-dev-null",load_level=str(rate),repeat=seq,status="ok" if ok else "failed",
        exit_code=process.returncode,measurement_s=elapsed,raw_path="raw/"+tid+"/",command=list(map(str,cmd)))
    (d/"trial.json").write_text(json.dumps(meta,indent=2)+"\n")
    print(tid,process.returncode,flush=True)
    if not ok: raise RuntimeError(tid)
    return eligible/pairs
if __name__=="__main__":
    targets={}
    for mode in ("hw-official","hw-full"):
        rates=[sample(mode,rate,4,"calibration",i) for i,rate in enumerate((2000,12000,30000,0),1)]
        targets[mode]=math.ceil(101000/statistics.median(rates[:2]))
    print("target pairs per second",targets,flush=True)
    for repeat in range(1,6):
        order=["hw-official","hw-full"] if repeat%2 else ["hw-full","hw-official"]
        for mode in order:
            sample(mode,targets[mode],2,"warmup",repeat)
            sample(mode,targets[mode],60,"target",repeat)
    print("CAPACITY_MATRIX_COMPLETE")
