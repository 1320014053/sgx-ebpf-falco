import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import time

base=Path(__file__).resolve().parent
root=base/"falco-poc"
data=base/"data"
wd=data/"falco-live-detectors-r01/recorded"
env=dict(os.environ,TZ="UTC",FALCO_HOSTNAME="falco-rz-live",LD_LIBRARY_PATH=str(base/"deps/runtime/usr/lib/x86_64-linux-gnu"))
checks=runpy.run_path(str(base/"poc/falco/live/check-detectors.py"))
fixture=checks["detector_results"](wd/"alerts.jsonl")
n_events=sum(1 for _ in (wd/"events.jsonl").open())
comparison=json.loads((wd.parent/"comparison.json").read_text())["recorded"]
n_packets=comparison["packets"]
inputs={s:hashlib.sha256((wd/s).read_bytes()).hexdigest() for s in ["events.jsonl","packets.pcap","reference.scap"]}
for repeat in range(1,6):
    for mode in (("native","hw") if repeat%2 else ("hw","native")):
        tid=f"plugin-replay-{mode}-r{repeat:02d}"
        d=data/tid
        d.mkdir()
        if mode=="native":
            cmd=[root/"deps/package/usr/bin/falco","-c","native.yaml","-o","engine.kind=modern_ebpf","--enable-source","raven_zeek"]
        else:
            cmd=[root/"build-ert/bin/falco-sgx",root/"build-ert/falco-enclave.signed","live.yaml","reference.scap","--plugin-host","events.jsonl","packets.pcap","falco_rules.yaml","raven_zeek_rules.yaml"]
        start=time.monotonic_ns()
        with (d/"alerts.jsonl").open("wb") as out, (d/"stderr.log").open("wb") as log:
            rc=subprocess.run(["/usr/bin/time","-f","%U %S %M","-o",d/"resources.txt",*cmd],cwd=wd,env=env,stdout=out,stderr=log).returncode
        elapsed=(time.monotonic_ns()-start)/1e9
        parity=rc==0 and checks["detector_results"](d/"alerts.jsonl")==fixture
        res=(d/"resources.txt").read_text().splitlines()[-1].split()
        metrics=dict(seconds=elapsed,normalized_events=n_events,packets=n_packets,inputs=inputs,
                     cpu_user_s=float(res[0]),cpu_sys_s=float(res[1]),peak_rss_kib=int(res[2]),matches_live=parity)
        (d/"metrics.json").write_text(json.dumps(metrics,indent=2)+"\n")
        meta=dict(trial_id=tid,experiment="plugin-replay",mode=mode,workload="fixed-jsonl-pcap",load_level="captured",repeat=repeat,
                  status="ok" if parity else "failed",exit_code=rc,measurement_s=elapsed,raw_path="raw/"+tid+"/",command=list(map(str,cmd)))
        (d/"trial.json").write_text(json.dumps(meta,indent=2)+"\n")
        print(tid,rc,parity,flush=True)
