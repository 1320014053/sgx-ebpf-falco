import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

base=Path(__file__).resolve().parent
data=base/"data"
rt=base/"falco-poc"
tool=base/"poc/falco/bench/raven-retention.py"
env=dict(os.environ,TZ="UTC",PYTHONHASHSEED="0",PYTHONDONTWRITEBYTECODE="1",LD_LIBRARY_PATH=str(base/"deps/runtime/usr/lib/x86_64-linux-gnu"))
work=base/"memory-inputs"
work.mkdir(exist_ok=True)
for n in (100000,1000000):
    inputs=work/str(n)
    subprocess.run([sys.executable,tool,"generate",inputs,"--events",str(n)],env=env,check=True)
    manifest=json.loads((inputs/"inputs.json").read_text())
    for case in ("repeat","churn"):
        for mode in ("native","sgx"):
            tid=f"raven-{mode}-{case}-{n}-r01"
            d=data/tid
            cmd=[sys.executable,tool,"run",rt/"deps/package",rt/"build-ert",data/"falco-offline-r02",d,inputs/(case+".jsonl"),
                 mode,case,"--events",str(n)]
            start=time.monotonic()
            result=subprocess.run(cmd,env=env)
            elapsed=time.monotonic()-start
            d.mkdir(exist_ok=True)
            (d/"input.json").write_text(json.dumps(manifest[case],indent=2)+"\n")
            meta=dict(trial_id=tid,experiment="raven-memory",mode=mode,workload=case,load_level=str(n),repeat=1,
                      status="ok" if result.returncode==0 else "failed",exit_code=result.returncode,measurement_s=elapsed,
                      raw_path="raw/"+tid+"/",command=[str(x) for x in cmd])
            (d/"trial.json").write_text(json.dumps(meta,indent=2)+"\n")
            print(tid,result.returncode,flush=True)
print("MEMORY_MATRIX_FINISHED")
