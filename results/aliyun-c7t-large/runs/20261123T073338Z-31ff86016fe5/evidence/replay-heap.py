"""Read the signed enclave's allocator high-water mark after an official-rules replay."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
base=Path(__file__).resolve().parent
data=base/"data"
b=base/"falco-poc/build-ert"
env=dict(os.environ,TZ="UTC",FALCO_HOSTNAME="falco-sgx-fixture",LD_LIBRARY_PATH=str(base/"deps/runtime/usr/lib/x86_64-linux-gnu"))
for copies in (1,500,5000):
    tid=f"falco-heap-{copies}-r01"
    d=data/tid
    d.mkdir()
    src=base/"offline-perf"/str(copies)
    for f in ("reference.scap","falco_rules.yaml","libcontainer.so"): (d/f).symlink_to(src/f)
    config=(data/"raven-sgx-repeat-100000-r01/falco.yaml").read_text().replace("rules_files: [falco_rules.yaml, raven_zeek_rules.yaml]","rules_files: [falco_rules.yaml]")
    (d/"probe.yaml").write_text(config)
    (d/"empty.jsonl").touch()
    cmd=[b/"bin/falco-sgx",b/"falco-enclave.signed","probe.yaml","reference.scap","--plugin-stream","empty.jsonl","falco_rules.yaml"]
    begin=time.monotonic()
    with (d/"alerts.tmp").open("wb") as out,(d/"collector.log").open("wb") as log:
        rc=subprocess.run(cmd,env=env,cwd=d,stdout=out,stderr=log).returncode
    elapsed=time.monotonic()-begin
    ok=False
    if rc==0:
        logs=(d/"collector.log").read_text().splitlines()
        rules=next(json.loads(line) for line in logs if line.startswith("{") and '"loaded_rules"' in line)
        samples=[json.loads(line[6:]) for line in logs if line.startswith("RZRET ")]
        official=json.loads((data/f"falco-replay-hw-{copies}-r01"/"metrics.json").read_text())
        h=hashlib.sha256()
        with (d/"alerts.tmp").open("rb") as stream:
            for line in stream:
                if line.startswith(b"{"): h.update(json.dumps(json.loads(line),sort_keys=True,separators=(",",":")).encode()+b"\n")
        peak=max((s["heap_peak"] for s in samples if "heap_peak" in s),default=0)
        ok=(len(rules["enabled"])==25 and h.hexdigest()==official["alerts_sha256"] and peak>0)
        result=dict(official_rules=len(rules["enabled"]),same_alerts=h.hexdigest()==official["alerts_sha256"],
                    input_events=official["events"],input_sha256=official["input_sha256"],empty_plugin_input_bytes=0,
                    heap_peak_bytes=peak,diagnostic_samples=samples)
        (d/"metrics.json").write_text(json.dumps(result,indent=2)+"\n")
        (d/"alerts.tmp").unlink()
    info=dict(trial_id=tid,experiment="replay-heap",mode="hw",workload="official-scap-empty-plugin-sampler",
              load_level=str(copies),repeat=1,status="ok" if ok else "failed",exit_code=rc,
              measurement_s=elapsed,raw_path="raw/"+tid+"/",command=list(map(str,cmd)))
    (d/"trial.json").write_text(json.dumps(info,indent=2)+"\n")
    print(tid,info["status"],flush=True)
