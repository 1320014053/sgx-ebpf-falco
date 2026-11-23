"""Measure complete process time on two sizes of the same offline workload."""
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import struct
import subprocess
import sys
import time
base = Path(__file__).resolve().parent
root = base / "falco-poc"
fixed = base / "data" / sys.argv[1]
build = root / "build-ert"
package = root / "deps/package"
env = dict(os.environ,TZ="UTC",FALCO_HOSTNAME="falco-sgx-fixture",LD_LIBRARY_PATH=str(base/"deps/runtime/usr/lib/x86_64-linux-gnu"))
capture = (fixed/"reference.scap").read_bytes()
offset = 0
while offset < len(capture):
    kind,size = struct.unpack_from("<II",capture,offset)
    if kind == 0x216: break
    offset += size
event = capture[offset:]
pos = 0
count = 0
positions = []
while pos < len(event):
    kind,size = struct.unpack_from("<II",event,pos)
    assert kind == 0x216 and size >= 12
    positions.append(pos+10)
    pos += size
    count += 1
assert pos == len(event)
work = base / "offline-perf"
work.mkdir(exist_ok=True)
for copies in ([int(v) for v in sys.argv[2:]] if len(sys.argv)>2 else (1,500)):
    d=work / str(copies)
    d.mkdir(exist_ok=True)
    for name in ("falco_rules.yaml","reference.yaml","libcontainer.so"):
        link = d/name
        if not link.exists(): link.symlink_to(fixed/name)
    with (d/"reference.scap").open("wb") as out:
        out.write(capture[:offset])
        for copy in range(copies):
            chunk=bytearray(event)
            for index in positions:
                ts=struct.unpack_from("<Q",event,index)[0]
                struct.pack_into("<Q",chunk,index,ts+copy*3_000_000_000)
            out.write(chunk)
    for repeat in range(1,6):
        order = ("native","hw") if repeat%2 else ("hw","native")
        for mode in order:
            tid=f"falco-replay-{mode}-{copies}-r{repeat:02d}"
            out=base/"data"/tid
            out.mkdir()
            cmd = ([package/"usr/bin/falco","-c","reference.yaml"] if mode=="native" else
                   [build/"bin/falco-sgx",build/"falco-enclave.signed","reference.yaml","reference.scap","falco_rules.yaml"])
            with (out/"stdout.tmp").open("wb") as alerts, (out/"stderr.log").open("wb") as log:
                begin=time.monotonic_ns()
                result=subprocess.Popen(["/usr/bin/time","-f","%U %S %M","-o",out/"resources.txt",*cmd],cwd=d,env=env,stdout=alerts,stderr=subprocess.PIPE)
                ready=finished=None
                for line in result.stderr:
                    stamp=time.monotonic_ns()
                    if ready is None and ((mode=="native" and b"Replaying events from the capture file" in line) or (mode=="hw" and b'"loaded_rules"' in line)):
                        ready=stamp
                    if ready and finished is None and ((mode=="native" and b"Syscall event drop monitoring" in line) or (mode=="hw" and b'"events"' in line and b'"alerts"' in line)):
                        finished=stamp
                    log.write(line)
                result.wait()
                end=time.monotonic_ns()
                seconds=(end-begin)/1e9
            digest=hashlib.sha256()
            n=0
            with (out/"stdout.tmp").open("rb") as stream:
                for line in stream:
                    if line.startswith(b"{"):
                        row=json.loads(line)
                        digest.update(json.dumps(row,sort_keys=True,separators=(",",":")).encode()+b"\n")
                        n+=1
            resources=(out/"resources.txt").read_text().strip().splitlines()[-1].split()
            metrics=dict(seconds=seconds,cold_to_ready_s=(ready-begin)/1e9 if ready else None,
                         ready_to_summary_s=(finished-ready)/1e9 if ready and finished else None,
                         ready_to_exit_s=(end-ready)/1e9 if ready else None,events=count*copies,alerts=n,alerts_sha256=digest.hexdigest(),
                         input_sha256=hashlib.sha256((d/"reference.scap").read_bytes()).hexdigest(),
                         user_s=float(resources[0]),sys_s=float(resources[1]),peak_rss_kib=int(resources[2]))
            (out/"metrics.json").write_text(json.dumps(metrics,indent=2)+"\n")
            metadata=dict(trial_id=tid,experiment="falco-replay",mode=mode,workload="official-scap",load_level=str(copies),
                          repeat=repeat,status="ok" if result.returncode==0 else "failed",exit_code=result.returncode,
                          measurement_s=seconds,raw_path="raw/"+tid+"/",command=[str(i) for i in cmd])
            (out/"trial.json").write_text(json.dumps(metadata,indent=2)+"\n")
            if result.returncode: raise RuntimeError(tid)
            (out/"stdout.tmp").unlink()
        left,right=[json.loads((base/"data"/f"falco-replay-{m}-{copies}-r{repeat:02d}"/"metrics.json").read_text()) for m in order]
        assert left["alerts"]==right["alerts"] and left["alerts_sha256"]==right["alerts_sha256"]
print("FALCO_REPLAY_COMPLETE")
