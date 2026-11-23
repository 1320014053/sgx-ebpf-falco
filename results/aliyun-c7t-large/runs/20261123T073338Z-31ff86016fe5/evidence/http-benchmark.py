import datetime
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time

base=Path(__file__).resolve().parent
root=base/"falco-poc"
build=root/"build-ert"
package=root/"deps/package"
env=dict(os.environ,TZ="UTC",FALCO_HOSTNAME="falco-http-bench",LD_LIBRARY_PATH=str(base/"deps/runtime/usr/lib/x86_64-linux-gnu"))
data=base/"data"
reference=base/"poc/falco"
affinity=sorted(os.sched_getaffinity(0))
tick=os.sysconf("SC_CLK_TCK")

def cpu(pid):
    line=Path(f"/proc/{pid}/stat").read_text().rsplit(")",1)[1].split()
    return (int(line[11])+int(line[12]))/tick

def system_cpu():
    return list(map(int,Path("/proc/stat").read_text().splitlines()[0].split()[1:9]))

def run_trial(mode,repeat,duration,port,marker,idle=False,low=False,suffix=""):
    kind="idle" if idle else "alert-latency" if low else "http"
    tid=f"{kind}-{mode}-r{repeat:02d}{suffix}"
    d=data/tid
    d.mkdir()
    for name,src in {"falco_rules.yaml":package/"etc/falco/falco_rules.yaml",
                     "libcontainer.so":package/"usr/share/falco/plugins/libcontainer.so",
                     "raven_zeek_rules.yaml":reference/"plugin/rules.yaml"}.items():
        (d/name).symlink_to(src)
    cfg=(reference/"reference.yaml").read_text().replace("  kind: replay\n  replay:\n    capture_file: reference.scap","  kind: modern_ebpf\n  modern_ebpf:\n    cpus_for_each_buffer: 0\n    buf_size_preset: 4")
    if mode=="hw-full":
        cfg=cfg.replace("rules_files: [falco_rules.yaml]","rules_files: [falco_rules.yaml, raven_zeek_rules.yaml]").replace("load_plugins: [container]","  - name: raven_zeek\nload_plugins: [container, raven_zeek]")
        cfg=cfg.replace("  - extra_fields: [evt.num, evt.type, thread.tid]","  - match: {source: syscall}\n    extra_fields: [evt.num, evt.type, thread.tid]")
    cfg+="\nbuffered_outputs: false\nbase_syscalls: {all: true}\nwebserver: {enabled: false}\n"
    if mode=="native":
        cfg+='metrics: {enabled: true, interval: 1s, output_file: native-metrics.jsonl, output_rule: false, kernel_event_counters_enabled: true, include_empty_values: true, libbpf_stats_enabled: false}\n'
    (d/"falco.yaml").write_text(cfg)
    collector=None
    received={}
    sent={}
    warnings=[]
    if mode=="native":
        cmd=[package/"usr/bin/falco","-c","falco.yaml"]
    elif mode.startswith("hw"):
        cmd=[root/"build-live/falco-live",build/"falco-enclave.signed","falco.yaml","8192","-","falco_rules.yaml"]
        if mode=="hw-full": cmd.append("raven_zeek_rules.yaml")
    else: cmd=[]
    def read_alerts(stream):
        with (d/"marker-arrivals.tsv").open("w") as dest:
            for line in stream:
                arrival=time.monotonic_ns()
                if b"sgxbench_" not in line: continue
                try: row=json.loads(line)
                except ValueError: continue
                if row.get("rule")!="Run shell untrusted": continue
                label=row.get("output_fields",{}).get("proc.cmdline","")
                found=re.search(r"sgxbench_[a-z0-9_]+",label)
                if found:
                    name=found[0]
                    received.setdefault(name,arrival)
                    dest.write(f"{name}\t{arrival}\n")
    def mark(name):
        output=subprocess.check_output([marker,name],user="nobody",group="nogroup",extra_groups=[],text=True)
        return int(output.split()[1])
    status=1
    elapsed=0
    started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        if cmd:
            with (d/"collector.log").open("wb") as log:
                collector=subprocess.Popen(cmd,cwd=d,env=env,stdout=subprocess.PIPE,stderr=log)
            reader=threading.Thread(target=read_alerts,args=(collector.stdout,))
            reader.start()
            ready=False
            for i in range(100):
                if collector.poll() is not None: raise RuntimeError("collector startup exit "+str(collector.returncode))
                if mode!="native" and '"mode":"capture_ready"' not in (d/"collector.log").read_text(errors="replace"):
                    time.sleep(.1)
                    continue
                name=f"sgxbench_warm_{i}"
                mark(name)
                time.sleep(.12)
                if name in received:
                    ready=True
                    break
            if not ready:
                raise RuntimeError("readiness marker missing")
        else: reader=None
        if not idle:
            subprocess.run([sys.executable,base/"http-load.py","client",str(port),"2",d/"warmup.json","0.1" if low else "0"],check=True)
        ends=threading.Event()
        def markers():
            idx=0
            while not ends.wait(.5):
                name=f"sgxbench_{mode.replace('-','')}_{repeat}_{idx}"
                try: sent[name]=mark(name)
                except Exception as error: warnings.append(str(error)); break
                idx+=1
        cpu0=system_cpu()
        proc0=cpu(collector.pid) if collector else 0
        begin=time.monotonic_ns()
        if idle:
            time.sleep(duration)
        else:
            m=threading.Thread(target=markers)
            m.start()
            try:
                subprocess.run([sys.executable,base/"http-load.py","client",str(port),str(duration),d/"workload.json","0.1" if low else "0"],check=True)
            finally:
                ends.set()
                m.join()
        end=time.monotonic_ns()
        elapsed=(end-begin)/1e9
        proc1=cpu(collector.pid) if collector else 0
        cpu1=system_cpu()
        if collector:
            (d/"collector-status.txt").write_text(next(l for l in Path(f"/proc/{collector.pid}/status").read_text().splitlines() if l.startswith("VmHWM:"))+"\n")
            collector.send_signal(signal.SIGTERM)
            collector.wait(timeout=90)
            reader.join(timeout=5)
            if collector.returncode: raise RuntimeError("collector exit "+str(collector.returncode))
        paired=[(key,start,received.get(key)) for key,start in sent.items()]
        with (d/"markers.tsv").open("w") as out:
            out.write("marker\ttrigger_ns\talert_ns\n")
            for key,start,stop in paired: out.write(f"{key}\t{start}\t{stop if stop else ''}\n")
        deltas=[b-a for a,b in zip(cpu0,cpu1)]
        summary=dict(window_s=elapsed,collector_cpu_s=proc1-proc0,system_ticks=deltas,clock_ticks_per_s=tick,
                     system_busy_fraction=(sum(deltas)-deltas[3]-deltas[4])/sum(deltas),affinity=affinity,
                     markers=len(sent),paired=sum(stop is not None for key,start,stop in paired),warnings=warnings)
        (d/"metrics.json").write_text(json.dumps(summary,indent=2)+"\n")
        status=0
    except Exception as exc:
        (d/"failure.txt").write_text(repr(exc))
    finally:
        if collector and collector.poll() is None:
            collector.terminate()
            try: collector.wait(timeout=30)
            except subprocess.TimeoutExpired: collector.kill(); collector.wait()
        info=dict(trial_id=tid,experiment=kind,mode=mode,workload="idle" if idle else "http-loopback-1KiB",
                  load_level="idle" if idle else "20-rps" if low else "2-connections",repeat=repeat,status="ok" if status==0 else "failed",
                  exit_code=status,measurement_s=elapsed if status==0 else None,raw_path="raw/"+tid+"/",
                  start_utc=started_utc,collector_command=[str(e) for e in cmd],duration=duration)
        (d/"trial.json").write_text(json.dumps(info,indent=2)+"\n")
    print(tid,info["status"],flush=True)
    return status

if __name__=="__main__":
    smoke=sys.argv[1:]==["smoke"]
    modes=["baseline","native","hw-official","hw-full"]
    with tempfile.TemporaryDirectory(prefix="falco-http-marker-") as tmp:
        os.chmod(tmp,0o755)
        marker=Path(tmp)/"httpd"
        subprocess.run(["cc","-O2","-o",marker,base/"http-marker.c"],check=True)
        marker.chmod(0o755)
        server=subprocess.Popen([sys.executable,base/"http-load.py","serve"],stdout=subprocess.PIPE,text=True)
        try:
            port=int(server.stdout.readline())
            if sys.argv[1:]==["retry-full"]:
                if run_trial("hw-full",0,3,port,marker,suffix="-retry2"): sys.exit(1)
            elif smoke:
                for mode in modes: run_trial(mode,0,3,port,marker)
            else:
                for mode in modes: run_trial(mode,1,15,port,marker,True)
                for repeat in range(1,6):
                    offset=(repeat-1)%4
                    order=modes[offset:]+modes[:offset]
                    for mode in order: run_trial(mode,repeat,60,port,marker)
                    for mode in order:
                        if mode!="baseline": run_trial(mode,repeat,60,port,marker,low=True)
        finally:
            server.terminate()
            server.wait()
