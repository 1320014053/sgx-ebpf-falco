import datetime
import json
import os
from pathlib import Path
import subprocess

base = Path(__file__).resolve().parent
data = base / "data"
binary = base / "poc/build/hw0/poc"
os.environ["LD_LIBRARY_PATH"] = str(base / "deps/runtime/usr/lib/x86_64-linux-gnu")
modes = ["baseline", "host", "ecall", "batch", "direct"]
levels = {"low": ["--interval-us", "1000"], "100k": ["--rate", "100000"], "max": ["--interval-us", "0"]}

def run(trial, experiment, mode, level, repeat, args):
    d = data / trial
    d.mkdir()
    command = [str(binary), "--mode", mode, *args]
    when = datetime.datetime.now(datetime.timezone.utc).isoformat()
    print(when, trial, flush=True)
    with (d / "stdout.json").open("w") as out, (d / "stderr.log").open("w") as err:
        result = subprocess.run(command, stdout=out, stderr=err, timeout=180)
    elapsed = None
    ok = False
    if result.returncode == 0:
        row = json.loads((d / "stdout.json").read_text())
        ok = row["ok"]
        if experiment == "smoke":
            if level == "overflow":
                ok = ok and row["reserve_failed"] > 0 and row["consumer_pos"] == row["producer_pos"]
            else:
                ok = ok and row["attempted"] == row["processed"] == 10003
        if mode == "direct":
            ok = ok and row["data_ecalls"] == 1
        elapsed = row["generator_wall_ns"] / 1e9
    (d / "trial.json").write_text(json.dumps(dict(trial_id=trial, experiment=experiment, mode=mode, workload="getpid",
        load_level=level, repeat=repeat, status="ok" if ok else "failed", exit_code=result.returncode,
        measurement_s=elapsed, raw_path="raw/"+trial+"/", start_utc=when, command=command), indent=2)+"\n")
    if not ok:
        raise RuntimeError(trial + " failed")

for mode in ("host", "ecall", "batch", "step", "direct"):
    run("getpid-smoke-"+mode+"-r01", "smoke", mode, "low", 1, ["--count","10003","--interval-us","1000"])
run("getpid-overflow-direct-r01", "smoke","direct","overflow",1,["--count","20000","--interval-us","0","--pause-ms","3000","--allow-drops"])
for repeat in range(1, 6):
    for i, level in enumerate(levels):
        offset = (repeat - 1 + i) % len(modes)
        for mode in modes[offset:] + modes[:offset]:
            prefix = f"getpid-{mode}-{level}-r{repeat:02d}"
            opts = levels[level] + ["--allow-drops"]
            run(prefix+"-warmup", "warmup", mode, level, repeat, ["--seconds","2",*opts])
            run(prefix, "getpid", mode, level, repeat, ["--seconds","60",*opts])
print("GETPID_MATRIX_COMPLETE", flush=True)
