"""Use sustained offered rates to tune a second 60 s series above 100k records/s."""
import json
import math
from pathlib import Path
import runpy
from statistics import median
base=Path(__file__).resolve().parent
sample=runpy.run_path(str(base/"falco-capacity.py"))["sample"]
targets={}
for mode in ("hw-official","hw-full"):
    group=[base/"data"/f"falco-capacity-{mode}-target-r{i:02d}" for i in range(1,6)]
    rates=[json.loads((p/"metrics.json").read_text())["offered_s"] for p in group]
    pairs=int(json.loads((group[0]/"trial.json").read_text())["load_level"])
    targets[mode]=math.ceil(pairs*108000/median(rates))
print("paired file operations/s",targets,flush=True)
cases=[("hw-full",12000,"lower"),("hw-official",targets["hw-official"],"100k"),("hw-full",targets["hw-full"],"100k")]
for repeat in range(1,6):
    pos=(repeat-1)%len(cases)
    for mode,rate,level in cases[pos:]+cases[:pos]:
        sample(mode,rate,2,level+"-warmup",repeat)
        sample(mode,rate,60,level,repeat)
print("FALCO_REFINED_CAPACITY_COMPLETE")
