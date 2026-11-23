"""Plot the measured distributions and counters from this batch."""
import csv
import json
from pathlib import Path
from statistics import median
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

base=Path(__file__).resolve().parents[1]
out=base/"summary"
def table(name):
    return list(csv.DictReader((out/name).open(encoding="utf-8-sig"))) if (out/name).is_file() else []
colors={"baseline":"#566373","host":"#6f83ab","ecall":"#d77c2e","batch":"#558763","direct":"#126c86",
        "native":"#687987","hw-official":"#166c85","hw-full":"#ca6930","sgx":"#166c85"}
plt.rcParams.update({"font.size":10,"axes.spines.top":False,"axes.spines.right":False,"figure.dpi":150})
def done(fig,name):
    fig.tight_layout()
    fig.savefig(out/name,bbox_inches="tight",facecolor="white")
    plt.close(fig)

micro=table("getpid-trials.csv")
if micro:
    fig,ax=plt.subplots(1,2,figsize=(10,4))
    modes=["host","ecall","batch","direct"]
    levels=["low","100k","max"]
    for offset,mode in enumerate(modes):
        for i,level in enumerate(levels):
            run=[r for r in micro if r["mode"]==mode and r["load"]==level]
            if not run: continue
            val=[float(r["processed_per_s"]) for r in run]
            loss=[100*int(r["lost"])/int(r["issued"]) for r in run]
            pos=i+(offset-1.5)*.17
            ax[0].scatter([pos]*len(val),val,color=colors[mode],s=14,alpha=.42)
            ax[0].scatter(pos,median(val),color=colors[mode],s=54,marker="_",label=mode if i==0 else None)
            ax[1].scatter([pos]*len(loss),loss,s=14,color=colors[mode],alpha=.42)
            ax[1].scatter(pos,median(loss),s=54,color=colors[mode],marker="_")
    for p in ax:
        p.set_xticks(range(3),["1 ms sleep","100k/s target","Unpaced"])
        p.grid(axis="y",alpha=.18)
    ax[0].set_yscale("log"); ax[0].set_ylabel("Processed events/s, including drain")
    ax[1].set_ylabel("Ring reservation failures (% of calls)")
    ax[0].legend(frameon=False,ncol=2)
    fig.suptitle("GETPID transport on ecs.c7t.large")
    done(fig,"getpid.png")

http=table("http-trials.csv")
if any(r["experiment"]=="http" for r in http):
    fig,axes=plt.subplots(1,2,figsize=(10,4))
    modes=["baseline","native","hw-official","hw-full"]
    for i,mode in enumerate(modes):
        run=[r for r in http if r["experiment"]=="http" and r["mode"]==mode]
        if not run: continue
        for p,k in zip(axes,("rps","request_p99_ms")):
            vals=list(map(float,(r[k] for r in run)))
            p.scatter([i]*len(vals),vals,s=27,color=colors[mode],alpha=.55)
            p.plot([i-.22,i+.22],[median(vals)]*2,color=colors[mode],linewidth=2)
    for p in axes:
        p.set_xticks(range(4),["Bare","Native","HW official","HW full"])
        p.grid(axis="y",alpha=.2); p.set_ylim(bottom=0)
    axes[0].set_ylabel("Requests/s"); axes[1].set_ylabel("Per-run request p99 (ms)")
    fig.suptitle("Loopback HTTP/1.1, 1 KiB responses, two clients")
    done(fig,"http.png")

groups=table("http-groups.csv")
low=[r for r in groups if r["experiment"]=="alert-latency" and r["alert_p99_ms"]]
if low:
    fig,ax=plt.subplots(figsize=(7,3.8))
    for i,row in enumerate(low):
        vals=[float(row["alert_"+k+"_ms"]) for k in ("p50","p95","p99")]
        ax.plot([0,1,2],vals,marker="o",color=colors[row["mode"]],label=row["mode"])
    ax.axhline(2,linestyle="--",color="#95372a",linewidth=1,label="2 ms target")
    ax.set_xticks([0,1,2],["p50","p95","p99"])
    ax.set_ylabel("Matched alert latency (ms, log scale)"); ax.set_yscale("log")
    ax.set_title("Alert latency at a 20 requests/s offered HTTP load")
    ax.grid(axis="y",alpha=.18); ax.legend(frameon=False)
    done(fig,"latency.png")

memory=table("memory.csv")
if memory:
    fig,axes=plt.subplots(1,2,figsize=(10,4))
    for ax,case in zip(axes,("repeat","churn")):
        for mode,key in (("native","rss"),("sgx","heap")):
            match=next((r for r in memory if r["mode"]==mode and r["workload"]==case and int(r["events"])==1000000),None)
            if not match: continue
            v=json.loads((base/"raw"/match["trial"]/"result.json").read_text())
            rows=[s for s in v["samples"] if s["phase"] in ("events","start")]
            ax.plot([s["seen"]/1000 for s in rows],[s[key]/2**20 for s in rows],color=colors[mode],
                    label="Native process RSS" if mode=="native" else "HW trusted heap")
        ax.set_title("Repeated path" if case=="repeat" else "Process and path churn")
        ax.set_xlabel("Events processed (thousands)"); ax.set_ylim(bottom=0); ax.grid(axis="y",alpha=.18)
    axes[0].set_ylabel("Memory (MiB)"); axes[0].legend(frameon=False)
    fig.suptitle("RAVEN memory sampled every 10,000 events")
    done(fig,"memory.png")

capacity=[r for r in table("capacity.csv") if r["experiment"] in ("capacity-floor","capacity-lower","falco-capacity","capacity-100k")]
if capacity:
    fig,axes=plt.subplots(1,2,figsize=(9,3.8))
    for mode in ("hw-official","hw-full"):
        points=[]
        for stage in ("capacity-floor","capacity-lower","falco-capacity","capacity-100k"):
            rows=[r for r in capacity if r["mode"]==mode and r["experiment"]==stage]
            if not rows: continue
            x=[float(r["offered_s"])/1000 for r in rows]
            rate=[float(r["delivered_s"])/1000 for r in rows]
            loss=[100*int(r["driver_drops"])/(int(r["kernel_records"])+int(r["driver_drops"])) for r in rows]
            points.append((median(x),median(rate),median(loss)))
            for p,y in zip(axes,(rate,loss)): p.scatter(x,y,color=colors[mode],alpha=.45,s=19)
        if points:
            points.sort()
            for j,p in enumerate(axes,1):
                p.plot([v[0] for v in points],[v[j] for v in points],marker="o",color=colors[mode],label=mode)
    axes[0].axhline(100,color="#95372a",linestyle="--",linewidth=1,label="100k/s target")
    axes[0].set_ylabel("Delivered syscall records/s (thousands)")
    axes[1].set_ylabel("Driver drops (% of offered records)")
    for p in axes:
        p.set_xlabel("Offered syscall records/s (thousands)"); p.set_ylim(bottom=0); p.grid(axis="y",alpha=.18)
    axes[0].legend(frameon=False,fontsize=8)
    fig.suptitle("Falco capacity with paced local file operations")
    done(fig,"capacity.png")
