"""Write a Chinese report from the archived, verified trial data."""
import csv
import json
from pathlib import Path
from statistics import median

base=Path(__file__).resolve().parents[1]
s=base/"summary"
def rows(file): return list(csv.DictReader((s/file).open(encoding="utf-8-sig")))
def js(path): return json.loads(path.read_text(encoding="utf-8-sig"))
def f(value,precision=0): return f"{float(value):,.{precision}f}" if value is not None and value!="" else "—"
def span(values,precision=0):
    return f"{f(median(values),precision)}（{f(min(values),precision)}–{f(max(values),precision)}）" if values else "—"
def table(head,body):
    return "\n".join(["| "+" | ".join(head)+" |","| "+" | ".join("---" for _ in head)+" |"]+["| "+" | ".join(map(str,r))+" |" for r in body])
lines=[]
def add(text): lines.extend([text,""])
def graph(file,alt): return f"![{alt}](summary/{file})"

micro=rows("getpid-trials.csv"); http=rows("http-trials.csv"); hgroups=rows("http-groups.csv"); mem=rows("memory.csv")
caps=rows("capacity.csv"); rt=rows("official-replay.csv"); plugins=rows("plugin-replay.csv")
formal_capacity=[r for r in caps if r["experiment"]=="capacity-100k"]
meta=list(csv.DictReader((base/"trials.csv").open(encoding="utf-8-sig")))
hmode={"baseline":"无监控","native":"普通 Falco","hw-official":"SGX 官方规则","hw-full":"SGX 官方规则 + RAVEN/Zeek"}
add("# 阿里云 ecs.c7t.large 硬件 SGX 非调试性能实测")
add(f"批次 `{base.name}`。上海地域、Ubuntu 22.04.5、内核 `5.15.0-198-generic`、Xeon Platinum 8369B。实例向客体提供同一物理核的 2 个线程，Linux 可见内存为 1,756,258,304 字节，驱动识别 1,984 MiB EPC。[环境输出](raw/host-preflight-r01/stdout.txt)")
add("GETPID 和 Falco 的运行中 REPORT 均为 **DEBUG=0**。两份报告的 MRENCLAVE、MRSIGNER 均与各自签名镜像匹配，SGX 驱动初始化成功。Falco 离线和实时使用同一签名镜像。客体暴露 PCID 和 INVPCID，CPUID 的 PKS 位为 0，MOAT 硬件对照缺少运行条件。[身份记录](record.md) · [Falco 签名核验](raw/falco-offline-r02/identity.json) · [CPUID](evidence/cpuid.txt)")
add("## 两项性能目标")
target=[]
for m in ("hw-official","hw-full"):
    run=[x for x in formal_capacity if x["mode"]==m]
    if not run: continue
    passed=sum(float(x["delivered_s"])>=100000 and not any(int(x[k]) for k in ("driver_drops","packet_drops","discarded","invalid")) for x in run)
    target.append([hmode[m]+" 现场吞吐",f"60 秒窗口交付 ≥100,000 条系统调用记录/秒且零丢失",f"{passed}/{len(run)} 轮达标，实收 "+span([float(x["delivered_s"]) for x in run])+" 条/秒"])
for a in hgroups:
    if a["experiment"]!="alert-latency": continue
    target.append([hmode[a["mode"]]+" 低负载告警","p99 < 2 ms",f'p99 {f(a["alert_p99_ms"],3)} ms，成功配对 {a["paired"]}/{a["markers"]}。'+("有未配对或丢失，条件未满足" if a["paired"]!=a["markers"] or any(float(a[k] or 0)>0 for k in ("source_drops_max","packet_drops_max")) else "达标" if a["alert_p99_ms"] and float(a["alert_p99_ms"])<2 else "未达标")])
add(table(["测试对象","判据","观测结果"],target))
add("吞吐采用驱动采集起止之间的系统调用实收条数。告警延迟采用同一主机的 CLOCK_MONOTONIC，从测试子进程即将执行标记命令，到宿主读到对应官方告警。低负载使用两条本机 HTTP 持久连接，每条目标 10 请求/秒。表中的区间为独立轮次最小值和最大值。[现场吞吐逐轮值](summary/capacity.csv) · [HTTP 与告警逐轮值](summary/http-trials.csv)")
add("## 正确性与丢失")
live=js(base/"raw/falco-live-official-r01/live-check.json")["driver"]
both=js(base/"raw/falco-live-detectors-r01/comparison.json")
add(f"GETPID 的 `host`、`ecall`、`batch`、`step`、`direct` 各处理 10,003/10,003 条。直接消费整轮 1 次数据 ECALL，结束时游标一致。故意暂停消费者 3 秒的满环用例中，20,000 次尝试有 16,029 次预留失败，剩余 3,971 条全部排空。[低速](raw/getpid-smoke-direct-r01/stdout.json) · [满环](raw/getpid-overflow-direct-r01/stdout.json)")
add(f"同一固定 SCAP 下，普通 Falco 和 SGX Falco 都启用 25 条官方规则，2 条告警的顺序及完整 JSON 一致。真实 Modern eBPF 官方用例处理 {live['driver_events']:,} 条系统调用记录，驱动丢失为 {live['driver_drops']}。完整检测的未录制用例处理 {both['ring-only']['syscall_records']:,} 条系统调用记录和 {both['ring-only']['packets']} 个报文，驱动及报文丢失均为 0。录制用例的原生、SGX 回放均复现现场检测结果。[固定回放](raw/falco-offline-r02/comparison.json) · [官方现场](raw/falco-live-official-r01/live-check.json) · [完整检测](raw/falco-live-detectors-r01/comparison.json)")
add("## GETPID 传输")
g=rows("getpid-groups.csv")
add(table(["负载","模式","轮数","实际生成/秒，中位数","实际处理/秒，中位数","零丢失轮数","消费 CPU，中位数"],[
    [{"low":"间隔 1 ms","100k":"目标 10 万/秒","max":"不限速"}[r["load"]],r["mode"],r["n"],f(r["issued_per_s_median"]),f(r["processed_per_s_median"]),
     r["rounds_zero_loss"] if r["rounds_zero_loss"] else "—", f(r["consumer_cpu_pct_median"],1)+"%" if r["mode"]!="baseline" else "—"] for r in g]))
add("每档 5 轮，每轮预热 2 秒，再独立测量 60 秒，模式顺序轮换。生成率使用发生器实际时间，处理率使用采集到排空的总时间。每轮记录预留失败、格式拒绝、数据 ECALL、封送与复制字节，以及发生器、消费者 CPU 和排空时间。100% 消费 CPU 对应占用一个逻辑处理器。[逐轮明细](summary/getpid-trials.csv) · [组内范围](summary/getpid-groups.csv)")
limits=[]
for mode in ("host","ecall","batch","direct"):
    modes=[x for x in g if x["mode"]==mode and int(x["n"])==5]
    success=[x for x in modes if int(x["rounds_zero_loss"])==5]
    first=next((x["load"] for x in modes if int(x["rounds_zero_loss"])<5),"已测档位均零丢失")
    if success:
        top=max(success,key=lambda x:float(x["processed_per_s_median"]))
        limits.append([mode,top["load"],f(top["processed_per_s_median"]),f(top["processed_per_s_min"])+ "–"+f(top["processed_per_s_max"]),first])
add(table(["模式","五轮零丢失的最高已测档","处理/秒，中位数","五轮范围","首次出现丢失的档位"],limits))
entry_counts={m:median(float(r["data_ecalls"]) for r in micro if r["mode"]==m and r["load"]=="100k") for m in ("ecall","batch","direct")}
add("在目标十万/秒的 60 秒轮次，逐条、批量和常驻直读的数据 ECALL 次数中位数分别为 "+f(entry_counts["ecall"])+"、"+f(entry_counts["batch"])+" 和 "+f(entry_counts["direct"])+"。")
add("直接消费每轮使用 1 次数据 ECALL，每条成功事件仍有 256 字节载荷复制到可信内存。各档的平均事件率使用整轮实际计数和相应窗口长度计算。[直接消费原始示例](raw/getpid-direct-100k-r01/stdout.json)")
add(graph("getpid.png","GETPID 各负载下的处理吞吐和预留失败比例"))
add("## Falco 实时吞吐与 HTTP 业务开销")
body=[]
for label,exp in (("4,000 次打开/关闭每秒","capacity-floor"),("12,000 次打开/关闭每秒","capacity-lower"),("首轮校准档","falco-capacity"),("十万目标档","capacity-100k")):
    for mode in ("hw-official","hw-full"):
        run=[r for r in caps if r["mode"]==mode and r["experiment"]==exp]
        if not run: continue
        body.append([label,hmode[mode],len(run),span([float(r["offered_s"]) for r in run]),span([float(r["delivered_s"]) for r in run]),
                     span([int(r["driver_drops"]) for r in run]),str(sum(all(int(r[k])==0 for k in ("driver_drops","packet_drops","discarded","invalid")) for r in run))+"/"+str(len(run)),
                     span([float(r["drain_ms"]) for r in run],1)])
add(table(["负载","模式","轮数","送入速率，条/秒","实收速率，条/秒","驱动丢失，条/轮","零丢失轮数","排空 ms"],body))
for mode in ("hw-official","hw-full"):
    levels=[]
    for exp in ("capacity-floor","capacity-lower","falco-capacity","capacity-100k"):
        measured=[r for r in caps if r["mode"]==mode and r["experiment"]==exp]
        if len(measured)!=5: continue
        rate=median(float(r["offered_s"]) for r in measured)
        delivered=median(float(r["delivered_s"]) for r in measured)
        ok=all(all(int(r[k])==0 for k in ("driver_drops","packet_drops","discarded","invalid")) for r in measured)
        levels.append((rate,delivered,ok))
    lossless=[t for t in levels if t[2]]
    losses=[t for t in levels if not t[2]]
    if lossless:
        best=max(lossless)
        sentence=hmode[mode]+"的 60 秒档位中，五轮全部零丢失的最高实测速率中位数为 "+f(best[1])+" 条/秒。"
        if losses:
            sentence+="首次出现丢失的已测档位，送入速率中位数为 "+f(min(losses)[0])+" 条/秒。"
        add(sentence)
add("通过本机进程循环打开、关闭 `/dev/null` 产生可计数的负载。先用四档短测校准，首批 60 秒实测约 7.8 万至 8.0 万条/秒。再按完整窗口的送入速率校准，两种配置交错测量十万目标档，完整配置在 12,000 与 4,000 次打开/关闭每秒另做两档，比较持续采集时的丢失。送入量取实收系统调用记录加驱动丢失，实收量扣除同一 ring 内的报文记录。事件集合、8 MiB ring 和输入生成方法固定。不同负载测得的最高值只适用于表中配置。[校准与正式原始计数](summary/capacity.csv)")
add(graph("capacity.png","受控系统调用负载的 Falco 吞吐与丢失"))
main=[r for r in hgroups if r["experiment"]=="http"]
add(table(["HTTP 模式","轮数","请求/秒，中位数（范围）","对同轮基线吞吐降幅","请求 p95 / p99，ms","采集进程 CPU"],[
    [hmode[r["mode"]],r["n"],f'{f(r["rps_median"])}（{f(r["rps_min"])}–{f(r["rps_max"])}）',f(r["paired_rps_decrease_pct_median"],1)+"%",
     f(r["request_p95_ms_median"],3)+" / "+f(r["request_p99_ms_median"],3),f(r["collector_cpu_pct_median"],1)+"%"] for r in main]))
idle=[r for r in hgroups if r["experiment"]=="idle"]
add("HTTP/1.1 服务和两个客户端均在本机回环，响应 1 KiB，每条连接循环请求。相同的两个 vCPU 供服务、客户端、标记发生器和采集器共享，同时保留云镜像的后台服务。轨迹录制关闭，硬件采集轮次逐一检查 `trace_ocalls=0` 及结束游标。官方规则比较对齐全量系统调用配置和单一 8 MiB 缓冲区。请求分位数取每个 60 秒样本后汇总。普通 Falco 的驱动指标来自每秒原生快照，硬件组来自停采后的累计计数，包含预热与排空。[负载及计时程序](evidence/http-benchmark.py) · [组内范围与丢失](summary/http-groups.csv)")
add("15 秒空闲窗口内，监控进程的 CPU 为"+"、".join(hmode[r["mode"]] + " " +f(r["collector_cpu_pct_median"],1)+"%" for r in idle if r["mode"]!="baseline")+"。[逐轮 CPU 与整机占用](summary/http-trials.csv)")
add(graph("http.png","HTTP 请求吞吐与请求 p99"))
add("仅运行官方规则时，首轮相邻标记的等待时间从约 8.05 秒按约 0.5 秒递减，再随下一批重新升高。该版本的 enclave 在告警文本积累到 64 KiB 或停采时发送输出，启用 RAVEN 后在消费循环内也会刷新。该行为与两组的延迟差异吻合。[逐条单调时间戳](raw/alert-latency-hw-official-r01/markers.tsv) · [输出实现](../../../../poc/falco/trusted/enclave.cpp)")
add(table(["低负载告警","配对 / 标记数","p50，ms","p95，ms","p99，ms"],[
    [hmode[v["mode"]],v["paired"]+" / "+v["markers"],f(v["alert_p50_ms"],3),f(v["alert_p95_ms"],3),f(v["alert_p99_ms"],3)]
    for v in hgroups if v["experiment"]=="alert-latency"]))
add("告警分位数按每种配置五轮全部已配对的单条标记合并计算，使用最近秩定义。HTTP 请求延迟独立计量。[告警逐轮分位](summary/http-trials.csv)")
add(graph("latency.png","低负载告警分位与 2 ms 目标"))
add("## Falco 离线回放")
replay_rows=[]
for mode in ("native","hw"):
    for count in sorted({int(x["events"]) for x in rt}):
        run=[x for x in rt if x["mode"]==mode and int(x["events"])==count]
        cold=[float(x["cold_to_ready_s"]) for x in run if x["cold_to_ready_s"]]
        steady=[count/float(x["ready_to_summary_s"] or x["ready_to_exit_s"]) for x in run if x["ready_to_summary_s"] or x["ready_to_exit_s"]]
        replay_rows.append(["普通 Falco" if mode=="native" else "SGX Falco",f(count),len(run),span([float(x["seconds"]) for x in run],3),
                            f(median(cold),3) if cold else "—",f(median(steady)) if steady else "—",f(median(float(x["peak_rss_kib"])/1024 for x in run),1)])
add(table(["模式","输入事件","轮数","新进程总耗时，s","就绪前，s","就绪后，条/秒","进程峰值 RSS，MiB"],replay_rows))
add("输入从同一固定 SCAP 生成，重复段按顺序平移事件时间。每对原生、硬件回放都核对了告警数量和完整 JSON 的规范化哈希。30 万事件组另外记录就绪和结束日志到达父进程的单调时钟。原生以打开回放文件为就绪标记，SGX 以发出已加载规则清单为标记。此口径包含就绪标记之后的回放设置及结束开销。[官方回放明细](summary/official-replay.csv)")
heaps=[]
for d in sorted((base/"raw").glob("falco-heap-*-r01")):
    if (d/"metrics.json").exists():
        v=js(d/"metrics.json")
        if v["same_alerts"] and v["heap_peak_bytes"]:
            heaps.append([v["input_events"],f(v["input_events"]),f(v["heap_peak_bytes"]/2**20,2),v["official_rules"]])
if heaps:
    add(table(["官方回放输入事件","可信堆峰值，MiB","启用的官方规则"],[x[1:] for x in sorted(heaps)]))
    add("可信堆诊断使用同一签名镜像，在官方 SCAP 回放结束后提交空 RAVEN 流，调用 enclave 内的分配器统计。数值包括诊断插件初始化，逐次核对了 25 条官方规则和相同的告警摘要。诊断轮次单独归档。[采样程序](evidence/replay-heap.py)")
plugrows=[]
for mode in ("native","hw"):
    run=[r for r in plugins if r["mode"]==mode]; count=int(run[0]["events"]); packets=int(run[0]["packets"])
    plugrows.append(["普通 Falco" if mode=="native" else "SGX Falco",count,packets,len(run),span([float(x["seconds"]) for x in run],3),
                     f(median(float(x["peak_rss_kib"])/1024 for x in run),1)])
add(table(["检测插件","归一化事件","报文","轮数","端到端回放，s","峰值 RSS，MiB"],plugrows))
add("RAVEN/Zeek 使用同一批现场录制的事件 JSONL 和 PCAP，逐轮与现场告警对照。SGX 入口还读取同批 SCAP。端到端时间包含加载和销毁。可信堆的直接采样见下节。[插件回放明细](summary/plugin-replay.csv)")
add("## RAVEN 内存")
add(table(["负载","事件数","模式","告警","耗时，s","进程峰值 RSS，MiB","可信堆峰值，MiB","回收次数"],[
    ["重复路径" if x["workload"]=="repeat" else "新进程与新路径",f(x["events"]),x["mode"],x["alerts"],f(x["wall_s"],2),
     f(x["rss_peak_mib"],1),f(x["heap_peak_mib"],1),x["retention_cycles"]] for x in sorted(mem,key=lambda r:(int(r["events"]),r["workload"],r["mode"]))]))
million=[v for v in mem if int(v["events"])==1000000]
add(table(["百万条连续负载","模式","后半程回收后基线极差，MiB","RAVEN 峰值计费，MiB","最大单条告警，字节"],[
    ["重复路径" if v["workload"]=="repeat" else "新进程与新路径",v["mode"],f(v["post_gc_span_mib"],3),f(v["peak_charged_mib"],2),f(v["max_alert_bytes"])]
    for v in sorted(million,key=lambda x:(x["workload"],x["mode"]))]))
add("四个百万条会话都完成至少 101 次回收。后 50 万条在同一回收阶段对比，普通态采样进程 RSS，硬件组采样可信堆。四组的实测极差均低于 8 MiB，RAVEN 峰值计费均低于 128 MiB，两组硬件可信堆峰值均低于 384 MiB。[项目内存判据](../../../../poc/falco/RAVEN-历史回收.md)")
add("这些长测在同一检测器会话持续送入按序生成的事件流。每个输入的原生与 SGX 运行核对同一输入指纹和规范化告警摘要。每万条事件记录一次，回收后另有采样。100 万事件的两种负载均产生 100 条预期告警，跳过和重置均为 0。进程 RSS 来自宿主，可信堆来自 enclave 内部的分配器计数。这版客体内核未通过本批检查的 procfs、sysfs 和 tracefs 接口导出 EPC 换页计数。[接口检查](evidence/epc-counters.txt) · [内存与输出明细](summary/memory.csv)")
add(graph("memory.png","百万事件下的每万条内存采样"))
add("## 复核与数据")
add(f"本批登记 {len(meta)} 个轮次或验收步骤。首次 Falco 报告读取因缺少 DCAP 共享库失败，完整检测的首次 HTTP 冒烟因官方输出附加字段作用于插件源失败。补库和修正配置后分配了独立复测记录，两次原始失败均保留。[逐轮索引](trials.csv) · [批次记录](record.md) · [构建补丁](evidence/hardware.patch)")
add("统计表由 `python evidence/summarize.py` 生成，图由安装了 Matplotlib 的 Python 执行 `python evidence/plots.py` 生成。本地接收端验证了服务端逐文件的 SHA-256。运行 `python evidence/audit.py` 可重新核查实验覆盖、运行时报告与两份文件清单。[普通文件清单](SHA256SUMS) · [现场轨迹和签名产物清单](bulk.sha256) · [复核输出](summary/audit.json)")
(base/"REPORT.md").write_text("\n".join(lines),encoding="utf-8")
