# Falco 实时检测验证记录

2026-11-24。基线 `6b8a940752783740c8082f9c39a227caf42ee6dd`。在同一台 Ubuntu 22.04、2 vCPU、4 GiB、无 EPC 的 QEMU TCG 客体中构建 Falco 用户态、探针和 SGX Simulation 镜像。快照标签依次为 `base`、`phase2`（阶段 1、2）、`phase4`（阶段 3、4）、`phase5`（5A）、`phase5b`（5B）。阶段 6 单独比较原版和改版。

## 正确性

| 阶段 | 已验证的结果 |
| --- | --- |
| 0 | 五个快照的离线回放、真实官方规则、真实组合规则、模拟 ring 均通过。真实采集均排空，驱动和报文丢失均为 0。每个快照的历史 ring 均为 8/8。历史 detector 各为 79 项通过、12 项原有差异，退出码 1，五份日志逐字节相同。 |
| 1 | 默认配置下，阶段 1、2 镜像在第 1 条告警后首次写出，原版在第 45 条后写出。最终 5B 的孤立官方告警在后续事件和停止信号之前已实际刷新 stdout，本轮耗时 49 ms。220 条告警默认刷新 220 次，显式开启缓冲后刷新 5 次，输出字节相同。 |
| 2 | memfd 双重映射单元测试通过，覆盖环绕、BUSY、DISCARD、损坏跨度、长度拒绝、位置溢出和停止后排空。篡改共享内存后，220 条告警仍与原生参考相同。 |
| 3 | 同一 raw-block inspector 先返回 SCAP_FAILURE，换批并执行 fseek(0) 后读出 42 个事件和 2 条完整参考告警。5A、5B 的六类故障注入均通过，包括真实截短块恢复。连续 16 次错误触发致命退出，独立比例预算探针在 64 次尝试中失败 43 次时退出，只打印 3 条诊断。关闭 stdout 或使录制文件写满均触发致命退出并完成线程收尾。 |
| 4 | 阶段 3、4 的官方规则采集有 534 次空闲轮询和 534 次睡眠，累计睡眠 2.018 秒，采集线程 CPU 为 0.657 秒。显式使用 `idle: spin` 时睡眠次数和时长均为 0。 |
| 5A | 签名 ERT 条件变量探针通过。消费位置写回后篡改源数据仍通过。混合夹具的两条官方告警、RAVEN 检测及 Zeek 扫描与基线完整总顺序相同。 |
| 5B | 在拆分前，对固定 MINIMAL_BUILD 引擎及 libs 进行完整 TSAN 构建；同一引擎并发得到 20000 次 syscall 匹配和 20000 次 plugin 匹配，无报告。跨来源交换通过，同来源倒序和用重复告警替换另一条均被检出。真实组合采集分别收到 76590 条系统调用、117 个报文和 50763 条系统调用、92 个报文；两轮私有块峰值均为 32，宿主队列载荷峰值为 17950 和 18724 字节。 |
| 6 | 固定测试进程的随机 ID 后，54 份归档 JSONL 的 98 次入口比较得到完全相同的输出字节和退出码。另有 2 项 ledger 时序比较通过，后代历史新出现内网连接时，检测在与原版相同的时点转为 context_filtered。 |

基线、5A 和 5B 均通过普通插件与签名 enclave 的默认、behavior、parity-audit、structure 和 lifecycle 套件。默认及后三套的比较报告逐字节相同；behavior 报告只有重建的插件、宿主和镜像的 SHA-256 不同。阶段 1、2 也完成了默认套件。detector 历史日志 SHA-256 为 `0a197e7744a06698ef89172d3a7f6e249a06a608b4ec827486abbca2e1dbf6e3`，ring 为 `c52b28f0d9c63179f5b4fe4d4a615198131146899a5abfd132a52d7b2002731c`。

## 主要验证命令

以下为各快照实际使用的入口。阶段 3、4 起的实时与 ring 历史测试使用 `--strict`。初次 Docker 组切换未启动测试，随后使用下面的 runuser 调用。构建故障镜像时通过与正式镜像相同的 OBJECT 编译方式解决了头文件冲突。故障断言按 libsinsp 实际读取的记录数比较后续的 evt.num。

```bash
W=/home/poc/falco-live-fix.PsSByxW5
P=$W/poc/build-falco/deps/package; V=$W/verification
S=$W/stages/$tag; F=$S/falco
flags=(); case $tag in phase4|phase5|phase5b) flags=(--strict);; esac
bash "$F/replay.sh" "$P" "$S" "$V/$tag-offline"
bash "$F/live/check-ring.sh" "${flags[@]}" "$P" "$S" "$S/live" "$V/$tag-ring-run"
bash "$F/live/check.sh" "${flags[@]}" "$P" "$S" "$S/live" "$V/$tag-live-official"
python3 -B "$F/live/check-detectors.py" "${flags[@]}" "$P" "$S" "$S/live" "$V/$tag-live-detectors"
python3 -B "$F/tests/check-history.py" detector "$S/bin/replay-detector"
python3 -B "$F/tests/check-history.py" ring "${flags[@]}" "$S/live/replay-ring" "$S/falco-enclave.signed" "$P/etc/falco/falco_rules.yaml"
sudo -n runuser -u poc -g docker -- env "PYTHONPATH=$W/pydeps/root/usr/lib/python3/dist-packages:$W/poc/build-falco/deps/raven" PYTHONHASHSEED=0 TZ=UTC \
    python3 -B "$F/plugin/check.py" "$P" "$S" "$V/$tag-offline" "$W/poc/build-falco/native-run" "$V/$name-run" "${opts[@]}"
python3 -B "$F/tests/check-faults.py" "$S/live" "$S/falco-fault-enclave.signed" "$P/etc/falco/falco_rules.yaml"
python3 -B "$F/tests/check-source-order.py" "$S/live/replay-ring" "$S/falco-enclave.signed" "$P/etc/falco/falco_rules.yaml"
```

`opts` 在默认套件为空，专项分别使用 `--behavior-review`、`--parity-audit`、`--structure-review`、`--lifecycle-review` 加对应的 `$F/tests/fixtures/*.json`。在 `$W` 下执行 `ninja -C tsan/build -j1 probe` 和 `TSAN_OPTIONS=halt_on_error=1 tsan/build/bin/probe`。该探针是审查前的 `engine-concurrency.cpp`，只并发匹配；仓库中的现行版本见下文“审查后修复”。构建、独立探针及完整性对照的记录保存在客体 `$W` 和 `$V`。

## 已测性能与验收范围

最终版命令为 `python3 -B "$F/bench/review-throughput.py" "$S/bin/replay-detector" --profile --background 10000`。单独计时背景处理可观察已有检测的复核开销；整轮还包含建链、匹配和输出。

| 保留链数 | 背景事件/秒 | 整轮事件/秒 | review / settle / lineage 调用 |
| ---: | ---: | ---: | --- |
| 0 | 1136 | 1121 | 10001 / 0 / 0 |
| 10 | 1424 | 1395 | 10021 / 10 / 60 |
| 100 | 1271 | 1132 | 10201 / 100 / 600 |
| 1000 | 1182 | 353 | 12001 / 1000 / 6000 |

原版使用 1000 条背景记录时，N=0、10、100 的整轮吞吐分别为 1126.4、318.4、14.9 事件/秒。相同背景长度下，Clang 改版的四组为 1314.5、903.5、539.1、108.1。独立的 Clang 改版在 10000 条背景记录下，四组背景吞吐为 1092、994、1018、1051，整轮为 1083、969、901、340。改版背景阶段未呈现随 N 持续下降的趋势，包含建链与输出的整轮吞吐仍会下降。只测建链时，`matches` 和 `expire_chains` 自身占 CPU 样本的 13.19% 和 7.70%。可选的部分链分桶未实施。

已结束的百万事件运行各产生 100 条告警。基线的 repeat 原生、churn 原生和 repeat SIM 均通过。5B 的 repeat 原生与基线告警摘要、大小及全部 203 个逻辑采样点相同。两者 RSS 峰值分别为 87.4 和 86.1 MiB，回收后跨度为 11.4 和 17.2 MiB，均超过既有 8 MiB 门槛。基线 repeat SIM 的堆峰值为 34.7 MiB，基线 churn 原生 RSS 峰值为 114.9 MiB。最终版的 repeat、churn 十万条归档前缀在原生与 SIM 的四次回放均通过，单独的上游统一对照已中止。

**not run (user decision: correctness only)**。中止原版 N=1000、基线百万 churn SIM、5B 百万 churn 原生和阶段 1、2 的 behavior 对照。其余中间快照清单、未完成的百万事件原生/SIM/真实采集及完整内存验收均跳过。c7t.large 的低负载 p99 对照 28.80 ms、空闲 CPU、HTTP 降幅对照 32.1% / 34.9%、官方规则十万事件/秒五轮零丢失，以及两台 SGX 机器上完整配置五轮零丢失实收超过 14958 事件/秒，均待硬件验证。

已停止本次后台作业，清除临时构建目录、签名镜像、测试二进制和大输入，保留源码、补丁和 66 MiB 验证记录。本次拉取的 Zeek 镜像已移除，Docker 恢复为停止状态。执行 `sudo -n poweroff` 后，在 Windows 宿主确认 QEMU 进程已退出，2222 端口已停止监听。

## 审查后修复

2026-11-24，Ubuntu 22.04.5，SGX Simulation。默认 WHPX 等待 5 分钟仍无 SSH 握手。TCG 引导成功并关机后，改用 `-accel whpx,kernel-irqchip=off` 成功引导同一磁盘。以下构建和测试都在 WHPX 下完成，使用 q35、`-cpu max`、8 vCPU、6144 MiB，Ninja 并行度为 6。

依赖下载与补丁 27 秒，bpftool 1 秒。正常及故障注入签名镜像、`falco-sgx` 和 `raven_zeek` 配置 3 秒、编译 50 秒。两个实时 ring 工具配置 1 秒、编译 1 秒。TSAN 探针配置 1 秒、编译 37 秒。

| 检查 | 结果 | 耗时 |
| --- | --- | --- |
| 故障注入 | 通过。四个新增阶段都排空 ring，且只有对应错误计数为 1。RAVEN 推进失败产生 `error` 缺口，原有恢复、限速和预算断言均通过 | 14 秒 |
| 严格 ring | 通过。223 条记录，220 条告警与原版一致，10 项错误计数全为 0，读写位置均为 196520 | 1 秒 |
| 严格历史回放 | 8/8 通过，与参考输出差异为 0 | 6 秒 |
| 双来源顺序 | 通过。系统调用和 raven_zeek 各 2 条告警，内容、次数及各来源内的顺序均一致 | 1 秒 |
| TSAN 双来源探针 | 退出 66。两个来源并发格式化时间时，libsinsp 的 `gmt2local()` 使用 `gmtime()` 的共享缓冲区。首个报告即停止，没有最终轮数和告警数 | 不足 1 秒 |

客体未安装 `unzip`。按 README 生成 `reference.scap` 后，改用 Python `zipfile` 原样提取并核对同一成员 `history/inputs/live-recorded.jsonl`（38682 字节），以 `TSAN_OPTIONS=halt_on_error=1` 运行。线程 ECALL 失败时调用 `falco_live_cancel` 的路径仅做代码审查，未触发。

从依赖下载开始到 TSAN 退出共 3 分 35 秒，含引导排查、结果核对和关机的宿主总耗时约 16 分 30 秒。已删除三个客体构建目录及依赖，保留 `/home/poc/falco-review-fix.S4MKe2/verification` 的 1.3 MiB 日志。关机后在 Windows 确认 QEMU 已退出，2222 端口已关闭。

### 告警格式化加锁后复测

固定版本 libsinsp 的 `gmt2local()` 和 ISO 8601 格式化路径都调用不可重入的 `gmtime()`。分析线程和检测线程现在共用 `Detector::format_mutex`，每次只在调用 `format_event()` 时持锁。读取、匹配和写入各自的告警缓冲区均在锁外。TSAN 探针使用相同的锁范围。

在同一 WHPX 配置下从新目录构建，下载依赖和 bpftool 共 25 秒。正式及故障注入镜像配置 2 秒、编译和签名 50 秒。实时工具配置 1 秒、编译不足 1 秒。TSAN 配置 1 秒、编译 36 秒。

| 检查 | 加锁后的结果 | 耗时 |
| --- | --- | --- |
| 故障注入 | 全部通过。四个新增阶段均排空 ring，仅对应错误计数为 1，RAVEN 推进失败产生 `error` 缺口 | 15 秒 |
| 严格 ring | 223 条记录，220 条告警与原版一致，10 项错误计数全为 0，读写位置均为 196520 | 1 秒 |
| 严格历史回放 | 8/8 通过，与参考输出差异为 0 | 6 秒 |
| 双来源顺序 | 两个来源各 2 条告警，内容、次数和各自顺序均通过 | 不足 1 秒 |
| TSAN 双来源探针 | 退出 0，无 TSAN 报告。系统调用 100 轮、4200 条告警，raven_zeek 15 轮、30 条告警 | 不足 1 秒 |

TSAN 沿用相同输入和 `halt_on_error=1`。从下载到五项检查完成共 2 分 17 秒。三个构建目录及依赖已清理，1.3 MiB 日志保存在客体 `/home/poc/falco-review-fix.HXh4X8/verification`。关机后在 Windows 确认 QEMU 已退出，2222 端口已关闭。`falco_live_cancel` 的 ECALL 失败路径仍仅做代码审查。

## 变更文件

下列路径相对 `poc/falco/`，跨阶段文件只列一次。

| 阶段 | 文件 |
| --- | --- |
| 0、1 及实时主流程 | `trusted/enclave.cpp`、`bench/review-throughput.py` |
| 2 | `trusted/bpf_ring.hpp`、`tests/bpf-ring-test.cpp`、`../README.md` |
| 3、4 及严格模式 | `trusted/live_errors.hpp`、`CMakeLists.txt`、`trusted/CMakeLists.txt`、`tests/check-faults.py`、`live/check.sh`、`live/check-ring.sh`、`live/check-detectors.py`、`live/check-moat.py`、`tests/check-history.py` |
| 5A 及宿主线程 | `Falco.edl`、`host.hpp`、`host.cpp`、`live/live_host.cpp`、`live/ring.hpp`、`live/ring_test.cpp`、`live/CMakeLists.txt`、`tests/replay-ring.cpp` |
| 5B 及来源对照 | `engine.cmake`、`tests/CMakeLists.txt`、`tests/engine-concurrency.cpp`、`tests/tsan/CMakeLists.txt`、`tests/check-source-order.py`、`compare.py` |
| 6 | `plugin/raven.cpp`、`plugin/detectors.hpp`、`plugin/graph.hpp`、`tests/replay-detector.cpp` |
| 文档 | `README.md`、`tests/README.md`、`live/verification.md` |

## RAVEN 与 Zeek 分别启用

2026-11-25。基线 `c661d1a7369814416e6f88f2d63c46d900f81b2d`。初次 `git stash create` 得到 `b4319ed72943e0eade29bfa82680fc9687a71f05`，修复宿主清理后为 `4ab9ea54eec72dc2d625c8068c9c0c09ebab39af`。两次均核对快照与工作树无差异，在客体新目录校验归档 SHA-256 后解包。修复版归档 SHA-256 为 `3c9e8d39ccc2125a8397af4d15a577883f01203dd536d839fe37b781d512fee9`。

QEMU 11.1.0，Ubuntu 22.04.5，`5.15.0-198-generic`，SGX Simulation。原盘仅用作临时 qcow2 的 backing file。以下参数首次即完成引导和 SSH 握手。沙箱内启动时客体 DNS 解析失败，直连也超时；关机后用同一组参数和同一写时复制盘在宿主获准联网的环境重启，依赖下载成功。两次引导均记录过 `failed to get xsave state`，本轮未出现 `Unexpected VP exit code 4`。

```text
-accel whpx,kernel-irqchip=off -machine q35 -cpu max -smp 2 -m 4096
-drive file=<临时写时复制盘>,format=qcow2,if=virtio
-nic user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:2222-:22
-display none -serial file:<临时串口日志> -monitor none -no-reboot
```

按 Falco README 下载固定依赖及 bpftool 7.5.0。用 Clang、Ninja、`--parallel 2` 构建 Falco 用户态、普通插件、正式和故障注入签名 enclave、Modern eBPF 与报文探针、`falco-live`、`falco-ring-test`、`replay-ring` 和 `replay-detector`。修复版使用新的构建目录，复用同一份已准备的依赖。

| 实时配置 | syscall 记录 | RAVEN 输入 | 报文提交 / 消费 | 结果 |
| --- | ---: | ---: | ---: | --- |
| 全开，不录制 | 35114 | 259 | 92 / 92 | 工作负载退出前收到 RAVEN 告警和两类 Zeek 扫描告警 |
| 全开，录制 | 21823 | 193 | 91 / 91 | 普通 Falco、enclave 回放均与现场检测结果一致 |
| 仅 RAVEN，YAML 省略 `raven` | 20063 | 260 | 0 / 0 | 仅收到预期的 RAVEN 告警 |
| 仅 Zeek，JSON 字符串省略 `zeek` | 20010 | 0 | 92 / 92 | 收到两类 Zeek 告警 |

四轮均排空，驱动丢失、报文丢失、丢弃、格式拒绝和恢复错误均为 0。`detectors` 与各轮配置一致。五个反例都在采集开始前返回 1；两项录制冲突均清除了新轨迹和录制文件。逐轮原始结果见 [live-detectors-2026-11-25.json](../../../results/falco/raven-zeek-plugin/live-detectors-2026-11-25.json)。

初次快照通过原有矩阵和 17 轮历史回放。另行用已存在的 PCAP 测试全开录制时，宿主返回 1，留下 112032 字节的新轨迹和空 JSONL。文件创建位于清理异常处理之前。宿主现从创建第一个文件起覆盖启动失败，成功启动驱动后才保留输出。修复版录制轮先占用 PCAP，验证原内容逐字节保留、两份新文件均已删除，再释放该路径，用相同三个文件名完成录制和回放。

| 检查 | 结果 |
| --- | --- |
| 严格历史 ring | 17/17。仅在客体副本将 Zeek-only 的 syscall 提前返回移到 `queue_tick` 前，并将空闲 tick 条件改为要求 RAVEN。重签后 16/17，仅 `ring/timer-queue-30-syscall-tick/zeek-only` 在 `ordered alerts[0].ts` 失败，实得 `1700000010.0`，归档为 `1700000008.0`。恢复源码、核对字节并重签后再次 17/17 |
| 严格官方规则采集 | 12519 条驱动记录，零丢失、零恢复错误。现场、普通回放和 enclave 回放的 1 条告警一致 |
| 严格模拟 ring | 223 条记录、220 条预期告警，读写位置均为 196520。夹具的 1 条 DISCARD、2 条格式拒绝符合预期 |
| 故障注入与独立检查 | 匹配、格式化、读批、诊断限速、致命预算和 7 项检测处理阶段恢复均通过。混合来源顺序和 BPF ring 单元测试通过。单元测试按 CMake 实际输出路径运行 |
| 容器与离线回放 | containerd 普通及特权容器合计 8 条告警，现场与回放一致。离线官方规则 25 条启用、2 条告警一致 |
| 离线插件、历史 detector、TSAN | 插件默认套件 38 项普通态与 enclave 对照通过，使用客体已有的固定上游参考。历史 detector 为 79 项通过、12 项原有差异，退出 1，日志 SHA-256 与上次记录完全相同。TSAN 退出 0，syscall 100 轮、4200 条告警，raven_zeek 15 轮、30 条告警 |
| DNS | 修复版在两个新目录各跑一次，另从未改动的基线重新构建宿主和签名 enclave 作同环境对照。三次静态采集及双端回放均匹配 7 条告警。刷新阶段三次均退出 1：enclave 在 17 秒后仍匹配旧地址 `127.0.0.1`，未匹配新地址 `127.0.0.2`。修复版两次普通 Falco 均匹配新地址，enclave 两轮驱动丢失均为零。基线存在相同的 enclave 差异 |

以下命令从修复版 `poc/` 执行。`$V` 为本轮验证输出目录。

```bash
B=build-falco; L=build-falco-live; P=$B/deps/package
S=$B/falco-enclave.signed; F=$P/etc/falco/falco_rules.yaml
python3 -B falco/live/check-detectors.py --strict "$P" "$B" "$L" "$V/detectors"
python3 -B falco/tests/check-history.py ring --strict "$L/replay-ring" "$S" "$F"
cmake --build "$B" --parallel 2 --target sign-falco  # 变异和恢复后分别执行
bash falco/live/check.sh --strict "$P" "$B" "$L" "$V/official"
bash falco/live/check-ring.sh --strict "$P" "$B" "$L" "$V/ring"
python3 -B falco/tests/check-faults.py "$L" "$B/falco-fault-enclave.signed" "$F"
python3 -B falco/tests/check-source-order.py "$L/replay-ring" "$S" "$F"
"$B/tests/bpf-ring-test"
bash falco/replay.sh "$P" "$B" "$V/offline"
bash falco/live/check-container.sh "$P" "$B" "$L" "$V/container"
bash falco/live/check-dns.sh "$P" "$B" "$L" "$V/dns"
python3 -B falco/plugin/check.py "$P" "$B" "$V/offline" "$REFERENCE" "$V/plugin"
python3 -B falco/tests/check-history.py detector "$B/bin/replay-detector"
TSAN_OPTIONS=halt_on_error=1 build-tsan/bin/engine-concurrency build-tsan/input/reference.scap build-tsan/input/raven.jsonl
```

Kubernetes 补测复用 K3s v1.35.8+k3s1 和 containerd 2.2.1。节点 Ready 后，待 CoreDNS（`10.43.0.10`）实际将 `kubernetes.default.svc.cluster.local` 解析为 `10.43.0.1`，再运行原脚本。前次完成的采集接收 280075 条记录，独立重跑接收 283345 条，后者 ring 读写位置均为 20716008，驱动丢失和格式拒绝均为 0。普通 Falco 与 enclave 现场均通过三组 Pod 元数据断言，仅普通 Pod 访问 API Service 命中官方规则。普通回放与 enclave 回放各匹配 4 条告警（3 条测试规则、1 条官方规则）。

```bash
K=$(realpath ../k3s)
export KUBECONFIG=$(realpath ../kubeconfig)
/bin/busybox nslookup kubernetes.default.svc.cluster.local 10.43.0.10
bash falco/live/check-kubernetes.sh "$P" "$B" "$L" "$V/kubernetes-confirm" "$K"
```

| 运行时 | 驱动记录 / enclave 接收 | 现场与回放 |
| --- | ---: | --- |
| Docker 29.1.3 | 465392 / 465392 | 通过 |
| Podman 4.3.1 rootful | 364760 / 364760 | 通过 |
| Podman 4.3.1 rootless | 313800 / 313800 | 通过 |

三轮均核对已有容器和采集中创建的容器。普通 Falco 与 enclave 现场均匹配两条规则 × 两个容器，普通回放与 enclave 回放各匹配 4 条告警。三轮驱动丢失和格式拒绝均为 0。

客体自带 Podman 3.4.4 的两种模式在修复版和基线均退出 1。普通 Falco 和 enclave 的现场输出均出现插件要求 API 4.0.0、服务端仅提供 3.4.4 的告警，比较器读取 enclave 输出时遇到非 JSON 行。Podman 4.3.1 从 Debian bookworm 包解到本轮临时目录，使用独立的存储和套接字。首次 rootless 服务随用户会话退出，版本查询退出 125；在同一会话启动服务并执行脚本后通过。

```bash
I="$V/container/fixture-image.tar"
bash falco/live/check-runtime.sh "$P" "$B" "$L" "$V/docker" "$I" /usr/bin/docker /run/docker.sock
C="$V/podman-tools/usr/bin/podman"
bash falco/live/check-runtime.sh "$P" "$B" "$L" "$V/podman4-root" "$I" "$C" /run/falco-podman4.sock
bash falco/live/check-runtime.sh "$P" "$B" "$L" "$V/podman4-user-confirm" "$I" "$C" /run/user/1000/falco-podman4.sock
```

MOAT 使用 [Actions 运行 44609488889](https://github.com/1320014053/moat-kernel-build/actions/runs/44609488889) 的产物 `14573461439`。核对归档、包清单和内核镜像 SHA-256 后，按虚拟机说明用 TCG 从同一临时盘引导，`uname -r` 为 `6.1.38-moat-falco2`。修复版 enclave 的 8 MiB ring 接收 45894/45894 条记录，读写位置均为 3049752，驱动丢失、丢弃和格式拒绝均为 0。`openat` 和 `readv` 两条现场告警与普通回放、enclave 回放逐条一致。普通 Falco 独立冒烟命中两种标记访问，退出后确认其 8 MiB ring 已释放。两项检查退出 0，内核 taint 为 0。

```bash
test "$(uname -r)" = 6.1.38-moat-falco2
python3 -B falco/live/check-moat.py "$P" "$B" "$L" "$V/moat"
sudo -n env TMPDIR="$V" python3 -B ../moat-kernel-build/tests/falco-modern-smoke.py \
  --default-buffer "$(realpath "$P/usr/bin/falco")" "$(realpath "$B/deps/bpftool/bpftool")"
```

本轮执行了 `falco/live/` 下全部 8 个 `check*` 脚本。检测器开关矩阵在通用内核上执行，MOAT 覆盖标记文件工作负载。两种内核均使用 SGX Simulation，未验证硬件 SGX。

收尾时 K3s 已停止，containerd 的 `k8s.io` 运行任务为 0。客体内三个测试目录均已删除，两次关机的串口末尾均记录 `reboot: Power down`。宿主确认两个 QEMU 进程已退出，2222 端口无监听，已删除临时盘、归档、内核产物和日志。原盘修改时间仍为本地时间 `2026-11-24 23:15:31`。

## 按 Falco 规则选择系统调用

2026-11-25。基线 `df41ac2d6f1f263690d93e9c74d0aea7f731fcfa`，在其上测试未提交的工作树，内容与提交 `989c277` 相同。QEMU 使用 `-accel whpx,kernel-irqchip=off`、q35、`-cpu max`、4 vCPU、5120 MiB，直接引导原盘。客体为 Ubuntu 22.04.5、`5.15.0-198-generic`，SGX Simulation，Falco 0.45.2 发行包。

原版 Falco 的最终订阅取自 `-o log_level=debug` 输出的 `syscalls selected in total (final set)`，enclave 的取自 `event_selection` 行。

| 配置 | `all=false` | `all=true` | RAVEN 补订 |
| --- | ---: | ---: | ---: |
| 原版官方规则 | 72 | 72 | 0 |
| SGX 官方规则 | 72 | 72 | 0 |
| 两个检测器 | 80 | 80 | 8 |
| 仅 RAVEN | 80 | 80 | 8 |
| 仅 Zeek | 72 | 72 | 0 |

两组 72 个名称逐项相同，各官方规则配置的 `rules_not_activated` 均为空。RAVEN 补订 `chmod`、`fchmod`、`fchmodat`、`listen`、`pwrite`、`pwritev`、`write`、`writev`。`custom_set: [openat]` 在采集前退出 1。另在客体规则副本追加一条匹配 `write` 的规则作对照：关闭 RAVEN 时，`all=false` 下原版与 SGX 都选 72 个并报告 `write` 未启用；`all=true` 下两者都选 73 个。

同一 `check.sh` 夹具，改动前 enclave 接收 21819 条记录、57 种事件，改动后 485 条、27 种，且全部属于订阅集合。通用 `syscall`、`switch`、`futex`、`page_fault` 和 `poll` 降为 0。两次驱动丢失和恢复错误均为 0，都只产生 1 条 `Run shell untrusted`。

| 检查 | 结果 |
| --- | --- |
| 构建与 `raven-syscalls-test` | 通过。增量构建重新生成 EDL 绑定 |
| `check.sh`、`check-ring.sh`、离线回放 | 通过 |
| `check-event-set.py` | 通过。8 组 SGX 配置、2 组原版基线和无效配置反例。另以上述 `write` 规则对照运行一次，通过 |
| `check-detectors.py --strict` | 通过。四种检测器组合、五个启动反例；双检测器录制和仅 RAVEN 两轮各出现全部 10 类 RAVEN 输入标记 |
| 严格历史 ring、双来源顺序、BPF ring 单元测试 | 17/17，其余通过 |
| 故障注入 | 八组恢复与预算断言通过。测试后恢复 `FALCO_SGX_FAULT_INJECTION=OFF` 并重建 |
| 插件套件 | 默认 38 项、structure 23 项、lifecycle 22 项通过，使用客体已有的上游参考输出 |
| 历史 detector | 79 项通过、12 项原有差异，日志 SHA-256 仍为 `0a197e7744a06698ef89172d3a7f6e249a06a608b4ec827486abbca2e1dbf6e3` |
| Zeek 状态探针 | 客体无 `unzip`，改用 Python `zipfile` 提取后通过 |
| 容器、Docker、Kubernetes | 通过。Kubernetes 使用现有 K3s 测试集群 |
| DNS | 首次失败，修复夹具后两个新目录各通过一次 |

DNS 首次失败的原因：刷新阶段固定等待 17 秒，原版采集器第一次查询 A 记录时已经拿到改写后的地址，enclave 拿到旧地址，此后窗口内没有再查询。`check-dns.sh` 现在先等各自采集器输出首条 A 记录告警，再改写地址，并等解析器日志出现新地址后再继续。

未运行的项目：重新生成上游结果的 behavior-review 和 parity-audit 套件（客体缺固定的 RAVEN checkout 和 Zeek 镜像）、TSAN、硬件 SGX 和性能测试。缩小订阅后 RAVEN 输入与全量订阅一致，目前依据代码分析和十类输入标记，尚无同一轨迹的差分测试。

逐项命令输出和比较文件保存在宿主仓库外的 `tmp/event-selection-verify`，约 600 KiB。收尾时删除了客体测试目录（1.7 GiB），并删除测试从 `falco-poc` 和 `moby` 命名空间导入的固定镜像。K3s 集群原有的 `k8s.io` 镜像保留。客体执行 `sudo -n poweroff`，串口末尾记录 `reboot: Power down`。宿主确认 QEMU 已退出，2222 端口无监听。
