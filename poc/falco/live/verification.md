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
