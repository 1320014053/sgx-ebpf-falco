# ecs.c7t.xlarge 硬件测试批次记录

| 项目 | 实际值及证据 |
| --- | --- |
| 批次与目的 | `20261125T130226Z-13d592774b63`。2026-11-25 13:02:26 UTC 建批，14:13:13 补测结束，14:14:23 生成清单。E1–E8 测量实时采集、跨边界等待、业务开销、内存与回放，覆盖 RQ2、RQ3；RQ1 与 GETPID 不在范围内。[计划](../../README.md) |
| 主机 | 阿里云 ecs.c7t.xlarge，Ubuntu 22.04.5 LTS，内核 5.15.0-198-generic。Xeon Platinum 8369B，2 核 × 2 线程，4 vCPU。Linux 可见内存 3,666,493,440 B，预检时 available 为 3,132,956,672 B，无 swap。[CPU](preflight/lscpu.txt) · [内存](preflight/free.txt) |
| 硬件能力 | 4 KiB 页，EPC 4,160,749,568 B（3,968 MiB）。内核将 EPC 映射回 NUMA 节点 0。SGX1、SGX2、SGX_LC、PCID、INVPCID 均为 1，PKS 为 0；BTF 可读，BPF ring buffer 创建成功。[预检](preflight/preflight.json) · [内核输出](preflight/dmesg-sgx.txt) |
| 源码和交付包 | 提交 `13d592774b6375884b5fd831d1c9ff2d08ad7d6a` 加工作区改动。构建输入与最终快照相比只差上机说明和 ship-run.sh。交付包 SHA-256 为 `79045000d036758de616b292a817aca92e2a1894f4e5ecc4e63abf80e0535c8f`。[提交](evidence/source-commit.txt) · [未提交补丁](evidence/uncommitted.patch) · [新文件哈希](evidence/new-files.sha256) · [快照核对](evidence/snapshot-comparison.txt) |
| 构建与运行库 | Windows 本机的 Ubuntu QEMU 客体使用 Clang/Clang++、CMake、Ninja、Release、-O1、FALCO_SGX_HARDWARE=ON 构建，真机执行。普通离线和实时构建共用普通签名镜像，E7 另编译内存探针及签名镜像。原生使用 Falco 0.45.2 发行包。[实际构建命令](evidence/build.sh) · [构建输出](evidence/build.log) |
| 随包动态库 | Intel SGX 2.25.100.3-jammy1（enclave-common、urts、ae-pce、quote-ex、uae-service），DCAP 1.22.100.3-jammy1（dcap-ql、qe3-logic、pce-logic、ae-qe3、ae-id-enclave），Ubuntu libprotobuf23 3.12.4-1ubuntu7.22.04.6。通过交付包的 `runtime/usr/lib/x86_64-linux-gnu` 加载。[包名、版本及哈希](evidence/runtime-packages.txt) |
| 采样 | E1–E6 每档一次 30 秒，无额外预热，按 1 秒采样；CPU 100% 对应一个逻辑 CPU。现场采集共用一个 8 MiB ring，不绑核，轨迹录制关闭。E7、E8 按固定输入各运行一次。[逐点索引](trials.csv) |

## 镜像身份和配置

| 签名镜像 | MRENCLAVE | MRSIGNER | 硬件报告 |
| --- | --- | --- | --- |
| 普通 | `e3b0acfe93113a56a658fbd466a0641fb83fe50bdef065b0fead45b9d38044db` | `1cc2cbab46c069658003011c94727bf550fdc70a0349cfab5dca037c0fba213b` | DEBUG=0，两项度量均匹配。[普通预检](preflight/preflight.json) |
| E7 探针 | `4a60c294fe882a9c4e996c64bc805467efe6a5cc5db65f78adb62ec03cc92b45` | `48acfb2734b51cc8550d5b70df28b69591a5dd2da1535f3093f8b762e925956d` | DEBUG=0，两项度量均匹配。[探针预检](preflight-probe/preflight.json) |

本批没有单独运行计划「有效性检查」要求的逐配置硬件短冒烟。两份镜像通过硬件预检后，脚本直接进入正式测量。各 SGX 配置首次正式运行的 `metrics.json` 和 `stderr.log` 提供启动与计数证据：脚本核对 `event_selection` 订阅数（S1、S3 及 S1 变体为 72，S2、S4 为 80）、`detectors` 开关、`errors` 各项为零、`format_rejected=0`、`trace_bytes=0`，并核对停止后读写游标相等。告警交付以 E5 各采集配置和 E3 两种等待策略的实际标记配对数为准。B0 为无采集器基线。 [S1](e1/S1-cal6250/metrics.json) · [S2](e1/S2-cal6250/metrics.json) · [S3](e1/S3-cal6250/metrics.json) · [S4](e1/S4-cal6250/metrics.json) · [S1-spin](e3/S1-spin-10000/metrics.json) · [S1-buf](e5/S1-buf-markers/metrics.json)

## 执行记录

在 ECS 的 root tmux 会话中，从交付包根目录启动主脚本：

```bash
cd /root/c7t-xlarge-ship
bash src/results/aliyun-c7t-xlarge/scripts/ship-run.sh > /root/c7t-xlarge-run.log 2>&1
echo EXIT=$? >> /root/c7t-xlarge-run.log
```

| 阶段 | 实际结果和命令 |
| --- | --- |
| 主运行 | 两份预检通过。E1–E6 首次运行 87 点，75 有效、12 无效。测完 E6 后 `EXIT=1`。每个现场轮次目录含 command.txt、配置和计数。[主日志](evidence/c7t-xlarge-run.log) · [补测前索引](evidence/supplement/trials-before.csv) |
| E7、E8 | 独立 root tmux 会话执行 `bash evidence/continue-e7-e8.sh`，显式设置 LD_LIBRARY_PATH，先后以探针和普通构建运行 memory-bench.py、replay-bench.py。两阶段合计 20 轮，`EXIT=0`。[逐项命令](evidence/continue-e7-e8.sh) · [日志](evidence/continue-e7-e8.log) |
| E2 补测 | Windows 仓库修改 bench.py，经 py_compile 验证。脚本传到交付包外层的 `supplement/src/results/aliyun-c7t-xlarge/scripts/`，引用出货版 tcp-load.c 和 poc 配置。出货脚本 SHA-256 为 `2806058c380a8ca007e6ef02f1e93cc46d0570f93ad44da28c36b9f095c54f6a`，补测脚本为 `9efc0ae8216fca2cf75ab518ee33031158182f644051c50aa417ccff23c5d653`。[补丁](evidence/supplement/bench.patch) · [脚本](evidence/supplement/bench.py) |
| 选点和计时 | 真实指标 dry-run 跳过 12 个已有点，S2/S4 均先测 12k。root tmux 执行 `bash evidence/supplement/run.sh`；S2 后测 14k，S4 后测 10k。四个新目录，均标注后台告警；保留无效状态，命令 `EXIT=1`。逐文件校验原 E2 点，并逐字节核对 trials.csv 的原始前缀。[实参](evidence/supplement/run.sh) · [dry-run](evidence/supplement/dry-run.log) · [运行日志](evidence/supplement/run.log) |
| 汇总封存 | root tmux 执行 `bash evidence/supplement/finalize.sh`，运行出货版 summarize.py，按根进程和规则汇总后台告警，生成并校验 SHA256SUMS，归档退出 0。[精确命令](evidence/supplement/finalize.sh) · [汇总日志](evidence/supplement/summarize.log) · [封存日志](evidence/c7t-xlarge-finalize.log) |

| 实验 | 总轮数 | 有效或完成 | 无效 | 其中新增二分补测 |
| --- | ---: | ---: | ---: | ---: |
| E1 | 38 | 38 | 0 | 0 |
| E2 | 28 | 12 | 16 | 4 |
| E3 | 6 | 6 | 0 | 0 |
| E4 | 6 | 6 | 0 | 0 |
| E5 | 7 | 7 | 0 | 0 |
| E6 | 6 | 6 | 0 | 0 |
| E7 | 6 | 6 | 0 | 0 |
| E8 | 14 | 14 | 0 | 0 |
| 合计 | 111 | 95 | 16 | 4 |

E7、E8 按各自 summary.json 和退出状态计数；预检未计入实验轮数。原点重跑 0 次。E8 的 30 万事件输出对照属于原计划。[E7 明细](e7/summary.json) · [E8 明细](e8/summary.json)

## 异常与数据交接

服务器常驻阿里云盾代理，在所有配置（含 B0、N1）中均作为公共背景负载运行，本批没有停止它。测量期间通过 SSH 轮询，最初约每 3 分钟一次，发现背景告警后协调者停止轮询，执行端一度改为约 10 分钟，随后恢复 3–5 分钟。16 个 E2 无效点均只违反「raven_zeek 告警为 0」这一条；1,892 条中 1,837 条归于 AliYunDunMonito，其余涉及 SSH、轮询和 Python 等进程。E1、E4–E6 的 S2、S4 运行也有同一背景告警（20 轮共 2,007 条）。计划只对 E2 要求零告警，这些轮次按规则有效，见报告 E2 节。随后按秒对齐告警和 CPU 采样评估，后台干扰可忽略，报告把 16 个 E2 点按有效数据使用；`trials.csv` 的 `valid` 字段和 `summary/e2-limits.csv` 保留脚本按原规则的判定。按同一评估，22 轮出现的单秒非采集 CPU 尖峰没有触发补测。原阶梯全部跑完，原脚本只用有效点构造二分区间，因而跳过 S2/S4 的二分。经确认添加可选开关，仅在选点时采用单因后台告警无效点的丢失计数。正式有效性判定和普通入口沿用原规则。[逐点后台告警](summary/e2-background-alerts.csv) · [实验报告](REPORT.md)

服务端批次表观大小 1,060,575,838 B（du -sh 为 1015M），压缩包 98,103,426 B。归档 SHA-256 在云端和 Windows 接收端一致，为 `a641c2332dca8b3f647793daa291d229a70cef6855e40286700c2c07af5fcf09`。两端在批次根目录执行 `sha256sum --quiet -c SHA256SUMS`，1,045 项全部通过。[服务端清单](SHA256SUMS)

接收端将 12 个至少 10 MiB 的原始文件按相对路径存入 `bulk/`，原位置用同卷硬链接保留，两个位置均由本批 .gitignore 排除；仓库发布它们的 xz 压缩副本，解压后按服务端清单核对，步骤见 [archives/](archives/README.md)。仓库的 `.gitattributes` 保留本批原始字节，CSV 的 CRLF 换行不被改写。Windows 会话没有创建符号链接的权限，服务器上的 198 条符号链接保存在 `bulk/server-symlinks.tar`，其路径与原目标另见清单。原始普通文件均已校验。运行日志 `evidence/c7t-xlarge-run.log`、封存日志、链接映射、报告和记录均在生成服务端 SHA256SUMS 后加入；主日志接收端 SHA-256 为 `e64023173b92d539fed61b7a4d8bb2c1e96b7431b4938bea50728e89e413ee4c`。[链接映射](evidence/server-symlinks.tsv) · [本批忽略规则](.gitignore)
