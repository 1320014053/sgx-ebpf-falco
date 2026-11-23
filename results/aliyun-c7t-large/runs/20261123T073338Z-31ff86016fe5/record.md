# ecs.c7t.large 测试批次记录

| 项目 | 实际值或批次内证据路径 |
| --- | --- |
| 批次 ID、UTC 起止时间、状态 | `20261123T073338Z-31ff86016fe5`，2026-11-23 07:33:38 至 10:51:50 UTC，采样完成，数据已取回并复核。 |
| 本批目的、与前一批的关联 | 同一规格重装 Ubuntu 22.04 后进行硬件非调试测量，前批仅检查了 Ubuntu 24.04。 |
| 源码提交、工作区改动、计划快照 | 见 `evidence/source-commit.txt` 和 `evidence/plan.txt` |
| 实例规格、地域、镜像、内核版本及配置 | 实例元数据 `ecs.c7t.large`、`cn-shanghai`、`ubuntu_22_04_x64_20G_alibase_20261016.vhd`。Ubuntu 22.04.5，`5.15.0-198-generic`。 |
| CPU 拓扑、可用内存、EPC、页大小、SGX / SGX_LC、BTF / ring buffer | Xeon Platinum 8369B，1 核 2 线程。Linux 可见内存为 1,756,258,304 字节。EPC 区段 `0x100000000–0x17bffffff`，共 1,984 MiB。4 KiB 页，可见 `sgx`、`sgx_lc` 和内核 BTF。[环境原始输出](raw/host-preflight-r01/stdout.txt) |
| MOAT 能力与测试条件 | `CPUID.7.0:ECX[31]=0`，即 `PKS=0`。同时 `PCID=1`、`INVPCID=1`、`SGX_LC=1`、`SGX1=1`、`SGX2=1`。MOAT 对照缺少所需的客体能力。[原始 CPUID](evidence/cpuid.txt) |
| 构建与签名 | GETPID 在 ECS 使用 Intel SDK/PSW 2.25.100.3、`SGX_MODE=HW SGX_DEBUG=0`。Falco 0.45.2、libs 0.26.1 与 Edgeless RT 0.5.5 在临时 Ubuntu 22.04 编译机生成 Release 签名产物，离线和实时复用同一镜像。全部功能验收和性能计时均在 ECS 完成。[GETPID](evidence/build-getpid.txt) · [Falco](evidence/build-falco.txt) · [源码补丁](evidence/hardware.patch) |
| 规则、配置、输入及宿主 / 探针的 SHA-256 | [Falco 发布包所含程序和规则](evidence/falco-falco-ship.sha256) · [GETPID 产物](evidence/build-getpid.txt) · [各轮配置与输入](evidence/transfer.sha256) |
| 负载与采样 | 两个逻辑 CPU 同时供发生器与采集器使用。GETPID ring 为 1 MiB。HTTP 使用本机回环、两条持久连接、每次响应 1 KiB，业务组与低负载告警组使用单个 8 MiB Falco ring。采集器独占测量窗口，各实验串行。切换到 Falco 实验时在两轮 GETPID 之间暂停控制进程，当前测量完成后才启动 Falco。正式阶段关闭轨迹录制。 |

## 项目 enclave 硬件验收

两个项目镜像都通过了签名、运行时身份和驱动初始化三项核对。普通态对照运行在同一台 ECS。

| 签名镜像 | 镜像 SHA-256 | MRENCLAVE | MRSIGNER | REPORT 的 DEBUG 位 | 证据与判定 |
| --- | --- | --- | --- | --- | --- |
| GETPID | `dae0ab4b8060ddbf800dc3a7182c158b1449105df1d2bd34ec91f431f614c283` | `aab933c50af607cc3770072abf50cb5c17a4cb8666cbef86391e2dd4a7c65684` | `8b6e105b4d52fdc2d25e204695d768a1ecfe49b3472728fa99243be58dbc3fa0` | 0，flags `0x5` | 签名度量一致，驱动 `SGX_IOC_ENCLAVE_INIT = 0`。[REPORT](raw/getpid-identity-r01/report.txt) · [驱动](raw/getpid-identity-r01/driver.log) |
| Falco（离线与实时共用） | `f74df854e85462862359c9849c754a2d4a76679f45d1a073f742e0c3b726df8f` | `d47242afecc6f5aa13e6e96d0ecb23f126e8137d8c70a7c707ce091fd0421795` | `c9d59532070d43829d3bad6e757477951bfff7645a09a9ec17701c811f2aacd5` | 0 | 本地 REPORT 与 SIGSTRUCT 一致，驱动初始化成功。[身份核对](evidence/retry-falco.txt) |

## 执行记录

ECS 上的批次目录为 `/var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5`。下列脚本包含实际命令、参数和工作目录。每次尝试均有独立编号。[逐轮清单](trials.csv)

| 步骤或轮次 | 实际命令、工作目录 | 判定、日志或数据路径 |
| --- | --- | --- |
| 主机与运行库 | [环境检查](raw/host-preflight-r01/check.sh) · [Intel 发布包校验和解包](evidence/prepare-runtime.sh) | 阿里云元数据确认 `ecs.c7t.large`，校验通过。 |
| GETPID 正确性 | [编译与签名核对](evidence/build-getpid.sh) · [负载与计时](evidence/getpid-benchmark.py) | `host`、`ecall`、`batch`、`step`、`direct` 各 10,003 次全部处理，直接消费整轮 1 次数据 ECALL。人为暂停消费 3 秒时 20,000 次中 16,029 次预留失败，剩余 3,971 条全部排空。首轮 ring 测试输出有沿用的 SIM 文本，交叉核验使用硬件 REPORT、驱动与链接库。`getpid-ring-r02` 已修正该文本并复验。 |
| Falco 固定回放 | [首轮](evidence/verify-falco.sh) · [补充运行库](evidence/falco-runtime.sh) · [第二轮核验](evidence/retry-falco.sh) | 首轮 `oe_get_report` 返回 `OE_QUOTE_LIBRARY_LOAD_ERROR`。从已核对哈希的同一 Intel 包补齐共享库后，用原镜像重测通过。25 条规则启用，两个程序的两条告警完整一致。 |
| Falco 现场与回放 | [执行脚本](evidence/live-and-replay.sh) · [退出状态](evidence/live-and-replay.txt) | 官方规则现场对照、检测器的现场与同输入回放、固定长度回放测速均成功。 |
| RAVEN 稳定性 | [输入、运行与指纹](evidence/falco-memory.py) · [原始结果汇总](summary/memory.csv) | 10 万及 100 万事件，重复访问与持续新增路径均完成。两模式核对了同一输入、告警摘要及回收计数。百万事件时硬件可信堆峰值分别为 33.625 和 78.625 MiB。 |
| HTTP 与告警计时 | [负载与采样](evidence/http-benchmark.py) · [字段作用域修正与复测](evidence/http-retest.sh) | 高负载四组、低负载告警三组，每组 5 × 60 秒。另测四组各 15 秒空闲 CPU。完整配置首轮冒烟失败后，将官方附加字段限定到 syscall 源，复测沿用同一二进制。 |
| Falco 现场吞吐 | [第一阶段](evidence/falco-capacity.py) · [按持续速率再校准](evidence/falco-capacity-refine.py) · [低速复测](evidence/capacity-floor-stage.sh) | 通过本地 `/dev/null` 打开和关闭产生负载，记录实际送入、实收和驱动丢失。首批正式样本保留为中间档，完整配置另测每秒 12,000 和 4,000 次打开/关闭。 |

## 实测结论

正式 GETPID、现场吞吐、HTTP 吞吐及低负载告警均按档位独立测量 5 × 60 秒。全批共 326 条轮次或验收记录，其中 324 条完成，两次首次尝试分别在 `falco-offline-r02` 和 `http-hw-full-r00-retry2` 复测通过。[完整报告和图](REPORT.md) · [逐轮实测](trials.csv)

| 项目 | 结果 | 逐轮数据 |
| --- | --- | --- |
| GETPID | 75 个正式样本和 75 个预热样本齐全。十万次调用/秒档的四种采集方式共 20/20 轮零丢失，直读每轮 1 次数据 ECALL。 | [计数、CPU、复制与排空](summary/getpid-trials.csv) |
| Falco 现场十万条/秒 | 官方规则 5/5 轮零丢失，实收中位数 106,929 条/秒。完整配置同档实收中位数 50,284 条/秒，5/5 轮出现丢失。完整配置在已测档位中，五轮全部零丢失的最高实收速率中位数为 14,958 条/秒。 | [送入、实收及丢失](summary/capacity.csv) |
| HTTP 业务和低负载告警 | 普通 Falco、SGX 官方、SGX 完整配置相对同轮无监控 HTTP 的吞吐降幅中位数分别为 8.4%、32.1%、34.9%。三组低负载告警各配对 595/595，p99 分别为 28.805、8,047.168、4.659 毫秒，均高于 2 毫秒目标。 | [组内统计](summary/http-groups.csv) |
| RAVEN 百万事件 | 每种负载、每种运行方式各持续一个会话，后半程回收后同阶段内存极差均低于 8 MiB，跳过和强制重置均为零。 | [内存与匹配结果](summary/memory.csv) |
| MOAT 硬件对照 | ECS 客体实测 PKS 为 0，无法运行这项对照。 | [CPUID](evidence/cpuid.txt) |

## 数据回收

ECS 生成的传输包为 58,490,494 字节，接收端校验了整包 SHA-256，并逐项比对服务端清单中的 1,530 个文件。本批的 `raw/` 与 `evidence/` 共 1,552 个文件，`bulk/` 有 48 个文件。两份本地清单全部复核通过。公开签名产物存放在 `bulk/artifacts/`，完整现场轨迹存放在对应的 `bulk/<trial_id>/`，本批 46 个大文件随仓库按原路径发布，两份百万事件告警日志各自无损压缩，解压后可复核全部 48 个文件。[从 GitHub 还原完整批次](archives/README.md) · [接收回执](evidence/transfer-receipt.txt) · [证据与原始输出清单](SHA256SUMS) · [大文件清单](bulk.sha256) · [复核结果](summary/audit.json)

| 实采回放输入 | 字节 | 批次内持久副本 |
| --- | ---: | --- |
| 官方现场系统调用轨迹 | 439,644 | [SCAP](bulk/falco-live-official-r01/reference.scap) |
| 完整检测系统调用轨迹 | 862,316 | [SCAP](bulk/falco-live-detectors-r01/recorded/reference.scap) |
| 完整检测归一化事件 | 72,830 | [JSONL](bulk/falco-live-detectors-r01/recorded/events.jsonl) |
| 完整检测报文 | 6,124 | [PCAP](bulk/falco-live-detectors-r01/recorded/packets.pcap) |

从本批目录依次运行以下命令可复算统计表、图和报告，并核对原始文件、实验覆盖与硬件身份。绘图需要 Matplotlib。[固定回放生成命令](evidence/falco-replay-bench.py) · [RAVEN 合成输入生成命令](evidence/falco-memory.py)

```bash
python3 evidence/summarize.py
python3 evidence/plots.py
python3 evidence/report.py
python3 evidence/audit.py
```
