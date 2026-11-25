# 阿里云 ecs.c7t.large 硬件 SGX 非调试性能测试计划（已过时）

> **已过时。** 本批的 Falco 性能结果已被 2026-11-25 的 [ecs.c7t.xlarge 复测](../aliyun-c7t-xlarge/README.md)取代，当前结论以[新批次报告](../aliyun-c7t-xlarge/runs/20261125T130226Z-13d592774b63/REPORT.md)为准。本批运行的 `31ff860` 仍是单个 ECALL 忙等、订阅全部系统调用、告警按 64 KiB 刷新，与当前源码不同。GETPID 代码此后没有改动，新批次未重测，GETPID 结果仍以本批为准。告警一致性对照没有在新代码上重测，只作历史参考。

目标是在同一台 ECS 上测出 GETPID 各种传输方式的成本、Falco 能持续处理的事件速率，以及开启检测对 HTTP 服务的影响。凡是使用 enclave 的实验，从首次功能验证到正式压测，都使用真实 Intel SGX 硬件，要求运行中的 enclave 报告 `ATTRIBUTES.DEBUG=0`。无监控、普通用户态和普通 Falco 对照组在同一台机器原生运行。

计划建档于 2026-11-22，硬件适配前的源码基线为 `31ff86016fe5719600a65acee8c77204ed9fd63f`。仓库已有的 QEMU/SGX Simulation 验收提供功能期望。硬件测试的进展、逐轮数据和结论从批次索引查阅。[已有功能验收](../falco/acceptance.md) · [实测批次与归档约定](runs/README.md)

Ubuntu 22.04.5 硬件批次已完成。GETPID 和 Falco 均通过运行时非调试核验。报告给出每项指标的实测范围、逐轮原始输出以及不可运行的 MOAT 对照所缺的客体能力。[完整实测报告](runs/20261123T073338Z-31ff86016fe5/REPORT.md) · [逐轮数据](runs/20261123T073338Z-31ff86016fe5/trials.csv)

## 1. 准备硬件 Release 产物

| 程序 | 当前实现与适配内容 |
| --- | --- |
| GETPID，Intel SGX SDK 2.25 | 源码基线只支持 SIM。硬件适配后可用 `SGX_MODE=HW SGX_DEBUG=0` 构建，链接 `sgx_urts`、`sgx_trts`、`sgx_tservice`。硬件版以 `<DisableDebug>1</DisableDebug>` 签名。宿主和 ring 测试调用 `sgx_create_enclave()` 时都传 `debug=0`。[构建规则](../../poc/Makefile) · [签名配置](../../poc/enclave/Enclave.config.xml) · [宿主](../../poc/host/main.cpp) · [ring 测试](../../poc/tests/ring_tests.cpp) |
| Falco 离线与实时入口 | 沿用 Falco 0.45.2、Falco libs 0.26.1、Open Enclave 0.19.19 和 Edgeless RT 0.5.5。硬件构建使用 `Debug=0` 签名，在共用创建函数中指定 `OE_ENCLAVE_TYPE_SGX` 和 `flags=0`，清除 `OE_ENCLAVE_FLAG_SIMULATE` 和 `OE_ENCLAVE_FLAG_DEBUG`。让 `falco-sgx` 和 `falco-live` 加载同一份签名镜像。[构建说明](../../poc/falco/README.md) · [创建入口](../../poc/falco/host.cpp) · [签名配置](../../poc/falco/trusted/enclave.conf) |

构建、启动、冒烟和对照脚本均指向硬件 Release 目录，结果输出采用实际运行模式。可以在同版 Ubuntu 预编译探针、宿主和 enclave。保留适配后的完整源码提交、实际编译和链接参数、签名配置，以及二进制和规则的 SHA-256。正式采样复用验收过的产物。[GETPID 脚本](../../poc/scripts) · [Intel 硬件模式启动参数](https://cdrdv2-public.intel.com/671101/debugging-intel-sgx-enclaves-on-linux.pdf)

当前仓库的 GETPID 硬件入口为 `make SGX_MODE=HW SGX_DEBUG=0`，脚本使用同一组环境变量。构建 Falco 的离线和实时目录时均传 `-DFALCO_SGX_HARDWARE=ON`、`-DCMAKE_BUILD_TYPE=Release`，两者共用同一份非调试签名镜像。首次核验时设置 `FALCO_SGX_REPORT=1`，正式计时沿用已核验的产物。每一批实际使用的编译、签名、启动命令及原始计划均保存在对应批次的 `evidence/`。

## 2. 验收 ECS 和运行中的 enclave

1. **实例与内核。** 选用支持 vSGX 的 `ecs.c7t.large` 和 Ubuntu 22.04 x86-64 UEFI 镜像，先用镜像默认内核。标称配置为 2 vCPU、4 GiB 内存，其中 2 GiB 为加密内存。保存镜像、`uname -r`、CPU 拓扑、Linux 可用内存和客体实际可见的 EPC 容量。核对 CPUID 的 SGX、SGX_LC 及设备 `/dev/sgx_enclave`，准备匹配的硬件运行库。[阿里云规格](https://help.aliyun.com/zh/ecs/user-guide/enhanced-instance-families/) · [阿里云 SGX 环境指南](https://help.aliyun.com/zh/ecs/user-guide/build-an-sgx-encrypted-computing-environment)
2. **事件采集。** 确认页大小为 4 KiB、`/sys/kernel/btf/vmlinux` 可读、内核支持 BPF ring buffer，实际加载一次 Modern eBPF 探针并采到事件。[Falco 内核要求](https://falco.org/docs/concepts/event-sources/kernel/)
3. **项目镜像。** 分别启动 GETPID 和 Falco enclave，在计时前保存 SGX 驱动成功初始化镜像的记录，从实际运行的项目 enclave 读取 SGX REPORT。逐个核对镜像度量值 `MRENCLAVE`、签名者标识 `MRSIGNER` 与对应签名产物相符，且 `ATTRIBUTES.DEBUG=0`。记录镜像 SHA-256，并让后续测试引用该证据。若需第三方独立复核，为同一项目镜像生成并验证 DCAP ECDSA quote，保存验证结果。启动或属性核对失败时保留诊断，修复后重新验收。[Linux SGX 驱动](https://docs.kernel.org/arch/x86/sgx.html) · [Intel 对镜像身份和 DEBUG 属性的核验说明](https://download.01.org/intel-sgx/sgx-dcap/1.21/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf)

## 3. 验证正确性

| 项目 | 负载和通过条件 |
| --- | --- |
| GETPID | 以 1,000 µs 请求间隔生成 10,003 次调用。启用探针的 `host`、`ecall`、`batch`、`step`、`direct` 均满足 `attempted = submitted = processed = 10003`，预留失败和格式拒绝均为 0。`direct` 整轮应有 1 次数据 ECALL，退出时生产、消费游标相等。复用现有 ring 测试和满环恢复用例。[GETPID 验收入口](../../poc/scripts/smoke.sh) |
| Falco 离线回放 | 普通 Falco 与硬件 `falco-sgx` 读取相同的固定 `.scap`、规则和配置。基准用例应启用 25 条规则，产生 2 条预期告警，顺序和完整 JSON 一致。[离线对照](../../poc/falco/replay.sh) |
| Falco 现场采集 | 等待 `falco-live` 报告 `capture_ready`，执行仓库的本地工作负载，核对官方规则及 RAVEN/Zeek 预期告警。低负载下驱动和报文丢失、ring 丢弃、格式拒绝均为 0，停止后排空。录制一轮，用普通 Falco 与硬件 enclave 回放同批输入，核对输出。[官方规则现场对照](../../poc/falco/live/check.sh) · [检测器现场对照](../../poc/falco/live/check-detectors.py) |

首个上机里程碑是两份项目镜像均有匹配身份的非调试硬件报告，并通过低速功能验证。

## 4. 性能实验

| 实验 | 负载与对照 | 记录指标 |
| --- | --- | --- |
| GETPID 传输 | 同一发生器测 `baseline`（无探针）、`host`（普通消费）、`ecall`（逐条进入）、`batch`（批量进入）、`direct`（常驻直读）。从低速逐档增加到首次丢失和饱和。 | 实际产生率、成功处理率、预留失败、格式拒绝、ECALL 次数、有效载荷和 SDK 封送复制字节、发生器及消费者 CPU 时间、停采后的排空时间。 |
| Falco 同输入回放 | 普通 Falco 和硬件 `falco-sgx` 使用同一份规则、配置和输入。官方规则回放固定 `.scap`，RAVEN/Zeek 回放固定的事件 JSONL 和 PCAP。 | 告警一致性、冷启动时间、稳态事件吞吐、CPU、进程峰值 RSS、enclave 可信堆高水位。 |
| 现场业务开销 | 对固定的 HTTP 服务、客户端位置和并发，依次测无监控、普通 Falco、硬件 `falco-live`。后两组对齐官方规则、采集事件集合、ring 容量与输出。加跑启用 RAVEN/Zeek 的完整配置，并观测空闲时的常驻轮询。 | 请求数/秒、相对无监控时的吞吐降幅、请求 p95/p99、告警延迟、整机与采集进程 CPU、驱动及报文丢失。 |
| RAVEN 内存长测 | 分别反复访问同一文件、持续创建新进程与新路径。先以 10 万条核对输入输出，再在同一会话持续处理 100 万条。普通 Falco 与硬件 enclave 使用相同输入作对照。 | 每万条及回收后的 RSS、可信堆当前值和峰值、回收次数、丢失与输出计数。内核提供 EPC 换页计数时一并记录。[负载与稳定性标准](../../poc/falco/RAVEN-历史回收.md) |

**采样与判读**

- GETPID 和现场测量每档先预热，再独立跑 **5 轮 × 60 秒**，交错模式顺序。固定 CPU 预算、ring 大小、规则及输出方式。正式现场计时关闭轨迹录制，记录实际负载和每轮值，报告中位数及波动范围。离线回放固定输入条数，内存长测按事件数结束。
- GETPID 按发生器的实际调用数和生成时间计算发生率，同时记录成功处理数、含排空的总用时及独立的排空用时。检查 `attempted = submitted + reserve_failed`、`submitted = processed + format_rejected`。Falco 明示吞吐分母和事件来源，例如内核 ring 记录或送入 RAVEN 的归一化事件。报告最高持续零丢失速率及首次丢失的负载。
- HTTP 请求延迟由客户端统计。告警延迟用唯一标记配对“发出最后一个触发事件”和“宿主收到对应告警”两个时刻，两端使用同一单调时钟。报告 p50/p95/p99、成功配对数和缺失数。
- 项目提案的两个待验证目标为 **连续 60 秒以 100,000 事件/秒运行且零丢失**、**非饱和负载下告警 p99 < 2 ms**。分别对照实测结果，注明负载、模式、成功处理数、丢失和排空时间。若先达到这台机器的上限，给出实测上限及该点的业务开销。

## 5. MOAT 对照与交付

首次登录时记录客体是否暴露 PKS、PCID、INVPCID。默认内核主实验完成后，若客体具备所需能力，在 GitHub Actions 构建同版本、匹配配置的基线内核和 MOAT 内核，保存运行编号、配置与产物 SHA-256。验证 SGX 和 MOAT 隔离路径实际启用后，在两个内核上用同一份非调试签名镜像、规则和负载重复无监控、普通消费及常驻直读的对照。若条件不足，在批次记录写明实际暴露的能力和 MOAT 测试状态。[MOAT 硬件设计](https://www.usenix.org/system/files/usenixsecurity24-lu-hongyi.pdf#page=7) · [内核工作流](../../.github/workflows/build.yml)

交付可复现命令、两份镜像的硬件非调试验收记录、功能比对、逐轮原始输出和汇总图表。图表覆盖吞吐与丢失、业务开销、告警延迟和内存长测，每个结论引用实际批次与轮次。[批次索引、记录模板与数据管理](runs/README.md)
