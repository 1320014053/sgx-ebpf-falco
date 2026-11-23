# 首台 ECS 环境检查（用户换机中止）

2026-11-23 07:24:05 UTC，通过已匹配主机密钥的 SSH 会话执行一次只读检查，退出码为 0。实际系统为 Ubuntu 24.04.5，计划的参考环境为 Ubuntu 22.04。用户决定先更换机器，本批到此结束。性能采样为 0 轮。

| 项目 | 实际观测 |
| --- | --- |
| 内核与页大小 | Linux `6.8.0-147-generic`，x86-64，4,096 字节页 |
| CPU | 2 个在线逻辑 CPU，客体拓扑中属于同一核。CPU flags 显示 SGX、SGX_LC、PCID、INVPCID。 |
| 普通内存与磁盘 | `MemTotal=1850312 kB`，`MemAvailable=1423392 kB`，swap 为 0。根文件系统剩余约 26 GiB。 |
| SGX | `/dev/sgx_enclave` 与 `/dev/sgx_provision` 存在。节点 0 的 EPC 为 2,080,374,784 字节（1,984 MiB）。 |
| eBPF | 内核 BTF 文件及 `bpftool` 可见。加载探针和采集事件属于尚待执行的功能验收。 |

实例规格和地域仍待云端元数据核实。两份项目 enclave 的非调试硬件 REPORT、功能对照及性能数据均待在新机器上采集。本批读数只对应首台机器。

本次远端命令仅使用标准输出，归档文本保留了交互终端的换行并去除了终端控制序列。[实际命令](raw/host-preflight-r01/preflight.sh) · [环境输出](raw/host-preflight-r01/stdout.txt) · [逐轮清单](trials.csv)
