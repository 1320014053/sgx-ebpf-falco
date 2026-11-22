# 验收记录

## 仓库整理后的复测

2026-11-22，在 Ubuntu 24.04 WSL 中编译当前 C++ 检测器，在 Ubuntu 22.04 QEMU 临时快照中编译并签名 Falco enclave。客体内核为 `5.15.0-198-generic`。下表的行使用不同入口，部分共享样本。[本次计数、差异用例及构建指纹](../verification.json)

| 测试入口 | 实测结果 |
| --- | --- |
| Intel SGX SDK 2.25 SIM 解析器 | 环绕、BUSY、DISCARD、格式拒绝、描述符边界、尾批和排空通过 |
| QEMU 真实 GETPID eBPF | 五种消费模式各处理 10,003 条事件，另通过满环恢复测试 |
| 原版 Falco 规则与签名 enclave 离线回放 | 两端均启用 25 条规则，2 条告警逐字段一致 |
| 现行四份清单的 C++ 检测器回放 | 95/95 组符合各自清单的预期 |
| 普通 Falco 与签名 enclave 的结构回归 | 23/23 组通过。两端对 17 份有效输入给出预期告警，对 6 份无效输入给出预期的退出码与诊断 |
| 历史补充用例的 C++ 文件、流式与逐包入口 | 79/91 项与上游一致。其余 12 项对应 9 组已有差异的输入，其中 3 组同时在文件和逐包入口验证 |
| 签名 enclave 的历史 ring 回放 | 8/8 组通过，包括 UID 翻译、上下文更新和报文定时器 |
| Zeek 状态探针 | 两处会话存留状态和六处抑制表计数与归档一致 |

历史补充测试以固定上游的退出码和有序告警为预期。有差异时会返回非零，后续修复可以直接复用这些样本。[测试命令和清单](../../poc/falco/tests/README.md)

## 早期实验记录

| 实验 | 结论与记录 |
| --- | --- |
| GETPID 数据路径 | 记录每种模式的 ECALL 次数、复制字节和丢失计数。[实验报告](../getpid/conclusion.md) · [逐轮数据](../getpid/runs.csv) |
| Falco 容器与 Kubernetes | 在测试客体及记录的运行时环境中，累计覆盖当时启用的 25 条官方规则。[逐条规则覆盖](live/kubernetes-dns/rule-coverage.json) |
| RAVEN 和 Zeek 现场采集 | 记录模式和持续模式均在工作负载结束前得到预期告警，回放核对了同批输入。[现场计数](raven-zeek-plugin/live-ring.json) |
| RAVEN 历史回收 | 固定输入和现场同文件负载的普通 Falco RSS 极差为 10.00 MiB 和 9.63 MiB，均超过原定 8 MiB 阈值。[长测报告](raven-zeek-plugin/retention-results.md) |
| MOAT 内核 | Actions 产物 `6.1.38-moat-falco2` 在 QEMU 中以 8 MiB ring 采集 `openat` 和 `readv` 并触发签名 enclave 告警。[内核产物校验](../moat/6.1.38-moat-falco2/actions-verification.txt) · [现场与回放计数](../moat/6.1.38-moat-falco2/sgx-simulation/check.json) |

容器、Kubernetes、MOAT 内核与百万事件负载在本表中引用的是对应历史运行。硬件 SGX、MOAT 硬件隔离及事件来源认证仍待实机验证。
