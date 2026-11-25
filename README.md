# SGX eBPF Falco

本项目把 Falco 0.45.2 的事件解析、规则匹配和告警生成放进 SGX enclave。enclave 基于 Open Enclave，直接读取 Modern eBPF 驱动写入的共享 ring buffer，并通过 `raven_zeek` 插件做进程行为关联和 TCP 扫描检测，支持现场采集与离线回放。支持 SGX Simulation 和已在阿里云 ECS 验收的硬件非调试模式。

开发 Falco 之前，项目先用 GETPID 实验做了概念验证（POC）：基于 Intel SGX SDK，只观察一个测试进程的 `getpid()`，用来验证 eBPF ring 到 enclave 的通信路径并测量开销。它只用于前期论证，ring 解析不随 Falco 同步更新。

| 入口 | 内容 |
| --- | --- |
| [项目实现与测试总结](项目实现与测试总结.md) | 从一条系统调用读懂架构、硬件适配、验证方法和实测边界 |
| [Falco 构建与运行](poc/falco/README.md) | 原版规则、RAVEN 进程事件、Zeek 报文、容器及 Kubernetes 集成 |
| [回归测试](poc/falco/tests/README.md) | 固定上游参考、共享输入、历史独立用例及签名 enclave 回放 |
| [RAVEN 内存测试](poc/falco/RAVEN-历史回收.md) | 事件保留策略、长时间负载和验收阈值 |
| [阿里云 c7t.large 硬件 SGX 性能测试计划](results/aliyun-c7t-large/README.md) | 关闭 enclave 调试后的硬件验收、性能对照和[实测批次记录](results/aliyun-c7t-large/runs/README.md) |
| [阿里云 c7t.xlarge 硬件 SGX 性能复测计划](results/aliyun-c7t-xlarge/README.md) | 4 vCPU 上按 RAVEN、Zeek 分开测量吞吐、跨边界方式、业务开销、延迟、空闲、内存和回放，见[实测报告](results/aliyun-c7t-xlarge/runs/20261125T130226Z-13d592774b63/REPORT.md) |
| [MOAT 内核工作流](.github/workflows/build.yml) | 从固定提交构建 Linux 6.1.38，生成带校验和的 Debian 包 |
| [Windows QEMU 客体](vm/README.md) | 安装 Ubuntu、启动实验客体和传输源码 |
| [GETPID 前期实验](poc/README.md) | 概念验证：eBPF 探针、宿主、enclave、发生器和 ring 解析测试 |

## 构建与运行 Falco

在 Windows 上，从本仓库根目录按[虚拟机说明](vm/README.md)启动客体，并把待测 Git 提交传入新目录。先按 [Falco 构建说明](poc/falco/README.md)在 Ubuntu 22.04 x86-64 客体中安装编译依赖，再从客体内该提交的根目录运行以下命令，编译 enclave 并完成一次离线回放。

```bash
cd poc
bash falco/fetch.sh build-falco/deps
CC=clang CXX=clang++ cmake -S falco -B build-falco -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS_RELEASE=-O1 -DCMAKE_C_FLAGS_RELEASE=-O1
cmake --build build-falco --parallel 2
bash falco/replay.sh build-falco/deps/package build-falco build-falco/offline-run
```

`replay.sh` 生成 `build-falco/offline-run`，`upstream/check-reference.py` 生成 `build-falco/native-run`。两份结果供 `raven_zeek` 的普通 Falco 和签名 enclave 回归共用。各套件的命令和预期结果见[回归测试说明](poc/falco/tests/README.md)。现场采集的实时探针和宿主另行编译，见 Falco 构建说明的 [Modern eBPF 实时直读](poc/falco/README.md#modern-ebpf-实时直读)。

## 在 MOAT 上验证

在 GitHub Actions 中运行 **Build MOAT Linux 6.1.38**，下载该次运行生成的 `moat-linux-6.1.38-falco2-amd64` 产物。解压后运行 `sha256sum -c SHA256SUMS`。Windows 上可按[虚拟机说明](vm/README.md#用-actions-内核启动同一客体)直接引导包中的内核。进入客体后，从待测提交的根目录运行以下测试。

```bash
sudo python3 moat-kernel-build/tests/falco-modern-smoke.py --default-buffer \
    "$PWD/poc/build-falco/deps/package/usr/bin/falco" "$PWD/poc/build-falco/deps/bpftool/bpftool"
```

该测试核对标记文件的 `openat` 与 `readv` 告警、活动 ring 的容量和退出后的释放。工程使用 GitHub Actions 编译内核，本机可编译探针、用户态程序和 enclave。

## 验证记录

从完整 Git 提交重新构建的结果见[独立构建验收记录](results/repository-build.json)，其中记录了源码提交、编译产物指纹、TCG 现场测试和历史回归的实际差异。

已有验收涵盖 Falco 规则、检测器回放、MOAT 上的 SGX Simulation，以及 GETPID 前期实验。回放中仍有与固定上游不一致的用例，内存长测也保留了超过阈值的实测值。这批历史验收未覆盖硬件 SGX 隔离和内核事件来源认证。[验收摘要与原始记录](results/falco/acceptance.md)

阿里云 `ecs.c7t.large` 的硬件批次另行保存了 Falco 和 GETPID 的 `DEBUG=0` 运行报告、签名度量与性能记录。[硬件实测批次](results/aliyun-c7t-large/runs/README.md)

阿里云 `ecs.c7t.xlarge` 的复测批次在 4 vCPU 上分别测量 SGX + RAVEN、SGX + Zeek 和两者合用，覆盖 RQ2、RQ3。[实测报告](results/aliyun-c7t-xlarge/runs/20261125T130226Z-13d592774b63/REPORT.md) · [批次索引](results/aliyun-c7t-xlarge/runs/README.md)

## GETPID 前期实验

GETPID 是开发 Falco 之前的概念验证，用来比较宿主转发、批量 ECALL 和 enclave 直读 ring 三类路径的开销，结论见[项目实现与测试总结](项目实现与测试总结.md#前期实验getpid)。它使用 Intel SGX SDK，与 Falco 的构建互不依赖。首次准备客体时，安装脚本会配置 Intel SGX SDK 2.25 和编译依赖，已配置的客体可以跳过这一步。

```bash
cd poc
sudo bash scripts/setup-ubuntu.sh
bash scripts/build.sh
sudo bash scripts/smoke.sh
```

上述命令默认在签名的 SIM enclave 内测试解析器，再加载真实内核探针，检查五种消费方式和满环恢复后的排空。只跑解析器时可执行 `make test`。
