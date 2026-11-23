# SGX eBPF Falco

在 x86-64 Linux 上采集内核事件，用 SGX Simulation 验证 enclave 对共享 ring buffer 的读取、解析和告警。最小 GETPID 实验使用 Intel SGX SDK。完整检测链使用 Falco 0.45.2、Open Enclave 和 `raven_zeek` 插件，支持现场采集与离线回放。

| 入口 | 内容 |
| --- | --- |
| [GETPID 通信实验](poc/README.md) | eBPF 探针、宿主、enclave、发生器和 ring 解析测试 |
| [Falco 构建与运行](poc/falco/README.md) | 原版规则、RAVEN 进程事件、Zeek 报文、容器及 Kubernetes 集成 |
| [回归测试](poc/falco/tests/README.md) | 固定上游参考、共享输入、历史独立用例及签名 enclave 回放 |
| [RAVEN 内存测试](poc/falco/RAVEN-历史回收.md) | 事件保留策略、长时间负载和验收阈值 |
| [MOAT 内核工作流](.github/workflows/build.yml) | 从固定提交构建 Linux 6.1.38，生成带校验和的 Debian 包 |
| [Windows QEMU 客体](vm/README.md) | 安装 Ubuntu、启动实验客体和传输源码 |

## 先运行 GETPID 测试

在 Windows 上，从本仓库根目录按[虚拟机说明](vm/README.md)启动客体，并把待测 Git 提交传入新目录。下面的命令从客体内该提交的根目录运行。首次准备 Ubuntu 22.04 x86-64 客体时，安装脚本会配置 Intel SGX SDK 2.25 和编译依赖。已配置的客体可以跳过安装步骤。

```bash
cd poc
sudo bash scripts/setup-ubuntu.sh
bash scripts/build.sh
sudo bash scripts/smoke.sh
```

`smoke.sh` 在签名的 SIM enclave 内测试解析器，再加载真实内核探针，检查五种消费方式和满环恢复后的排空。只跑解析器时可执行 `make test`。

继续在同一份 `poc/` 源码中按 [Falco 构建说明](poc/falco/README.md)编译离线 enclave 和实时探针。`replay.sh` 生成 `build-falco/offline-run`，`upstream/check-reference.py` 生成 `build-falco/native-run`。两份结果供 `raven_zeek` 的普通 Falco 和签名 enclave 回归共用。各套件的命令和预期结果见[回归测试说明](poc/falco/tests/README.md)。

## 在 MOAT 上验证

在 GitHub Actions 中运行 **Build MOAT Linux 6.1.38**，下载该次运行生成的 `moat-linux-6.1.38-falco2-amd64` 产物。解压后运行 `sha256sum -c SHA256SUMS`。Windows 上可按[虚拟机说明](vm/README.md#用-actions-内核启动同一客体)直接引导包中的内核。进入客体后，从待测提交的根目录运行以下测试。

```bash
sudo python3 moat-kernel-build/tests/falco-modern-smoke.py --default-buffer \
    "$PWD/poc/build-falco/deps/package/usr/bin/falco" "$PWD/poc/build-falco/deps/bpftool/bpftool"
```

该测试核对标记文件的 `openat` 与 `readv` 告警、活动 ring 的容量和退出后的释放。工程使用 GitHub Actions 编译内核，本机可编译探针、用户态程序和 enclave。

## 验证记录

从完整 Git 提交重新构建的结果见[独立构建验收记录](results/repository-build.json)，其中记录了源码提交、编译产物指纹、TCG 现场测试和历史回归的实际差异。

已有验收涵盖 GETPID 通信、Falco 规则、检测器回放及 MOAT 上的 SGX Simulation。回放中仍有与固定上游不一致的用例，内存长测也保留了超过阈值的实测值。硬件 SGX 隔离和内核事件来源认证仍待验证。[验收摘要与原始记录](results/falco/acceptance.md)
