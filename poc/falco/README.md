# Falco 原版规则在 SGX Simulation 中运行

Falco 0.45.2 的 `falco_engine`、libs 0.26.1 的 `libscap` / `libsinsp` 和 Falco 的 JSON 告警格式化器运行在 Open Enclave 0.19.19 SGX Simulation 中。构建使用 Edgeless RT 0.5.5 提供的 GNU C++ ABI 和 Go 工具链。GETPID 入口使用 Intel SGX SDK Simulation。[Edgeless RT 发行说明](https://github.com/edgelesssys/edgelessrt/releases/tag/v0.5.5)

## 离线回放

Host 读取 YAML 和未压缩的 `.scap`，把字节交给 enclave，并写出 enclave 生成的告警。

在 Ubuntu 22.04 x86-64 客体准备 `clang`、`g++`、`cmake`（≥ 3.22）、`ninja-build`、`libssl-dev`、`libbtrfs-dev`、`linux-libc-dev`、`curl`、`patch`、`openssl` 和 `python3`。在 `poc/` 中执行以下命令。

```bash
bash falco/fetch.sh build-falco/deps
CC=clang CXX=clang++ cmake -S falco -B build-falco -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS_RELEASE=-O1 -DCMAKE_C_FLAGS_RELEASE=-O1
cmake --build build-falco --parallel 2
bash falco/replay.sh build-falco/deps/package build-falco build-falco/offline-run
```

`fetch.sh` 只准备构建依赖与官方发行包。签名使用构建目录中的本地实验密钥。运行回放不需要 root、联网、加载驱动或执行样本里的动作。`replay.sh` 需要一个新输出目录；它保存原版 YAML、配置、轨迹、启用规则、两侧输出和比较结果。可信入口支持本目录示例的离线配置，校验规则文件顺序，接受最大 64 MiB 的未压缩 `.scap`。`fixture.py` 生成确定性的 x86-64 `.scap`、初始进程表和预期告警。

先用发行包的 Falco 回放两次，再用 `open_raw_block` 在 enclave 内回放相同字节。比较保留告警顺序和重复项，逐项比较整个 JSON，包括规则名、优先级、时间戳、`evt.num`、`evt.type`、`thread.tid`、原文和输出字段。

`falco_rules.yaml` 取自 Falco 0.45.2 发行包，SHA-256 为 `30a1a60263ab97650c851011468da03b17fc0096a7cfa3b6686eba5de73b865b`。普通态加载发行包中的 `container` 0.7.6，enclave 静态链接同版本上游 C++ 插件和完整 Go worker。启动时，依赖库通过只读映射读取当前进程的 `/proc/self`，加载配置前卸载该映射。回放的初始状态和容器元数据均来自 `.scap`。[Falco 发行包](https://github.com/falcosecurity/falco/releases/tag/0.45.2) · [固定版本容器插件源码](https://github.com/falcosecurity/plugins/tree/9064e9d620538aebf32912fa00f6b9ef95d46a37/plugins/container)

DNS 规则的离线入口接受 `falco-sgx ENCLAVE CONFIG CAPTURE --dns-hosts FILE RULES...`。文件每行写 IP 地址和对应主机名，采用 `/etc/hosts` 格式。Enclave 按规则首次查询的顺序从文件载入固定应答，缺失名称按空应答处理。实时入口通过 Open Enclave 接入客体的系统解析器。`libs-sgx-dns.patch` 使用互斥锁保护不依赖 oneTBB 的 DNS 缓存，后台刷新保留上游的地址替换和退避逻辑。

## RAVEN 与 Zeek

`raven_zeek` 是 C++ Falco 事件源和字段提取插件。现场入口 `falco-live` 在同一个 enclave 内持续消费一个 Modern eBPF ring。RAVEN 从 libsinsp 解析出的主机事件更新进程树和时序规则。Linux 报文探针把当前网络命名空间的双向 IP 报文写入同一个 ring，Zeek 从报文更新 TCP 状态和扫描统计。命中由 Falco 的 `plugin/rules.yaml` 输出，完整记录在 `output_fields["rz.result"]`。[实施步骤与验证范围](RAVEN-Zeek-实施记录.md)

从下一节构建的 Linux 宿主运行现场检测。在工作目录提供 `plugin/live.yaml`、官方 `falco_rules.yaml` 和另存为 `raven_zeek_rules.yaml` 的 `plugin/rules.yaml`。

```bash
sudo falco-live falco-enclave.signed live.yaml 4096 - falco_rules.yaml raven_zeek_rules.yaml
```

宿主输出 `capture_ready` 后持续监听。Ctrl+C 或 SIGTERM 会停止采集、排空 ring 并输出统计。测试时可以追加 `-- WORKLOAD [ARGS...]`，让采集随工作负载退出。

`-` 关闭 syscall 轨迹录制。需要保存检测输入做测试时，在规则文件前加 `--record-inputs events.jsonl packets.pcap`，用新文件名，任一位置可用 `-` 跳过。JSONL 保存交给 RAVEN 的事件，PCAP 保存 ring 中的原始 IP 报文和采集时间，每包最多 16 KiB。回放本机录制的两份文件时，`falco-sgx` 使用 `--plugin-host EVENTS PCAP`，普通 Falco 在 `open_params` 中设置 `"host_capture":true`。这样能识别本机发送路径上等待网卡补全的 TCP 校验和。运行 `python3 falco/live/check-detectors.py FALCO_PACKAGE BUILD_DIR LIVE_BUILD_DIR NEW_RUN_DIRECTORY` 可验证关闭录制、开启录制及双端回放。

普通 Linux 对照需要 Python 3.10 或更高版本、PyYAML、psutil 和 Docker 守护进程访问权限。在 `poc/` 运行以下命令。`native-run` 保留输入、原版 RAVEN 字段及 Zeek 日志。

```bash
bash falco/upstream/fetch-raven.sh build-falco/deps/raven
PYTHONPATH="$(realpath build-falco/deps/raven)" PYTHONHASHSEED=0 TZ=UTC \
  python3 -B falco/upstream/check-reference.py build-falco/native-run
```

上一节的 CMake 构建同时生成 `lib/libraven_zeek.so` 和 `falco-enclave.signed`。对照脚本使用插件配置启动普通 Falco，再把同样的原始文件传给已有的 enclave。测试步骤如下。

```bash
python3 falco/plugin/check.py build-falco/deps/package build-falco \
  build-falco/offline-run build-falco/native-run build-falco/plugin-comparison
```

文件回放使用 `plugin/replay.yaml`。在工作目录提供官方规则、容器插件、共享插件，并将 `plugin/rules.yaml` 放为 `raven_zeek_rules.yaml`。普通态用 `falco -c replay.yaml -o engine.kind=modern_ebpf --enable-source raven_zeek` 读取配置里的 `open_params`。两个文件路径与 `format` 位于该 JSON 对象中。enclave 用 `falco-sgx ENCLAVE replay.yaml reference.scap --plugin EVENTS PCAP falco_rules.yaml raven_zeek_rules.yaml`，Tetragon 使用 `--plugin-tetragon`。每个回放文件上限为 64 MiB。

RAVEN 默认在内存中保留最近 600 秒的历史。常驻状态的计费达到 128 MiB 时，优先释放最早的可回收证据，目标为 96 MiB。截断后的告警在 `meta.retention` 给出可连续追溯的起点、边界序号和原因。受保护状态超出预算会输出带序号范围的 `gap` 诊断。

对于持续输入的归一化 RAVEN JSONL，普通 Falco 可将 `open_params` 设为 `{"format":"stream","events":"events.jsonl"}`，签名 enclave 对应使用 `--plugin-stream EVENTS`。两者逐条送入同一个会话，命中时输出告警。测试采样通过 `"retention_metrics":true` 开启，每万条记录一次，回收后另行采样。现场 eBPF 入口使用相同的回收策略。[回收设计与验收标准](RAVEN-历史回收.md)

## Modern eBPF 实时直读

在支持 Modern eBPF 和 BTF 的 x86-64 Linux 客体中，额外安装 `libelf-dev`、`zlib1g-dev`、`make` 和 `pkg-config`。使用 bpftool 7.5.0 生成 skeleton。在 `poc/` 目录继续执行。

```bash
mkdir -p build-falco/deps/bpftool
curl -fsSL https://github.com/libbpf/bpftool/releases/download/v7.5.0/bpftool-v7.5.0-amd64.tar.gz \
    | tar -xz -C build-falco/deps/bpftool bpftool
chmod u+x build-falco/deps/bpftool/bpftool
cmake -S falco/live -B build-falco-live -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DMODERN_BPFTOOL_EXE="$(realpath build-falco/deps/bpftool/bpftool)"
cmake --build build-falco-live --parallel 2
bash falco/live/check.sh build-falco/deps/package build-falco build-falco-live build-falco/live-run
bash falco/live/check-ring.sh build-falco/deps/package build-falco build-falco-live build-falco/ring-run
```

`check.sh` 在客体内用 `sudo -n` 装载探针，以当前账号运行回环工作负载，并将实时告警、普通 Falco 回放告警和 enclave 回放告警逐条比较。`check-ring.sh` 无需特权。它检查环绕、BUSY、DISCARD、格式拒绝，并在一批事件处理期间修改共享映射中的末条载荷，验证原版告警仍匹配私有副本。

```text
falco-live ENCLAVE CONFIG RING_KIB TRACE_OR_- RULES... [-- WORKLOAD [ARGS...]]
```

Host 初始化固定版本驱动和 procfs 快照，核对所有 CPU 指向同一个真实 ring map。它保留失败的 syscall exit，并关闭 BPF 迭代器。宿主调用 `falco_live_setup` 校验映射和快照，再让采集线程与分析线程分别进入 `falco_live_run`。采集线程把载荷复制到 enclave 私有块后立即写回消费位置。分析线程运行 libsinsp 和官方规则。启用 raven_zeek 时，第三个宿主线程进入 enclave，按顺序接收分析线程交付的 RAVEN 行、报文和时钟更新。检测线程处理完一个私有块，采集线程才可复用它。官方规则和 raven_zeek 各自按来源顺序输出，两个来源的告警可以交错。两个线程并行匹配，但格式化告警时串行，因为固定版本 libsinsp 的时间格式化使用不可重入的 `gmtime()`。停止时依次排空 ring、私有块和宿主输出队列，再由 `falco_live_finish` 输出统计。`TRACE_OR_-` 传新文件名时批量导出同一份输入，传 `-` 时仅输出告警和统计。ring 容量为 16 至 65536 KiB 的二次幂，运行要求 4 KiB 页。

实时配置默认 `buffered_outputs: false`，每个有告警的事件交付一次，由宿主线程写 stdout。设为 `true` 后按 64 KiB 刷新，停止时写出余量。ring 读空时按 libscap 的常量从 500 µs 退避到 30 ms，`idle: spin` 可用于忙等对照。`live_block_count` 默认 32，`live_block_bytes` 默认 262144。统计中的 `ingest_stalls` 是采集线程等待空闲块的次数，`peak_blocks` 与 `output_queue_peak` 分别记录在用块数和宿主待写块数的峰值。`output_queue_peak_bytes` 记录宿主队列同时待写的最大载荷字节数。驱动单独报告丢失。

实时统计的 `errors` 按 raw-block 读取（`batch`）、官方规则的匹配和格式化（`match`、`format`）、raven_zeek 告警的匹配和格式化（`plugin_match`、`plugin_format`）、翻译（`translate`）、RAVEN 事件和时钟推进（`raven`、`raven_advance`）、Zeek 报文和时钟推进（`zeek`、`zeek_advance`）分项计数，两个来源各自计算错误预算。RAVEN 事件或时钟推进出错时以 `error` 缺口重置状态，Zeek 跳过出错的报文或时钟推进。可恢复错误默认继续，每类只打印前三条。某类连续失败 16 次，或从首次失败起的一秒采样窗口内至少尝试 64 次且超过半数失败，采集以非零状态结束。运行 `live/check.sh`、`live/check-ring.sh`、`live/check-detectors.py` 时可在首参数加 `--strict`，令任何恢复计数都使测试失败。`tests/check-history.py ring` 也接受此选项。

## 容器元数据与官方规则

实时配置启用容器运行时后，enclave 内的上游 Go worker 通过 Open Enclave 的文件系统和 Unix socket 接口查询运行时。`libs-raw-block-async.patch` 让 `libsinsp` 把 worker 的异步元数据与从 ring 取得的事件合并。导出的 `.scap` 保留合并后的事件顺序，普通 Falco 和 enclave 可分别回放同一份轨迹。

在隔离客体启动 containerd，准备 `ctr` 和静态链接的 `/bin/busybox`，再从 `poc/` 运行以下命令。脚本在本地构建镜像，运行两个临时容器，验证普通与特权状态、完整 ID、镜像仓库和运行时类型。它用官方 YAML 核对 8 条现场告警及两种回放的完整 JSON。

```bash
bash falco/live/check-container.sh build-falco/deps/package build-falco build-falco-live build-falco/container-run
```

## Kubernetes 与 DNS

在隔离客体启动单节点 K3s，通过 `--container-runtime-endpoint unix:///run/containerd/containerd.sock` 使用现有 containerd。等待 CoreDNS 就绪，在 containerd 的 `k8s.io` 命名空间导入容器用例生成的 `fixture-image.tar`，并提供测试集群的 `KUBECONFIG`。脚本验证普通 Pod 访问 API Service、普通 Pod 访问其他 Service，以及 `kube-system` Pod 访问 API Service。三种连接均核对 Pod 元数据，现场和回放使用同一份官方 YAML。[K3s server 参数](https://docs.k3s.io/cli/server)

DNS 测试需要 `dnsmasq-base`。两项测试都在独立挂载命名空间为测试进程配置解析，DNS 脚本分别验证固定应答和现场缓存刷新。

```bash
bash falco/live/check-kubernetes.sh build-falco/deps/package build-falco build-falco-live build-falco/k8s-run /path/to/k3s
bash falco/live/check-dns.sh build-falco/deps/package build-falco build-falco-live build-falco/dns-run
```

固定上游对照、历史回放和签名 ring 测试的入口见[回归测试说明](tests/README.md)。[验收记录](../../results/falco/acceptance.md) 包含运行证据和待验证范围。
