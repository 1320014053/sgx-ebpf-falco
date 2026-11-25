# c7t.xlarge 上机步骤

从本批对应提交的仓库根目录运行。机器为 4 vCPU 的 x86-64 Linux，使用支持 SGX 的内核、可用的 EPC、`/dev/sgx_enclave`、4 KiB 页、内核 BTF 和 BPF ring buffer。现场采集需要 root。先准备 `cc`、Clang、G++、CMake ≥ 3.22、Ninja、Make、Git、curl、patch、OpenSSL、binutils、pkg-config、Python 3.10+、GNU time、util-linux、libssl-dev、libelf-dev、zlib1g-dev、libbtrfs-dev 和 linux-libc-dev。汇总 CSV 只用 Python 标准库，安装 matplotlib 后另出 PNG。

## 准备产物

方案一是在服务器编译，需要能下载 GitHub 固定提交、发行包及构建依赖。离线、现场和探针三套均使用旧批次的硬件开关和 Release 配置。探针需要重新编译签名镜像和共享插件，只用于 E7。

```bash
set -euo pipefail
R=$PWD
S=$R/results/aliyun-c7t-xlarge/scripts
B=$R/poc/build-falco
L=$R/poc/build-falco-live
D=$B/deps
P=$D/package
export CC=clang CXX=clang++
opts=(-G Ninja -DFALCO_SGX_HARDWARE=ON -DCMAKE_BUILD_TYPE=Release
      -DCMAKE_C_FLAGS_RELEASE=-O1 -DCMAKE_CXX_FLAGS_RELEASE=-O1)
bash poc/falco/fetch.sh "$D"
mkdir -p "$D/bpftool"
curl -fsSL https://github.com/libbpf/bpftool/releases/download/v7.5.0/bpftool-v7.5.0-amd64.tar.gz |
    tar -xz -C "$D/bpftool" bpftool
chmod u+x "$D/bpftool/bpftool"
cmake -S poc/falco -B "$B" "${opts[@]}"
cmake --build "$B" --parallel 2
cmake -S poc/falco/live -B "$L" "${opts[@]}" -DMODERN_BPFTOOL_EXE="$D/bpftool/bpftool"
cmake --build "$L" --parallel 2

T=$(mktemp -d)
mkdir -p "$T/poc"
cp -a poc/falco "$T/poc/"
patch -p1 -d "$T/poc/falco" < "$S/memory-probe.patch"
M=$T/poc/build-falco
cmake -S "$T/poc/falco" -B "$M" "${opts[@]}" -DDEPS="$D"
cmake --build "$M" --parallel 2
```

方案二在兼容的 Ubuntu 22.04 x86-64 构建机完成编译。交付包根目录有 `src/`、`runtime/`、`evidence/` 和 `SHA256SUMS`。源码快照在 `src/`，普通构建、现场构建和原生发行包沿用方案一的相对路径，E7 探针位于 `src/probe/poc/build-falco`。E8 使用快照中旧批次的 `bulk/falco-live-detectors-r01/recorded/` 和 `raw/plugin-replay-native-r01/metrics.json`。运行所需的 Intel SGX、DCAP 动态库随包解压到 `runtime/usr/lib/x86_64-linux-gnu/`。构建记录、源码版本和两套签名镜像的度量在 `evidence/`。

在服务器的 root 会话中校验压缩包，将其解到新目录，再启动 tmux。以下命令从压缩包和同名 `.sha256` 文件所在目录执行：

```bash
sha256sum -c c7t-xlarge-ship.tar.gz.sha256 &&
mkdir c7t-xlarge-ship &&
tar -xzf c7t-xlarge-ship.tar.gz -C c7t-xlarge-ship &&
cd c7t-xlarge-ship &&
tmux new -s falco-bench
```

在该 tmux 会话内直接运行：

```bash
bash src/results/aliyun-c7t-xlarge/scripts/ship-run.sh
```

`ship-run.sh` 先核对包内文件清单，再设置 `LD_LIBRARY_PATH`，将构建证据复制到 `src/results/aliyun-c7t-xlarge/runs/<UTC>-<提交前12位>/evidence/`，然后调用 `run-all.sh`。使用 root 直接运行，避免 sudo 清除库路径。续跑时从解包根目录执行同一命令，末尾加上已创建的批次目录。服务器需有 GNU `/usr/bin/time` 和 `objcopy`，供回放计时和签名度量使用。

本地 Windows QEMU 的 SSH 使用 `-o StrictHostKeyChecking=yes -o UserKnownHostsFile=工作区（仓库外）的 vm\runtime\known_hosts.target`。云服务器使用其独立核验的主机密钥。

## 建批、运行与续跑

```bash
batch=$PWD/results/aliyun-c7t-xlarge/runs/$(date -u +%Y%m%dT%H%M%SZ)-$(git rev-parse --short=12 HEAD)
mkdir "$batch"
sudo bash "$S/run-all.sh" "$P" "$B" "$L" "$M" "$batch"
```

续跑时使用原 `batch` 路径、源码和产物。包装脚本在两套签名镜像上各做一次预检，核对运行中的 REPORT、DEBUG=0 和签名度量，再运行 E1–E8、生成汇总及 SHA256SUMS 并校验。E1–E6 按点读取已有 metrics.json；发现无效点会报告失败。E7、E8 按整项续跑，中断的目录改名为 `.partial.*` 保存。完整硬件批次按计划预留约 3 小时，其中 E1 约 27 分钟，E2 约 21 分钟，E3–E6 共约 17 分钟，E7–E8 共约 15 分钟。下载与编译用时取决于机器和缓存。

逐项执行时使用以下命令。预检、E7、E8 均要求新的输出目录。

```bash
sudo bash "$S/check-host.sh" "$batch/preflight" --build "$B"
sudo bash "$S/check-host.sh" "$batch/preflight-probe" --build "$M"
sudo python3 "$S/bench.py" all --package "$P" --build "$B" --live "$L" --out "$batch"
sudo python3 "$S/memory-bench.py" --package "$P" --build "$M" --out "$batch/e7"
sudo python3 "$S/replay-bench.py" --package "$P" --build "$B" --out "$batch/e8"
sudo python3 "$S/summarize.py" "$batch"
(cd "$batch" && sudo bash -c 'set -eo pipefail; find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum > SHA256SUMS; sha256sum --quiet -c SHA256SUMS')
```

## 命令参数

| 入口 | 参数与用时 |
| --- | --- |
| `bash run-all.sh PACKAGE BUILD LIVE PROBE_BUILD BATCH` | 以 root 顺序运行硬件批次 |
| `bash check-host.sh OUTDIR [--build DIR] [--sim]` | 本批传构建目录；每次启动一个短回放 |
| `python3 bench.py {all,e1,e2,e3,e4,e5,e6} --package P --build B --live L --out BATCH [--duration SEC] [--configs S1,S4] [--sim] [--dry-run]` | 默认每点 30 秒，另有启动和排空；dry-run 打印点位 |
| `python3 memory-bench.py --package P --build M --out NEW [--sim] [--quick]` | RAVEN 两种输入各 100 万事件，Zeek 按会话数结束；quick 缩小输入和 RAVEN 回收阈值供冒烟 |
| `python3 replay-bench.py --package P --build B --out NEW [--sim] [--quick]` | 正式档位 60、3 万、10 万、30 万、60 万；quick 用小档位执行相同回放路径 |
| `python3 summarize.py BATCH` | 读取已完成的点，生成表格，通常数秒 |
| `falco-load RATE SECONDS OUT.json` | 每秒 open/close 对数；0 表示不限速，运行 SECONDS 秒 |
| `tcp-load RATE SECONDS OUT.json [--port P] [--sources N]` | 每秒 TCP 短连接数，0 表示不限速；默认端口 18080、256 个回环源地址 |
| `python3 http-load.py serve` | 输出本地端口，持续到终止 |
| `python3 http-load.py client PORT SECONDS OUT [--rate R] [--gate]` | 每条连接每秒 R 个请求，默认不限速；gate 等标准输入放行 |
| `httpd LABEL_PREFIX INTERVAL_SECONDS DURATION_SECONDS [--gate]` | http-marker.c 的可执行文件名必须是 httpd；由 nobody 用户按间隔运行标记 |
| `python3 zeek-sessions.py --out NEW.pcap` | 生成 1,180,016 个合成包，耗时随磁盘和 CPU 而异 |

bench.py 自动用 `cc -O2` 编译 falco-load 和 httpd，用 `cc -O2 -pthread` 编译 tcp-load。Simulation 冒烟在各测量入口加 `--sim`，E1–E6 缩短 `--duration`，E7/E8 加 `--quick`，使用仓库外独立目录。
