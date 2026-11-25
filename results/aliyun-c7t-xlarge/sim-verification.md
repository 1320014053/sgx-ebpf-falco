# c7t.xlarge 脚本的 SGX Simulation 冒烟

2026-11-25。WHPX 客体从启动到关机约 18 分钟。E1–E6 共运行 61 个点，每点 5 秒，八种配置全部启动。E7 和 E8 只跑缩小输入。以下数据用于验收脚本。

## 环境和源码

Windows 宿主启动一台 QEMU，使用 `-accel whpx,kernel-irqchip=off -machine q35 -cpu max -smp 4 -m 5120`。系统盘使用新的 qcow2 覆盖盘，以 `sgx-ebpf-sim.qcow2` 为 backing file。客体 Ubuntu 22.04.5、`5.15.0-198-generic`、4 KiB 页，BTF 可读，BPF ring map 创建成功。SSH 为 `poc@127.0.0.1:2222`，使用 `StrictHostKeyChecking=yes` 和 `工作区（仓库外）的 vm\runtime\known_hosts.target`。首次使用旧主机记录时 SSH 在认证前拒绝连接；核对指定文件的 ED25519 指纹后重新连接。

基线提交为 `13d592774b6375884b5fd831d1c9ff2d08ad7d6a`，构建和测试包含 Windows 工作树的未提交改动。两次完整归档均按 `git ls-files -co --exclude-standard` 收集，在客体核对 SHA-256 后解压。

| 文件 | SHA-256 |
| --- | --- |
| 首次构建的源码归档 | `8f7ff49d8688236476b99064ce0d5dd92e17466bf5d0585b99b204d24a39bd0f` |
| 最后一次测试的源码归档，生成于本记录之前 | `21ea35e076d57eda08b69fc53f7106185fad80c36309ae6b77b48c1bc563f8de` |
| 普通 Simulation 签名镜像 | `1305cccb202044ac4d3a00c3bfb5c7ac5a099cb3804e25581c3958d425c3de72` |
| E7 探针 Simulation 签名镜像 | `a52171d570a90cfd6505414f24e8c079c277ec3031a37efb0175a69e2c0360a9` |

最终归档中的 Falco 源目录与构建时逐文件比较，只有 `live/verification.md` 的记录发生变化。现场脚本与现场短测时逐文件比较，变化在离线回放和 PCAP 生成脚本。E7、E8 和独立 PCAP 生成命令从最终归档重新运行。

## 命令

以下命令中的 R 为客体新解压的仓库目录，V 为仓库内新建的 smoke 目录。两次源码位于不同目录时，最后的 E7、E8 和汇总命令通过 S 选用最终归档的脚本。

```bash
cd "$R/poc"
S=$R/results/aliyun-c7t-xlarge/scripts
B=$PWD/build-falco; L=$PWD/build-falco-live; D=$B/deps; P=$D/package
M=$R/probe/poc/build-falco; V=$R/smoke; mkdir -p "$V"
export CC=clang CXX=clang++
opts=(-G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS_RELEASE=-O1 -DCMAKE_CXX_FLAGS_RELEASE=-O1)
bash falco/fetch.sh "$D"
mkdir -p "$D/bpftool"
curl -fsSL https://github.com/libbpf/bpftool/releases/download/v7.5.0/bpftool-v7.5.0-amd64.tar.gz |
    tar -xz -C "$D/bpftool" bpftool
chmod u+x "$D/bpftool/bpftool"
cmake -S falco -B "$B" "${opts[@]}" && cmake --build "$B" --parallel 2
cmake -S falco/live -B "$L" "${opts[@]}" -DMODERN_BPFTOOL_EXE="$D/bpftool/bpftool"
cmake --build "$L" --parallel 2
mkdir -p "$R/probe/poc"; cp -a falco "$R/probe/poc/"
(cd "$R/probe" && git apply --directory=poc/falco "$S/memory-probe.patch")
cmake -S "$R/probe/poc/falco" -B "$M" "${opts[@]}" -DDEPS="$D"
cmake --build "$M" --parallel 2

unset FALCO_LIVE_STATS_MS
bash falco/live/check.sh --strict "$P" "$B" "$L" "$V/strict-live"
bash falco/live/check-ring.sh --strict "$P" "$B" "$L" "$V/strict-ring"
python3 falco/live/check-detectors.py --strict "$P" "$B" "$L" "$V/strict-detectors"
sudo bash "$S/check-host.sh" "$V/preflight" --build "$B" --sim

args=(--sim --duration 5 --package "$P" --build "$B" --live "$L" --out "$V/batch")
sudo python3 "$S/bench.py" e1 "${args[@]}" --configs N1,S1,S4
sudo python3 "$S/bench.py" e2 "${args[@]}" --configs S1,S3
for e in e3 e4 e5 e6; do sudo python3 "$S/bench.py" "$e" "${args[@]}"; done
sudo python3 "$S/bench.py" e6 "${args[@]}"
sudo python3 "$S/summarize.py" "$V/batch"
python3 "$S/memory-bench.py" --package "$P" --build "$M" --out "$V/e7-final" --sim --quick
python3 "$S/replay-bench.py" --package "$P" --build "$B" --out "$V/e8-final" --sim --quick
python3 "$S/zeek-sessions.py" --out "$V/standalone.pcap"
```

线程名检查在 `strict-detectors/recorded` 目录中，以 root 启动以下采集命令。第一次带 `-- /bin/sleep 5`，该入口按工作负载退出，没有 `capture_ready` 行，未及时读到线程名。改用下列持续采集入口，等 `capture_ready` 后读取 `/proc/$pid/task/*/comm`，约 5 秒后发送 SIGTERM 并等待退出。

```bash
FALCO_LIVE_STATS_MS=1000 "$L/falco-live" "$B/falco-enclave.signed" live.yaml 8192 - falco_rules.yaml raven_zeek_rules.yaml
```

## 结果

| 步骤 | 用时 | 验收结果 |
| --- | ---: | --- |
| 构建 | 5 分 21 秒，含 bpftool 下载 | Clang、Ninja、Release、-O1。普通与探针构建均生成 falco-sgx、签名 enclave、libraven_zeek.so；现场宿主和 BPF 探针构建成功。原生侧使用 fetch.sh 核过哈希的 Falco 0.45.2 发行包 |
| 严格回归 | 3.29、1.18、17.10 秒 | 三项退出 0。默认关闭统计时，日志中没有周期 tick |
| 1 秒 tick 与线程名 | 5 秒窗口 | 四个 fl-* 线程名齐全。周期样本间隔 0.999–1.000 秒，另有停采末条。末条与 modern_ebpf 的驱动事件、驱动丢失、报文提交和丢失均相等 |
| 预检 | 一次夹具回放 | pass=true，falco_exit=0，errors 为空。硬件检查标为 sim |
| E1 | 4 分 3 秒 | N1、S1、S4 各 8 点，校准、不限速、二分路径均运行，24/24 有效 |
| E2 | 1 分 27 秒 | S1、S3 各 6 点，12/12 有效。S1 报文为零。S3 各点收到 50,046–271,394 个报文，检测器告警全部为零 |
| E3 | 43 秒 | 两种等待策略各 3 点，6/6 有效；实际产生的 298 个标记全部配对 |
| E4 | 41 秒 | B0、N1、S1–S4，6/6 有效。每配置完成 23,863–29,480 个 HTTP 请求 |
| E5 | 63 秒 | 7/7 有效。每配置配对 100/100，S1 的 100 次告警刷新在 S1-buf 中合并为 5 次 |
| E6 | 47 秒 | 6/6 有效。S1 有 219 次睡眠 OCALL，S1-spin 为 0；采集线程分别约占单核 0.4% 和 99.9% |
| 续跑与汇总 | 0.04 秒、1.10 秒 | 同目录再次调用 E6 跳过六点。前后 61 份 metrics.json 的路径和修改时间完全相同。六张逐点 CSV 的行数与指标数一致，另有两张边界表、六张图 |
| E7 | 6.79 秒 | RAVEN 两类输入各 4 万条，原生与 SGX 每组各 4 条告警，归一化摘要相同。repeat 与 churn 各回收 523 和 906 次。Zeek 58,016 包、零告警，超时后连接数为 0，SGX 可信堆从峰值 11,116,544 字节降至 6,063,904 字节 |
| E8 | 5.76 秒 | 60、300、600、3000、6000 条分别产生 2、10、20、100、200 条告警，两侧摘要相同。3000 条另测原生文件和 /dev/null。旧夹具 287 个事件、92 个包，两侧均有 5 条告警，检测结果与归档现场一致 |
| 独立 PCAP 入口 | 1.67 秒 | 默认生成 66,080,728 字节，未使用该文件做全量测量 |

逐点读回 SGX 的 metrics.json、ticks.jsonl 和 stderr.log。启用 RAVEN 时选 80 个系统调用，其余选 72 个；检测器标志与配置吻合。各项 errors、trace_bytes、format_rejected 为零，停止后游标相等。每点 CPU 采样覆盖五秒，fl-ingest、fl-analysis、fl-writer 均有独立字段，只有启用检测器的配置出现 fl-detect。每点最后四项 tick 计数与 modern_ebpf 对齐。

## 修复和验证边界

- E8 先前在归档输入缺失时写出 skipped，并能以成功状态结束；包装脚本会把 E8 标为完成。现改为报缺失文件并失败。临时空目录反例及完整夹具的正例均通过。
- 为缩短验证，E7、E8 增加 `--quick`。E7 按短输入的实际事件数检查次数与摘要，把 RAVEN 历史高水位降为 1 MiB，使短输入也能验证回收。PCAP 生成器按传入的会话数构造流量。正式入口仍使用原事件数、会话数与内存阈值。
- 在同一客体用阶段替身核对 run-all.sh 的调用、两次续跑、残留目录保留和 SHA256SUMS 校验；随后以实际脚本和产物运行硬件入口，按预期在硬件预检处退出。
- 本轮没有验证真实 SGX、DEBUG=0、EPC、云实例性能、正式 30 秒档位、E7 百万事件的稳定性、E8 正式大档位或硬件批次包装脚本的成功路径。

客体删除本轮测试根目录（含构建和输入），确认目录消失后执行 `sudo -n poweroff`。串口以 `reboot: Power down` 结束，宿主确认 PID 10540 已退出、2222 无监听，删除本轮覆盖盘、归档和串口日志。基础盘启动前与清理后大小均为 20,119,224,320 字节，修改时间均为 2026-11-25 10:39:41 UTC。
