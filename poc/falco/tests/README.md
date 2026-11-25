# Falco 回归测试

从 `poc/` 目录运行以下命令。先按 [Falco 构建说明](../README.md) 构建普通插件和签名 enclave，运行 `replay.sh` 得到 `build-falco/offline-run`。原版参考通过 `upstream/check-reference.py` 生成在 `build-falco/native-run`。

## 普通 Falco 和签名 enclave 对照

`plugin/check.py` 的默认套件检查两个入口的有序告警、原版规则和错误返回。下面的示例运行 45 组历史行为对照。每次运行使用新的输出目录。需要生成上游结果的套件使用锁定的 RAVEN 源码、Python 依赖和 Zeek 镜像。

```bash
export PYTHONPATH="$(realpath build-falco/deps/raven)" PYTHONHASHSEED=0 TZ=UTC
python3 -B falco/plugin/check.py build-falco/deps/package build-falco \
    build-falco/offline-run build-falco/native-run build-falco/behavior-run \
    --behavior-review falco/tests/fixtures/behavior.json
```

| 专项参数 | 清单 | 检查内容 |
| --- | --- | --- |
| `--behavior-review` | [behavior.json](fixtures/behavior.json) | 45 组固定输入、上游输出与历史窗口行为 |
| `--parity-audit` | [parity-audit.json](fixtures/parity-audit.json) | 8 份归档输入，以及组合输入、错误处理等对照 |
| `--structure-review` | [structure.json](fixtures/structure.json) | 23 组字段、报文时间及 PCAPNG 结构用例 |
| `--lifecycle-review` | [lifecycle.json](fixtures/lifecycle.json) | 19 份归档输入，以及定时器与名称边界对照 |

各清单共用 [regression.zip](fixtures/regression.zip)。包中存放测试输入与参考输出，每份清单记录包的 SHA-256 和原始审查包的指纹。两个入口依赖同一份输入时直接引用相同的成员。

## 历史独立用例

这些用例来自早先的审查与复测。原有套件已覆盖的相同输入和运行方式已去重。对同一抓包，文件解码和逐 IP 包接口可以各有断言。比较使用完整有序记录，并核对流式输出中初始告警与后续更新的 ID 关系。[用例、上游预期和来源](fixtures/history.json)

普通 C++ 检测器可以单独回放文件、事件流和逐包输入。

```bash
cmake --build build-falco --target replay-detector
python3 -B falco/tests/check-history.py detector build-falco/bin/replay-detector
```

如只需运行这组离线用例，可用 C++17 编译器及 nlohmann/json 3.11.3 直接链接同一套源码。以下命令使用 `fetch.sh` 的头文件目录，已安装该头文件的 Linux 系统也可使用系统包含路径。

```bash
mkdir -p build
c++ -std=c++17 -O1 -Ifalco/plugin -Ibuild-falco/deps/njson/single_include \
    falco/tests/replay-detector.cpp falco/plugin/{raven,graph,zeek}.cpp -o build/replay-detector
python3 -B falco/tests/check-history.py detector build/replay-detector
```

同一份状态探针也可单独检查 TCP 会话到期和 Notice 抑制表。下面第一轮的两个采样点应依次得到 `49001 1 1` 和 `49002 1 0`。第二轮同时核对抑制表和到期队列。[Zeek 会话参考探针](../upstream/check-sessions.zeek) · [Zeek 抑制表参考探针](../upstream/check-suppression.zeek)

```bash
mkdir -p build
c++ -std=c++17 -O1 -Ibuild-falco/deps/njson/single_include \
    falco/plugin/check-suppression.cpp -o build/check-zeek-state
unzip -p falco/tests/fixtures/regression.zip inputs/idle-service-sessions.pcap > build/sessions.pcap
unzip -p falco/tests/fixtures/regression.zip inputs/suppression-expiry.pcap > build/suppression.pcap
build/check-zeek-state --sessions build/sessions.pcap
build/check-zeek-state build/suppression.pcap
```

签名 enclave 的 ring 套件共回放 17 次。8 组归档输入先后在双检测器配置和对应的单检测器配置下各运行一次。4 组 RAVEN 用例逐条比较翻译后的事件、告警和检测 ID 的引用关系。4 组 Zeek 用例逐条比较完整 Notice，包括时间戳、顺序和空结果。单检测器配置从 `plugin/live.yaml` 派生，并核对 enclave 报告的检测器开关。每轮都检查 ring 读指针排空，加 `--strict` 可要求各阶段的恢复错误计数均为零。

额外一轮 `timer-queue-30-syscall-tick/zeek-only` 专门检查 syscall 推进 TCP 超时。原始 `timer-queue` 输入只有报文，报文本身会推进 Zeek 时钟。这个派生用例保留 `timer-queue-30` 的 45 个 SYN，将末尾三个 ACK 换成一条时间为 `1700000008` 的归档 execve，并把结束 tick 设为 `1700000010`。它复用原用例的完整 Notice 预期。如果跳过 syscall tick，EOF 才会结算扫描，`ordered alerts[0].ts` 会得到 `1700000010`，预期为 `1700000008`。

```bash
cmake --build build-falco-live --target replay-ring
python3 -B falco/tests/check-history.py ring build-falco-live/replay-ring \
    build-falco/falco-enclave.signed build-falco/deps/package/etc/falco/falco_rules.yaml
```

历史用例以固定上游为预期。有差异时会列出用例名、运行入口和首项差异，最后返回非零。`previously differed` 表示该用例在原审查中也出现过差异。最近的实测计数见 [验收记录](../../../results/falco/acceptance.md)。

## 实时 ring 与错误恢复

在 `poc/` 下执行。单元测试使用 memfd 的双重映射。故障注入测试使用同一份规则和输入，逐条核对剩余告警、错误计数、诊断限速和错误预算。测试镜像使用独立的签名文件名。

```bash
cmake --build build-falco --target bpf-ring-test
build-falco/bin/bpf-ring-test
cmake -S falco -B build-falco -DFALCO_SGX_FAULT_INJECTION=ON
cmake --build build-falco --target sign-falco-fault
cmake --build build-falco-live --target falco-ring-test replay-ring
python3 -B falco/tests/check-faults.py build-falco-live build-falco/falco-fault-enclave.signed \
    build-falco/deps/package/etc/falco/falco_rules.yaml
```

RAVEN 微基准生成 0、10、100、1000 条可复核链。`--profile` 单独计时背景文件事件，并报告复核、判定和祖先查询次数。整轮吞吐还包括构造与匹配这些链的时间。

```bash
cmake --build build-falco --target replay-detector
python3 -B falco/bench/review-throughput.py build-falco/bin/replay-detector --profile
```

双来源并发探针使用普通 Linux 进程和项目固定的引擎及 libs。它按实时分析线程和检测线程的分工运行两个线程，共用同一个引擎和格式化器。系统调用线程用 raw-block inspector 把 `fixture.py` 生成的事件块读 100 轮；raven_zeek 线程用静态链接的插件反复读取归档的 RAVEN 事件流，直到系统调用线程结束。两个线程都完成读取、匹配和格式化，探针要求每一轮都产生告警。

```bash
CC=clang CXX=clang++ cmake -S falco/tests/tsan -B build-tsan -G Ninja
cmake --build build-tsan --target engine-concurrency
mkdir -p build-tsan/input
(cd build-tsan/input && python3 ../../falco/fixture.py)
unzip -p falco/tests/fixtures/regression.zip history/inputs/live-recorded.jsonl > build-tsan/input/raven.jsonl
TSAN_OPTIONS=halt_on_error=1 build-tsan/bin/engine-concurrency build-tsan/input/reference.scap \
    build-tsan/input/raven.jsonl
```

混合来源测试把官方规则的进程快照、httpd 启动 shell 的系统调用和历史扫描报文放入同一个 ring。它使用单分析线程原版的完整告警摘要，核对每项内容的出现次数及两个来源各自的顺序，保留 RAVEN 检测 ID 的引用关系。

```bash
python3 -B falco/tests/check-source-order.py build-falco-live/replay-ring \
    build-falco/falco-enclave.signed build-falco/deps/package/etc/falco/falco_rules.yaml
```
