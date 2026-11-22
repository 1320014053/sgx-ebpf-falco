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

签名 enclave 的 8 组回放使用归档的进程快照和 ring 记录。测试检查读指针排空、翻译后的事件及输出告警。

```bash
cmake --build build-falco-live --target replay-ring
python3 -B falco/tests/check-history.py ring build-falco-live/replay-ring \
    build-falco/falco-enclave.signed build-falco/deps/package/etc/falco/falco_rules.yaml
```

历史用例以固定上游为预期。有差异时会列出用例名、运行入口和首项差异，最后返回非零。`previously differed` 表示该用例在原审查中也出现过差异。最近的实测计数见 [验收记录](../../../results/falco/acceptance.md)。
