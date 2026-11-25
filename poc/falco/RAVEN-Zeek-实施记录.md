# RAVEN 和 Zeek 的 Falco 插件

目标是让普通 Falco 动态加载一个 `raven_zeek` 插件，并将同一份 C++ 源码静态编入项目现有的 `falco-enclave.signed`。插件接收事件和报文，独立生成检测结果。上游程序用于离线对照测试。

## 实施步骤

1. 固定 RAVEN 提交 `3b5fbf5f33e2d1287d3ff0f546023106f787a92e` 的默认 `full` 模式和 Zeek 6.0.9 提交 `7a7864f89297e0fc3f3779ec2f8dc5100d8449c0` 的 `policy/misc/scan.zeek`。核对输入格式、默认规则、结果字段和顺序。[RAVEN](https://github.com/Arthurs011/raven/tree/3b5fbf5f33e2d1287d3ff0f546023106f787a92e) · [Zeek](https://github.com/zeek/zeek/blob/7a7864f89297e0fc3f3779ec2f8dc5100d8449c0/scripts/policy/misc/scan.zeek)
2. 在插件里实现 RAVEN 的 JSONL 和 Tetragon 输入、进程关系、七条有序规则、风险分解、事件图和上下文结算。
3. 在插件里解析双向 TCP 报文，实现 Zeek 的失败连接判定、两个去重统计、统计周期和 Notice 抑制。
4. 将两套逻辑注册为同一个 Falco 事件源，用 Falco 规则逐条输出命中。普通态插件读取指定的回放文件，enclave 从已有宿主接收原始字节。
5. 删除原先的运行时镜像、Wasm 桥接和单独签名目标，保留独立参考测试。
6. 构建共享插件和同一个签名 enclave，用相同输入对照普通 Falco、SGX Simulation 和上游结果。核对官方 syscall 规则回归、上下文过滤、空输入和边界样例。
7. 保存对照摘要和复现命令，清理验证快照及临时构建产物。在下文单独注明验证范围。

## 实时输入

现场配置为 `plugin/live.yaml`。启用 RAVEN 时，enclave 将 syscall 翻译为执行、进程关系、文件、身份和连接事件。官方 syscall 规则在各组合下都运行。启用 Zeek 时，报文探针复用 Falco 所有 CPU 共用的 ring map。一条消费游标同时接收 syscall 和带类型标记的 IP 报文，enclave 先把载荷复制到私有内存，再校验和分发。报文推进 Zeek 的连接状态，空闲期间的时钟也会推进无响应连接的超时。每批命中在工作负载运行期间输出。RAVEN 的初次命中和后续良性上下文更新使用同一检测 ID。[现场消费](trusted/enclave.cpp) · [系统调用映射](trusted/raven_syscalls.cpp) · [报文探针](live/packet_tap.bpf.c)

JSONL 和 PCAP 是可选录制。两个检测器都开启时，现场验收让工作负载持有回环测试端口，等到外部进程实际读到 `server_spawns_shell`、`Scan::Address_Scan` 和 `Scan::Port_Scan` 后才允许退出。Ubuntu 22.04、Linux 5.15.0-198 和 SGX Simulation 的常驻运行从同一个 map 收到 7,953 条 syscall 和 92 条报文，未录制输入。SIGTERM 停采后读写游标一致。开启录制的独立运行收到 7,890 条 syscall 和 92 条报文。两次的驱动丢失、报文丢失和格式拒绝计数均为 0。普通 Falco 与 enclave 回放后，RAVEN 的证据事件、风险分解和最终状态，以及 Zeek Notice 的各字段均与现场一致。[验收程序](live/check-detectors.py) · [实时验证记录](../../results/falco/raven-zeek-plugin/live-ring.json)

RAVEN 映射跳过采集宿主自身的文件写入，以免一条测试录制再产生下一条输入。原版 syscall 检测仍消费这些 ring 记录。RAVEN 的 `full` 证据图按采集会话积累，以上实测覆盖现场功能和回放一致性，长期内存占用尚待测量。

## 文件回放与早期联合验证

普通 Falco 动态加载 `lib/libraven_zeek.so`。enclave 在创建 Falco 引擎时注册同一份插件的静态 API 表，为 `syscall` 和 `raven_zeek` 分别创建事件源。离线宿主先回放 syscall，再通过同一个 enclave 句柄传入 JSONL 和 PCAP。EDL 将两个缓冲区复制到可信内存，插件从这些字节建立进程树和 TCP 连接状态。每个命中经插件的 `next_batch` 进入 Falco 引擎，由独立 YAML 输出。Falco 的外层 JSON 使用项目的规则名和优先级，上游记录中的规则名、风险、严重等级及证据位于 `output_fields["rz.result"]`。[插件入口](plugin/plugin.cpp) · [可信入口](trusted/enclave.cpp) · [输出规则](plugin/rules.yaml)

RAVEN 按输入顺序推进匹配。截止时间包含等号，七条规则使用各自的窗口、进程关系和事件条件。同一规则按证据事件 ID 集合去重，原始风险项按进程与原因去重。命中时保留图中的节点和边，后续事件可以更新这些节点及边上的事件 ID。回放结束时再次结算良性上下文，`context_filtered` 会作为单独的信息记录输出。[关联与评分](plugin/raven.cpp) · [证据图](plugin/graph.cpp)

Zeek 侧接收实际的双向报文。地址扫描按“发起地址、目标端口”统计不同目标地址，默认阈值 25。端口扫描按“发起地址、目标地址”统计不同端口，默认阈值 15。两者的统计周期均为 5 分钟，同一发起地址、同一 Notice 类型的抑制期为 1 小时。代码处理 SYN、SYN-ACK、拒绝、复位、已传输数据、超时与回放结束时的待定连接，保留 Notice 的时间、地址、端口、消息和动作。[报文与统计实现](plugin/zeek.cpp)

## 对照方法

在项目的 Ubuntu 客体中用固定上游生成独立的 JSONL 与 `notice.log`，再让正式的 Falco 0.45.2 发行包和签名的 SGX Simulation enclave 读取原始输入。JSON 对象按键比较，数值按值比较。比较保留记录顺序、重复次数、时间、风险分解、证据事件、叙述文本、图的节点与边，以及 Notice 所有字段。RAVEN 每次运行生成新的 UUID，对照脚本校验格式和唯一性，统一生成的 ID 并在图里使用同一映射。输入自带的事件 ID 逐字比较。`rule_source` 只统一安装目录前缀。两端 Falco 外层告警另作比较，syscall 告警与普通态官方规则基线逐条比较。[独立参考入口](upstream/check-reference.py) · [双端验收](plugin/check.py)

复现时先按 [构建说明](README.md) 准备 `build-falco/deps/package`、`build-falco/offline-run` 和签名映像。在 `poc/` 下运行以下命令。现场用例需要先构建 Modern eBPF 宿主，并以能在客体中执行 `sudo -n` 的普通用户运行。

```bash
bash falco/upstream/fetch-raven.sh build-falco/deps/raven
TZ=UTC PYTHONPATH="$(realpath build-falco/deps/raven)" \
  python3 -B falco/upstream/check-reference.py build-falco/native-run
python3 -B falco/plugin/check.py build-falco/deps/package build-falco \
  build-falco/offline-run build-falco/native-run build-falco/plugin-comparison \
  --live-build build-falco-live
```

这轮文件对照使用固定上游的默认配置和 UTC。RAVEN 的自定义规则目录、其他检测层级以及 Zeek 的自定义脚本和站点配置超出此次移植范围。Zeek 侧覆盖指定扫描策略所需的 IP/TCP 处理，隧道内层协议及任意畸形流量的行为等价性仍待验证。当时的现场联合测试在 ring 排空后回放独立文件。实时入口的验证见上节。

## 已验证的规则行为

| 输入 | 原版结果及插件对照 |
|---|---|
| RAVEN A–G、idle | 活动命中依次为 1、1、1、3、1、3、0、0。G 另有 1 条上下文过滤记录 |
| RAVEN 边界输入 | 6 条活动命中及 1 条上下文过滤记录。覆盖恰好 60 秒、超窗、错误父进程、同一 PID、后代和重复事件 ID |
| Tetragon 适配 | 用两份原始导出覆盖进程执行、退出、克隆、连接、监听和文件探针。命令参数的拆分覆盖 ASCII 空格、制表符及 Unicode 空格 |
| Zeek 基准 PCAP | 原版记录 90 条连接，输出 1 条地址扫描及 1 条端口扫描。比较包括消息正文、时间和抑制字段 |
| TCP 状态及统计周期 | 已建立连接、复位、无响应、5 分钟周期切换和 1 小时抑制到期分别与原版同输入对照 |
| 其他报文输入 | 反向 SYN-ACK 后结束回放、IPv6 加 VLAN、乱序 IPv4 分片和带时间精度选项的 PCAPNG 都各产生 1 条端口扫描 Notice |

对场景 F 的普通态和 enclave 回放分别跟踪了 `execve` 和 `execveat`。普通态记录了 `falco`，enclave 侧记录了 `falco-sgx`，两条路径各启动一个程序。可信 ELF 的符号表中同时包含 `raven_zeek_api`、`rz::raven` 和 `rz::zeek`。

逐字段检查曾定位到两处差异。场景 D 中，上游证据图的进程节点随下一事件更新，插件最初冻结了节点时间。修正后，图中保留命中时的成员及上游会更新的字段。混合 Tetragon 输入中，enclave 的标准流把 `service test` 读为一个参数。插件现在显式采用 Python `str.split()` 的 Unicode 空白集合，在两侧执行相同的拆分逻辑。

## 文件回放版本的验收记录

2026-11-21 在 x86_64 QEMU 的 Ubuntu 22.04 中完成 20 组验证，使用 Falco 0.45.2 和 Open Enclave SGX Simulation 的最终签名映像。

| 验证 | 实测结果 |
|---|---|
| 17 组有效离线输入 | 普通 Falco 与 enclave 均通过逐字段对照。空输入产生 0 条插件记录。场景 F 在两端均得到 3 条 RAVEN 活动告警、2 条 Zeek Notice 和 2 条官方 syscall 告警。[逐组结果](../../results/falco/raven-zeek-plugin/comparison.json) · [场景 F 的 enclave 原始输出](../../results/falco/raven-zeek-plugin/F-enclave.jsonl) |
| 2 组损坏输入 | 对格式错误的 JSONL 和截断的 PCAP，两端均以错误状态退出，分别报告 RAVEN 输入的行号和截断的 PCAP 报文头。[错误结果](../../results/falco/raven-zeek-plugin/comparison.json) |
| 1 组现场联合验证 | 同一 enclave 接收全部 13,440 条 Modern eBPF ring 记录，驱动丢失、ring 丢弃及格式拒绝均为 0。现场 syscall 触发 1 条官方告警，随后在同一 enclave 回放场景 F 的 JSONL 与 PCAP，输出 3 条 RAVEN 和 2 条 Zeek 告警。[现场计数与构建标识](../../results/falco/raven-zeek-plugin/build-and-live.json) |

官方规则单独回归时加载并启用 25 条规则，2 条 `Run shell untrusted` 与普通态基线一致。联合配置启用这 25 条和插件的 4 条输出规则。已核对最终签名映像和共享库的 SHA-256、工作区 6 个 C++ 源码及头文件和插件规则的 SHA-256，并保存两条完整回放命令的内核进程执行跟踪。[构建与回归记录](../../results/falco/raven-zeek-plugin/build-and-live.json)

验收结果归档后，已关闭本次 QEMU，清理一次性写时复制快照、下载缓存和临时构建产物。

## 2026-11-21 原版差异复测

上次复查留下了 10 份离线输入的 SHA-256。回归脚本现在按原始字节重建这 10 份输入，每次运行先校验哈希，再用固定提交的 RAVEN 和 Zeek 6.0.9 生成期望结果。普通 Falco 和签名 enclave 分别对照完整、有序的检测记录。比较时归一化自动生成的 ID 和规则安装路径。对拒绝的输入，同时检查退出码、出错的时间字符串和插件告警数。[初次复查](tests/fixtures/upstream-parity-review.json) · [原版回放](upstream/check-reference.py) · [Falco 回放](plugin/check.py)

RAVEN 的数字目标用户 `1001` 在证据图中生成 `user:1001`。时间戳 `1700000000.9999998` 的 UTC 时间线显示 `22:13:21`。固定版本的 Tetragon 适配器要求时间能完整转换为数字，RFC 3339 样本的预期行为是退出码 1、零条插件告警。[证据图](plugin/graph.cpp) · [时间处理](plugin/raven.cpp)

Zeek 用 SYN-ACK 的确认号辨认随后到达的 SYN，15 条乱序成功握手产生零条 Notice。PPP Serial 的正常握手也产生零条，带告警的 IPv4、IPv6 和 MPLS 对照验证了实际解包。纳秒报文先依原版捕获精度截到微秒，再推进检测时间。[报文处理](plugin/zeek.cpp)

原版 Notice 框架在一小时抑制期满后的表清理定时器上删除条目。复测用同一份 PCAP 在六个时点读取原版和共享 C++ 实现，两侧有效条目数依次是 `2 → 2 → 1 → 0 → 1 → 0`，C++ 到期队列大小也逐次相同。第 3603 秒保留两条，第 3690 秒只剩一条。原版的无探针回放与带探针回放输出相同的三条 Notice。[Zeek 读表探针](upstream/check-suppression.zeek) · [C++ 读表探针](plugin/check-suppression.cpp)

普通 Falco 0.45.2 和签名 enclave（SGX Simulation）在原批次上均由 4/10 提高到 10/10。包含原批次在内，共 34 组离线回归通过。逐组记录保留输入哈希、三方有序告警的摘要、错误退出和最终构建指纹。[复测结果](../../results/falco/raven-zeek-plugin/upstream-parity-fixed.json)

上次的现场控制仅保留了输入哈希。本次重新录制同一项成功的回环连接工作负载，得到 144 条 RAVEN 事件和 8 条报文。现场检测与原版 RAVEN 的两个活动告警快照一致，原版 Zeek 和插件均为零条 Notice。普通 Falco 和 enclave 回放本次录制也与原版最终结果一致。[本次现场原始输入清单](tests/fixtures/behavior.json)

## RAVEN 完整证据的容量测量

用同文件重复访问和持续产生新进程、新路径两种负载，各回放 10 万条事件。普通 Falco 与签名 enclave 的逐万条内存增量、全程峰值、最大单条告警和旧证据存储判断见[容量报告](../../results/falco/raven-zeek-plugin/memory-benchmark.md)。

## 45 组归档输入的双端回放

归档中有 20 份 RAVEN 输入和 25 份 Zeek 抓包。验收脚本核对压缩包和每份输入的 SHA-256，然后分别运行固定原版、普通 Falco 和签名 enclave。比较包括进程退出码和每条完整告警的顺序及字段。对 601 秒重投这一例，两端还须逐字段匹配修复前归档的两条告警，包括证据图和回收标记。[原始输入和对照清单](tests/fixtures/behavior.json) · [去重边界](RAVEN-历史回收.md)

在 Ubuntu 22.04 的同一份输入上，普通 Falco 0.45.2 和签名 SGX Simulation enclave 的 RAVEN 均有 19/20 组与原版一致，Zeek 均为 25/25。唯一差异是 601 秒后重投的 RAVEN 告警。原有 34 组回归两端均全部通过。[逐例结果和构建指纹](../../results/falco/raven-zeek-plugin/behavior-parity-fixed.json)

在 `poc/` 下用新的输出目录运行。三次 Python 调用依次生成原版参考数据、重跑 34 组回归、验证 45 组归档输入。

```bash
export TZ=UTC PYTHONPATH="$(realpath build-falco/deps/raven)"
python3 -B falco/upstream/check-reference.py build-falco/refs-new
python3 -B falco/plugin/check.py build-falco/deps/package build-falco build-falco/offline-run \
  build-falco/refs-new build-falco/regression-34
python3 -B falco/plugin/check.py build-falco/deps/package build-falco build-falco/offline-run \
  build-falco/refs-new build-falco/review-45 --behavior-review ../results/falco/raven-zeek-plugin/behavior-review.json
```

## 五项离线回放修复的验收

2026-11-22，普通 Falco 和签名 SGX Simulation 均通过 27 组专项回放。联合回放分别损坏 JSONL 和 PCAP 时，健康一侧的完整告警先交付，进程随后报告对应输入并返回 1。其余样本覆盖以太网 PPPoE、Tetragon 连接和监听端口、经典 PCAP 2.3 的两种长度顺序，以及交互服务的连接回收。连接表实测中，SSH 和 HTTP 在第 20 秒都存在，第 420 秒仅 SSH 仍在。620 秒的维护样本按项目的历史回收设计产生一条活动告警。[逐例结果](../../results/falco/raven-zeek-plugin/parity-fixes-2026-11-22.json)

生成上一节的原版参考数据后，在 `poc/` 下运行专项回归。

```bash
python3 -B falco/plugin/check.py build-falco/deps/package build-falco build-falco/offline-run \
  build-falco/refs-new build-falco/audit-27 --parity-audit ../results/falco/raven-zeek-plugin/parity-audit-2026-11-21.json
```

## 首次 UID 切换、抓包截断和空镜像字段

2026-11-22，在 QEMU 的签名 SGX Simulation 中，两个已在启动快照里的进程分别从有效 UID 0 切换到 1000。第一条记录就切换的进程和先执行一次同 UID 调用的进程各触发一条 `privilege_change_chain`。现场告警逐字段对照原版 RAVEN 的 `on_event()` 返回值，文件回放对照原版结算后的结果。

普通 Falco 和同一签名 enclave 均通过 15 组定向回放、38 组基础回归和 27 组既有专项回归。PCAP 与 PCAPNG 的截断样本都先交付已触发的两条 Notice，再返回退出码 1。Tetragon 输入的镜像名为 `null`、空串或缺省时，三者的容器节点标签均为输入中的容器 ID。另行复跑的 45 组原版对照中，两端均有 44 组完全一致，第 601 秒重投样本按项目的 600 秒历史窗口触发第二条告警。[逐项结果](../../results/falco/raven-zeek-plugin/runtime-parity-fixes-2026-11-22.json)

## RAVEN 空值、Zeek 乱序时间和 PCAPNG 接口约束

2026-11-22，普通 Falco 和签名 SGX Simulation 的 23 组专项回放均与固定原版逐条一致，含上轮审查的 13 组和新增的 10 组边界样本。RAVEN 为两条 `event_id` 显式为 `null` 的事件分别生成 ID，Tetragon 容器 ID 为 `null` 时在进程节点保留该值。Zeek 对同组报文顺序和乱序读取均在 `1700000006.05` 产生 Notice。PCAPNG 接口有效抓取长度或分段字节序冲突时返回 1，读到冲突前已产生的两条 Notice 仍可见。[逐例结果](../../results/falco/raven-zeek-plugin/structure-parity-fixes-2026-11-22.json)

6 组流式输入与原版一致。QEMU 现场的两种采集模式均在工作负载结束前收到一条 RAVEN 检测和两种 Zeek Notice，记录模式的回放在普通和签名入口复现了现场结果。38 组基础回归和 27 组既有专项回归均通过。45 组历史输入中，两端各有 44 组与原版一致，第 601 秒重投仍按项目历史窗口处理。

生成原版参考数据后，在 `poc/` 下运行全部 23 组专项。

```bash
python3 -B falco/plugin/check.py build-falco/deps/package build-falco build-falco/offline-run \
  build-falco/native-run build-falco/structure-23 --structure-review falco/tests/fixtures/structure.json
```
