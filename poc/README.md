# eBPF → SGX SDK Simulation 最小通信闭环

在 x86-64 Linux 客体中，通过内核 eBPF 的 `syscalls:sys_enter_getpid` 采集事件，使用 Intel SGX SDK 2.25 的 SIM 库验证 enclave 的消费路径。

Falco 原版规则与扩展使用独立的离线回放和 Modern eBPF 实时直读入口，见 [Falco SGX Simulation](falco/README.md)。

## 构建与运行

Windows 上安装及启动客体见 `../vm/README.md`。把 `poc/` 上传到客体后执行：

```bash
cd ~/poc
sudo bash scripts/setup-ubuntu.sh
bash scripts/check-environment.sh > ../environment.log
bash scripts/build.sh
sudo bash scripts/run.sh --mode direct --count 10000 --interval-us 1000
sudo bash scripts/smoke.sh | tee ../smoke.log
```

已有 SDK 安装包时，把它的路径作为 `setup-ubuntu.sh` 的第一个参数。`SGX_SDK` 默认为 `/opt/intel/sgxsdk`。构建只允许 `SGX_MODE=SIM`，Debug 默认开启；优化构建使用 `SGX_DEBUG=0 bash scripts/build.sh`，运行和测试也设置相同的 `SGX_DEBUG`。生成的签名密钥仅用于本地实验。

运行输出一行 JSON。成功时 `ok=true`，进程退出码为 0。默认任何丢失、格式错误或计数不一致都会失败；饱和实验可用 `--allow-drops`，此时仍检查提交及消费守恒。

```bash
# 单次有限消费入口对照；每次最多消费 64 条
sudo bash scripts/run.sh --mode step --count 10003 --interval-us 1000
# 整轮仅一次数据运行 ECALL；停止后排空
sudo bash scripts/run.sh --mode direct --seconds 60 --interval-us 1000
# 延后消费者，产生积压与预留失败，再恢复排空
sudo bash scripts/run.sh --mode direct --count 20000 --interval-us 0 --pause-ms 3000 --allow-drops
# 五种模式各重复五次，结果包含计数、调用次数、CPU、墙钟与复制量
sudo python3 scripts/compare.py --output ../results/runs.csv
```

## 已实现的数据路径

| 模式 | 路径 |
|---|---|
| `baseline` / M0 | 发生器，不加载探针 |
| `host` / M1 | eBPF → libbpf 回调 → 普通用户态校验 |
| `ecall` / M2 | eBPF → libbpf 回调 → 固定 256 B `[in]` ECALL |
| `batch` / M3 | eBPF → libbpf → 固定最大 64 条的 `[in]` 批对象 |
| `step` | enclave 每次最多直接消费 64 条真实 mmap 记录 |
| `direct` / M4 | 一次 `ecall_run`，enclave 常驻直接消费真实 mmap |

Host 先创建单线程发生器并让它阻塞在管道上，再配置目标 TGID、挂载探针及初始化消费者，最后放开发生器。每个事件对应一次显式 `syscall(SYS_getpid)`。探针在预留前递增测试序号，预留失败也计入 attempted。

`direct` 不创建 libbpf 消费者，只用 libbpf 加载探针。Host 映射消费者读写页、生产者只读页和连续双映射数据区；描述符通过固定大小 `[in]` 参数登记。enclave 检查外部范围、对齐、容量、重叠及整数溢出，内部保留消费位置。读取索引及头部使用 acquire，合法载荷只复制一次到内部预分配数组，随后只校验副本；消费位置用 release 写回。EDL 没有 OCALL。

停止顺序为：发生器退出 → 卸载探针 → 控制页请求排空 → 消费线程返回 → 统计核对 → 销毁 enclave 和映射。普通、ECALL、批量与直接模式共用同一套事件校验及 TGID/GETPID 匹配逻辑。批量按 64 条或 100 μs 目标封批，并提交尾批；调度可能延长实际等待时间。

## 统计与测试边界

- `attempted = submitted + reserve_failed`；`submitted = processed + format_rejected`。低速实验额外要求丢失和拒绝均为 0。
- `data_ecalls` 只计数据入口；`total_ecalls` 还包括初始化及统计入口。M4 正常为 1 次数据 ECALL、3 次总 ECALL、0 次 OCALL。
- `payload_copy_bytes` 是有效事件载荷跨 enclave 边界的复制量。M4 为 `processed × 256`；头部与索引读取另列。初始化描述符和退出统计不计入载荷。
- `sdk_input_bytes` 是 M2/M3 的 SDK 数据输入封送量；M3 每次复制固定 `sizeof(poc_batch)`，包括未使用槽位。`host_pack_bytes` 单独记录整理批次的额外复制量。
- 计时在初始化完成、放开发生器前开始，不含探针加载和 enclave 创建。`wall_ns` 包含发生器与停止排空；`generation_wall_ns` 和 `drain_ns` 分开列出。CPU 时间分别记录发生器、Host 进程及其中的消费者线程，后两者存在包含关系，不能相加。
- `make test` / `ring_tests` 在真正的 SIM enclave 中验证匿名测试映射的环绕、BUSY、DISCARD、长度/索引/描述符边界、版本及重复序号拒绝、回放一致性、尾批和停止排空。匿名映射只用于解析器测试；`smoke.sh` 另跑真实内核链路。

本轮只支持一个单线程发生器、一个 ring buffer、一个 enclave 数据线程。尚未实施多发生器、外部载荷并发修改实验、恶意取消映射实验或硬件 SGX 验收。格式合法的匿名输入会被接受，测试会明确报告来源认证缺口。SIM 不提供硬件内存隔离，TCG/SIM 时间不能用于估算硬件 SGX 收益。

## 实现参考

映射和记录布局参考 [libbpf v0.5.0 ringbuf.c](https://github.com/libbpf/libbpf/blob/v0.5.0/src/ringbuf.c) 与 [Linux ring buffer 文档](https://docs.kernel.org/bpf/ringbuf.html)；SDK 构建参考 [Intel SGX 2.25 示例](https://github.com/intel/linux-sgx/tree/sgx_2.25/SampleCode/SampleEnclave)。Ubuntu 安装脚本使用 [Canonical 的 autoinstall 流程](https://canonical-subiquity.readthedocs-hosted.com/en/latest/howto/autoinstall-quickstart.html)。
