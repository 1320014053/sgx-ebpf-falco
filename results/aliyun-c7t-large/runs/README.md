# ecs.c7t.large 实测批次与数据归档

执行范围、硬件非调试验收条件和性能指标以[测试计划](../README.md)为准。修订方案时更新该文件。在同一实例、内核、源码和二进制组合下做的一组实验记作一个批次，每次独立执行记作一轮。更换内核或重建待测程序后新建批次，并在记录里引用前一批，便于前后对照。

## 批次索引

批次以 UTC 开始时间排序。进入批次记录可以查到硬件身份、逐轮原始数据、正式报告和校验清单。首台系统的环境检查单独保留。

| 批次（UTC） | 内核 | 实验范围 | 状态 | 主要发现 |
| --- | --- | --- | --- | --- |
| [20261123T072405Z-31ff86016fe5](20261123T072405Z-31ff86016fe5/record.md) | `6.8.0-147-generic` | 首台 ECS 只读环境检查 | 用户换机中止 | Ubuntu 24.04.5，SGX 设备可见，EPC 1,984 MiB，性能采样 0 轮。 |
| [20261123T073338Z-31ff86016fe5](20261123T073338Z-31ff86016fe5/record.md) | `5.15.0-198-generic` | Ubuntu 22.04.5 硬件非调试 | 完成并校验 | 两份硬件 REPORT 的 DEBUG 均为 0。官方规则 5/5 轮实收超过 10 万条/秒且零丢失，完整配置同档有丢失。低负载告警均超出 2 ms 目标。[完整报告](20261123T073338Z-31ff86016fe5/REPORT.md) |

## 开始一批测试

在待测仓库根目录用 Bash 执行。批次目录名采用 UTC 时间和 12 位 Git 提交号，格式为 `YYYYMMDDTHHMMSSZ-<git12>`。同名目录已存在时，初始化会停止。命令会复制[批次记录模板](../templates/record.md)、[逐轮 CSV 表头](../templates/trials.csv)和本批实际使用的计划原文。

```bash
(
  set -eu
  suite_dir=results/aliyun-c7t-large
  run_id="$(date -u +%Y%m%dT%H%M%SZ)-$(git rev-parse --short=12 HEAD)"
  run_dir="$suite_dir/runs/$run_id"
  mkdir "$run_dir"
  mkdir "$run_dir/evidence" "$run_dir/raw"
  cp "$suite_dir/templates/record.md" "$suite_dir/templates/trials.csv" "$run_dir/"
  cp "$suite_dir/README.md" "$run_dir/evidence/plan.txt"
  git rev-parse HEAD > "$run_dir/evidence/source-commit.txt"
  printf '%s\n' "$run_dir"
)
```

| 批次内路径 | 保存内容 |
| --- | --- |
| `record.md` | 本批目的、真实环境、执行命令、验收结论、异常和复测关系。硬件状态写入 REPORT 实际读数。 |
| `evidence/` | 计划快照、源码版本、环境、实际编译和签名配置、产物与输入指纹、SGX 初始化记录、REPORT 核对结果。如构建含未提交改动，附对应补丁及参与构建的新文件。签名私钥留在签名环境。 |
| `trials.csv` | 一轮一行。填写唯一 `trial_id`、实验、模式、负载、档位、重复序号、执行状态、退出码、有效计时秒数，以及指向原始数据的批次内相对路径。 |
| `raw/<trial_id>/` | 保留该轮程序直接输出的 JSON、CSV、计数、比对结果和适合入库的日志，保留原始单位与字节。让已有脚本把结果写入该轮的新目录。 |
| `summary/` | 按需生成汇总表和图，注明来源批次、轮次与生成命令。更正汇总时在记录中写明原因。 |
| `bulk/` | 存放完整 PCAP、SCAP、大体积 JSONL 或含现场细节的原始日志，按需创建。该目录默认由 Git 忽略。已公开批次在各自记录里注明随仓库分发的文件和还原方式。若脚本将轨迹和统计写进同一目录，可将输出指向 `bulk/<trial_id>/`，再把小型计数和比对结果原样复制到 `raw/<trial_id>/`。 |

`trial_id` 可采用 `getpid-direct-low-r01` 这样的名称。`status` 使用 `ok`（执行完成且数据有效）、`failed`（命令或正确性检查失败）、`interrupted`（中断）。饱和丢失和未达性能目标仍应填写实测值。未取得的数值留空并在记录中说明。复测分配新 `trial_id`，写明对应的原轮次。普通态基线的 enclave 属性填“不适用”。

## 结束与复核

在批次目录下、原始文件收齐后生成校验清单。清单中的路径相对于当前批次，可随目录在 Linux 与 Windows 工作区之间移动。

```bash
(
  set -euo pipefail
  find evidence raw -type f -exec sha256sum {} + | LC_ALL=C sort -k 2 > SHA256SUMS
  sha256sum -c SHA256SUMS
)
```

若已归档大文件，在同一位置另执行 `find bulk -type f -exec sha256sum {} + > bulk.sha256`。对用于回放的真实采集文件，记录持久副本的位置和字节数。可重建的合成输入另记生成命令、参数及指纹。

将批次和用于复核的原始数据从 ECS 取回到持久存储，在接收端用 `sha256sum -c SHA256SUMS` 复核，取回大文件时也核对 `sha256sum -c bulk.sha256`。补齐批次记录和上方索引，随后清理可重建的临时二进制及构建目录。源码、补丁、工作流和验证记录按仓库约定保留。
