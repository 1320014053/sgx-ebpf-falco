# 从 GitHub 还原完整测试批次

本批次的代码、脚本、逐轮原始输出、汇总图表、签名程序和现场 SCAP、PCAP、JSONL 随仓库发布。`bulk/` 清单共 48 个文件，其中 46 个可以直接按原路径读取。另两个是 RAVEN 对同一路径连续处理 100 万条事件时产生的完整告警日志，分别以 gzip 压缩的 tar 包保存。每个包包含一个带原始相对路径的文件。

| 压缩包 | 解压后的批次内路径 | 原始字节数 |
| --- | --- | ---: |
| [普通 Falco 告警](raven-native-million-alerts.tar.gz) | `bulk/raven-native-repeat-1000000-r01/alerts.jsonl` | 158,516,304 |
| [硬件 SGX 告警](raven-sgx-million-alerts.tar.gz) | `bulk/raven-sgx-repeat-1000000-r01/alerts.jsonl` | 158,519,099 |

从仓库根目录，在 Linux 或 Git Bash 中执行以下命令。前一步核对下载的压缩包，最后一步核对解压后的原始字节、实验覆盖和运行时报告。归档中的现场轨迹与指标保留了实测时的进程、网络及主机元数据。[整批复核记录](../summary/audit.json) · [原始大文件清单](../bulk.sha256)

```bash
cd results/aliyun-c7t-large/runs/20261123T073338Z-31ff86016fe5
(cd archives && sha256sum -c SHA256SUMS)
tar -xzf archives/raven-native-million-alerts.tar.gz
tar -xzf archives/raven-sgx-million-alerts.tar.gz
python3 evidence/audit.py
```
