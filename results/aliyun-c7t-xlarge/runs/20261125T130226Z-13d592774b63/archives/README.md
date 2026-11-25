# 从 GitHub 还原完整测试批次

本批的脚本、逐轮原始输出、汇总表和证据随仓库发布。12 个不小于 10 MiB 的原始文件不直接入库，以 xz 压缩后按原相对路径存放在本目录，解压后共 966,221,108 字节。服务器上的 198 条符号链接指向交付包内的规则和插件，用 tar 打包保存，不参与校验。[链接清单](../evidence/server-symlinks.tsv)

| 压缩文件 | 解压后的批次内路径 | 原始字节数 |
| --- | --- | ---: |
| [churn 输入](e7/inputs/churn.jsonl.xz) | `e7/inputs/churn.jsonl` | 186,418,796 |
| [repeat 输入](e7/inputs/repeat.jsonl.xz) | `e7/inputs/repeat.jsonl` | 209,778,738 |
| [Zeek PCAP](e7/inputs/zeek.pcap.xz) | `e7/inputs/zeek.pcap` | 66,080,728 |
| [repeat 原生告警](e7/repeat-native/alerts.jsonl.xz) | `e7/repeat-native/alerts.jsonl` | 158,516,304 |
| [repeat SGX 告警](e7/repeat-sgx/alerts.jsonl.xz) | `e7/repeat-sgx/alerts.jsonl` | 158,519,099 |
| [30 万条 SCAP](e8/input-300000/reference.scap.xz) | `e8/input-300000/reference.scap` | 28,102,804 |
| [60 万条 SCAP](e8/input-600000/reference.scap.xz) | `e8/input-600000/reference.scap` | 56,202,804 |
| [30 万条原生告警](e8/native-300000/alerts.jsonl.xz) | `e8/native-300000/alerts.jsonl` | 14,656,417 |
| [30 万条原生写文件告警](e8/native-300000-file/alerts.jsonl.xz) | `e8/native-300000-file/alerts.jsonl` | 14,656,417 |
| [60 万条原生告警](e8/native-600000/alerts.jsonl.xz) | `e8/native-600000/alerts.jsonl` | 29,316,417 |
| [30 万条 SGX 告警](e8/sgx-300000/alerts.jsonl.xz) | `e8/sgx-300000/alerts.jsonl` | 14,656,292 |
| [60 万条 SGX 告警](e8/sgx-600000/alerts.jsonl.xz) | `e8/sgx-600000/alerts.jsonl` | 29,316,292 |
| [服务器符号链接](server-symlinks.tar.xz) | 198 条指向 `/root/c7t-xlarge-ship/` 的链接 | 122,880 |

从仓库根目录，在 Linux 或 Git Bash 中执行以下命令。第一步核对压缩文件，最后一步用服务器生成的清单核对全部 1,045 个原始文件。仓库通过 `.gitattributes` 保留本批原始字节，CSV 中的 CRLF 换行也不会被改写。

```bash
cd results/aliyun-c7t-xlarge/runs/20261125T130226Z-13d592774b63
(cd archives && sha256sum -c SHA256SUMS)
for f in $(cd archives && find e7 e8 -name '*.xz'); do xz -dc "archives/$f" > "${f%.xz}"; done
sha256sum --quiet -c SHA256SUMS
```
