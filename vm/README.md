# Windows 上的 Ubuntu 测试客体

在 Windows 上准备 QEMU、Python 3 和 OpenSSH 客户端。将 Ubuntu 22.04.5 Server amd64 安装镜像放在仓库根目录，文件名为 `ubuntu-22.04.5-live-server-amd64.iso`。从仓库根目录的 PowerShell 安装客体。

```powershell
.\vm\Start-VM.ps1 -Install
```

脚本默认从 `C:\Program Files\qemu` 启动 QEMU，并在 PATH 中查找 `python`。可用 `-QemuDirectory` 和 `-Python` 指定本机安装位置。安装创建 40 GiB 稀疏磁盘 `sgx-ebpf-sim.qcow2`，遇到已有磁盘会停止。安装期间的进度在 `vm/runtime/serial.log`，完成后客体自动关机。

再次启动并保持该终端运行。

```powershell
.\vm\Start-VM.ps1
```

在另一个 PowerShell 中上传工程源码并登录。默认 SSH 端口为本机回环地址的 2222，首次连接需核对主机指纹。

```powershell
scp -i .\vm\runtime\id_ed25519 -P 2222 -r .\poc poc@127.0.0.1:~/
ssh -i .\vm\runtime\id_ed25519 -p 2222 poc@127.0.0.1
```

客体采用 TCG、2 个 vCPU 和 4 GiB 内存。`poc` 账号通过安装时生成的 SSH 密钥登录并可执行免密 sudo。结束实验后在客体内运行 `sudo poweroff`。[GETPID 构建与测试](../poc/README.md) · [Falco 构建与测试](../poc/falco/README.md)
