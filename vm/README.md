# Windows 上的 Ubuntu 测试客体

以下 PowerShell 命令从仓库根目录运行。准备 Git、QEMU 和 OpenSSH 客户端。已有客体的磁盘在仓库上一级、密钥和运行日志在该目录的 `vm/runtime/` 时，直接启动它并保持这个终端运行。

```powershell
.\vm\Start-VM.ps1 -DataRoot ..
```

新建客体还需要 Python 3 和 `ubuntu-22.04.5-live-server-amd64.iso`。默认数据目录是仓库根目录。将 ISO 放在数据目录，在启动命令上加 `-Install`。安装创建 40 GiB 稀疏磁盘 `sgx-ebpf-sim.qcow2`，遇到已有磁盘会停止。安装进度在数据目录的 `vm/runtime/serial.log`，完成后客体自动关机。再次启动时使用同一数据目录。脚本默认从 `C:\Program Files\qemu` 启动 QEMU，并在 PATH 中查找 `python`，也可指定 `-QemuDirectory` 和 `-Python`。

## 在客体中打开一个完整提交

另开一个 PowerShell，从仓库根目录运行下面的命令。`$dataRoot` 与启动参数相同，使用默认数据目录时填 `'.'`。首次 SSH 连接需核对客体的主机指纹。示例导出 `HEAD`，也可将它替换为要验证的提交号。Git 归档保留脚本的 Linux 执行权限，每次传输都创建新的客体目录。

```powershell
$dataRoot = '..'
$guest = 'poc@127.0.0.1'
$connection = @('-i', (Resolve-Path "$dataRoot\vm\runtime\id_ed25519").Path, '-o', 'Port=2222')
$commit = git rev-parse --verify 'HEAD^{commit}'
if ($LASTEXITCODE) { throw 'git rev-parse failed' }
$archive = [IO.Path]::GetTempFileName()
try {
    git archive --format=tar --output=$archive $commit
    if ($LASTEXITCODE) { throw 'git archive failed' }
    $guestDir = ssh @connection $guest "mktemp -d sgx-ebpf-falco-$($commit.Substring(0,12)).XXXXXXXX"
    if ($LASTEXITCODE) { throw 'mktemp failed' }
    scp @connection $archive "${guest}:$guestDir/source.tar"
    if ($LASTEXITCODE) { throw 'scp failed' }
    $sha = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    ssh @connection $guest "cd $guestDir && echo '$sha  source.tar' | sha256sum -c - && tar -xf source.tar && rm source.tar"
    if ($LASTEXITCODE) { throw 'source archive verification or extraction failed' }
} finally {
    Remove-Item -LiteralPath $archive
}
ssh -t @connection $guest "cd $guestDir && exec bash"
```

此时客体的工作目录是该提交的仓库根目录，可直接执行[项目 README](../README.md) 中的命令。客体默认采用 TCG、2 个 vCPU 和 4 GiB 内存。已启用 Windows Hypervisor Platform 的主机可在启动命令后加 `-Accelerator whpx -Cpus 4 -MemoryMB 5120`；使用 TCG 时也可单独调整 CPU 数和内存。`poc` 账号通过安装时生成的 SSH 密钥登录并可执行免密 sudo。结束实验后在客体内运行 `sudo poweroff`。

## 用 Actions 内核启动同一客体

先在通用内核下准备好要测的 Falco 和 bpftool。用 `findmnt -no SOURCE /` 确认客体根分区，下面的示例是 `/dev/vda2`。在客体内执行 `sudo poweroff`。下载本仓库的 MOAT Actions 产物，在 Linux 上执行 `sha256sum -c SHA256SUMS`，从 `linux-image-6.1.38-moat-falco2` 的 Debian 包中解出 `boot/vmlinuz-6.1.38-moat-falco2`，将镜像放到 Windows 数据目录。

从仓库根目录运行下列 PowerShell 命令。MOAT 的 QEMU 配置使用四级分页 `la57=off`，内核命令行使用 `nokaslr`。`snapshot=on` 将本次写入保存在临时磁盘中。需要保存的验收结果应在客体关机前用 `scp` 取回。

```powershell
$dataRoot = '..'
$disk = (Resolve-Path "$dataRoot\sgx-ebpf-sim.qcow2").Path
$kernel = (Resolve-Path "$dataRoot\vmlinuz-6.1.38-moat-falco2").Path
& 'C:\Program Files\qemu\qemu-system-x86_64.exe' `
    -accel 'tcg,thread=multi' -machine q35 -cpu 'max,la57=off' -smp 2 -m 4096 `
    -drive "file=$disk,format=qcow2,if=virtio,snapshot=on" `
    -nic 'user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:2222-:22' `
    -display none -serial stdio -monitor none -no-reboot -kernel $kernel `
    -append 'root=/dev/vda2 rootfstype=ext4 ro rootwait console=ttyS0,115200n8 nokaslr panic=3'
```

在另一个终端用同一把 SSH 密钥登录。先用 `uname -r` 核对 `6.1.38-moat-falco2`，再从客体内的 Git 源码目录运行[项目的 MOAT 冒烟测试](../README.md#在-moat-上验证)。
