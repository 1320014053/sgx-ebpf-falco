param(
    [switch]$Install,
    [string]$QemuDirectory = 'C:\Program Files\qemu',
    [string]$Python = 'python',
    [int]$SshPort = 2222
)
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
$runtime = Join-Path $PSScriptRoot 'runtime'
$disk = Join-Path $workspace 'sgx-ebpf-sim.qcow2'
$iso = Join-Path $workspace 'ubuntu-22.04.5-live-server-amd64.iso'
$qemu = Join-Path $QemuDirectory 'qemu-system-x86_64.exe'
$qemuImg = Join-Path $QemuDirectory 'qemu-img.exe'
New-Item -ItemType Directory -Force -Path $runtime | Out-Null
if (Test-Path (Join-Path $runtime 'qemu.pid')) {
    $qemuProcessId = [int](Get-Content -Raw (Join-Path $runtime 'qemu.pid')).Trim()
    $existingProcess = Get-Process -Id $qemuProcessId -ErrorAction SilentlyContinue
    if ($existingProcess -and $existingProcess.ProcessName -eq 'qemu-system-x86_64') {
        throw "VM process $qemuProcessId is still running. Shut it down before starting another VM."
    }
}
$arguments = @(
    '-accel tcg,thread=multi', '-machine q35', '-cpu max', '-smp 2', '-m 4096',
    "-drive file=`"$disk`",format=qcow2,if=virtio",
    "-nic user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:${SshPort}-:22",
    '-display none', "-serial file:`"$(Join-Path $runtime 'serial.log')`"",
    '-monitor none', '-no-reboot'
)
if ($Install) {
    if (Test-Path $disk) { throw "Refusing to reinstall over existing disk: $disk" }
    if (!(Test-Path $iso)) { throw "Missing Ubuntu ISO: $iso" }
    & $qemuImg create -f qcow2 $disk 40G
    if ($LASTEXITCODE) { throw 'qemu-img failed' }
    & tar.exe -xf $iso -C $runtime casper/vmlinuz casper/initrd
    if ($LASTEXITCODE) { throw 'ISO extraction failed' }
    $key = Join-Path $runtime 'id_ed25519'
    if (!(Test-Path $key)) {
        & ssh-keygen.exe -q -t ed25519 -N '' -f $key
        if ($LASTEXITCODE) { throw 'ssh-keygen failed' }
    }
    $publicKey = (Get-Content "$key.pub").Trim()
    $seed = Join-Path $runtime 'seed'
    New-Item -ItemType Directory -Force -Path $seed | Out-Null
    $userData = @"
#cloud-config
autoinstall:
  version: 1
  refresh-installer:
    update: false
  locale: en_US.UTF-8
  keyboard:
    layout: us
  identity:
    hostname: sgx-ebpf-sim
    username: poc
    password: '!'
  ssh:
    install-server: true
    allow-pw: false
    authorized-keys:
      - $publicKey
  storage:
    layout:
      name: direct
  apt:
    geoip: false
    conf: |
      Unattended-Upgrade::Package-Blacklist { ".*"; };
  late-commands:
    - 'rm -f /target/etc/apt/apt.conf.d/94curtin-config'
    - 'echo "poc ALL=(ALL) NOPASSWD:ALL" > /target/etc/sudoers.d/poc'
    - 'chmod 440 /target/etc/sudoers.d/poc'
    - 'echo ''GRUB_CMDLINE_LINUX="console=tty0 console=ttyS0,115200n8"'' >> /target/etc/default/grub'
    - 'curtin in-target --target=/target -- update-grub'
  shutdown: poweroff
"@
    [IO.File]::WriteAllText((Join-Path $seed 'user-data'), $userData.Replace("`r`n", "`n"))
    [IO.File]::WriteAllText((Join-Path $seed 'meta-data'), "instance-id: sgx-ebpf-sim`n")
    [IO.File]::WriteAllText((Join-Path $seed 'vendor-data'), "")
    $server = Start-Process -FilePath $Python -ArgumentList "-m http.server 3003 --bind 127.0.0.1 --directory `"$seed`"" -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $runtime 'seed-http.log') -RedirectStandardError (Join-Path $runtime 'seed-http.err.log')
    Set-Content (Join-Path $runtime 'seed-http.pid') $server.Id
    $arguments += @(
        "-cdrom `"$iso`"",
        "-kernel `"$(Join-Path $runtime 'casper/vmlinuz')`"",
        "-initrd `"$(Join-Path $runtime 'casper/initrd')`"",
        '-append "autoinstall noprompt ds=nocloud-net;s=http://10.0.2.2:3003/ console=ttyS0,115200n8"'
    )
} elseif (!(Test-Path $disk)) {
    throw 'Disk does not exist. Run with -Install first.'
}
$process = Start-Process -FilePath $qemu -ArgumentList ($arguments -join ' ') -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $runtime 'qemu.stdout.log') -RedirectStandardError (Join-Path $runtime 'qemu.stderr.log')
Set-Content (Join-Path $runtime 'qemu.pid') $process.Id
Write-Host "QEMU PID: $($process.Id)"
Write-Host "Disk: $disk"
Write-Host "Serial log: $(Join-Path $runtime 'serial.log')"
Write-Host "SSH after installation: ssh -i `"$(Join-Path $runtime 'id_ed25519')`" -p $SshPort poc@127.0.0.1"
Wait-Process -Id $process.Id
if ($Install -and !$server.HasExited) { Stop-Process -Id $server.Id }
