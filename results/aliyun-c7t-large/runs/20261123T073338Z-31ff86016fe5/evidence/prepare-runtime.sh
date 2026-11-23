set -eu
set -o pipefail 2>/dev/null || true
umask 077
mkdir -p /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5/deps /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5/data
cd /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5/deps
curl --proto '=https' --fail --location --retry 1 --connect-timeout 8 --max-time 120 --silent --show-error -o sgx_debian_local_repo.tgz https://download.01.org/intel-sgx/sgx-linux/2.25/distro/ubuntu22.04-server/sgx_debian_local_repo.tgz
echo '1b3916a77a2867c443940022d2d3cba652fde5972e9742fe8b0abe0bfd332827  sgx_debian_local_repo.tgz' | sha256sum -c -
tar -xzf sgx_debian_local_repo.tgz
for pkg in libsgx-enclave-common libsgx-urts; do
  deb=$(find . -type f -name "${pkg}_*.deb" | head -1)
  dpkg-deb -f "$deb" Package Version
  dpkg-deb -x "$deb" runtime
done
ls -l runtime/usr/lib/x86_64-linux-gnu/libsgx*
