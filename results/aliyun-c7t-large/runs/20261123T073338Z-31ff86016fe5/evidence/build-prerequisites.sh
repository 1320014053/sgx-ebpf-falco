set -eu
umask 077
cd /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5/deps
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Retries=2 -qq update
apt-get -y -qq --no-install-recommends install clang-14 libbpf-dev libelf-dev pkg-config
curl --proto '=https' -fsSL --retry 2 --connect-timeout 8 --max-time 180 https://download.01.org/intel-sgx/sgx-linux/2.25/distro/ubuntu22.04-server/sgx_linux_x64_sdk_2.25.100.3.bin -o sdk.bin
echo '1acf6fa1d3d50d14242737118e39428a2cefb00bfff2795c9a2acc37639ac6e4  sdk.bin' | sha256sum -c -
bash sdk.bin --prefix "$PWD/intel"
test -x intel/sgxsdk/bin/x64/sgx_sign
