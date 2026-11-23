set -euo pipefail
cd /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5/deps
export LD_LIBRARY_PATH=$PWD/runtime/usr/lib/x86_64-linux-gnu
for pkg in libsgx-dcap-ql libsgx-qe3-logic libsgx-pce-logic libsgx-ae-qe3 libsgx-ae-pce libsgx-quote-ex libsgx-uae-service libsgx-ae-id-enclave; do
  deb=$(find . -type f -name "${pkg}_*.deb" -print -quit)
  if test -n "$deb"; then dpkg-deb -f "$deb" Package Version; dpkg-deb -x "$deb" runtime; fi
done
ls -l "$LD_LIBRARY_PATH"/libsgx_dcap_ql*
ldd "$LD_LIBRARY_PATH/libsgx_dcap_ql.so.1"
if ! test -x /usr/bin/time; then DEBIAN_FRONTEND=noninteractive apt-get -y -qq --no-install-recommends install time; fi
