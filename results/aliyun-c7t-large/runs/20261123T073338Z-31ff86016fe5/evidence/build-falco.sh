set -euo pipefail
cd /home/poc/falco-poc
mkdir -p /home/poc/hw-release-src
tar -xzf /home/poc/hw-falco-source.tgz -C /home/poc/hw-release-src
rsync -rc /home/poc/hw-release-src/falco/ falco/
bash falco/fetch.sh deps
cmake -S falco -B build-ert -DFALCO_SGX_HARDWARE=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-ert --parallel 2 --target falco-sgx sign-falco raven_zeek --verbose
cmake -S falco/live -B build-live -DFALCO_SGX_HARDWARE=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-live --parallel 2 --target falco-live httpd --verbose
cat build-ert/trusted/enclave.conf
sha256sum build-ert/bin/falco-sgx build-ert/falco-enclave.signed build-ert/lib/libraven_zeek.so build-live/{falco-live,httpd} deps/package/{etc/falco/falco_rules.yaml,usr/bin/falco,usr/share/falco/plugins/libcontainer.so}
ldd build-ert/bin/falco-sgx
ldd build-live/falco-live
