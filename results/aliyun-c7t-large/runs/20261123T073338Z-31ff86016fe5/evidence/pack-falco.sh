set -euo pipefail
cd /home/poc/falco-poc
files=( build-ert/bin/falco-sgx build-ert/falco-enclave.signed build-ert/lib/libraven_zeek.so build-ert/trusted/enclave.conf build-live/falco-live build-live/httpd deps/package/etc/falco/falco_rules.yaml deps/package/usr/bin/falco deps/package/usr/share/falco/plugins/libcontainer.so )
ldd deps/package/usr/bin/falco
sha256sum "${files[@]}" > /home/poc/falco-ship.sha256
tar -czf /home/poc/falco-hardware.tgz "${files[@]}" -C /home/poc falco-ship.sha256
sha256sum /home/poc/falco-hardware.tgz
