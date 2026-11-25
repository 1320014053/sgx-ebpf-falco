#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
W=$PWD
E=$W/ship/evidence
manifest() {
    (cd "$W/ship"
     find . \( -type f -o -type l \) ! -path ./SHA256SUMS -print0 |
        LC_ALL=C sort -z | xargs -0 -r sha256sum > SHA256SUMS
     sha256sum --quiet -c SHA256SUMS)
}
manifest
mkdir verify
tar -C ship -cf - . | tar -C verify -xf -
cd verify
sha256sum --quiet -c SHA256SUMS
S=$PWD/src/results/aliyun-c7t-xlarge/scripts
B=$PWD/src/poc/build-falco
L=$PWD/src/poc/build-falco-live
M=$PWD/src/probe/poc/build-falco
P=$B/deps/package
export LD_LIBRARY_PATH=$PWD/runtime/usr/lib/x86_64-linux-gnu
bash -n "$S/ship-run.sh"
test -z "$(find runtime -xtype l -print)"
{
    echo "OE host code is linked from liboehost.a; see oehost-link.txt. Check the executables, plugins and the SGX libraries used by local REPORT."
    for f in "$L/falco-live" "$B/bin/falco-sgx" "$M/bin/falco-sgx" "$P/usr/bin/falco" "$P/usr/share/falco/plugins/libcontainer.so" "$B/lib/libraven_zeek.so" "$M/lib/libraven_zeek.so" "$LD_LIBRARY_PATH"/{libsgx_enclave_common.so.1,libsgx_urts.so.2,libsgx_dcap_ql.so.1,libsgx_quote_ex.so.1,libsgx_qe3_logic.so,libsgx_pce_logic.so.1,libsgx_uae_service.so.2}; do
        printf '\n%s\n' "$f"
        deps=$(ldd "$f")
        printf '%s\n' "$deps"
        if grep -Fq 'not found' <<< "$deps"; then exit 1; fi
        awk -v path="$LD_LIBRARY_PATH/" '$1 ~ /^libsgx_/ && index($3,path)!=1 {exit 1}' <<< "$deps"
    done
    python3 - <<'PY'
import ctypes, os
from pathlib import Path
lib = Path(os.environ['LD_LIBRARY_PATH'])
for name in ['libsgx_enclave_common.so.1','libsgx_urts.so.2','libsgx_dcap_ql.so.1','libsgx_quote_ex.so.1','libsgx_qe3_logic.so','libsgx_pce_logic.so.1','libsgx_uae_service.so.2']:
    ctypes.CDLL(name)
    assert str((lib/name).resolve()) in Path('/proc/self/maps').read_text()
    print('dlopen from bundle:', name)
for name in ['libsgx_qe3.signed.so.1','libsgx_pce.signed.so.1','libsgx_id_enclave.signed.so.1']:
    assert (lib/name).read_bytes().startswith(b'\x7fELF')
    print('architectural enclave:',name)
PY
    "$P/usr/bin/falco" --version
    "$B/deps/bpftool/bpftool" version
} > "$E/ldd.txt" 2>&1
python3 "$S/bench.py" all --package "$P" --build "$B" --live "$L" --out "$W/dry-run" --dry-run > "$E/dry-run.txt"
for stage in e1 e2 e3 e4 e5 e6; do grep -q "^$stage " "$E/dry-run.txt"; done
code=0
sudo -n bash "$S/ship-run.sh" > "$W/wrapper.log" 2>&1 || code=$?
cat "$W/wrapper.log"
test "$code" = 1
batch=$(sed -n 's/^batch=//p' "$W/wrapper.log")
test -d "$batch/evidence"
cmp evidence/enclaves.tsv "$batch/evidence/enclaves.tsv"
cp "$W/wrapper.log" "$E/guest-preflight.log"
cp "$batch/preflight/preflight.json" "$E/guest-preflight.json"
python3 - "$E/guest-preflight.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
assert d['pass'] is False and d['checks']['hardware_sgx'] is False and d['sgx_enclave'] is False
assert d['falco_exit'] not in (0,126,127) and any('hardware SGX unavailable' in msg for msg in d['errors'])
PY
sha256sum --quiet -c SHA256SUMS
cd "$W"
manifest
tar --owner=0 --group=0 --numeric-owner -C ship -czf c7t-xlarge-ship.tar.gz .
sha256sum c7t-xlarge-ship.tar.gz > c7t-xlarge-ship.tar.gz.sha256
mkdir unpacked
tar -xzf c7t-xlarge-ship.tar.gz -C unpacked
(cd unpacked && sha256sum --quiet -c SHA256SUMS)
stat -c '%n %s bytes' c7t-xlarge-ship.tar.gz
cat c7t-xlarge-ship.tar.gz.sha256
