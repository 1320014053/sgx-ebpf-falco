set -euo pipefail
umask 077
cd /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5/falco-poc
sha256sum -c falco-ship.sha256
export LD_LIBRARY_PATH=/var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5/deps/runtime/usr/lib/x86_64-linux-gnu
ldd deps/package/usr/bin/falco
ldd deps/package/usr/share/falco/plugins/libcontainer.so
ldd build-ert/bin/falco-sgx
export FALCO_SGX_REPORT=1
d=/var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5/data/falco-offline-r02
b=$PWD/build-ert
p=$PWD/deps/package
bash /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5/poc/falco/replay.sh "$p" "$b" "$d"
cd "$d"
export FALCO_HOSTNAME=falco-sgx-fixture TZ=UTC
strace -f -qq -e trace=ioctl -o /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5/falco-ioctl.log "$b/bin/falco-sgx" "$b/falco-enclave.signed" reference.yaml reference.scap falco_rules.yaml > traced-alerts.jsonl 2>traced.log
grep -E 'SGX_IOC_ENCLAVE_INIT|0xa4, 0x2,' /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5/falco-ioctl.log > driver-init.log
cmp traced-alerts.jsonl sgx-alerts.jsonl
python3 - "$b/falco-enclave.signed" <<'PY'
import hashlib, json, pathlib, re, sys
elf = pathlib.Path(sys.argv[1]).read_bytes()
report = re.search(r'^REPORT DEBUG=(\d) MRENCLAVE=([a-f0-9]{64}) MRSIGNER=([a-f0-9]{64})$',pathlib.Path('sgx.log').read_text(),re.M)
assert report and report[1] == '0'
prefix = bytes.fromhex('06000000e10000000000010000000000')
for candidate in re.finditer(re.escape(prefix),elf):
    sig = elf[candidate.start():candidate.start()+1808]
    m = sig[960:992].hex()
    s = hashlib.sha256(sig[128:512]).hexdigest()
    if (m,s) == (report[2],report[3]):
        flags,mask = (int.from_bytes(sig[i:i+8],'little') for i in (928,944))
        assert flags & 2 == 0 and mask & 2
        break
else:
    raise ValueError('REPORT and signed Falco image differ')
assert re.search(r'= 0\s*$',pathlib.Path('driver-init.log').read_text(),re.M)
identity = dict(debug=0,mrenclave=m,mrsigner=s,sigstruct_flags=flags,sigstruct_mask=mask,image_sha256=hashlib.sha256(elf).hexdigest())
pathlib.Path('identity.json').write_text(json.dumps(identity,indent=2)+'\n')
print(json.dumps(identity))
PY
