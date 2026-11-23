set -euo pipefail
cd /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5
sha256sum getpid-source.tgz
tar -xzf getpid-source.tgz
cd poc
export SGX_SDK=/var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5/deps/intel/sgxsdk
export LD_LIBRARY_PATH=/var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5/deps/runtime/usr/lib/x86_64-linux-gnu
gcc --version | head -1
clang-14 --version | head -1
pkg-config --modversion libbpf
make -j2 SGX_MODE=HW SGX_DEBUG=0 CLANG=clang-14
b=build/hw0
sha256sum "$b"/{poc,generator,probe.bpf.o,enclave.signed.so,ring_tests}
ldd "$b/poc"
mkdir -p /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5/data/getpid-identity-r01
d=/var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5/data/getpid-identity-r01
cp "$b/Enclave.config.xml" "$d/"
"$SGX_SDK/bin/x64/sgx_sign" dump -enclave "$b/enclave.signed.so" -dumpfile "$d/signature.txt" -cssfile "$d/signature.bin"
strace -o "$d/driver.log" -e trace=openat,ioctl "$b/ring_tests" "$b/enclave.signed.so" >"$d/report.txt" 2>"$d/stderr.txt" || { cat "$d/stderr.txt"; exit 1; }
cat "$d/report.txt"
python3 - "$d" <<'PY'
import hashlib, pathlib, re, sys
p = pathlib.Path(sys.argv[1])
sig = (p/'signature.bin').read_bytes()
assert len(sig) == 1808
m, s = sig[960:992].hex(), hashlib.sha256(sig[128:512]).hexdigest()
print('signed MRENCLAVE='+m, 'MRSIGNER='+s, 'attribute mask='+hex(int.from_bytes(sig[944:952],'little')))
assert int.from_bytes(sig[944:952], 'little') & 2 and not int.from_bytes(sig[928:936], 'little') & 2
assert 'DEBUG=0 MRENCLAVE='+m+' MRSIGNER='+s in (p/'report.txt').read_text()
print('GETPID_identity_matches')
PY
