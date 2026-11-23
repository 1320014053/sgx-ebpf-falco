set -euo pipefail
cd /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5
gcc -O2 -x c -o cpu-bits - <<'C'
#include <cpuid.h>
#include <stdio.h>
int main(void) {
    unsigned a,b,c,d;
    __cpuid_count(1,0,a,b,c,d);
    printf("leaf1 ecx=%08x PCID=%u\n",c,(c>>17)&1);
    __cpuid_count(7,0,a,b,c,d);
    printf("leaf7.0 ebx=%08x ecx=%08x SGX=%u INVPCID=%u PKS=%u SGX_LC=%u\n",b,c,(b>>2)&1,(b>>10)&1,(c>>31)&1,(c>>30)&1);
    __cpuid_count(0x12,0,a,b,c,d);
    printf("leaf12.0 eax=%08x SGX1=%u SGX2=%u\n",a,a&1,(a>>1)&1);
    return 0;
}
C
./cpu-bits
type -p time || true
command -v runuser sudo
