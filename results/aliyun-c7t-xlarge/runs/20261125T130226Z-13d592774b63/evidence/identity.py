import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile

print('build\timage_sha256\tmrenclave\tmrsigner\tdebug\tflags\tmask')
for role,image in zip(('B','M'),map(Path,sys.argv[1:]),strict=True):
    with tempfile.TemporaryDirectory() as directory:
        out = Path(directory)/'oeinfo'
        subprocess.run(['objcopy','-O','binary','--only-section=.oeinfo',image,out],check=True)
        data = out.read_bytes()
    prefix = bytes.fromhex('06000000e10000000000010000000000')
    assert data.count(prefix) == 1
    offset = data.index(prefix)
    sig = data[offset:offset+1808]
    assert len(sig) == 1808
    flags,mask = (int.from_bytes(sig[i:i+8],'little') for i in (928,944))
    assert not flags & 2 and mask & 2, (role,flags,mask)
    print(role,hashlib.sha256(image.read_bytes()).hexdigest(),sig[960:992].hex(),
          hashlib.sha256(sig[128:512]).hexdigest(),0,hex(flags),hex(mask),sep='\t')
