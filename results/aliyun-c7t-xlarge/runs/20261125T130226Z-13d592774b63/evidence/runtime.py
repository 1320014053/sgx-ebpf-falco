#!/usr/bin/env python3
import hashlib
from pathlib import Path
import subprocess
from urllib.parse import urljoin
import urllib.request

work = Path(__file__).resolve().parent
packages = work / 'debs'
packages.mkdir(exist_ok=True)
runtime = work / 'ship/runtime'
runtime.mkdir(parents=True, exist_ok=True)
base = 'https://download.01.org/intel-sgx/sgx_repo/ubuntu/'
index = packages / 'Packages'
def fetch(url, dest):
    subprocess.run(['curl','--proto','=https','--proto-redir','=https','-fsSL','--retry','2',url,'-o',dest], check=True)
def sha(data):
    return hashlib.sha256(data).hexdigest()
fetch(base+'dists/jammy/main/binary-amd64/Packages',index)
blocks = {}
for block in index.read_text().split('\n\n'):
    fields = dict(line.split(': ',1) for line in block.splitlines() if line and not line[0].isspace() and ': ' in line)
    if 'Package' in fields:
        blocks[fields['Package'], fields['Version']] = fields
groups = {
 '2.25.100.3-jammy1': ['libsgx-enclave-common','libsgx-urts','libsgx-ae-pce','libsgx-quote-ex','libsgx-uae-service'],
 '1.22.100.3-jammy1': ['libsgx-dcap-ql','libsgx-qe3-logic','libsgx-pce-logic','libsgx-ae-qe3','libsgx-ae-id-enclave']}
pins = [(name,version) for version,names in groups.items() for name in names]
missing = [(name,version) for name,version in pins if (name,version) not in blocks]
if missing:
    raise SystemExit(f'Pinned entries absent from Jammy Packages: {missing}')
print('Index', index.name, sha(index.read_bytes()), flush=True)
for name,version in pins:
    entry = blocks[name,version]
    file = entry['Filename']
    deb = packages / Path(file).name
    fetch(urljoin(base, file),deb)
    digest = sha(deb.read_bytes())
    assert digest == entry['SHA256'], name
    for field,value in [('Package',name),('Version',version)]:
        assert subprocess.check_output(['dpkg-deb','-f',deb,field],text=True).strip() == value
    subprocess.run(['dpkg-deb','-x',deb,runtime],check=True)
    print(name,version,digest,file,flush=True)
