"""Collect regular files from completed experiments. Hash the same bytes on ECS and at reception."""
import hashlib
import io
from pathlib import Path
import tarfile

base=Path(__file__).resolve().parent
files={}
for d in sorted((base/"data").iterdir()):
    if not d.is_dir(): continue
    for path in sorted(d.rglob("*")):
        if path.is_symlink() or not path.is_file() or path.name.endswith(".tmp"): continue
        name=path.name
        field="raw"
        if d.name.startswith("falco-live") and (path.suffix in (".scap",".pcap",".jsonl") or name=="native-rules.json"):
            field="bulk"
        if name=="native-metrics.jsonl": field="bulk"
        if d.name.startswith("raven-") and name=="alerts.jsonl": field="bulk"
        if d.name.startswith("plugin-replay") and name=="alerts.jsonl": field="bulk"
        files[f"{field}/{path.relative_to(base/'data').as_posix()}"]=path
for name in ("getpid-matrix.log","live-official.log","live-detectors.log","offline-perf.log","http-smoke.log","http-formal.log","http-retry.log","capacity.log","capacity-refine.log","capacity-floor.log","large-replay.log","replay-heap.log","plugin-perf.log","raven-memory.log"):
    if (base/name).is_file(): files["evidence/"+name]=base/name
for name in ("falco-ship.sha256","build-ert/trusted/enclave.conf"):
    files["evidence/falco-"+Path(name).name]=base/"falco-poc"/name
for name in ("enclave.signed.so","probe.bpf.o","poc","generator","ring_tests"):
    files["bulk/artifacts/getpid/"+name]=base/"poc/build/hw0"/name

with tarfile.open(base/"results-transfer.tgz","w:gz",compresslevel=3) as archive:
    manifest=[]
    for name,path in sorted(files.items()):
        digest=hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda:stream.read(1024*1024),b""): digest.update(block)
        archive.add(path,arcname=name,recursive=False)
        manifest.append(f"{digest.hexdigest()}  {name}\n")
    raw="".join(manifest).encode()
    header=tarfile.TarInfo("evidence/transfer.sha256")
    header.size=len(raw)
    archive.addfile(header,io.BytesIO(raw))
print("regular_files",len(files), "archive_bytes",(base/"results-transfer.tgz").stat().st_size)
