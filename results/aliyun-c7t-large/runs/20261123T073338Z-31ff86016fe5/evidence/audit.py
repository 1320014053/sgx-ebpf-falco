"""Check transferred bytes, experimental coverage and the accepted failure/retest pairs."""
import csv
import hashlib
import json
import re
import tarfile
from pathlib import Path

base=Path(__file__).resolve().parents[1]
checks={}
def stream_digest(stream):
    result=hashlib.sha256()
    for block in iter(lambda:stream.read(1024*1024),b""): result.update(block)
    return result.hexdigest()
def digest(p):
    with p.open("rb") as file: return stream_digest(file)
def verify_manifest(file):
    lines=file.read_text(encoding="utf-8-sig").splitlines()
    names=set()
    for row in lines:
        value,name=row.split("  ",1)
        assert name not in names,name
        names.add(name)
        p=(base/name).resolve()
        assert p.is_relative_to(base.resolve()) and digest(p)==value,name
    sections={"SHA256SUMS":("evidence","raw"),"bulk.sha256":("bulk",)}
    if file.name in sections:
        actual={p.relative_to(base).as_posix() for folder in sections[file.name] for p in (base/folder).rglob("*") if p.is_file()}
        assert names==actual,(file.name,names.symmetric_difference(actual))
    return len(lines)
for file in ("evidence/transfer.sha256","SHA256SUMS","bulk.sha256"):
    checks[file]=verify_manifest(base/file)
rows=list(csv.DictReader((base/"trials.csv").open(encoding="utf8")))
assert len(rows)==len(set(x["trial_id"] for x in rows))
failed={x["trial_id"] for x in rows if x["status"]!="ok"}
assert failed=={"falco-offline-r01","http-hw-full-r00"},failed
counts={"getpid":75,"warmup":75,"raven-memory":8,"falco-replay":30,"plugin-replay":10,
        "falco-capacity":10,"capacity-calibration":8,"capacity-warmup":10,"capacity-100k":10,"capacity-100k-warmup":10,"capacity-lower":5,"capacity-lower-warmup":5,"capacity-floor":5,"capacity-floor-warmup":5,"alert-latency":15,"idle":4,"replay-heap":3}
for key,n in counts.items():
    valid=[r for r in rows if r["experiment"]==key and r["status"]=="ok"]
    assert len(valid)==n,(key,len(valid),n)
    checks[key]=n
http=[r for r in rows if r["experiment"]=="http" and r["repeat"]!="0" and r["status"]=="ok"]
assert len(http)==20
checks["http_formal"]=len(http)
for k in ("getpid","http","alert-latency","falco-capacity","capacity-100k","capacity-lower","capacity-floor"):
    selected=[r for r in rows if r["experiment"]==k and r["repeat"]!="0"]
    assert all(float(r["measurement_s"])>=60 for r in selected)
    keys={(r["mode"],r["load_level"]) for r in selected}
    for mode,load in keys:
        assert {r["repeat"] for r in selected if r["mode"]==mode and r["load_level"]==load}==set("12345"),(k,mode,load)
for r in rows:
    assert (base/r["raw_path"]).is_dir(),r["trial_id"]
for rel in ("bulk/artifacts/getpid/enclave.signed.so","bulk/artifacts/falco-hardware.tgz"):
    expect={"bulk/artifacts/getpid/enclave.signed.so":"dae0ab4b8060ddbf800dc3a7182c158b1449105df1d2bd34ec91f431f614c283",
            "bulk/artifacts/falco-hardware.tgz":"54aab02912b9a7acadf5febe84abc6fe9c52aff8799e09a4f13d0457740be2f9"}[rel]
    assert digest(base/rel)==expect
getpid=base/"raw/getpid-identity-r01"
sig=(getpid/"signature.bin").read_bytes()
assert len(sig)==1808 and int.from_bytes(sig[944:952],"little") & 2 and not int.from_bytes(sig[928:936],"little") & 2
expected="DEBUG=0 MRENCLAVE="+sig[960:992].hex()+" MRSIGNER="+hashlib.sha256(sig[128:512]).hexdigest()
assert expected in (getpid/"report.txt").read_text()
checks["getpid_runtime_report_matches"]=True
identity=json.loads((base/"raw/falco-offline-r02/identity.json").read_text())
for fn in ("falco-offline-r02/sgx.log","falco-live-official-r01/sgx.log","falco-live-detectors-r01/ring-only/live.log","falco-live-detectors-r01/recorded/live.log"):
    data=(base/"raw"/fn).read_text(errors="replace")
    assert "REPORT DEBUG=0 MRENCLAVE="+identity["mrenclave"]+" MRSIGNER="+identity["mrsigner"] in data,fn
with tarfile.open(base/"bulk/artifacts/falco-hardware.tgz") as tar:
    with tar.extractfile("build-ert/falco-enclave.signed") as stream:
        assert stream_digest(stream)==identity["image_sha256"]
for name in ("getpid-identity-r01/driver.log","falco-offline-r02/driver-init.log"):
    assert re.search(r"SGX_IOC_ENCLAVE_INIT.*= 0",(base/"raw"/name).read_text())
checks["falco_runtime_report_matches"]=4
checks["rows"]=len(rows)
checks["superseded_failures"]=sorted(failed)
print(json.dumps(checks,indent=2))
