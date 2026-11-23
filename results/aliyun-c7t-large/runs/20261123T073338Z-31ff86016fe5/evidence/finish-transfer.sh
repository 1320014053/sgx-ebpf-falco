set -euo pipefail
cd /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5
python3 - <<'PY'
import os
from pathlib import Path
import time
pid = int(Path("getpid-matrix.pid").read_text())
deadline = time.monotonic() + 95*60
while time.monotonic() < deadline:
    log=Path("getpid-matrix.log").read_text()
    if "GETPID_MATRIX_COMPLETE" in log:
        break
    if "Traceback (most recent call last)" in log or not Path(f"/proc/{pid}").exists():
        raise SystemExit("GETPID matrix exited before completion")
    time.sleep(15)
else:
    raise SystemExit("GETPID matrix completion not observed")
PY
grep -q 'FALCO_CAPACITY_COMPLETE' capacity-launch/run.log
grep -q 'FALCO_REFINED_STAGE_COMPLETE' refine-launch/run.log
python3 collect-results.py
sha256sum results-transfer.tgz > results-transfer.sha256
cat results-transfer.sha256
date -u +%FT%TZ
