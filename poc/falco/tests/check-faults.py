"""Exercise live recovery with a separately signed simulation image."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from zipfile import ZipFile


def run(command, cwd, fatal=False):
    proc = subprocess.run(command, cwd=cwd, capture_output=True, timeout=180)
    if (proc.returncode != 0) != fatal:
        raise RuntimeError(proc.stderr.decode(errors="replace"))
    stats = [json.loads(line) for line in proc.stderr.splitlines() if line.startswith(b"{")]
    live = next(row for row in stats if row.get("mode") == "live")
    return proc.stdout.splitlines(), live, proc.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("live_build", "fault_image", "rules"):
        parser.add_argument(name, type=lambda value: Path(value).resolve(strict=True))
    args = parser.parse_args()
    here = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as directory:
        cwd = Path(directory)
        shutil.copyfile(args.rules, cwd / "falco_rules.yaml")
        subprocess.run([sys.executable, here / "fixture.py"], cwd=cwd, check=True)
        defaults = (here / "reference.yaml").read_text() + "\n"
        config = defaults + "live_block_bytes: 70000\nlive_block_count: 2\n"
        yaml = cwd / "reference.yaml"
        yaml.write_text(config)
        command = [args.live_build / "falco-ring-test", args.fault_image, yaml, "reference.scap",
                   "falco_rules.yaml", "expected.scap"]
        expected, stats, _ = run(command, cwd)
        assert len(expected) == 220 and not any(stats["errors"].values())
        assert 0 < stats["peak_blocks"] <= stats["block_count"] == 2
        yaml.write_text(defaults + "buffered_outputs: true\nidle: spin\n")
        alerts, stats, err = run(command, cwd)
        assert alerts == expected and 0 < stats["alert_flushes"] < len(alerts)
        host = json.loads(err.splitlines()[-1])
        assert host["sleep_ocalls"] == 0 and host["output_queue_peak"] > 0
        for stage in ("match", "format", "batch", "raw_block"):
            yaml.write_text(config + f"fault_injection: {{stage: {stage}, first: 2}}\n")
            alerts, stats, _ = run(command, cwd)
            counter = "batch" if stage == "raw_block" else stage
            assert stats["errors"][counter] == sum(stats["errors"].values()) == 1
            if counter == "batch":
                # This fixture uses equal-sized frames. The malformed raw input replaces block two.
                missing = len(expected) - len(alerts)
                start = 1 if stage == "batch" else missing
                assert missing > 0 and start + missing < len(expected)
                kept = expected[:start] + expected[start + missing:]
                for i, (actual, original) in enumerate(zip(alerts, kept)):
                    wanted = json.loads(original)
                    if i >= start:
                        # The injected status follows a successful next(), which counted that event.
                        wanted["output_fields"]["evt.num"] -= missing - int(stage == "batch")
                    assert json.loads(actual) == wanted
            else:
                assert alerts == expected[:1] + expected[2:]
        yaml.write_text(config + "fault_injection: {stage: match, repeat: 16}\n")
        _, stats, err = run(command, cwd, fatal=True)
        assert stats["errors"]["match"] == 16 and b"match error budget exceeded" in err
        assert err.count(b"match: injected failure") == 3
        print("PASS match, format, batch, diagnostic rate limit and fatal budget")

        config = (here / "plugin/live.yaml").read_text()
        shutil.copyfile(here / "plugin/rules.yaml", cwd / "raven_zeek_rules.yaml")
        with ZipFile(here / "tests/fixtures/regression.zip") as archive:
            (cwd / "snapshot.scap").write_bytes(archive.read("history/ring/lifecycle.scap"))
            for stage, fixture in (("translate", "early-review"), ("raven", "early-review"),
                                   ("raven_advance", "early-review"), ("plugin_match", "early-review"),
                                   ("plugin_format", "early-review"), ("zeek", "timer-queue-30"),
                                   ("zeek_advance", "timer-queue-30")):
                (cwd / "ring.bin").write_bytes(archive.read(f"history/inputs/{fixture}.bin"))
                (cwd / "live.yaml").write_text(config + f"\nfault_injection: {{stage: {stage}}}\n")
                _, stats, err = run([args.live_build / "replay-ring", args.fault_image, "0", "0",
                                     "falco_rules.yaml", "raven_zeek_rules.yaml"], cwd)
                assert stats["errors"][stage] == sum(stats["errors"].values()) == 1
                assert stats["records"] and stats["consumer"] == stats["producer"]
                if stage.startswith("raven"):
                    gaps = [json.loads(line[6:]) for line in err.splitlines() if line.startswith(b"RZRET ")]
                    # A failed tick consumes no event, so its gap may cover no events.
                    assert any(row.get("phase") == "gap" and row["reason"] == "error" and
                               (stage == "raven_advance" or row["first"] <= row["last"]) for row in gaps)
                print(f"PASS {stage} recovery")


if __name__ == "__main__":
    main()
