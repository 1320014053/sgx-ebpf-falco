"""Compare falco-live's syscall subscriptions with the pinned native Falco."""

import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


def native_selection(binary, cwd, config, label):
    log = cwd / f"{label}-native.log"
    log.touch()
    # Signal the actual Falco process from the privileged shell that started it.
    script = r"""
        "$1" -c "$2" -o engine.kind=modern_ebpf -o engine.modern_ebpf.disable_iterators=true \
            -o log_level=debug >/dev/null 2>"$3" &
        pid=$!
        trap 'kill -TERM "$pid" 2>/dev/null || true' EXIT
        until grep -q 'with modern BPF probe' "$3"; do
            kill -0 "$pid"
            sleep 0.2
        done
        kill -INT "$pid"
        wait "$pid"
        trap - EXIT
    """
    subprocess.run(["sudo", "-n", "timeout", "--kill-after=5", "120", "bash", "-eu", "-c",
                    script, "bash", binary, config, log], cwd=cwd, check=True)
    lines = log.read_text()
    (count, names), = re.findall(r"\((\d+)\) syscalls selected in total \(final set\): (.+)$", lines, re.M)
    selected = names.split(", ")
    assert len(selected) == int(count) and selected == sorted(set(selected)), log
    warnings = re.findall(r"Loaded rules match syscalls that are not activated.*\(unsupported-evttype\): (.+)$",
                          lines, re.M)
    return selected, warnings[0].split(", ") if warnings else []


def check(package, build, live, out):
    here = Path(__file__).resolve().parents[1]
    out.mkdir()
    rules = ["falco_rules.yaml", "raven_zeek_rules.yaml"]
    shutil.copy2(package / "etc/falco" / rules[0], out)
    shutil.copy2(here / "plugin/rules.yaml", out / rules[1])
    (out / "libcontainer.so").symlink_to(package / "usr/share/falco/plugins/libcontainer.so")
    official = (here / "reference.yaml").read_text()
    plugin = (here / "plugin/live.yaml").read_text()
    both = "{raven: true, zeek: true}"
    assert plugin.count(both) == 1
    collector = ["sudo", "-n", "timeout", "--kill-after=5", "120", live / "falco-live", build / "falco-enclave.signed"]
    raven_only_names = {"listen", "chmod", "fchmod", "fchmodat", "write", "pwrite", "writev", "pwritev"}
    summary = {}
    for all_io in (False, True):
        label = str(all_io).lower()
        base = f"\nbase_syscalls: {{all: {label}, custom_set: [], repair: false}}\n"
        config = out / f"{label}-official.yaml"
        config.write_text(official + base)
        native, inactive = native_selection(package / "usr/bin/falco", out, config, label)
        baseline = set(native)
        cases = {"native": {"selected": native, "rules_not_activated": inactive}}
        for name, settings in (("official", None), ("both", both), ("raven-only", "{zeek: false}"),
                               ("zeek-only", """'{"raven":false}'""")):
            config = out / f"{label}-{name}.yaml"
            if settings is not None:
                config.write_text(plugin.replace(both, settings) + base)
            log = config.with_suffix(".log")
            cmd = [*collector, config, "4096", "-", *(rules if settings else rules[:1]), "--",
                   "sh", "-ec", 'cat "$1" > /dev/null; sleep 0.2', "sh", config]
            with log.open("xb") as err:
                subprocess.run(cmd, cwd=out, stderr=err, stdout=subprocess.DEVNULL, check=True)
            rows = [json.loads(line) for line in log.read_text().splitlines() if line.startswith("{")]
            diag, = (r for r in rows if r.get("mode") == "event_selection")
            stats, = (r for r in rows if r.get("mode") == "live")
            assert diag["base_syscalls_all"] is all_io, log
            for field in ("selected", "raven_added", "rules_not_activated"):
                assert diag[field] == sorted(set(diag[field])), (log, field)
            selected, added = set(diag["selected"]), set(diag["raven_added"])
            official_names = selected - added
            assert added <= selected, (log, added - selected)
            assert official_names == baseline, (log, "missing", baseline - official_names, "extra", official_names - baseline)
            if name in ("both", "raven-only"):
                assert added and added <= raven_only_names, (log, added)
            else:
                assert not added, (log, added)
            if name == "official":
                assert diag["rules_not_activated"] == inactive, (log, inactive)
            observed = set(stats["event_types"])
            assert "openat" in observed, log
            assert not (({"switch", "page_fault", "futex", "poll"} & observed) - selected), (log, observed - selected)
            cases[name] = {**diag, "event_types": stats["event_types"]}
        assert cases["both"]["raven_added"] == cases["raven-only"]["raven_added"], label
        summary[label] = cases

    config = out / "invalid.yaml"
    config.write_text(official + "\nbase_syscalls: {custom_set: [openat]}\n")
    log = config.with_suffix(".log")
    with log.open("xb") as err:
        invalid = subprocess.run([*collector, config, "4096", "-", rules[0], "--", "/bin/true"],
                                 cwd=out, stdout=subprocess.DEVNULL, stderr=err)
    assert invalid.returncode not in (0, 124, 137), log
    assert "falco-live implements only base_syscalls.all" in log.read_text(), log
    summary["invalid_custom_set"] = {"returncode": invalid.returncode}
    (out / "comparison.json").write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit("usage: check-event-set.py PACKAGE BUILD LIVE NEW_RUN_DIR")
    check(*(Path(arg).resolve() for arg in sys.argv[1:]))
