#!/usr/bin/env python3
import json
from ipaddress import ip_address
from pathlib import Path
from struct import pack

# x86-64 libscap 0.26.1 savefile v1.2: synthetic events only.
EPOCH = 1_700_000_000_000_000_000
MS = 1_000_000


def block(kind, payload):
    payload += bytes(-len(payload) % 4)
    size = 12 + len(payload)
    return pack("<II", kind, size) + payload + pack("<I", size)


def strings(*items):
    return b"".join(pack("<H", len(item)) + item for item in items)


def process(pid, ppid, name):
    name = name.encode()
    entry = (pack("<5Q", pid, pid, ppid, pid, pid) +
             strings(name, name, b"/usr/bin/" + name, b"", b"/") +
             pack("<Q6I2Q", 1024, 0, 1000, 1000, 0, 0, 0, 0, 0) +
             strings(b"") + pack("<2Q", pid, pid) + strings(b"", b"/") +
             pack("<Q2IB3QB3QBBQ", EPOCH - 100 * MS, 0, 1000, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, pid))
    return pack("<I", len(entry) + 4) + entry


def event(ms, tid, kind, *params):
    data = b"".join(pack("<H", len(param)) for param in params) + b"".join(params)
    header = pack("<QQIHI", EPOCH + ms * MS, tid, 26 + len(data), kind, len(params))
    return block(0x216, pack("<H", 0) + header + data)


def execve(ms, tid, ppid, path):
    name = Path(path).name.encode() + b"\0"
    path = path.encode() + b"\0"
    q = lambda n: pack("<Q", n)
    i = lambda n: pack("<I", n)
    return event(ms, tid, 293, q(0), name, b"\0", q(tid), q(tid), q(ppid), b"/\0",
                 q(1024), q(0), q(0), i(0), i(0), i(0), name, b"", b"", i(0),
                 q(tid), i(1000), i(0), q(0), q(0), q(0), q(tid), q(0), q(0),
                 i(1000), path, q(tid), i(1000), path)


def connect(ms, tid, host, result, port=8080):
    addr = ip_address(host).packed
    dport = pack("<H", port)
    dst = b"\x02" + addr + dport
    src = ip_address("192.0.2.100").packed + pack("<H", 40000)
    fd = pack("<q", ms)
    return (event(ms - 2, tid, 19, fd, pack("<I", 2), pack("<I", 1), pack("<I", 0), pack("<I", 0)) +
            event(ms - 1, tid, 22, fd, dst) +
            event(ms, tid, 23, pack("<q", result), b"\x02" + src + addr + dport if result == 0 else b"", fd, dst))


def write_fixture():
    threads = [(1, 0, "init"), (100, 1, "httpd"), (101, 100, "worker"), (102, 100, "worker")]
    threads += [(tid, 1, "worker") for tid in range(103, 110)]
    capture = block(0x0A0D0D0A, pack("<IHHQ", 0x1A2B3C4D, 1, 2, 2**64 - 1))
    capture += block(0x201, pack("<IQQ128s4Q", 1, 2**30, 32768, b"fixture", EPOCH - 100 * MS, 0, 0, 0))
    user = pack("<BII", 0, 1000, 1000) + strings(b"fixture", b"/home/fixture", b"/bin/bash")
    capture += block(0x220, pack("<I", len(user) + 4) + user)
    capture += block(0x215, b"".join(process(*row) for row in threads))

    capture += execve(10, 101, 100, "/usr/bin/bash") + connect(20, 101, "192.0.2.1", 0)
    capture += connect(40, 102, "192.0.2.1", 0) + execve(50, 102, 100, "/usr/bin/bash")
    capture += execve(60, 103, 1, "/tmp/example") + connect(70, 104, "192.0.2.1", 0)
    capture += execve(80, 105, 1, "/tmp/example")
    capture += execve(90, 106, 1, "/tmp/example")
    for ms, host in zip((100, 110, 120, 130, 140), (1, 1, 2, 3, 3)):
        capture += connect(ms, 106, f"192.0.2.{host}", -111)
    capture += connect(150, 107, "192.0.2.1", -111) + connect(160, 107, "192.0.2.2", -111)
    for ms, host in zip((170, 180, 190), (1, 2, 3)):
        capture += connect(ms, 108, f"192.0.2.{host}", 0)
    capture += connect(1100, 105, "192.0.2.1", 0) + connect(2200, 107, "192.0.2.3", -111)
    capture += connect(2210, 109, "192.0.2.1", -111) + connect(2220, 109, "192.0.2.2", -111)
    capture += execve(2230, 109, 1, "/tmp/example") + connect(2240, 109, "192.0.2.3", -111)
    Path("reference.scap").write_bytes(capture)
    Path("expected.json").write_text(json.dumps({
        "original": {"Run shell untrusted": [101, 102]},
    }, indent=2) + "\n")


if __name__ == "__main__":
    write_fixture()
