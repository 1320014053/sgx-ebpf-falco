"""Generate the E7 classic raw-IP PCAP. All TCP flows have one destination and port.

100,000 distinct sources send SYN only over one capture second. Then 180,000
sessions complete sequentially, one every 10 ms. Six packets per session keep
the input below the 64 MiB per-file replay limit. At most about 500 closed
sessions await Zeek's 5 s removal timer. After a 3,601 s capture-time gap, 16
UDP packets advance the clock without creating new TCP state (300 due timers
per dispatch). Each failed source sees only one host and one port.
"""

import argparse
from pathlib import Path
import struct


HALF_OPEN = 100_000
COMPLETE = 180_000
TAIL = 16
GAP_SECONDS = 3601
DEST = 0xc0000201
PORT = 8080


def checksum(data):
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def ipv4(src, dst, protocol, body):
    header = struct.pack("!BBHHHBBHII", 0x45, 0, 20 + len(body), 0, 0, 64, protocol, 0, src, dst)
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + body


def tcp(src, dst, sport, dport, seq, ack, flags):
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 65535, 0, 0)
    pseudo = struct.pack("!IIBBH", src, dst, 0, 6, len(header))
    header = header[:16] + struct.pack("!H", checksum(pseudo + header)) + header[18:]
    return ipv4(src, dst, 6, header)


def generate(path, half_open=HALF_OPEN, complete=COMPLETE):
    epoch = 1_700_000_000
    with path.open("xb") as out:
        out.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))

        def packet(us, data):
            sec, usec = divmod(us, 1_000_000)
            out.write(struct.pack("<IIII", epoch + sec, usec, len(data), len(data)) + data)

        for i in range(half_open):
            packet(i * 10, tcp(0x0a000001 + i, DEST, 40000, PORT, 1, 0, 0x02))
        for i in range(complete):
            client = 0x0a100001 + i
            us = half_open * 10 + i * 10_000
            packet(us, tcp(client, DEST, 40000, PORT, 1, 0, 0x02))
            packet(us + 1, tcp(DEST, client, PORT, 40000, 10, 2, 0x12))
            packet(us + 2, tcp(client, DEST, 40000, PORT, 2, 11, 0x10))
            packet(us + 3, tcp(client, DEST, 40000, PORT, 2, 11, 0x11))
            packet(us + 4, tcp(DEST, client, PORT, 40000, 11, 3, 0x11))
            packet(us + 5, tcp(client, DEST, 40000, PORT, 3, 12, 0x10))
        after_gap = us + 5 + GAP_SECONDS * 1_000_000
        tick = ipv4(0x0a000001, DEST, 17, struct.pack("!HHHH", 40000, PORT, 8, 0))
        for i in range(TAIL):
            packet(after_gap + i * 1000, tick)
    if path.stat().st_size > 64 * 1024**2:
        raise ValueError("Zeek PCAP exceeds the 64 MiB replay limit")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="new PCAP file")
    generate(parser.parse_args().out)
