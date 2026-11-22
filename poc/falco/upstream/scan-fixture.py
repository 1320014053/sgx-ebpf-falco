"""Write an offline Ethernet PCAP of refused service health checks on TEST-NET addresses."""

from ipaddress import IPv4Address
from pathlib import Path
from struct import iter_unpack, pack
import sys


def checksum(data):
    words = iter_unpack("!H", data + bytes(len(data) % 2))
    total = sum(word for word, in words)
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return total ^ 0xffff


def frame(src, dst, sport, dport, sequence, ack, flags):
    src, dst = IPv4Address(src).packed, IPv4Address(dst).packed
    tcp = pack("!HHIIBBHHH", sport, dport, sequence, ack, 0x50, flags, 8192, 0, 0)
    tcp_sum = checksum(src + dst + pack("!BBH", 0, 6, len(tcp)) + tcp)
    tcp = tcp[:16] + pack("!H", tcp_sum) + tcp[18:]
    ip = pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, src, dst)
    ethernet = bytes.fromhex("0200000000020200000000010800")
    if flags & 4:
        ethernet = ethernet[6:12] + ethernet[:6] + ethernet[12:]
    return ethernet + ip[:10] + pack("!H", checksum(ip)) + ip[12:] + tcp


def write_capture(path):
    with path.open("xb") as stream:
        stream.write(pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        serial = 0

        def refused(second, src, dst, port):
            nonlocal serial
            serial += 1
            sport = 40000 + serial
            packets = (frame(src, dst, sport, port, 100, 0, 2),
                       frame(dst, src, port, sport, 0, 101, 0x14))
            for direction, packet in enumerate(packets):
                stream.write(pack("<IIII", 1700000000 + second, serial * 100 + direction,
                                  len(packet), len(packet)) + packet)

        # Two groups reach the unmodified defaults. The duplicate is a separate TCP flow.
        for victim in [1, *range(1, 26)]:
            refused(1, "192.0.2.10", f"198.51.100.{victim}", 443)
        for port in range(8000, 8015):
            refused(2, "192.0.2.20", "203.0.113.5", port)
        # A new epoch inside the Notice suppression interval, and a below-threshold control.
        for victim in range(1, 26):
            refused(310, "192.0.2.10", f"198.51.100.{victim}", 443)
        for victim in range(1, 25):
            refused(311, "192.0.2.30", f"198.51.100.{victim}", 443)


if __name__ == "__main__":
    write_capture(Path(sys.argv[1]))
