"""Generate passive boundary inputs for the detector reference comparisons."""

import json
from ipaddress import IPv6Address
from pathlib import Path
from runpy import run_path
from struct import pack, unpack_from


def write_controls(directory):
    fixture = run_path(str(Path(__file__).with_name("scan-fixture.py")))
    frame, checksum = fixture["frame"], fixture["checksum"]
    rows = []

    def event(ts, kind, pid, parent, exe, **extra):
        rows.append(dict(ts=ts, event_id=f"sample-{len(rows)}", event_type=kind, pid=pid, ppid=parent, exe=exe, **extra))

    event(1, "process_exec", 10, 1, "/usr/bin/nginx")
    event(61, "process_exec", 11, 10, "/bin/sh")
    event(61, "net_connect", 11, 10, "/bin/sh", dst_ip="8.8.8.8", dst_port=443)
    event(62, "process_exec", 12, 10, "/bin/sh")
    event(120, "process_exec", 20, 1, "/usr/bin/nginx")
    event(121, "process_exec", 21, 99, "/bin/sh")
    event(122, "process_exec", 22, 20, "/usr/bin/curl")
    event(123, "net_connect", 23, 22, "/usr/bin/curl", dst_ip="8.8.8.8", dst_port=443)
    event(124, "net_connect", 22, 20, "/usr/bin/curl", dst_ip="8.8.8.8", dst_port=443)
    event(200, "file_access", 30, 1, "/usr/bin/cat", file_path="/etc/shadow", tags={"reviewed": True})
    rows.append(dict(rows[-1]))
    event(201, "privilege_change", 31, 30, "/usr/bin/sudo", uid=1000, euid=0)
    event(300, "process_exec", 40, 1, "/usr/bin/nginx")
    event(301, "process_exec", 41, 40, "/bin/sh")
    event(302, "process_fork", 42, 41, "/usr/bin/curl")
    event(304, "net_connect", 42, 41, "/usr/bin/curl", dst_ip="127.0.0.1", dst_port=80)
    (directory / "boundaries.jsonl").write_text(json.dumps({"events": rows}) + "\n")

    tetragon = []
    for i, (kind, pid, parent, binary, extra) in enumerate([
            ("process_exec", 50, 1, "/usr/bin/nginx", {}),
            ("process_exec", 51, 50, "/bin/sh", {}),
            ("process_clone", 52, 51, "/bin/sh", {}),
            ("process_listen", 52, 51, "/bin/sh", {"ip": "::1", "port": 8080}),
            ("process_connect", 52, 51, "/bin/sh", {"address": "8.8.8.8", "port": "443"}),
            ("process_kprobe", 51, 50, "/bin/sh", {"function_name": "security_file_open",
                "args": [{"type": "path_arg", "path": "/etc/sudoers"}]}),
            ("process_kprobe", 51, 50, "/bin/sh", {"function_name": "unused_marker"}),
            ("process_exit", 51, 50, "/bin/sh", {})]):
        tetragon.append({"ts": (1700000000+i)*10**9, kind: {"process": {"pid": pid, "binary": binary, "uid": 0,
            "arguments": None if i == 0 else "service test\tmode\u2003標記", "container": {"id": "example", "image": "fixture"}},
            "parent": {"pid": parent}, **extra}})
    (directory / "tetragon-mixed.jsonl").write_text("".join(json.dumps(row)+"\n" for row in tetragon))

    change = {"event_id": "uid-1", "ts": 1700000000, "event_type": "privilege_change",
              "pid": 310, "uid": 1000, "euid": 1001, "exe": "/usr/bin/sudo"}
    controls = {
        "numeric-new-user": [dict(change, metadata={"new_user": 1001})],
        "utc-second-boundary": [dict(change, ts=1700000000.9999998)],
        "special-purpose-ipv4": [
            dict(event_id="srv", ts=1, pid=60, event_type="process_exec", exe="/usr/bin/nginx"),
            dict(event_id="child", ts=2, pid=61, ppid=60, event_type="process_exec", exe="/usr/bin/curl"),
            dict(event_id="net", ts=3, pid=61, ppid=60, event_type="net_connect", exe="/usr/bin/curl",
                 dst_ip="192.0.0.8", dst_port=80)],
        "tetragon-rfc3339": [
            {"time": ts, "process_exec": {"process": {"pid": pid, "binary": binary}, "parent": {"pid": parent}}}
            for ts, pid, parent, binary in [("2025-01-01T12:00:00Z", 41, 1, "/usr/bin/nginx"),
                                            ("2025-01-01T12:02:00Z", 42, 41, "/bin/sh")]]}
    for name, events in controls.items():
        (directory / (name + ".jsonl")).write_text("".join(json.dumps(e, ensure_ascii=False)+"\n" for e in events))

    records = []
    def put(ts, payload):
        records.append((ts, payload))

    def healthcheck(ts, src, dst, sport, dport, outcome):
        put(ts, frame(src, dst, sport, dport, 100, 0, 2))
        if outcome == "timeout":
            return
        if outcome == "refused":
            put(ts + 1, frame(dst, src, dport, sport, 0, 101, 20))
            return
        put(ts + 1, frame(dst, src, dport, sport, 200, 101, 18))
        put(ts + 2, frame(src, dst, sport, dport, 101, 201, 16))
        put(ts + 3, frame(src, dst, sport, dport, 101, 201, 20 if outcome == "reset" else 17))

    def save(name, endian="<", nano=False, link=1, extra_ns=0):
        with (directory / name).open("xb") as stream:
            stream.write(pack(endian + "IHHIIII", 0xa1b23c4d if nano else 0xa1b2c3d4, 2, 4, 0, 0, 65535, link))
            for us, packet in sorted(records, key=lambda row: row[0]):
                sec, fraction = divmod(us, 1_000_000)
                stream.write(pack(endian + "4I", 1700000000 + sec, fraction * (1000 if nano else 1) + extra_ns,
                                  len(packet), len(packet)) + packet)
        records.clear()

    for i in range(15):
        for src, outcome in [("192.0.2.40", "established"), ("192.0.2.41", "reset"), ("192.0.2.42", "timeout")]:
            healthcheck(1_000_000 + 100*i, src, "198.51.100.1", 40000+i, 9000+i, outcome)
    healthcheck(8_000_000, "192.0.2.50", "198.51.100.2", 45000, 443, "established")
    save("states.pcap")

    for i in range(15):
        healthcheck(1_000_000 + 100*i, "192.0.2.40", "198.51.100.1", 40000+i, 9000+i, "established")
        records.pop()  # through the final handshake ACK
    handshakes = records.copy()
    save("successful-handshakes.pcap")
    for i in range(0, len(handshakes), 3):
        syn, syn_ack, ack = handshakes[i:i+3]
        records.extend([(syn[0], syn_ack[1]), (syn_ack[0], syn[1]), ack])
    save("reordered-successful-handshakes.pcap")
    records.extend((us, bytes.fromhex("ff030021") + packet[14:]) for us, packet in handshakes)
    save("ppp-serial-handshakes.pcap", link=50)

    base_capture = directory / "healthchecks.pcap"
    if not base_capture.exists():
        fixture["write_capture"](base_capture)
    classic = base_capture.read_bytes()
    pos = 24
    while pos < len(classic):
        sec, us, size, wire = unpack_from("<4I", classic, pos)
        put((sec-1700000000)*1_000_000 + us, classic[pos+16:pos+16+size])
        pos += 16 + size
    healthchecks = records.copy()
    save("nanosecond-healthchecks.pcap", nano=True, extra_ns=900)
    records.extend((us, bytes.fromhex("ff030021") + packet[14:]) for us, packet in healthchecks)
    save("ppp-serial-healthchecks.pcap", link=50)

    for second, ports in [(1, range(14)), (310, range(14, 29)), (620, range(15)), (3950, range(15))]:
        for i in ports:
            healthcheck(second*1_000_000 + 100*i, "192.0.2.60", "203.0.113.1", 45000+i, 8100+i, "refused")
    save("epochs.pcap", ">", True)

    for second, src in [(1, "192.0.2.60"), (601, "192.0.2.61"), (901, "192.0.2.60"),
                        (3602, "192.0.2.60"), (4501, "192.0.2.60")]:
        for i in range(15):
            healthcheck(second*1_000_000 + 100*i, src, "203.0.113.1", 45000+i, 8100+i, "refused")
    for second in sorted((*range(30, 8220, 30), 3603)):
        marker = second in (930, 3603, 3690, 4320, 4590, 8190)
        healthcheck(second*1_000_000, "192.0.2.251" if marker else "192.0.2.250",
                    "203.0.113.2", 50000+second, 443, "established")
    save("suppression-expiry.pcap")

    for i in range(15):
        a, b = IPv6Address("2001:db8::10").packed, IPv6Address("2001:db8::20").packed
        for j, (src, dst, sport, dport, seq, ack, flags) in enumerate([
                (a,b,46000+i,8200+i,100,0,2), (b,a,8200+i,46000+i,0,101,20)]):
            tcp = pack("!HHIIBBHHH",sport,dport,seq,ack,0x50,flags,8192,0,0)
            total = checksum(src + dst + pack("!I3xB",len(tcp),6) + tcp)
            tcp = tcp[:16] + pack("!H",total) + tcp[18:]
            ip = pack("!IHBB",6 << 28,len(tcp),6,64) + src + dst
            put(1_000_000 + 100*i + j, bytes.fromhex("0200000000020200000000018100000186dd") + ip + tcp)
    ipv6 = records.copy()
    save("ipv6-vlan.pcap")
    for name, header in [("ipv6", "ff030057"), ("mpls", "ff0302810001004000020140")]:
        records.extend((us, bytes.fromhex(header) + packet[18:]) for us, packet in ipv6)
        save(f"ppp-serial-{name}.pcap", link=50)

    for i in range(15):
        put(1_000_000 + 100*i, frame("198.51.100.8", "192.0.2.70", 8300+i, 47000+i, 300, 101, 18))
    save("reverse-eof.pcap")

    for i in range(15):
        for side, (src, dst, sport, dport, seq, ack, flags) in enumerate([
                ("192.0.2.80","198.51.100.9",48000+i,8400+i,100,0,2),
                ("198.51.100.9","192.0.2.80",8400+i,48000+i,0,101,20)]):
            pkt = frame(src,dst,sport,dport,seq,ack,flags)
            for part, (start, end, bits) in enumerate([(8,20,1), (0,8,0x2000)]):
                hdr = bytearray(pkt[14:34])
                hdr[2:8] = pack("!HHH",20+end-start,2*i+side+1,bits)
                hdr[10:12] = bytes(2)
                hdr[10:12] = pack("!H",checksum(hdr))
                put(1_000_000+100*i+2*side+part, pkt[:14]+hdr+pkt[34+start:34+end])
    save("fragments.pcap")

    def block(kind, data):
        data += bytes(-len(data) % 4)
        return pack("<II",kind,12+len(data)) + data + pack("<I",12+len(data))
    for name, extra_ns in [("pcapng", 0), ("pcapng-submicrosecond", 900)]:
        ng = block(0x0a0d0d0a, pack("<IHHq",0x1a2b3c4d,1,0,-1))
        ng += block(1,pack("<HHIHHB3xHH",1,0,65535,9,1,9,0,0))
        for us, packet in ipv6:
            ns = 1700000000*10**9 + us*1000 + extra_ns
            ng += block(6,pack("<5I",0,ns >> 32,ns & 0xffffffff,len(packet),len(packet)) + packet)
        (directory / (name + ".pcap")).write_bytes(ng)
